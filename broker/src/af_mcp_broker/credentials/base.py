from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar

import structlog

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)


class CredentialKind(StrEnum):
    BEARER = "bearer"
    X509_PROXY_REF = "x509_proxy_ref"
    NONE = "none"


class ExecutionModel(StrEnum):
    DELEGATED = "delegated"
    ON_BEHALF = "on_behalf"


@dataclass(frozen=True)
class IssuedCredential:
    """A resolved credential ready for server-side injection.

    Credentials NEVER transit to the LLM or client — they are injected
    server-side by the broker when forwarding requests to a target service.
    The payload for x509 holds only a handle/path reference, never the
    raw key material or passphrase.
    """

    cred_class: str  # "oidc_native" | "service_account" | "user_x509"
    target: str
    kind: CredentialKind
    expires_at: float  # epoch seconds (UTC)
    # bearer: {"access_token": ..., "token_type": "Bearer"}
    # x509:   {"proxy_handle": ..., "proxy_path": ..., "delivery": "direct"}
    # service:{"access_token": ..., "on_behalf_of": ..., "token_type": "Bearer"}
    payload: dict
    audit_id: str
    source: str  # which provider backend produced this credential
    execution_model: ExecutionModel


class NeedsUnlock(Exception):
    """Raised when a credential requires user interaction (e.g. passphrase entry)
    before it can be issued. The caller should surface `unlock_endpoint` to the
    user so they know where to POST the passphrase.
    """

    def __init__(
        self,
        target: str,
        reason: str,
        unlock_endpoint: str = "/v1/x509/proxy",
    ) -> None:
        self.target = target
        self.reason = reason
        self.unlock_endpoint = unlock_endpoint
        super().__init__(
            f"Credential for {target!r} needs unlock ({reason}); "
            f"POST passphrase to {unlock_endpoint}"
        )


class CredentialProvider(ABC):
    """Abstract base for all credential providers.

    Subclasses declare their ``cred_class`` and ``execution_model`` as class
    variables so the registry can inspect them without instantiation.
    """

    cred_class: ClassVar[str]
    execution_model: ClassVar[ExecutionModel]

    @abstractmethod
    async def handles(self, target: str) -> bool:
        """Return True if this provider can issue credentials for *target*."""

    @abstractmethod
    async def is_linked(self, principal: Principal) -> bool:
        """Whether this principal has completed the external-identity linkage
        this provider needs to mint a credential. Called BEFORE `issue()` to
        surface a clean 404/403 instead of an opaque failure inside `issue()`.
        Each provider owns the concrete check appropriate to its storage
        backend — Keycloak federated_identity for OIDC providers, filesystem
        presence for x509, KV lookup for future providers, etc.

        This is an authoritative check, not a hint: callers gate on it before
        ever calling `issue()`, so a False here must mean the credential
        genuinely cannot be minted yet, not merely "we didn't check."
        """

    @abstractmethod
    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,
    ) -> IssuedCredential:
        """Return a usable credential or raise NeedsUnlock / well-typed errors.

        Implementations must:
        - Check the cache before hitting any external service.
        - NEVER log or persist passphrases, private keys, or refresh tokens.
        - For ON_BEHALF providers, always write an audit record.
        """

    async def revoke(self, principal: Principal, target: str) -> None:  # noqa: B027
        """Revoke / purge a cached credential.  Default is a no-op.

        X509Provider overrides this to zero-overwrite the proxy file before
        unlinking it, then removes the cache entry.
        """


def _new_audit_id() -> str:
    """Generate a short, collision-resistant audit correlation ID."""
    return uuid.uuid4().hex


class CredentialRegistry:
    """Maps target names to providers.

    Loaded at startup from ``backends.yaml`` (via ``Settings.backends_file``).
    Targets are registered explicitly; an unknown target raises ``KeyError``
    rather than falling through silently — fail-closed is the right default for
    a credential broker.
    """

    def __init__(self, providers: list[CredentialProvider]) -> None:
        # Ordered list for `handles()` scanning; explicit map populated by register()
        self._providers: list[CredentialProvider] = list(providers)
        # target -> provider (populated by register() or auto-scanned at startup)
        self._target_map: dict[str, CredentialProvider] = {}
        self._log = structlog.get_logger(__name__).bind(component="CredentialRegistry")

    def register(self, target: str, provider: CredentialProvider) -> None:
        """Explicitly bind *target* to *provider*.

        Call this from the startup routine after reading ``backends.yaml``.
        """
        if target in self._target_map:
            existing = self._target_map[target]
            self._log.warning(
                "credential_registry.overwrite",
                target=target,
                old_provider=type(existing).__name__,
                new_provider=type(provider).__name__,
            )
        self._target_map[target] = provider
        self._log.info(
            "credential_registry.registered",
            target=target,
            provider=type(provider).__name__,
            cred_class=provider.cred_class,
            execution_model=provider.execution_model,
        )

    async def resolve(self, target: str) -> CredentialProvider:
        """Return the provider bound to *target*, or raise ``KeyError``."""
        if target in self._target_map:
            return self._target_map[target]
        # Fall back to scanning the ordered provider list via handles()
        for provider in self._providers:
            if await provider.handles(target):
                self._log.debug(
                    "credential_registry.resolved_via_scan",
                    target=target,
                    provider=type(provider).__name__,
                )
                return provider
        raise KeyError(
            f"No credential provider registered for target {target!r}. "
            "Check backends.yaml or call CredentialRegistry.register()."
        )

    async def issue(
        self,
        principal: Principal,
        target: str,
        **kwargs,
    ) -> IssuedCredential:
        """Convenience: resolve the provider for *target* and call issue()."""
        provider = await self.resolve(target)
        self._log.debug(
            "credential_registry.issuing",
            target=target,
            uid=principal.uid,
            provider=type(provider).__name__,
        )
        return await provider.issue(principal, target, **kwargs)

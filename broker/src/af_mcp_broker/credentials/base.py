from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, ClassVar

import structlog
from pydantic import SecretBytes

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)


class CredentialKind(str, Enum):
    BEARER = "bearer"
    X509_PROXY_REF = "x509_proxy_ref"
    NONE = "none"


class ExecutionModel(str, Enum):
    DELEGATED = "delegated"
    ON_BEHALF = "on_behalf"


from dataclasses import dataclass, field


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

    async def revoke(self, principal: Principal, target: str) -> None:
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

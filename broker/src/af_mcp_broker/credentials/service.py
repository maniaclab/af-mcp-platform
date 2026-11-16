from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

import anyio
import jwt
import structlog

from af_mcp_broker.audit.logger import AuditRecord, write_audit
from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
)

if TYPE_CHECKING:
    import httpx2
    from pydantic import SecretBytes

    from af_mcp_broker.config import Settings
    from af_mcp_broker.principal import Principal

log = structlog.get_logger(__name__)

# Targets served by the service provider
_DEFAULT_SERVICE_TARGETS: frozenset[str] = frozenset(
    {"openmagic", "docs", "monitoring", "metadata"}
)

# Refresh the service token this many seconds before it expires to avoid
# issuing credentials backed by an about-to-expire service token.
_SERVICE_TOKEN_REFRESH_BUFFER_SECONDS = 60


@dataclass(frozen=True)
class _ServiceToken:
    """A service token with the expiry it was minted with.

    Immutable so a reader always sees a token and the expiry that belongs to
    it, even when another task refreshes the cache in between.
    """

    token: str
    # None: the token carries no expiry (a static token without an exp claim)
    expires_at: float | None


class ServiceProvider(CredentialProvider):
    """Issues on-behalf-of credentials using the AF service account.

    This provider uses a single shared AF service credential (sourced from an
    env var or a mounted secret file) to call downstream services *on behalf of*
    a named human principal.  Every issuance writes an audit record so the real
    user is always traceable in AF logs even though the downstream sees the
    service account identity.

    The service token is cached in-process (not per-user) and refreshed via the
    OAuth2 client_credentials grant before it expires.  Passphrases, private
    keys, and refresh tokens are never persisted.
    """

    cred_class: ClassVar[str] = "service_account"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.ON_BEHALF

    def __init__(
        self,
        settings: Settings,
        targets: frozenset[str] = _DEFAULT_SERVICE_TARGETS,
        *,
        http_client: httpx2.AsyncClient,
    ) -> None:
        self._settings = settings
        self._http_client = http_client
        self._targets = targets
        self._log = structlog.get_logger(__name__).bind(provider="ServiceProvider")

        # Shared (non-per-user) service token cache
        self._service_token: _ServiceToken | None = None
        self._static_no_expiry_warned = False
        self._refresh_lock = asyncio.Lock()

    async def is_linked(self, principal: Principal) -> bool:  # noqa: ARG002 (interface)
        """Return True unconditionally — the broker's own service account is the credential source, so there is no user-side linkage to check."""
        return True

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,  # noqa: ARG002 (interface)
    ) -> IssuedCredential:
        """Return a bearer credential backed by the AF service account.

        Always records an audit entry — this is the "AF logs the real user"
        invariant for on-behalf credentials.
        """
        svc_token = await self._get_service_token(min_remaining_seconds)
        audit_id = uuid.uuid4().hex

        cred = IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.BEARER,
            expires_at=svc_token.expires_at,
            payload={
                "access_token": svc_token.token,
                "on_behalf_of": principal.email,
                "token_type": "Bearer",
            },
            audit_id=audit_id,
            source="af_service_account",
            execution_model=self.execution_model,
        )

        # Audit record is mandatory for all ON_BEHALF issuances.
        await self._write_audit(principal, target, audit_id)

        self._log.info(
            "service.issue.success",
            uid=principal.uid,
            target=target,
            on_behalf_of=principal.email,
            audit_id=audit_id,
        )
        return cred

    # ------------------------------------------------------------------
    # Service token management
    # ------------------------------------------------------------------

    def _is_usable(self, min_remaining_seconds: int) -> bool:
        """Return True when the cached token outlives both the refresh buffer and *min_remaining_seconds*."""
        if self._service_token is None:
            return False
        if self._service_token.expires_at is None:
            return True
        remaining = self._service_token.expires_at - time.time()
        return (
            remaining > _SERVICE_TOKEN_REFRESH_BUFFER_SECONDS
            and remaining >= min_remaining_seconds
        )

    async def _get_service_token(self, min_remaining_seconds: int = 0) -> _ServiceToken:
        """Return a service token with at least *min_remaining_seconds* left, refreshing if needed.

        A freshly refreshed token is returned even when its lifetime is still
        shorter than requested, the same as the per-user providers.
        """
        if self._service_token is not None and self._is_usable(min_remaining_seconds):
            return self._service_token

        async with self._refresh_lock:
            # Re-check under lock to avoid double-refresh
            if self._service_token is not None and self._is_usable(
                min_remaining_seconds
            ):
                return self._service_token

            token, expires_at = await self._refresh_service_token()
            self._service_token = _ServiceToken(token, expires_at)
            return self._service_token

    def _static_token_expires_at(self, token: str, source: str) -> float | None:
        """Return the expiry of a static *token* from its JWT ``exp`` claim, None when it carries none.

        The signature is deliberately not verified: the broker is not the
        token's audience and only needs the lifetime the issuer stamped on it.
        A token without a readable ``exp`` (opaque, or a JWT lacking the
        claim) is treated as non-expiring and logged once at warning level,
        because the broker cannot tell when it stops working.

        Raises:
            RuntimeError: if the token's ``exp`` is already in the past.

        """
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.DecodeError:
            claims = {}
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, int | float):
            if not self._static_no_expiry_warned:
                self._static_no_expiry_warned = True
                self._log.warning("service.token.static_no_expiry", source=source)
            return None
        if exp <= time.time():
            raise RuntimeError(
                f"The static AF service token from {source} has expired "
                f"(exp={exp}); replace it."
            )
        return float(exp)

    async def _refresh_service_token(self) -> tuple[str, float | None]:
        """Perform the client_credentials grant to get a fresh service token.

        Token source priority:
          1. ``AF_SERVICE_TOKEN`` env var (plain token string, for dev/testing).
          2. ``AF_SERVICE_TOKEN_FILE`` env var pointing to a mounted secret file.
          3. OAuth2 client_credentials grant using ``AF_SERVICE_CLIENT_ID`` /
             ``AF_SERVICE_CLIENT_SECRET`` against the Keycloak token endpoint.

        The second element is the token's expiry in epoch seconds, or None for
        a static token that carries none.

        Never stores the client secret or any refresh token.
        """
        # Option 1: static token from env (dev/testing shortcut only)
        static_token = os.environ.get("AF_SERVICE_TOKEN")
        if static_token:
            self._log.debug("service.token.from_env")
            return static_token, self._static_token_expires_at(
                static_token, "AF_SERVICE_TOKEN"
            )

        # Option 2: token file (Kubernetes Secret mounted as file)
        token_file = os.environ.get("AF_SERVICE_TOKEN_FILE")
        if token_file:
            token = (await anyio.Path(token_file).read_text()).strip()
            if not token:
                # An empty mount (e.g. a Secret not yet populated) must fail
                # loudly, not issue "Bearer " credentials to every backend.
                raise RuntimeError(f"AF_SERVICE_TOKEN_FILE {token_file} is empty.")
            self._log.debug("service.token.from_file", path=token_file)
            return token, self._static_token_expires_at(
                token, f"AF_SERVICE_TOKEN_FILE {token_file}"
            )

        # Option 3: OAuth2 client_credentials grant
        client_id = os.environ.get("AF_SERVICE_CLIENT_ID")
        client_secret = os.environ.get("AF_SERVICE_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise RuntimeError(
                "No AF service credential configured. Set AF_SERVICE_TOKEN, "
                "AF_SERVICE_TOKEN_FILE, or AF_SERVICE_CLIENT_ID + "
                "AF_SERVICE_CLIENT_SECRET."
            )

        token_endpoint = f"{self._settings.oidc_backchannel_url.rstrip('/')}/protocol/openid-connect/token"
        resp = await self._http_client.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        data = resp.json()

        access_token: str = data["access_token"]
        expires_in: int = int(data.get("expires_in", 300))
        expires_at: float = time.time() + expires_in

        self._log.info("service.token.refreshed", expires_at=expires_at)
        # The client_secret is only referenced locally and never stored
        return access_token, expires_at

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    async def _write_audit(
        self, principal: Principal, target: str, audit_id: str
    ) -> None:
        """Write an audit record for this on-behalf issuance.

        Delegates to ``af_mcp_broker.audit.logger.write_audit`` so that all
        audit output goes through a single, consistently-formatted channel.
        """
        record = AuditRecord(
            principal_sub=principal.subject,
            principal_uid=principal.uid,
            permission=self.cred_class,
            target=target,
            action="credential.issued",
            action_type="state_change",
            args_summary=(
                f"on_behalf_of={principal.email} "
                f"username={principal.unixname or '<no-posix-identity>'}"
            ),
            timestamp=time.time(),
            request_id=audit_id,
            audit_id=audit_id,
            execution_model=self.execution_model.value,
        )
        await write_audit(record)

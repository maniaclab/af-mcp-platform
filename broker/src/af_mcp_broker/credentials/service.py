from __future__ import annotations

import asyncio
import os
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

import structlog
from pydantic import SecretBytes

from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)

# Targets served by the service provider
_DEFAULT_SERVICE_TARGETS: frozenset[str] = frozenset(
    {"openmagic", "docs", "monitoring", "metadata"}
)

# Refresh the service token this many seconds before it expires to avoid
# issuing credentials backed by an about-to-expire service token.
_SERVICE_TOKEN_REFRESH_BUFFER_SECONDS = 60


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
    ) -> None:
        self._settings = settings
        self._targets = targets
        self._log = structlog.get_logger(__name__).bind(provider="ServiceProvider")

        # Shared (non-per-user) service token cache
        self._service_token: str | None = None
        self._service_token_expires_at: float = 0.0
        self._refresh_lock = asyncio.Lock()

    async def handles(self, target: str) -> bool:
        return target in self._targets

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,  # noqa: ARG002 (interface)
        passphrase: SecretBytes | None = None,  # noqa: ARG002 (interface)
    ) -> IssuedCredential:
        """Return a bearer credential backed by the AF service account.

        Always records an audit entry — this is the "AF logs the real user"
        invariant for on-behalf credentials.
        """
        svc_token = await self._get_service_token()
        audit_id = uuid.uuid4().hex

        cred = IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.BEARER,
            expires_at=self._service_token_expires_at,
            payload={
                "access_token": svc_token,
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

    async def _get_service_token(self) -> str:
        """Return a valid service token, refreshing via client_credentials if needed."""
        remaining = self._service_token_expires_at - time.time()
        if (
            self._service_token is not None
            and remaining > _SERVICE_TOKEN_REFRESH_BUFFER_SECONDS
        ):
            return self._service_token

        async with self._refresh_lock:
            # Re-check under lock to avoid double-refresh
            remaining = self._service_token_expires_at - time.time()
            if (
                self._service_token is not None
                and remaining > _SERVICE_TOKEN_REFRESH_BUFFER_SECONDS
            ):
                return self._service_token

            token, expires_at = await self._refresh_service_token()
            self._service_token = token
            self._service_token_expires_at = expires_at
            return self._service_token

    async def _refresh_service_token(self) -> tuple[str, float]:
        """Perform the client_credentials grant to get a fresh service token.

        Token source priority:
          1. ``AF_SERVICE_TOKEN`` env var (plain token string, for dev/testing).
          2. ``AF_SERVICE_TOKEN_FILE`` env var pointing to a mounted secret file.
          3. OAuth2 client_credentials grant using ``AF_SERVICE_CLIENT_ID`` /
             ``AF_SERVICE_CLIENT_SECRET`` against the Keycloak token endpoint.

        Never stores the client secret or any refresh token.
        """
        # Option 1: static token from env (dev/testing shortcut only)
        static_token = os.environ.get("AF_SERVICE_TOKEN")
        if static_token:
            self._log.debug("service.token.from_env")
            # Assume it expires far in the future — caller will never refresh
            return static_token, time.time() + 3600

        # Option 2: token file (Kubernetes Secret mounted as file)
        token_file = os.environ.get("AF_SERVICE_TOKEN_FILE")
        if token_file:
            token = Path(token_file).read_text().strip()
            self._log.debug("service.token.from_file", path=token_file)
            return token, time.time() + 3600

        # Option 3: OAuth2 client_credentials grant
        client_id = os.environ.get("AF_SERVICE_CLIENT_ID")
        client_secret = os.environ.get("AF_SERVICE_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise RuntimeError(
                "No AF service credential configured. Set AF_SERVICE_TOKEN, "
                "AF_SERVICE_TOKEN_FILE, or AF_SERVICE_CLIENT_ID + "
                "AF_SERVICE_CLIENT_SECRET."
            )

        token_endpoint = (
            f"{self._settings.keycloak_issuer.rstrip('/')}"
            "/protocol/openid-connect/token"
        )
        resp = await get_http_client().post(
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
        This import is deferred to avoid a circular dependency at module load.
        """
        try:
            from af_mcp_broker.audit import logger as audit_logger
            from af_mcp_broker.audit.logger import AuditRecord

            record = AuditRecord(
                principal_sub=principal.subject,
                principal_uid=principal.uid,
                capability=self.cred_class,
                target=target,
                action="credential.issued",
                action_type="state_change",
                args_summary=f"on_behalf_of={principal.email} username={principal.unixname}",
                timestamp=time.time(),
                request_id=audit_id,
                audit_id=audit_id,
                execution_model=self.execution_model.value,
            )
            await audit_logger.write_audit(record)
        except ImportError:
            # audit module not yet implemented — log a warning so it is visible
            self._log.warning(
                "service.audit.module_missing",
                audit_id=audit_id,
                target=target,
                uid=principal.uid,
                on_behalf_of=principal.email,
            )

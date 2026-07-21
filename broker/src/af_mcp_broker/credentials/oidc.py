from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING, ClassVar

import structlog
from fastapi import HTTPException
from pydantic import SecretBytes

from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)

# Targets served by the OIDC provider — config-overridable at construction time
_DEFAULT_OIDC_TARGETS: frozenset[str] = frozenset({"rucio", "opendata", "af-internal"})


class OIDCProvider(CredentialProvider):
    """Issues delegated OIDC bearer tokens by retrieving the user's brokered
    IAM token from Keycloak.

    Auth flow:
      1. User authenticates to Keycloak (realm: *connect*) and receives a
         Keycloak access token — this is ``principal.raw_token``.
      2. Keycloak has an identity provider link to ATLAS IAM; it stores the
         brokered IAM token internally.
      3. We call the Keycloak stored-brokered-token endpoint:
           GET {KEYCLOAK_ISSUER}/broker/{ATLAS_IAM_BROKER_ALIAS}/token
           Authorization: Bearer {principal.raw_token}
         to retrieve the user's current ATLAS IAM access token.
      4. That IAM token is what downstream services (rucio-mcp, etc.) expect.
         Rucio itself performs the RFC 8693 ``aud=rucio`` token exchange
         independently — we hand it the IAM token and it handles the rest.

    Credentials never transit to the LLM/client; they are injected
    server-side by the broker.
    """

    cred_class: ClassVar[str] = "oidc_native"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED

    def __init__(
        self,
        settings: Settings,
        cache: CredentialCache,
        targets: frozenset[str] = _DEFAULT_OIDC_TARGETS,
    ) -> None:
        self._settings = settings
        self._cache = cache
        self._targets = targets
        self._log = structlog.get_logger(__name__).bind(provider="OIDCProvider")

    async def handles(self, target: str) -> bool:
        return target in self._targets

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,  # noqa: ARG002 (interface)
    ) -> IssuedCredential:
        """Return a bearer credential carrying the user's ATLAS IAM token.

        Raises:
            HTTPException(403): if the principal has no linked IAM identity.
            HTTPException(401): if the Keycloak brokered-token endpoint rejects
                the principal's token (session expired — user must re-link).
            HTTPException(404): if no brokered token is stored yet (user must
                visit /v1/identities/link to connect their ATLAS account).
        """
        self._log.debug(
            "oidc.issue.start",
            uid=principal.uid,
            target=target,
        )

        if principal.iam_sub is None:
            raise HTTPException(
                status_code=403,
                detail=(
                    "ATLAS IAM identity not linked. "
                    "Visit /v1/identities/link to connect your ATLAS account."
                ),
            )

        # Cache hit — avoid a round-trip to Keycloak
        cached = await self._cache.get(
            principal.uid, target, min_remaining=min_remaining_seconds
        )
        if cached is not None:
            self._log.debug("oidc.issue.cache_hit", uid=principal.uid, target=target)
            return cached

        iam_token, expires_at = await self._fetch_brokered_token(principal)

        audit_id = uuid.uuid4().hex
        cred = IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.BEARER,
            expires_at=expires_at,
            payload={
                "access_token": iam_token,
                "token_type": "Bearer",
            },
            audit_id=audit_id,
            source="keycloak_brokered_token",
            execution_model=self.execution_model,
        )

        await self._cache.put(principal.uid, target, cred)
        self._log.info(
            "oidc.issue.success",
            uid=principal.uid,
            target=target,
            audit_id=audit_id,
            expires_at=expires_at,
        )
        return cred

    async def _fetch_brokered_token(self, principal: Principal) -> tuple[str, float]:
        """Call Keycloak's stored-brokered-token endpoint.

        Returns ``(iam_access_token, expires_at_epoch)``.

        Raises HTTPException on 401 (session expired) and 404 (no stored
        token — user must re-link).
        """
        broker_token_url = (
            f"{self._settings.keycloak_issuer.rstrip('/')}"
            f"/broker/{self._settings.atlas_iam_broker_alias}/token"
        )

        resp = await get_http_client().get(
            broker_token_url,
            headers={
                "Authorization": f"Bearer {principal.raw_token.get_secret_value()}"
            },
            timeout=10.0,
        )

        if resp.status_code == 401:
            raise HTTPException(
                status_code=401,
                detail=(
                    "Your Keycloak session has expired or the ATLAS IAM "
                    "identity link is invalid. Please re-authenticate and "
                    "visit /v1/identities/link to reconnect your ATLAS account."
                ),
            )
        if resp.status_code == 404:
            raise HTTPException(
                status_code=404,
                detail=(
                    "No ATLAS IAM token stored for your account. "
                    "Visit /v1/identities/link to connect your ATLAS account."
                ),
            )

        resp.raise_for_status()
        data = resp.json()

        iam_access_token: str = data["access_token"]
        # Keycloak returns expires_in (relative seconds); compute absolute epoch
        expires_in: int = int(data.get("expires_in", 300))
        expires_at: float = time.time() + expires_in

        return iam_access_token, expires_at

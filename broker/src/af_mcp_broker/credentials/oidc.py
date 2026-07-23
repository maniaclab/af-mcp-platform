from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

import httpx
import structlog
from fastapi import HTTPException

from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials.cache import CredentialCache
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)

# Targets served by the OIDC provider — config-overridable at construction time
_DEFAULT_OIDC_TARGETS: frozenset[str] = frozenset({"rucio", "opendata", "af-internal"})

# is_linked() probes Keycloak's stored-brokered-token endpoint, which is a
# real network round-trip; cache the result per uid for this many seconds so
# a burst of calls for the same user (e.g. the aggregator checking several
# tool calls in quick succession) costs one Keycloak request rather than one
# per call. 60s is a defensible middle ground: short enough that a user who
# just completed the linking flow sees it reflected almost immediately, long
# enough to absorb realistic call bursts without hammering Keycloak.
_LINK_CACHE_TTL_SECONDS = 60


@dataclass
class _LinkStatus:
    linked: bool
    checked_at: float  # time.monotonic()


class OIDCProvider(CredentialProvider):
    """Issues delegated OIDC bearer tokens by retrieving the user's brokered
    IAM token from Keycloak.

    Auth flow:
      1. User authenticates to Keycloak (realm: *connect*) and receives a
         Keycloak access token — this is ``principal.raw_token``.
      2. Keycloak has an identity provider link to ATLAS IAM; it stores the
         brokered IAM token internally.
      3. We call the Keycloak stored-brokered-token endpoint:
           GET {OIDC_ISSUER}/broker/{OIDC_IDP_ALIAS}/token
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
        self._link_cache: dict[int, _LinkStatus] = {}
        self._log = structlog.get_logger(__name__).bind(provider="OIDCProvider")

    async def handles(self, target: str) -> bool:
        return target in self._targets

    async def is_linked(self, principal: Principal) -> bool:
        """Return True if Keycloak holds a brokered ATLAS IAM token for *principal*.

        Probes ``GET {oidc_issuer}/broker/{oidc_idp_alias}/token`` with the
        principal's own bearer token: HTTP 200 means Keycloak has a stored
        brokered token (the user completed IdP linking). Any other outcome —
        a 4xx/5xx response or an unreachable Keycloak — is treated as "not
        linked", since a credential broker should fail closed rather than
        assume linkage it cannot verify. Results are cached per uid for
        ``_LINK_CACHE_TTL_SECONDS`` seconds (see module docstring comment).
        """
        now = time.monotonic()
        cached = self._link_cache.get(principal.uid)
        if cached is not None and (now - cached.checked_at) <= _LINK_CACHE_TTL_SECONDS:
            return cached.linked

        linked = await self._probe_linked(principal)
        self._link_cache[principal.uid] = _LinkStatus(linked=linked, checked_at=now)
        return linked

    async def _probe_linked(self, principal: Principal) -> bool:
        broker_token_url = (
            f"{self._settings.oidc_issuer.rstrip('/')}"
            f"/broker/{self._settings.oidc_idp_alias}/token"
        )
        headers = {"Authorization": f"Bearer {principal.raw_token.get_secret_value()}"}
        try:
            resp = await get_http_client().head(
                broker_token_url, headers=headers, timeout=10.0
            )
            if resp.status_code == 405:
                # Some Keycloak versions don't allow HEAD on this endpoint —
                # fall back to a minimal GET and discard the body.
                resp = await get_http_client().get(
                    broker_token_url, headers=headers, timeout=10.0
                )
        except httpx.HTTPError as exc:
            self._log.warning(
                "oidc.is_linked.probe_failed", uid=principal.uid, error=str(exc)
            )
            return False
        return resp.status_code == 200

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,  # noqa: ARG002 (interface)
    ) -> IssuedCredential:
        """Return a bearer credential carrying the user's ATLAS IAM token.

        Callers are expected to have gated on ``is_linked()`` already (see
        ``api/credentials.py``); this method assumes linkage and only handles
        the narrower failure modes of the fetch itself.

        Raises:
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
            f"{self._settings.oidc_issuer.rstrip('/')}"
            f"/broker/{self._settings.oidc_idp_alias}/token"
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

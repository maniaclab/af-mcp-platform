from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

import structlog
from fastapi import HTTPException
from pydantic import AnyHttpUrl, BaseModel, SecretStr, field_validator

from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)

# An access token is refreshed once fewer than this many seconds remain,
# regardless of the caller's requested `min_remaining_seconds` — see issue
# #66 decision D4. Protects against handing out a credential that expires
# before a slow downstream call can use it.
_MIN_REFRESH_WINDOW_SECONDS = 300


class StoredOAuthCredential(BaseModel):
    """Normalized OAuth 2.1 token pair persisted in a ``TokenStore``.

    The provider translates whichever token-response shape a backend
    authorization server returns into this shape before persisting, so the
    storage schema stays stable when a backend changes its response format.
    """

    alias: str
    subject: str
    access_token: SecretStr
    refresh_token: SecretStr | None
    expires_at: datetime
    refresh_expires_at: datetime | None
    scope: list[str]
    issuer: str
    token_endpoint: AnyHttpUrl
    metadata: dict[str, Any] = {}

    @field_validator("expires_at", "refresh_expires_at")
    @classmethod
    def _require_tz_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at/refresh_expires_at must be tz-aware (UTC)")
        return value


class VersionConflict(Exception):
    """Raised by ``TokenStore.write_cas`` when ``expected_version`` is stale."""


class TokenStore(Protocol):
    """Abstract persistence for per-subject, per-alias OAuth 2.1 credentials.

    Implementations provide compare-and-swap (CAS) semantics on write so
    concurrent broker replicas racing to refresh the same token never
    silently clobber a fresher write with a stale one.
    """

    async def get(
        self, subject: str, alias: str
    ) -> tuple[StoredOAuthCredential, int] | None:
        """Return the stored credential and its version, or None if absent."""
        ...

    async def write_cas(
        self,
        subject: str,
        alias: str,
        cred: StoredOAuthCredential,
        expected_version: int | None,
    ) -> int:
        """Write *cred*, enforcing CAS against *expected_version*.

        ``expected_version=None`` means "create; fail if an entry already
        exists". Returns the new version on success; raises
        ``VersionConflict`` when *expected_version* does not match the
        entry's current version.
        """
        ...

    async def delete(self, subject: str, alias: str) -> None:
        """Remove the stored credential, if any. Idempotent."""
        ...


class InMemoryTokenStore:
    """In-process ``TokenStore`` — single-replica only, lost on restart.

    Sufficient for PR1's validation scope (see issue #66 D5); a persistent
    implementation of the same protocol (Vault-backed) lands in a later PR.
    """

    def __init__(self) -> None:
        # (subject, alias) -> (credential, version)
        self._entries: dict[tuple[str, str], tuple[StoredOAuthCredential, int]] = {}
        self._lock = asyncio.Lock()

    async def get(
        self, subject: str, alias: str
    ) -> tuple[StoredOAuthCredential, int] | None:
        return self._entries.get((subject, alias))

    async def write_cas(
        self,
        subject: str,
        alias: str,
        cred: StoredOAuthCredential,
        expected_version: int | None,
    ) -> int:
        async with self._lock:
            key = (subject, alias)
            current = self._entries.get(key)
            current_version = current[1] if current is not None else None
            # None == None (missing, create) and N == N (in-place update) are
            # the only matches; every other combination — creating over an
            # existing entry, or updating against a stale/missing version —
            # is a conflict.
            if expected_version != current_version:
                raise VersionConflict(
                    f"expected_version={expected_version!r} does not match "
                    f"current version={current_version!r} for "
                    f"subject={subject!r} alias={alias!r}"
                )
            new_version = 1 if current_version is None else current_version + 1
            self._entries[key] = (cred, new_version)
            return new_version

    async def delete(self, subject: str, alias: str) -> None:
        async with self._lock:
            self._entries.pop((subject, alias), None)


def normalize_token_response(
    data: dict[str, Any],
    *,
    alias: str,
    subject: str,
    issuer: str,
    token_endpoint: str,
    existing: StoredOAuthCredential | None = None,
) -> StoredOAuthCredential:
    """Translate a backend token-endpoint JSON response into a
    ``StoredOAuthCredential``.

    Falls back to *existing*'s ``refresh_token`` / ``scope`` /
    ``refresh_expires_at`` / ``metadata`` when the response omits them — many
    authorization servers do not reissue a refresh_token or restate scope on
    every refresh. Shared by ``OAuth21Provider._refresh`` (refresh grant) and
    the initial authorization_code exchange in ``api/oauth21.py``.
    """
    now = datetime.now(UTC)
    expires_in = int(data.get("expires_in", _MIN_REFRESH_WINDOW_SECONDS))
    expires_at = now + timedelta(seconds=expires_in)

    refresh_token_raw = data.get("refresh_token")
    if refresh_token_raw is not None:
        refresh_token: SecretStr | None = SecretStr(refresh_token_raw)
    else:
        refresh_token = existing.refresh_token if existing is not None else None

    refresh_expires_in = data.get("refresh_expires_in")
    if refresh_expires_in is not None:
        refresh_expires_at: datetime | None = now + timedelta(
            seconds=int(refresh_expires_in)
        )
    else:
        refresh_expires_at = (
            existing.refresh_expires_at if existing is not None else None
        )

    scope_raw = data.get("scope")
    if scope_raw:
        scope = str(scope_raw).split()
    else:
        scope = list(existing.scope) if existing is not None else []

    metadata = dict(existing.metadata) if existing is not None else {}

    return StoredOAuthCredential(
        alias=alias,
        subject=subject,
        access_token=SecretStr(data["access_token"]),
        refresh_token=refresh_token,
        expires_at=expires_at,
        refresh_expires_at=refresh_expires_at,
        scope=scope,
        issuer=issuer,
        token_endpoint=AnyHttpUrl(token_endpoint),
        metadata=metadata,
    )


class OAuth21Provider(CredentialProvider):
    """Issues delegated bearer tokens for an OAuth 2.1 backend authorization
    server that the broker is a direct client to (see docs/auth.md and issue
    #66 for why ``OIDCProvider``'s Keycloak-brokered pattern does not work
    for backends that are OAuth 2.1 authorization servers, not OIDC IdPs).

    The browser-facing PKCE linking flow lives in ``api/oauth21.py`` — this
    provider only reads and refreshes what that flow already wrote to the
    ``TokenStore``.
    """

    cred_class: ClassVar[str] = "oauth21"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED

    def __init__(
        self,
        alias: str,
        targets: frozenset[str],
        authorization_endpoint: str,
        token_endpoint: str,
        issuer: str,
        scope: str,
        store: TokenStore,
    ) -> None:
        self._alias = alias
        self._targets = targets
        self._authorization_endpoint = authorization_endpoint
        self._token_endpoint = token_endpoint
        self._issuer = issuer
        self._scope = scope
        self._store = store
        self._log = structlog.get_logger(__name__).bind(
            provider="OAuth21Provider", alias=alias
        )

    @property
    def alias(self) -> str:
        return self._alias

    @property
    def authorization_endpoint(self) -> str:
        return self._authorization_endpoint

    @property
    def token_endpoint(self) -> str:
        return self._token_endpoint

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def scope(self) -> str:
        return self._scope

    async def handles(self, target: str) -> bool:
        return target in self._targets

    async def is_linked(self, principal: Principal) -> bool:
        entry = await self._store.get(principal.subject, self._alias)
        if entry is None:
            return False
        cred, _version = entry
        return cred.expires_at > datetime.now(UTC)

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,  # noqa: ARG002 (interface)
    ) -> IssuedCredential:
        """Return a bearer credential, refreshing the stored token if needed.

        Callers are expected to have gated on ``is_linked()`` already (see
        ``api/credentials.py``); this method assumes linkage and only handles
        the narrower failure modes of the read/refresh itself.

        Raises:
            HTTPException(404): if no token is stored yet for this alias.
            HTTPException(401): if the stored token cannot be refreshed
                (expired/missing refresh_token, or the backend AS rejects the
                refresh attempt) — the user must re-link.
        """
        entry = await self._store.get(principal.subject, self._alias)
        if entry is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No OAuth 2.1 token stored for alias {self._alias!r}. "
                    "Link this account from the portal's Identities page."
                ),
            )
        cred, version = entry

        # Refresh window is 5 minutes or the caller's requested
        # min_remaining_seconds, whichever is larger — issue #66 decision D4.
        threshold = max(min_remaining_seconds, _MIN_REFRESH_WINDOW_SECONDS)
        remaining = (cred.expires_at - datetime.now(UTC)).total_seconds()
        if remaining > threshold:
            return self._to_issued(cred, target)

        if cred.refresh_token is None:
            raise HTTPException(
                status_code=401,
                detail=(
                    f"OAuth 2.1 token for alias {self._alias!r} has expired "
                    "and no refresh token is available. Please re-link this "
                    "account from the portal's Identities page."
                ),
            )

        refreshed = await self._refresh(cred)
        try:
            new_version = await self._store.write_cas(
                principal.subject, self._alias, refreshed, expected_version=version
            )
        except VersionConflict:
            # Another replica refreshed concurrently — use whatever is there
            # now rather than clobbering a fresher write with ours.
            self._log.info("oauth21.issue.refresh_race", subject=principal.subject)
            raced_entry = await self._store.get(principal.subject, self._alias)
            if raced_entry is None:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        f"No OAuth 2.1 token stored for alias {self._alias!r}. "
                        "Link this account from the portal's Identities page."
                    ),
                ) from None
            refreshed, new_version = raced_entry

        self._log.info(
            "oauth21.issue.refreshed",
            subject=principal.subject,
            target=target,
            version=new_version,
        )
        return self._to_issued(refreshed, target)

    async def _refresh(self, cred: StoredOAuthCredential) -> StoredOAuthCredential:
        """POST the refresh_token grant to the backend's token endpoint.

        Raises HTTPException(401) when the backend rejects the refresh
        (400/401 — refresh token invalid, revoked, or expired).
        """
        if cred.refresh_token is None:  # pragma: no cover - guarded by caller
            raise HTTPException(
                status_code=401,
                detail=f"No refresh token available for alias {self._alias!r}.",
            )
        resp = await get_http_client().post(
            self._token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": cred.refresh_token.get_secret_value(),
            },
            timeout=10.0,
        )
        if resp.status_code in (400, 401):
            self._log.warning(
                "oauth21.refresh_rejected",
                subject=cred.subject,
                status_code=resp.status_code,
            )
            raise HTTPException(
                status_code=401,
                detail=(
                    f"OAuth 2.1 token for alias {self._alias!r} could not be "
                    "refreshed; please re-link this account from the "
                    "portal's Identities page."
                ),
            )
        resp.raise_for_status()
        return normalize_token_response(
            resp.json(),
            alias=self._alias,
            subject=cred.subject,
            issuer=self._issuer,
            token_endpoint=self._token_endpoint,
            existing=cred,
        )

    def _to_issued(self, cred: StoredOAuthCredential, target: str) -> IssuedCredential:
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.BEARER,
            expires_at=cred.expires_at.timestamp(),
            payload={
                "access_token": cred.access_token.get_secret_value(),
                "token_type": "Bearer",
            },
            audit_id=uuid.uuid4().hex,
            source=f"oauth21:{self._alias}",
            execution_model=self.execution_model,
        )

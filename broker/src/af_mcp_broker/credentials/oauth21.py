from __future__ import annotations

import asyncio
import math
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

import httpx
import structlog
from fastapi import HTTPException
from pydantic import AnyHttpUrl, BaseModel, SecretStr, field_validator

from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.credentials.errors import VersionConflictError
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

# A stored token with no refresh_token cannot be renewed, so the 5-minute
# refresh window above would only make it unusable early. Such a token is
# instead served until this many seconds before its expiry -- enough to
# absorb clock skew and one downstream round trip -- and then requires a
# re-link.
_NO_REFRESH_EXPIRY_SKEW_SECONDS = 60


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
    # None when the token response omitted `expires_in` (only RECOMMENDED by
    # RFC 6749 §5.1): an AS such as Indico or a GitHub OAuth App issues
    # tokens that do not expire, and the token is served until a backend
    # rejects it -- see issue #344.
    expires_at: datetime | None
    refresh_expires_at: datetime | None
    scope: list[str]
    issuer: str
    token_endpoint: AnyHttpUrl
    metadata: dict[str, Any] = {}
    # Set when a backend answered HTTP 401 to this access token (issue #344).
    # The token is kept rather than deleted: only the user can re-link, since
    # the AS may need their consent again. Defaults to None so records
    # written before this field existed load as not rejected.
    rejected_at: datetime | None = None
    # Set when this token came from the one refresh a backend 401 earns
    # (``OAuth21Provider.mark_rejected``), so a 401 for it rejects instead of
    # refreshing again. A routine refresh or a re-link builds a fresh
    # credential, which resets it. Defaults to False for the same reason as
    # rejected_at.
    refreshed_after_rejection: bool = False

    @field_validator("expires_at", "refresh_expires_at", "rejected_at")
    @classmethod
    def _require_tz_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError(
                "expires_at/refresh_expires_at/rejected_at must be tz-aware (UTC)"
            )
        return value


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
        ``VersionConflictError`` when *expected_version* does not match the
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
                raise VersionConflictError(
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
    """Translate a backend token-endpoint JSON response into a ``StoredOAuthCredential``.

    Falls back to *existing*'s ``refresh_token`` / ``scope`` /
    ``refresh_expires_at`` / ``metadata`` when the response omits them — many
    authorization servers do not reissue a refresh_token or restate scope on
    every refresh. Shared by ``OAuth21Provider._refresh`` (refresh grant) and
    the initial authorization_code exchange in ``api/oauth21.py``.
    """
    now = datetime.now(UTC)
    expires_in = data.get("expires_in")
    expires_at = (
        now + timedelta(seconds=int(expires_in)) if expires_in is not None else None
    )

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
    """Issues delegated bearer tokens for an OAuth 2.1 backend authorization server that the broker is a direct client to (see docs/auth.md and issue #66 for why ``OIDCProvider``'s Keycloak-brokered pattern does not work for backends that are OAuth 2.1 authorization servers, not OIDC IdPs).

    The browser-facing PKCE linking flow lives in ``api/oauth21.py`` — this
    provider only reads and refreshes what that flow already wrote to the
    ``TokenStore``.
    """

    cred_class: ClassVar[str] = "oauth21"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED
    tracks_rejection: ClassVar[bool] = True

    def __init__(
        self,
        alias: str,
        targets: frozenset[str],
        authorization_endpoint: str,
        token_endpoint: str,
        issuer: str,
        scope: str,
        store: TokenStore,
        client_id: str,
        client_secret: SecretStr | None = None,
        revocation_endpoint: str | None = None,
    ) -> None:
        self._alias = alias
        self._targets = targets
        self._authorization_endpoint = authorization_endpoint
        self._token_endpoint = token_endpoint
        self._issuer = issuer
        self._scope = scope
        self._store = store
        self._client_id = client_id
        self._client_secret = client_secret
        self._revocation_endpoint = revocation_endpoint
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

    @property
    def client_id(self) -> str:
        return self._client_id

    def client_auth_params(self) -> dict[str, str]:
        """Client identification for a token-endpoint or revocation request body.

        Always ``client_id`` (OAuth 2.1 requires a public client to send it on
        every token request too, see issue #68); plus ``client_secret`` for a
        confidential client, i.e. ``client_secret_post`` (RFC 6749 §2.3.1).
        """
        params = {"client_id": self._client_id}
        if self._client_secret is not None:
            params["client_secret"] = self._client_secret.get_secret_value()
        return params

    @staticmethod
    def _usable_seconds(cred: StoredOAuthCredential) -> float:
        """Seconds the stored access token can still be handed out for.

        A token with a refresh_token is usable until ``expires_at`` (``issue``
        refreshes it ahead of that); one without can never be renewed, so it
        stops being usable ``_NO_REFRESH_EXPIRY_SKEW_SECONDS`` early. A token
        with no known expiry is usable indefinitely, so it is never inside
        any refresh window.
        """
        if cred.expires_at is None:
            return math.inf
        remaining = (cred.expires_at - datetime.now(UTC)).total_seconds()
        if cred.refresh_token is None:
            return remaining - _NO_REFRESH_EXPIRY_SKEW_SECONDS
        return remaining

    async def is_linked(self, principal: Principal) -> bool:
        entry = await self._store.get(principal.subject, self._alias)
        if entry is None:
            return False
        cred, _version = entry
        if cred.rejected_at is not None:
            return False
        return self._usable_seconds(cred) > 0

    async def is_rejected(self, principal: Principal) -> bool:
        entry = await self._store.get(principal.subject, self._alias)
        return entry is not None and entry[0].rejected_at is not None

    async def mark_rejected(self, principal: Principal, access_token: str) -> None:
        """Handle a backend's 401 for *access_token*: refresh once, else mark it rejected.

        Acts only if *access_token* is still the one stored, so a late 401
        for a superseded token (since refreshed, or re-linked) leaves its
        replacement alone. A lost CAS race means something newer was
        written, so it is dropped the same way.

        A credential with a refresh token first gets one refresh, since the
        AS may still honor the refresh token. The refreshed token is flagged
        ``refreshed_after_rejection``, so a 401 for it rejects rather than
        refreshing again. Only a definite refusal from the AS rejects; if
        the AS can't be reached the credential is left as it was and the
        next 401 tries again. The request that got the 401 is never
        replayed, since a tool call may have side effects.
        """
        entry = await self._store.get(principal.subject, self._alias)
        if entry is None:
            return
        cred, version = entry
        if cred.access_token.get_secret_value() != access_token:
            return

        if cred.refresh_token is not None and not cred.refreshed_after_rejection:
            try:
                refreshed = await self._refresh(cred)
            except HTTPException:
                pass  # the AS refused the refresh token: reject below
            except httpx.HTTPError as exc:
                self._log.warning(
                    "oauth21.mark_rejected.refresh_failed",
                    subject=principal.subject,
                    error=str(exc),
                )
                return
            else:
                flagged = refreshed.model_copy(
                    update={"refreshed_after_rejection": True}
                )
                if await self._write_unless_superseded(principal, flagged, version):
                    self._log.info(
                        "oauth21.refreshed_after_rejection",
                        subject=principal.subject,
                    )
                return

        rejected = cred.model_copy(update={"rejected_at": datetime.now(UTC)})
        if await self._write_unless_superseded(principal, rejected, version):
            self._log.warning("oauth21.credential_rejected", subject=principal.subject)

    async def _write_unless_superseded(
        self, principal: Principal, cred: StoredOAuthCredential, version: int
    ) -> bool:
        """CAS-write *cred* over *version*; False if something newer was written first."""
        try:
            await self._store.write_cas(
                principal.subject, self._alias, cred, expected_version=version
            )
        except VersionConflictError:
            self._log.info(
                "oauth21.mark_rejected.superseded", subject=principal.subject
            )
            return False
        return True

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

        if cred.rejected_at is not None:
            raise HTTPException(
                status_code=401,
                detail=(
                    f"OAuth 2.1 token for alias {self._alias!r} was rejected "
                    "by the service. Please re-link this account from the "
                    "portal's Identities page."
                ),
            )

        if cred.refresh_token is None:
            # Nothing to refresh, so neither the refresh window nor the
            # caller's min_remaining_seconds can be met any better than by
            # the stored token itself: serve it for as long as it is usable.
            if self._usable_seconds(cred) > 0:
                return self._to_issued(cred, target)
            raise HTTPException(
                status_code=401,
                detail=(
                    f"OAuth 2.1 token for alias {self._alias!r} has expired "
                    "and no refresh token is available. Please re-link this "
                    "account from the portal's Identities page."
                ),
            )

        # Refresh window is 5 minutes or the caller's requested
        # min_remaining_seconds, whichever is larger — issue #66 decision D4.
        threshold = max(min_remaining_seconds, _MIN_REFRESH_WINDOW_SECONDS)
        if self._usable_seconds(cred) > threshold:
            return self._to_issued(cred, target)

        refreshed = await self._refresh(cred)
        try:
            new_version = await self._store.write_cas(
                principal.subject, self._alias, refreshed, expected_version=version
            )
        except VersionConflictError:
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

    async def revoke(self, principal: Principal, target: str) -> None:  # noqa: ARG002 (interface; revocation is alias-scoped, not target-scoped)
        """Unlink this alias: best-effort RFC 7009 revocation, then delete.

        The stored token covers every target this alias is bound to, not
        just *target* -- so there is nothing target-specific to do here; the
        parameter only exists to satisfy ``CredentialProvider.revoke``'s
        interface. The revocation-endpoint POST never blocks the local
        delete: an unreachable or rejecting backend AS must not prevent the
        portal's unlink button from working.
        """
        entry = await self._store.get(principal.subject, self._alias)
        if entry is not None and self._revocation_endpoint is not None:
            cred, _version = entry
            if cred.refresh_token is not None:
                token = cred.refresh_token
                token_type_hint = "refresh_token"
            else:
                token = cred.access_token
                token_type_hint = "access_token"
            try:
                resp = await get_http_client().post(
                    self._revocation_endpoint,
                    data={
                        "token": token.get_secret_value(),
                        "token_type_hint": token_type_hint,
                        **self.client_auth_params(),
                    },
                    timeout=10.0,
                )
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                self._log.warning(
                    "oauth21.revoke.upstream_failed",
                    subject=principal.subject,
                    error=str(exc),
                )
        await self._store.delete(principal.subject, self._alias)
        self._log.info("oauth21.revoke.deleted", subject=principal.subject)

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
                **self.client_auth_params(),
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
            expires_at=(
                cred.expires_at.timestamp() if cred.expires_at is not None else None
            ),
            payload={
                "access_token": cred.access_token.get_secret_value(),
                "token_type": "Bearer",
            },
            audit_id=uuid.uuid4().hex,
            source=f"oauth21:{self._alias}",
            execution_model=self.execution_model,
        )

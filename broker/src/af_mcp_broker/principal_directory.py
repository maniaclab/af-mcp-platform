"""Resolves a principal id's *current* attributes from Keycloak (issue #144 step 2a).

A JWT is self-contained: `identity._extract_principal` reads uid/gid/
unixname/groups straight off claims the client just presented, re-validated
on every request. A PAT carries none of that -- it is an opaque bearer whose
record (`token_registry.TokenRecord`) stores identity/metadata only, no
authorization data (see that module's docstring on the PAT-store/
principal-cache split). So answering "what authority does this token
carry?" for a PAT means *asking Keycloak, right now*, what the owning
principal's groups/uid/gid/unixname currently are -- this module is that
lookup.

`PrincipalDirectory` is an ABC (not a Protocol) so a future LDAP/SCIM/
local-DB implementation is a drop-in replacement satisfying an explicit
contract -- consistent with `CredentialProvider` and `TokenRegistryBackend`
elsewhere in this codebase, and Giordon's standing preference for explicit
inheritance over duck typing.

`KeycloakPrincipalDirectory` is the first (and, for now, only)
implementation, backed by Keycloak's Admin REST API:

* ``GET /admin/realms/{realm}/users/{id}`` -- user representation, including
  ``email`` and the ``attributes`` map the `posix` client-scope mappers
  source `uid`/`gid`/`unixname` from (see docs/auth.md's "Token claims
  required by the broker" section -- the *same* underlying profile
  attributes, just read directly instead of via a minted JWT's mapped
  claims). Each attribute value comes back as a list of strings (Keycloak's
  user-attributes are multi-valued by design); this only ever reads the
  first.
* ``GET /admin/realms/{realm}/users/{id}/groups`` -- group representations.
  Uses each group's ``name`` (not ``path``) so the result matches exactly
  what the Group Membership mapper puts in a JWT's `groups` claim -- AF
  Keycloak's mapper is configured with "Full group path: OFF" (see
  docs/auth.md), i.e. bare names with no leading ``/``, and the policy
  engine (authorization/) string-matches those bare names.

Both endpoints require an admin-scoped access token; this class obtains one
via the `client_credentials` grant against the same OIDC token endpoint
`identity.py`/`credentials/service.py` use, authenticated as
``settings.keycloak_admin_client_id``/``keycloak_admin_client_secret`` -- a
confidential client granted the realm-management roles `view-users` and
`query-groups` (the narrowest roles satisfying the two calls above; see
docs/auth.md). The admin token is cached in-process and refreshed before
expiry, mirroring `credentials/service.py`'s `ServiceProvider._get_service_token`.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings

log = structlog.get_logger(__name__)

# Refresh the admin token this many seconds before it expires -- same margin
# ServiceProvider uses for its own client_credentials-sourced token.
_ADMIN_TOKEN_REFRESH_BUFFER_SECONDS = 60


@dataclass(frozen=True)
class PrincipalAttributes:
    """A principal's current groups/POSIX identity, as resolved right now from the directory -- never cached inside this class itself (see principal_cache.py for the caching layer)."""

    uid: int
    gid: int
    unixname: str
    groups: list[str]
    email: str


class PrincipalNotFoundError(Exception):
    """Raised by ``PrincipalDirectory.resolve()`` when *principal_id* does not exist in the directory (e.g. a Keycloak user deleted after a PAT was minted)."""

    def __init__(self, principal_id: str) -> None:
        self.principal_id = principal_id
        super().__init__(f"Principal {principal_id!r} not found in directory")


class PrincipalDirectory(ABC):
    """Resolves a principal id's current groups/uid/gid/unixname/email.

    An ABC, not a Protocol -- see this module's docstring. Implementations
    answer only "what does the directory say right now"; staleness handling,
    refresh scheduling, and fail-closed/serve-stale behavior all live one
    layer up, in ``principal_cache.PrincipalCache``.
    """

    @abstractmethod
    async def resolve(self, principal_id: str) -> PrincipalAttributes:
        """Return *principal_id*'s current attributes.

        Raises ``PrincipalNotFoundError`` if the directory has no such
        principal. Any other failure (network error, malformed response,
        missing posix attributes) should raise -- callers (the principal
        cache) are responsible for stale-serving/fail-closed decisions, not
        this method.
        """


def _admin_base_url(issuer: str) -> str:
    """Derive the Keycloak Admin REST API base from an OIDC issuer URL.

    ``{server}/realms/{realm}`` -> ``{server}/admin/realms/{realm}`` -- the
    standard Keycloak layout; both the issuer and the admin API live under
    the same server, differing only in this path segment.
    """
    marker = "/realms/"
    if marker not in issuer:
        raise ValueError(
            f"oidc_issuer {issuer!r} does not contain {marker!r} -- cannot "
            "derive the Keycloak Admin REST API base URL from it."
        )
    return issuer.replace(marker, "/admin/realms/", 1)


class KeycloakPrincipalDirectory(PrincipalDirectory):
    """``PrincipalDirectory`` backed by the Keycloak Admin REST API -- see this module's docstring for the exact endpoints and why ``name`` (not ``path``) is used for group membership."""

    def __init__(
        self,
        settings: Settings,
        admin_client_id: str,
        admin_client_secret: str,
    ) -> None:
        self._settings = settings
        self._admin_client_id = admin_client_id
        self._admin_client_secret = admin_client_secret
        self._admin_base = _admin_base_url(settings.oidc_issuer)
        self._log = structlog.get_logger(__name__).bind(
            component="KeycloakPrincipalDirectory"
        )

        self._admin_token: str | None = None
        self._admin_token_expires_at: float = 0.0
        self._refresh_lock = asyncio.Lock()

    async def resolve(self, principal_id: str) -> PrincipalAttributes:
        token = await self._get_admin_token()
        headers = {"Authorization": f"Bearer {token}"}
        client = get_http_client()

        user_resp = await client.get(
            f"{self._admin_base}/users/{principal_id}", headers=headers, timeout=10.0
        )
        if user_resp.status_code == 404:
            raise PrincipalNotFoundError(principal_id)
        user_resp.raise_for_status()
        user = user_resp.json()

        groups_resp = await client.get(
            f"{self._admin_base}/users/{principal_id}/groups",
            headers=headers,
            timeout=10.0,
        )
        groups_resp.raise_for_status()
        groups = [g["name"] for g in groups_resp.json()]

        attributes: dict[str, list[str]] = user.get("attributes") or {}
        missing = [k for k in ("uid", "gid", "unixname") if not attributes.get(k)]
        if missing:
            raise ValueError(
                f"Keycloak user {principal_id!r} is missing profile attribute(s) "
                f"{missing} -- cannot resolve POSIX identity for a PAT-"
                "authenticated request. See docs/auth.md's 'Token claims "
                "required by the broker' section for the attributes the "
                "`posix` client scope's mappers source these from."
            )

        return PrincipalAttributes(
            uid=int(attributes["uid"][0]),
            gid=int(attributes["gid"][0]),
            unixname=str(attributes["unixname"][0]),
            groups=groups,
            email=str(user.get("email") or ""),
        )

    async def _get_admin_token(self) -> str:
        remaining = self._admin_token_expires_at - time.time()
        if (
            self._admin_token is not None
            and remaining > _ADMIN_TOKEN_REFRESH_BUFFER_SECONDS
        ):
            return self._admin_token

        async with self._refresh_lock:
            remaining = self._admin_token_expires_at - time.time()
            if (
                self._admin_token is not None
                and remaining > _ADMIN_TOKEN_REFRESH_BUFFER_SECONDS
            ):
                return self._admin_token

            token, expires_at = await self._refresh_admin_token()
            self._admin_token = token
            self._admin_token_expires_at = expires_at
            return self._admin_token

    async def _refresh_admin_token(self) -> tuple[str, float]:
        token_endpoint = (
            f"{self._settings.oidc_issuer.rstrip('/')}/protocol/openid-connect/token"
        )
        resp = await get_http_client().post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self._admin_client_id,
                "client_secret": self._admin_client_secret,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()

        access_token: str = data["access_token"]
        expires_in: int = int(data.get("expires_in", 60))
        expires_at: float = time.time() + expires_in

        self._log.info("keycloak_admin.token_refreshed", expires_at=expires_at)
        return access_token, expires_at

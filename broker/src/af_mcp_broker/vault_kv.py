"""Vault/OpenBao KV-v2 transport client, shared by ``credentials/vault.py``'s ``VaultTokenStore`` and ``token_registry.py``'s ``VaultTokenRegistryBackend``.

Scope boundary: transport only -- Kubernetes auth, the four KV-v2 verbs, and
error taxonomy. No domain records, no path layouts, no retry policies; those
stay with each caller (see this module's ``VaultKV`` docstring). Non-goals,
deliberately, not gaps to fill in later:

* no generic storage abstraction spanning in-memory *and* Vault backends --
  ``InMemoryTokenStore``/``InMemoryTokenRegistryBackend`` share no code with
  this module and shouldn't; a shared ABC across such different storage
  models would only blur what each implementation actually guarantees.
* no ``hvac`` dependency -- talks to Vault's HTTP API directly via httpx, the
  same way the rest of the broker talks to Keycloak.
* no inheritance -- consumers hold a ``VaultKV`` instance (composition), they
  never subclass it.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    import httpx

# Vault K8s auth tokens are re-minted this many seconds before their lease
# actually expires, so a call that starts just under the wire never presents
# an already-expired token to Vault.
_AUTH_SAFETY_MARGIN_SECONDS = 60


class VaultError(Exception):
    """Raised when Vault's HTTP API returns an unexpected response."""


class CasConflict(Exception):
    """Raised by ``write_cas()`` when Vault's check-and-set version guard rejects the write -- the caller's ``expected_version`` no longer matches the entry's current version."""


class VaultKV:
    """Vault/OpenBao KV-v2 transport: Kubernetes auth + four KV verbs.

    No domain knowledge: callers own their path layouts, record shapes, and
    retry policies. *path* arguments below are full paths under the KV
    mount (e.g. ``"mcp/tokens/<subject>/<alias>"``) -- this class only ever
    prefixes them with ``{kv_mount}/data/`` or ``{kv_mount}/metadata/``.

    Not thread-safe across processes (Vault's CAS semantics on the KV-v2
    write handle cross-replica races; this class only guards its own
    in-process re-authentication with an ``asyncio.Lock``).
    """

    def __init__(
        self,
        *,
        addr: str,
        auth_mount: str,
        auth_role: str,
        kv_mount: str,
        sa_token_path: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._addr = addr.rstrip("/")
        self._auth_mount = auth_mount
        self._auth_role = auth_role
        self._kv_mount = kv_mount
        self._sa_token_path = sa_token_path
        self._http_client = http_client

        self._client_token: str | None = None
        self._expires_at: datetime | None = None
        self._auth_lock = asyncio.Lock()

        self._log = structlog.get_logger(__name__).bind(component="VaultKV")

    def _http(self) -> httpx.AsyncClient:
        return self._http_client if self._http_client is not None else get_http_client()

    async def _authenticate(self) -> str:
        """Return a valid Vault client token, re-authenticating if the cached one is missing or within ``_AUTH_SAFETY_MARGIN_SECONDS`` of expiry.

        Locked so concurrent callers racing to refresh don't each POST their
        own login request to Vault -- do NOT use ``auth/token/renew-self``
        here; re-reading the SA JWT and logging in again is simpler and more
        resilient (renew-self requires the token to still be valid and
        renewable, and the SA JWT is always available on disk regardless).
        """
        async with self._auth_lock:
            now = datetime.now(UTC)
            if (
                self._client_token is not None
                and self._expires_at is not None
                and now < self._expires_at
            ):
                return self._client_token

            jwt = Path(self._sa_token_path).read_text().strip()
            resp = await self._http().post(
                f"{self._addr}/v1/auth/{self._auth_mount}/login",
                json={"role": self._auth_role, "jwt": jwt},
                timeout=10.0,
            )
            if resp.status_code != 200:
                raise VaultError(
                    "vault k8s auth login failed: "
                    f"status={resp.status_code} body={resp.text!r}"
                )

            auth = resp.json()["auth"]
            client_token: str = auth["client_token"]
            lease_duration = int(auth["lease_duration"])

            self._client_token = client_token
            self._expires_at = now + timedelta(
                seconds=lease_duration - _AUTH_SAFETY_MARGIN_SECONDS
            )
            self._log.info("vault_kv.reauthenticated", lease_duration=lease_duration)
            return client_token

    async def get(self, path: str) -> tuple[dict[str, Any], int] | None:
        """KV-v2 data read. Returns ``(data, version)``, or None on a 404."""
        token = await self._authenticate()
        resp = await self._http().get(
            f"{self._addr}/v1/{self._kv_mount}/data/{path}",
            headers={"X-Vault-Token": token},
            timeout=10.0,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise VaultError(
                f"vault kv read failed for path={path!r}: "
                f"status={resp.status_code} body={resp.text!r}"
            )
        body = resp.json()["data"]
        return body["data"], int(body["metadata"]["version"])

    async def write_cas(
        self, path: str, data: dict[str, Any], expected_version: int | None
    ) -> int:
        """KV-v2 data write, check-and-set on *expected_version* (``None`` -> ``cas=0``, i.e. "create; fail if an entry already exists"). Returns the new version; raises ``CasConflict`` if *expected_version* no longer matches the entry's current version."""
        token = await self._authenticate()
        cas = 0 if expected_version is None else expected_version

        resp = await self._http().post(
            f"{self._addr}/v1/{self._kv_mount}/data/{path}",
            headers={"X-Vault-Token": token},
            json={"options": {"cas": cas}, "data": data},
            timeout=10.0,
        )
        if resp.status_code == 200:
            return int(resp.json()["data"]["version"])

        if resp.status_code == 400:
            errors = resp.json().get("errors", [])
            if any("check-and-set" in err for err in errors):
                raise CasConflict(
                    f"vault cas write conflict for path={path!r} "
                    f"expected_version={expected_version!r}"
                )

        raise VaultError(
            f"vault kv write failed for path={path!r}: "
            f"status={resp.status_code} body={resp.text!r}"
        )

    async def list(self, path: str) -> list[str]:
        """KV-v2 metadata LIST: immediate child keys under *path*, or ``[]`` on a 404 (path has no children)."""
        token = await self._authenticate()
        resp = await self._http().request(
            "LIST",
            f"{self._addr}/v1/{self._kv_mount}/metadata/{path}",
            headers={"X-Vault-Token": token},
            timeout=10.0,
        )
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise VaultError(
                f"vault kv list failed for path={path!r}: "
                f"status={resp.status_code} body={resp.text!r}"
            )
        return list(resp.json()["data"]["keys"])

    async def delete_metadata(self, path: str) -> None:
        # Deletes via the metadata endpoint (not data) so all versions AND
        # the version counter are destroyed -- a data-endpoint soft-delete
        # would leave metadata behind, permanently breaking a subsequent
        # write_cas(expected_version=None) (cas=0) for this path.
        token = await self._authenticate()
        resp = await self._http().delete(
            f"{self._addr}/v1/{self._kv_mount}/metadata/{path}",
            headers={"X-Vault-Token": token},
            timeout=10.0,
        )
        if resp.status_code in (204, 404):
            return
        raise VaultError(
            f"vault kv delete failed for path={path!r}: "
            f"status={resp.status_code} body={resp.text!r}"
        )

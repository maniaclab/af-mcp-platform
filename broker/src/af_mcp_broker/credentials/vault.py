"""Vault/OpenBao-backed ``TokenStore`` (issue #66 PR3).

Persists ``StoredOAuthCredential`` entries in a KV-v2 secrets engine, using
Vault's Kubernetes auth method so the broker never handles a long-lived
Vault credential of its own -- it re-authenticates from its ServiceAccount
JWT, which Kubernetes already mounts into the pod and rotates.

Talks to Vault's HTTP API directly via httpx (no ``hvac`` dependency), the
same way the rest of the broker talks to Keycloak.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from af_mcp_broker.credentials.oauth21 import (
    StoredOAuthCredential,
    VersionConflict,
)
from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    import httpx

# Vault K8s auth tokens are re-minted this many seconds before their lease
# actually expires, so a call that starts just under the wire never presents
# an already-expired token to Vault.
_AUTH_SAFETY_MARGIN_SECONDS = 60


class VaultError(Exception):
    """Raised when Vault's HTTP API returns an unexpected response."""


class VaultTokenStore:
    """``TokenStore`` backed by Vault/OpenBao KV-v2, authenticated via the
    Vault Kubernetes auth method.

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
        kv_path_prefix: str,
        sa_token_path: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._addr = addr.rstrip("/")
        self._auth_mount = auth_mount
        self._auth_role = auth_role
        self._kv_mount = kv_mount
        self._kv_path_prefix = kv_path_prefix.strip("/")
        self._sa_token_path = sa_token_path
        self._http_client = http_client

        self._client_token: str | None = None
        self._expires_at: datetime | None = None
        self._auth_lock = asyncio.Lock()

        self._log = structlog.get_logger(__name__).bind(provider="VaultTokenStore")

    def _http(self) -> httpx.AsyncClient:
        return self._http_client if self._http_client is not None else get_http_client()

    def _kv_path(self, endpoint: str, subject: str, alias: str) -> str:
        """Build a KV-v2 URL path: ``{kv_mount}/{endpoint}/{prefix}/{subject}/{alias}``.

        *endpoint* is ``"data"`` (read/write current+versioned data) or
        ``"metadata"`` (delete all versions + metadata).
        """
        return f"{self._kv_mount}/{endpoint}/{self._kv_path_prefix}/{subject}/{alias}"

    async def _authenticate(self) -> str:
        """Return a valid Vault client token, re-authenticating if the
        cached one is missing or within ``_AUTH_SAFETY_MARGIN_SECONDS`` of
        expiry.

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
            self._log.info(
                "vault_token_store.reauthenticated", lease_duration=lease_duration
            )
            return client_token

    async def get(
        self, subject: str, alias: str
    ) -> tuple[StoredOAuthCredential, int] | None:
        token = await self._authenticate()
        resp = await self._http().get(
            f"{self._addr}/v1/{self._kv_path('data', subject, alias)}",
            headers={"X-Vault-Token": token},
            timeout=10.0,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise VaultError(
                f"vault kv read failed for subject={subject!r} alias={alias!r}: "
                f"status={resp.status_code} body={resp.text!r}"
            )

        body = resp.json()["data"]
        cred = StoredOAuthCredential.model_validate(body["data"])
        version = int(body["metadata"]["version"])
        return cred, version

    async def write_cas(
        self,
        subject: str,
        alias: str,
        cred: StoredOAuthCredential,
        expected_version: int | None,
    ) -> int:
        token = await self._authenticate()
        cas = 0 if expected_version is None else expected_version

        resp = await self._http().post(
            f"{self._addr}/v1/{self._kv_path('data', subject, alias)}",
            headers={"X-Vault-Token": token},
            json={"options": {"cas": cas}, "data": _reveal_secrets(cred)},
            timeout=10.0,
        )
        if resp.status_code == 200:
            return int(resp.json()["data"]["version"])

        if resp.status_code == 400:
            errors = resp.json().get("errors", [])
            if any("check-and-set" in err for err in errors):
                raise VersionConflict(
                    f"vault cas write conflict for subject={subject!r} "
                    f"alias={alias!r} expected_version={expected_version!r}"
                )

        raise VaultError(
            f"vault kv write failed for subject={subject!r} alias={alias!r}: "
            f"status={resp.status_code} body={resp.text!r}"
        )

    async def delete(self, subject: str, alias: str) -> None:
        # Deletes via the metadata endpoint (not data) so all versions AND
        # the version counter are destroyed -- a data-endpoint soft-delete
        # would leave metadata behind, permanently breaking a subsequent
        # write_cas(expected_version=None) (cas=0) for this subject/alias.
        token = await self._authenticate()
        resp = await self._http().delete(
            f"{self._addr}/v1/{self._kv_path('metadata', subject, alias)}",
            headers={"X-Vault-Token": token},
            timeout=10.0,
        )
        if resp.status_code in (204, 404):
            return
        raise VaultError(
            f"vault kv delete failed for subject={subject!r} alias={alias!r}: "
            f"status={resp.status_code} body={resp.text!r}"
        )


def _reveal_secrets(cred: StoredOAuthCredential) -> dict[str, Any]:
    """Serialize *cred* for Vault storage with ``SecretStr`` fields revealed.

    ``StoredOAuthCredential.model_dump(mode="json")`` masks ``SecretStr``
    fields as ``"**********"`` -- pydantic 2's unconditional default for
    that type, verified empirically (no ``context=`` kwarg changes it).
    That's the right behavior for logs but wrong for persistence, so the
    secret values are read back out and substituted in before the payload is
    sent. On read, ``StoredOAuthCredential.model_validate(...)`` re-wraps the
    plain string values Vault hands back into ``SecretStr`` on its own --
    no custom validator needed for that half of the round trip.
    """
    revealed = cred.model_dump(mode="json")
    revealed["access_token"] = cred.access_token.get_secret_value()
    revealed["refresh_token"] = (
        cred.refresh_token.get_secret_value()
        if cred.refresh_token is not None
        else None
    )
    return revealed

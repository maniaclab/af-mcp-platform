"""Tests for the Vault/OpenBao-backed ServiceX credential store (issue #295).

``VaultServiceXStore`` persists, per subject, a link half (refresh token,
durable) and a token half (last-redeemed access token + expiry, written on
every redeem) -- one KV-v2 record at ``{prefix}/{subject}/servicex`` over
the shared ``VaultKV`` transport, mirroring ``credentials/x509_vault.py``'s
``VaultX509Store``/``krb5_vault.py``'s ``Krb5VaultStore`` layout and CAS
conventions. A fake Vault HTTP API is built with ``httpx.MockTransport``
(same harness shape as ``test_x509_vault.py``/``test_krb5_vault.py``).
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from pydantic import SecretStr

from af_mcp_broker.credentials.servicex_vault import VaultServiceXStore
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from pathlib import Path

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"
KV_PATH_PREFIX = "mcp/servicex"

SUBJECT = "kc-subject-123"

_REFRESH_TOKEN = "a-servicex-refresh-token"
_ACCESS_TOKEN = "a-servicex-access-token"


class _FakeVault:
    """In-memory fake of the subset of Vault's HTTP API this store uses.

    ``entries`` maps the KV path under the prefix (i.e. ``{subject}/servicex``)
    to ``{"data": dict, "version": int}``. Absent keys behave as Vault does
    for never-written or metadata-destroyed paths: GET 404s, and a CAS write
    with ``cas=0`` succeeds.
    """

    def __init__(self) -> None:
        self.entries: dict[str, dict[str, Any]] = {}

    def _kv_key_from_path(self, path: str) -> str | None:
        for verb in ("data", "metadata"):
            prefix = f"{KV_MOUNT}/{verb}/{KV_PATH_PREFIX}/"
            if path.startswith(prefix):
                return path[len(prefix) :]
        return None

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "auth": {
                        "client_token": "vault-test-token",
                        "lease_duration": 3600,
                        "renewable": True,
                    }
                },
                request=request,
            )

        key = self._kv_key_from_path(path)
        if key is None:
            return httpx.Response(
                404, json={"errors": ["unknown path"]}, request=request
            )

        is_metadata = path.startswith(f"{KV_MOUNT}/metadata/")

        if request.method == "GET":
            entry = self.entries.get(key)
            if entry is None:
                return httpx.Response(404, json={"errors": []}, request=request)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "data": entry["data"],
                        "metadata": {"version": entry["version"]},
                    }
                },
                request=request,
            )

        if request.method == "POST" and not is_metadata:
            body = json.loads(request.content.decode())
            cas = body["options"]["cas"]
            current_version = self.entries.get(key, {}).get("version", 0)
            if cas != current_version:
                return httpx.Response(
                    400,
                    json={
                        "errors": [
                            "check-and-set parameter did not match the current version"
                        ]
                    },
                    request=request,
                )
            new_version = current_version + 1
            self.entries[key] = {"data": body["data"], "version": new_version}
            return httpx.Response(
                200, json={"data": {"version": new_version}}, request=request
            )

        if request.method == "DELETE" and is_metadata:
            self.entries.pop(key, None)
            return httpx.Response(204, request=request)

        return httpx.Response(
            404, json={"errors": ["unhandled"]}, request=request
        )  # pragma: no cover


@pytest.fixture
def sa_token_path(tmp_path: Path) -> Path:
    path = tmp_path / "sa-token"
    path.write_text("fake-sa-jwt\n")
    return path


@pytest.fixture
def fake_vault() -> _FakeVault:
    return _FakeVault()


@pytest.fixture
def store(fake_vault: _FakeVault, sa_token_path: Path) -> VaultServiceXStore:
    vault_kv = VaultKV(
        addr=ADDR,
        auth_mount=AUTH_MOUNT,
        auth_role=AUTH_ROLE,
        kv_mount=KV_MOUNT,
        sa_token_path=str(sa_token_path),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake_vault.handle)),
    )
    return VaultServiceXStore(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)


async def _link(store: VaultServiceXStore, subject: str = SUBJECT) -> None:
    await store.store_link(subject, refresh_token=SecretStr(_REFRESH_TOKEN))


async def _store_token(
    store: VaultServiceXStore,
    subject: str = SUBJECT,
    *,
    remaining: float = 3600.0,
) -> float:
    expires_at = time.time() + remaining
    await store.store_token(subject, access_token=_ACCESS_TOKEN, expires_at=expires_at)
    return expires_at


# ---------------------------------------------------------------------------
# Link half: store_link / get_link / path layout
# ---------------------------------------------------------------------------


class TestLink:
    async def test_get_link_returns_none_when_never_linked(self, store) -> None:
        assert await store.get_link(SUBJECT) is None

    async def test_store_link_roundtrips_refresh_token(self, store) -> None:
        await _link(store)
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.refresh_token is not None
        assert link.refresh_token.get_secret_value() == _REFRESH_TOKEN

    async def test_record_lives_at_prefix_subject_servicex(
        self, store, fake_vault
    ) -> None:
        await _link(store)
        assert f"{SUBJECT}/servicex" in fake_vault.entries

    async def test_relink_replaces_previous_refresh_token(self, store) -> None:
        await _link(store)
        await store.store_link(SUBJECT, refresh_token=SecretStr("new-token"))
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.refresh_token is not None
        assert link.refresh_token.get_secret_value() == "new-token"

    async def test_relink_clears_previously_stored_token(self, store) -> None:
        await _link(store)
        await _store_token(store)
        await store.store_link(SUBJECT, refresh_token=SecretStr("new-token"))
        assert await store.get_token(SUBJECT) is None


# ---------------------------------------------------------------------------
# Token half: store_token / get_token
# ---------------------------------------------------------------------------


class TestToken:
    async def test_get_token_returns_none_when_never_stored(self, store) -> None:
        assert await store.get_token(SUBJECT) is None

    async def test_store_token_roundtrips(self, store) -> None:
        await _link(store)
        expires_at = await _store_token(store)
        record = await store.get_token(SUBJECT)
        assert record is not None
        assert record.access_token is not None
        assert record.access_token.get_secret_value() == _ACCESS_TOKEN
        assert record.expires_at == pytest.approx(expires_at)

    async def test_store_token_preserves_link_half(self, store) -> None:
        await _link(store)
        await _store_token(store)
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.refresh_token is not None
        assert link.refresh_token.get_secret_value() == _REFRESH_TOKEN

    async def test_get_token_respects_min_remaining(self, store) -> None:
        await _link(store)
        await _store_token(store, remaining=100.0)
        assert await store.get_token(SUBJECT, min_remaining=50.0) is not None
        assert await store.get_token(SUBJECT, min_remaining=200.0) is None

    async def test_expired_token_reads_as_absent(self, store) -> None:
        await _link(store)
        await _store_token(store, remaining=-10.0)
        assert await store.get_token(SUBJECT) is None

    async def test_clear_token_removes_token_but_keeps_link(self, store) -> None:
        await _link(store)
        await _store_token(store)
        await store.clear_token(SUBJECT)
        assert await store.get_token(SUBJECT) is None
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.refresh_token is not None

    async def test_clear_token_on_unlinked_subject_is_a_noop(self, store) -> None:
        await store.clear_token(SUBJECT)  # must not raise
        assert await store.get_link(SUBJECT) is None


# ---------------------------------------------------------------------------
# delete (unlink)
# ---------------------------------------------------------------------------


class TestDelete:
    async def test_delete_removes_link_and_token(self, store) -> None:
        await _link(store)
        await _store_token(store)
        await store.delete(SUBJECT)
        assert await store.get_link(SUBJECT) is None
        assert await store.get_token(SUBJECT) is None

    async def test_delete_on_unlinked_subject_is_a_noop(self, store) -> None:
        await store.delete(SUBJECT)  # must not raise


# ---------------------------------------------------------------------------
# CAS conflict retry
# ---------------------------------------------------------------------------


class TestCasRetry:
    async def test_concurrent_store_token_calls_both_succeed(self, store) -> None:
        """CAS write-modify-read retries absorb a version race rather than propagating it."""
        await _link(store)
        await asyncio.gather(
            _store_token(store, remaining=100.0),
            _store_token(store, remaining=200.0),
        )
        record = await store.get_token(SUBJECT, min_remaining=0.0)
        assert record is not None

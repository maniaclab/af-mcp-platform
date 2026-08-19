"""Tests for the Vault/OpenBao-backed x509 credential store (issue #112 follow-up).

``VaultX509Store`` persists, per subject, the Globus passphrase captured at
link time (the custodianship model chosen for hands-free renewal), the POSIX
identity every re-mint request needs, and the current proxy PEM with its
metadata — one KV-v2 record at ``{prefix}/{subject}/x509`` over the shared
``VaultKV`` transport, mirroring ``credentials/vault.py``'s VaultTokenStore
layout and CAS conventions. A fake Vault HTTP API is built with
``httpx.MockTransport`` (same harness shape as ``test_oauth21_vault.py``).
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from pydantic import SecretStr

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials.x509_vault import VaultX509Store
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from pathlib import Path

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"
KV_PATH_PREFIX = "mcp/x509"

SUBJECT = "kc-subject-123"

_PEM = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
_DN = "/DC=ch/DC=cern/CN=Test User"
_VOMS_ATTRS = ["/atlas/Role=NULL", "/atlas"]


class _FakeVault:
    """In-memory fake of the subset of Vault's HTTP API this store uses.

    ``entries`` maps the KV path under the prefix (i.e. ``{subject}/x509``)
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
def store(fake_vault: _FakeVault, sa_token_path: Path) -> VaultX509Store:
    vault_kv = VaultKV(
        addr=ADDR,
        auth_mount=AUTH_MOUNT,
        auth_role=AUTH_ROLE,
        kv_mount=KV_MOUNT,
        sa_token_path=str(sa_token_path),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake_vault.handle)),
    )
    return VaultX509Store(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)


async def _link(store: VaultX509Store, subject: str = SUBJECT) -> None:
    await store.store_link(
        subject,
        passphrase=SecretStr("hunter2-passphrase"),
        unixname="auser",
        uid=50123,
        gid=5000,
    )


async def _store_proxy(
    store: VaultX509Store,
    subject: str = SUBJECT,
    *,
    remaining: float = 3600.0,
    nickname: str | None = None,
) -> float:
    not_after = time.time() + remaining
    await store.store_proxy(
        subject,
        pem=_PEM,
        dn=_DN,
        voms_attributes=_VOMS_ATTRS,
        not_after=not_after,
        nickname=nickname,
    )
    return not_after


# ---------------------------------------------------------------------------
# Link half: store_link / get_link / path layout
# ---------------------------------------------------------------------------


class TestLink:
    async def test_get_link_returns_none_when_never_linked(self, store) -> None:
        assert await store.get_link(SUBJECT) is None

    async def test_store_link_roundtrips_passphrase_and_posix(self, store) -> None:
        await _link(store)
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.passphrase is not None
        assert link.passphrase.get_secret_value() == "hunter2-passphrase"
        assert link.unixname == "auser"
        assert link.uid == 50123
        assert link.gid == 5000

    async def test_record_lives_at_prefix_subject_x509(self, store, fake_vault) -> None:
        await _link(store)
        assert list(fake_vault.entries) == [f"{SUBJECT}/x509"]

    async def test_passphrase_is_stored_revealed_not_masked(
        self, store, fake_vault
    ) -> None:
        """pydantic masks SecretStr as ********** on model_dump; persistence
        must store the real value (same reveal discipline as VaultTokenStore)."""
        await _link(store)
        stored = fake_vault.entries[f"{SUBJECT}/x509"]["data"]
        assert stored["passphrase"] == "hunter2-passphrase"

    async def test_relink_replaces_passphrase_and_clears_stale_proxy(
        self, store
    ) -> None:
        """A re-link means a possibly-new passphrase (the user changed their
        Globus password) — the previous proxy may no longer be re-mintable
        and must not survive the link."""
        await _link(store)
        await _store_proxy(store)
        await store.store_link(
            SUBJECT,
            passphrase=SecretStr("new-passphrase"),
            unixname="auser",
            uid=50123,
            gid=5000,
        )
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.passphrase is not None
        assert link.passphrase.get_secret_value() == "new-passphrase"
        assert await store.get_proxy(SUBJECT) is None


# ---------------------------------------------------------------------------
# Proxy half: store_proxy / get_proxy expiry awareness
# ---------------------------------------------------------------------------


class TestProxy:
    async def test_get_proxy_returns_none_when_nothing_stored(self, store) -> None:
        assert await store.get_proxy(SUBJECT) is None

    async def test_store_proxy_roundtrips_pem_and_metadata(self, store) -> None:
        await _link(store)
        not_after = await _store_proxy(store)
        record = await store.get_proxy(SUBJECT)
        assert record is not None
        assert record.proxy_pem is not None
        assert record.proxy_pem.get_secret_value() == _PEM
        assert record.dn == _DN
        assert record.voms_attributes == _VOMS_ATTRS
        assert record.not_after == pytest.approx(not_after)

    async def test_store_proxy_preserves_the_link(self, store) -> None:
        await _link(store)
        await _store_proxy(store)
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.passphrase is not None
        assert link.passphrase.get_secret_value() == "hunter2-passphrase"

    async def test_get_proxy_is_expiry_aware(self, store) -> None:
        await _link(store)
        await _store_proxy(store, remaining=-10.0)
        assert await store.get_proxy(SUBJECT) is None

    async def test_get_proxy_honors_min_remaining(self, store) -> None:
        await _link(store)
        await _store_proxy(store, remaining=100.0)
        assert await store.get_proxy(SUBJECT, min_remaining=300) is None
        assert await store.get_proxy(SUBJECT, min_remaining=50) is not None

    async def test_expired_proxy_does_not_hide_the_link(self, store) -> None:
        """An expired proxy with a stored passphrase is exactly the
        hands-free-renewal state: get_proxy says no, get_link still says yes."""
        await _link(store)
        await _store_proxy(store, remaining=-10.0)
        assert await store.get_proxy(SUBJECT) is None
        assert await store.get_link(SUBJECT) is not None

    async def test_records_are_per_subject(self, store) -> None:
        await _link(store, subject="someone-else")
        await _store_proxy(store, subject="someone-else")
        assert await store.get_proxy(SUBJECT) is None
        assert await store.get_link(SUBJECT) is None

    async def test_store_proxy_roundtrips_nickname(self, store) -> None:
        await _link(store)
        await _store_proxy(store, nickname="jdoe")
        record = await store.get_proxy(SUBJECT)
        assert record is not None
        assert record.nickname == "jdoe"

    async def test_store_proxy_nickname_defaults_to_none(self, store) -> None:
        """A voms-token-service that hasn't shipped nicknames yet must not
        make store_proxy() raise or leave nickname unset."""
        await _link(store)
        await _store_proxy(store)
        record = await store.get_proxy(SUBJECT)
        assert record is not None
        assert record.nickname is None


class TestClearProxy:
    async def test_clear_proxy_removes_proxy_but_keeps_the_link(self, store) -> None:
        """Proxy revocation (DELETE /v1/x509/proxy) must not unlink the
        identity — the passphrase stays so the next issue() renews
        hands-free."""
        await _link(store)
        await _store_proxy(store)
        await store.clear_proxy(SUBJECT)
        assert await store.get_proxy(SUBJECT) is None
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.passphrase is not None
        assert link.passphrase.get_secret_value() == "hunter2-passphrase"

    async def test_clear_proxy_when_nothing_stored_is_a_noop(self, store) -> None:
        await store.clear_proxy(SUBJECT)  # must not raise
        assert await store.get_link(SUBJECT) is None


# ---------------------------------------------------------------------------
# delete (unlink)
# ---------------------------------------------------------------------------


class TestDelete:
    async def test_delete_removes_link_and_proxy(self, store, fake_vault) -> None:
        await _link(store)
        await _store_proxy(store)
        await store.delete(SUBJECT)
        assert await store.get_link(SUBJECT) is None
        assert await store.get_proxy(SUBJECT) is None
        assert fake_vault.entries == {}

    async def test_delete_is_idempotent(self, store) -> None:
        await store.delete(SUBJECT)  # never linked — must not raise

    async def test_relink_after_delete_succeeds(self, store) -> None:
        """delete() must destroy metadata (not soft-delete data) so the next
        store_link's cas=0 create succeeds — same reasoning as
        VaultKV.delete_metadata's docstring."""
        await _link(store)
        await store.delete(SUBJECT)
        await _link(store)
        assert await store.get_link(SUBJECT) is not None


# ---------------------------------------------------------------------------
# CAS behavior
# ---------------------------------------------------------------------------


class TestCas:
    async def test_store_proxy_retries_on_cas_conflict(
        self, store, fake_vault, monkeypatch
    ) -> None:
        """A concurrent writer bumping the version between this store's read
        and write (cross-replica renewal race) must be absorbed by re-reading
        and retrying, not surfaced to the caller."""
        await _link(store)

        original_write_cas = store._vault_kv.write_cas
        raced = {"done": False}

        async def racing_write_cas(path, data, expected_version):
            if not raced["done"]:
                raced["done"] = True
                # Simulate another replica writing first: bump the stored
                # version so this call's expected_version is stale.
                entry = fake_vault.entries[f"{SUBJECT}/x509"]
                entry["version"] += 1
            return await original_write_cas(path, data, expected_version)

        monkeypatch.setattr(store._vault_kv, "write_cas", racing_write_cas)
        await _store_proxy(store)
        record = await store.get_proxy(SUBJECT)
        assert record is not None


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TestSettings:
    def test_kv_path_prefix_default_is_distinct_from_other_vault_stores(self) -> None:
        settings = Settings()
        assert settings.x509_kv_path_prefix == "mcp/x509"
        assert settings.x509_kv_path_prefix not in {
            settings.vault_kv_path_prefix,
            settings.token_registry_kv_path_prefix,
            settings.principal_cache_kv_path_prefix,
        }


# ---------------------------------------------------------------------------
# Custody modes (remember=false): proxy persists, passphrase does not
# ---------------------------------------------------------------------------


class TestCustodyMode:
    async def _link_until_expiry(self, store: VaultX509Store) -> None:
        await store.store_link(
            SUBJECT, passphrase=None, unixname="auser", uid=50123, gid=5000
        )

    async def test_store_link_without_passphrase_stores_posix_only(
        self, store, fake_vault
    ) -> None:
        await self._link_until_expiry(store)
        stored = fake_vault.entries[f"{SUBJECT}/x509"]["data"]
        assert stored["passphrase"] is None
        assert stored["unixname"] == "auser"
        assert stored["uid"] == 50123

    async def test_get_link_returns_none_without_a_stored_passphrase(
        self, store
    ) -> None:
        """Renewal paths key off get_link — without a passphrase there is
        nothing to renew with, so the record must not read as a link."""
        await self._link_until_expiry(store)
        assert await store.get_link(SUBJECT) is None

    async def test_get_returns_none_when_nothing_stored(self, store) -> None:
        assert await store.get(SUBJECT) is None

    async def test_get_returns_the_record_regardless_of_halves(self, store) -> None:
        """link_status derives linked-until-expiry from the whole record in
        one read — get() must serve it even when get_link/get_proxy would
        both answer None."""
        await self._link_until_expiry(store)
        record = await store.get(SUBJECT)
        assert record is not None
        assert record.passphrase is None
        assert record.unixname == "auser"
        assert record.proxy_pem is None

    async def test_proxy_after_unremembered_link_round_trips(self, store) -> None:
        await self._link_until_expiry(store)
        await _store_proxy(store)
        record = await store.get_proxy(SUBJECT)
        assert record is not None
        assert record.passphrase is None
        assert record.proxy_pem is not None
        assert record.proxy_pem.get_secret_value() == _PEM

    async def test_unremembered_relink_clears_a_previously_stored_passphrase(
        self, store
    ) -> None:
        """Re-linking with remember=false is a custody downgrade the user
        chose: the previously stored passphrase must not survive it."""
        await _link(store)
        await _store_proxy(store)
        await self._link_until_expiry(store)
        record = await store.get(SUBJECT)
        assert record is not None
        assert record.passphrase is None
        # store_link semantics are unchanged: a (re-)link never keeps the
        # previous proxy either.
        assert record.proxy_pem is None

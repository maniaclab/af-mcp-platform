"""Tests for ``VaultKV``, the shared Vault/OpenBao KV-v2 transport client.

A fake Vault HTTP API is built with ``httpx.MockTransport`` -- no real Vault
process, no ``hvac``. Covers the Kubernetes auth login/re-auth flow (caching,
safety margin, single-flight lock) and the four KV verbs' error mapping,
independent of any consumer's path layout or record shape -- see
``test_oauth21_vault.py`` and ``test_token_registry.py`` for the consumers
built on top of this.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from af_mcp_broker.vault_kv import CasConflict, VaultError, VaultKV

if TYPE_CHECKING:
    from pathlib import Path

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"

PATH = "some/prefix/entry"


class _FakeVault:
    """In-memory fake of the subset of Vault's HTTP API ``VaultKV`` uses.

    ``entries`` maps a full KV path (below the mount) -> ``{"data": dict,
    "version": int}``. A key absent from ``entries`` behaves as Vault does
    for a path that has never been written to *or* whose metadata has been
    destroyed: GET 404s, LIST 404s, and a CAS write with ``cas=0`` succeeds
    (current version is 0).
    """

    def __init__(
        self, *, login_lease_duration: int = 3600, kv_status: int | None = None
    ) -> None:
        self.entries: dict[str, dict[str, Any]] = {}
        self.login_calls: list[dict[str, Any]] = []
        self.login_lease_duration = login_lease_duration
        # When set, every KV data/metadata request responds with this status
        # instead of running the normal CAS logic -- for error-mapping tests.
        self.kv_status = kv_status

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
            body = _json_body(request)
            self.login_calls.append(body)
            return httpx.Response(
                200,
                json={
                    "auth": {
                        "client_token": "vault-test-token",
                        "lease_duration": self.login_lease_duration,
                        "renewable": True,
                    }
                },
                request=request,
            )

        data_prefix = f"{KV_MOUNT}/data/"
        meta_prefix = f"{KV_MOUNT}/metadata/"

        if path.startswith(data_prefix):
            key = path[len(data_prefix) :]
            is_metadata = False
        elif path.startswith(meta_prefix):
            key = path[len(meta_prefix) :]
            is_metadata = True
        else:
            return httpx.Response(
                404, json={"errors": ["unknown path"]}, request=request
            )

        if self.kv_status is not None:
            return httpx.Response(
                self.kv_status, json={"errors": ["internal error"]}, request=request
            )

        if request.method == "GET" and not is_metadata:
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
            body = _json_body(request)
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

        if request.method == "LIST" and is_metadata:
            keys = sorted(
                {
                    k[len(key) :].lstrip("/").split("/")[0]
                    for k in self.entries
                    if k.startswith(key)
                }
            )
            if not keys:
                return httpx.Response(404, json={"errors": []}, request=request)
            return httpx.Response(200, json={"data": {"keys": keys}}, request=request)

        if request.method == "DELETE" and is_metadata:
            self.entries.pop(key, None)
            return httpx.Response(204, request=request)

        return httpx.Response(
            404, json={"errors": ["unhandled"]}, request=request
        )  # pragma: no cover


def _json_body(request: httpx.Request) -> dict[str, Any]:
    import json

    return json.loads(request.content.decode())


def _make_vault_kv(fake: _FakeVault, sa_token_path: Path, **overrides: Any) -> VaultKV:
    kwargs: dict[str, Any] = {
        "addr": ADDR,
        "auth_mount": AUTH_MOUNT,
        "auth_role": AUTH_ROLE,
        "kv_mount": KV_MOUNT,
        "sa_token_path": str(sa_token_path),
        "http_client": httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)),
    }
    kwargs.update(overrides)
    return VaultKV(**kwargs)


@pytest.fixture
def sa_token_path(tmp_path: Path) -> Path:
    path = tmp_path / "sa-token"
    path.write_text("fake-sa-jwt\n")
    return path


# ---------------------------------------------------------------------------
# K8s auth: login, caching, re-authentication
# ---------------------------------------------------------------------------


async def test_authenticate_reads_sa_jwt_and_logs_in(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    token = await vault_kv._authenticate()

    assert token == "vault-test-token"
    assert len(fake.login_calls) == 1
    assert fake.login_calls[0] == {"role": AUTH_ROLE, "jwt": "fake-sa-jwt"}


async def test_authenticate_caches_token_across_calls(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    await vault_kv._authenticate()
    await vault_kv._authenticate()

    assert len(fake.login_calls) == 1


async def test_authenticate_reauthenticates_when_near_expiry(
    sa_token_path: Path,
) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    await vault_kv._authenticate()
    assert len(fake.login_calls) == 1

    # Force the cached token to look like it's within the safety margin of
    # expiry (or already past it) without needing to sleep in the test.
    vault_kv._expires_at = datetime.now(UTC) - timedelta(seconds=1)

    await vault_kv._authenticate()
    assert len(fake.login_calls) == 2


async def test_authenticate_concurrent_callers_login_once(
    sa_token_path: Path,
) -> None:
    """The asyncio.Lock around re-authentication must prevent a login storm
    when multiple coroutines race to authenticate with no cached token yet.
    """
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    await asyncio.gather(*(vault_kv._authenticate() for _ in range(5)))

    assert len(fake.login_calls) == 1


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------


async def test_get_returns_none_on_404(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    assert await vault_kv.get(PATH) is None


async def test_get_returns_data_and_version(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    got = await vault_kv.get(PATH)

    assert got is not None
    data, version = got
    assert data == {"foo": "bar"}
    assert version == 1


async def test_get_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = _FakeVault(kv_status=500)
    vault_kv = _make_vault_kv(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await vault_kv.get(PATH)


# ---------------------------------------------------------------------------
# write_cas() CAS semantics
# ---------------------------------------------------------------------------


async def test_write_cas_none_creates_when_missing(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    version = await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    assert version == 1


async def test_write_cas_none_conflicts_when_existing(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    with pytest.raises(CasConflict):
        await vault_kv.write_cas(PATH, {"foo": "baz"}, expected_version=None)


async def test_write_cas_with_matching_version_succeeds(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)  # v1

    version = await vault_kv.write_cas(PATH, {"foo": "baz"}, expected_version=1)

    assert version == 2


async def test_write_cas_with_stale_version_conflicts(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)  # v1
    await vault_kv.write_cas(PATH, {"foo": "baz"}, expected_version=1)  # v2

    with pytest.raises(CasConflict):
        await vault_kv.write_cas(PATH, {"foo": "qux"}, expected_version=1)


async def test_write_cas_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = _FakeVault(kv_status=500)
    vault_kv = _make_vault_kv(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


async def test_list_returns_empty_on_404(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    assert await vault_kv.list("some/prefix") == []


async def test_list_returns_child_keys(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas("some/prefix/one", {}, expected_version=None)
    await vault_kv.write_cas("some/prefix/two", {}, expected_version=None)

    keys = await vault_kv.list("some/prefix")

    assert sorted(keys) == ["one", "two"]


async def test_list_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = _FakeVault(kv_status=500)
    vault_kv = _make_vault_kv(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await vault_kv.list("some/prefix")


# ---------------------------------------------------------------------------
# delete_metadata()
# ---------------------------------------------------------------------------


async def test_delete_metadata_existing_then_get_returns_none(
    sa_token_path: Path,
) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    await vault_kv.delete_metadata(PATH)

    assert await vault_kv.get(PATH) is None


async def test_delete_metadata_then_write_cas_none_succeeds_again(
    sa_token_path: Path,
) -> None:
    """The metadata-endpoint delete must fully reset the version counter, or
    a subsequent create (``expected_version=None`` -> ``cas=0``) would fail
    forever against Vault's soft-delete semantics.
    """
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)
    await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)
    await vault_kv.delete_metadata(PATH)

    version = await vault_kv.write_cas(PATH, {"foo": "bar"}, expected_version=None)

    assert version == 1


async def test_delete_metadata_nonexistent_is_idempotent(sa_token_path: Path) -> None:
    fake = _FakeVault()
    vault_kv = _make_vault_kv(fake, sa_token_path)

    await vault_kv.delete_metadata(PATH)  # must not raise


async def test_delete_metadata_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = _FakeVault(kv_status=500)
    vault_kv = _make_vault_kv(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await vault_kv.delete_metadata(PATH)

"""Tests for the token-registry backends (issue #115).

Covers the shared ``TokenRegistryBackend`` contract parametrized across both
implementations (``InMemoryTokenRegistryBackend``, ``VaultTokenRegistryBackend``
— the latter against a fake Vault HTTP API via ``httpx.MockTransport``, same
technique as ``test_oauth21_vault.py``), plus ``RevokedJtiCache``'s
refresh/staleness behavior.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest

if TYPE_CHECKING:
    from pathlib import Path

from af_mcp_broker.token_registry import (
    InMemoryTokenRegistryBackend,
    RevokedJtiCache,
    TokenRecord,
    TokenRegistryBackend,
    VaultTokenRegistryBackend,
)

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"
KV_PATH_PREFIX = "mcp/token-registry"


def _make_record(**overrides: Any) -> TokenRecord:
    now = time.time()
    defaults: dict[str, Any] = {
        "jti": "jti-1",
        "uid": 1000,
        "subject": "kc-subject-1",
        "name": "claude-desktop",
        "issued_at": now,
        "expires_at": now + 3600.0,
        "revoked_at": None,
        "minted_via": "portal",
    }
    defaults.update(overrides)
    return TokenRecord(**defaults)


# ---------------------------------------------------------------------------
# Fake Vault KV-v2 HTTP API (generic get/write_cas -- no delete needed, the
# registry never removes an entry, only sets revoked_at -- see the module
# docstring in token_registry.py for why unbounded Vault-side growth is an
# accepted, documented tradeoff.)
# ---------------------------------------------------------------------------


class _FakeRegistryVault:
    def __init__(self, *, login_lease_duration: int = 3600) -> None:
        self.entries: dict[str, dict[str, Any]] = {}
        self.login_calls: list[dict[str, Any]] = []
        self.login_lease_duration = login_lease_duration

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
            body = json.loads(request.content.decode())
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

        prefix = f"{KV_MOUNT}/data/"
        if not path.startswith(prefix):
            return httpx.Response(
                404, json={"errors": ["unknown path"]}, request=request
            )
        key = path[len(prefix) :]

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

        if request.method == "POST":
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

        return httpx.Response(
            404, json={"errors": ["unhandled"]}, request=request
        )  # pragma: no cover


@pytest.fixture
def sa_token_path(tmp_path: Path) -> Path:
    path = tmp_path / "sa-token"
    path.write_text("fake-sa-jwt\n")
    return path


def _make_vault_backend(
    fake: _FakeRegistryVault, sa_token_path: Path
) -> VaultTokenRegistryBackend:
    return VaultTokenRegistryBackend(
        addr=ADDR,
        auth_mount=AUTH_MOUNT,
        auth_role=AUTH_ROLE,
        kv_mount=KV_MOUNT,
        kv_path_prefix=KV_PATH_PREFIX,
        sa_token_path=str(sa_token_path),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)),
    )


# ---------------------------------------------------------------------------
# Shared TokenRegistryBackend contract, parametrized across both backends.
# ---------------------------------------------------------------------------


@pytest.fixture(params=["in_memory", "vault"])
def backend(
    request: pytest.FixtureRequest, sa_token_path: Path
) -> TokenRegistryBackend:
    if request.param == "in_memory":
        return InMemoryTokenRegistryBackend()
    fake = _FakeRegistryVault()
    return _make_vault_backend(fake, sa_token_path)


async def test_list_for_uid_empty_when_nothing_minted(
    backend: TokenRegistryBackend,
) -> None:
    assert await backend.list_for_uid(1000) == []


async def test_add_then_list_for_uid_returns_it(backend: TokenRegistryBackend) -> None:
    record = _make_record()
    await backend.add(record)

    rows = await backend.list_for_uid(record.uid)

    assert len(rows) == 1
    assert rows[0].jti == record.jti
    assert rows[0].name == record.name
    assert rows[0].revoked_at is None


async def test_list_for_uid_excludes_other_uids(backend: TokenRegistryBackend) -> None:
    await backend.add(_make_record(jti="mine", uid=1000))
    await backend.add(_make_record(jti="theirs", uid=2000))

    rows = await backend.list_for_uid(1000)

    assert [r.jti for r in rows] == ["mine"]


async def test_get_unknown_jti_returns_none(backend: TokenRegistryBackend) -> None:
    assert await backend.get(1000, "does-not-exist") is None


async def test_get_returns_record(backend: TokenRegistryBackend) -> None:
    await backend.add(_make_record())
    got = await backend.get(1000, "jti-1")
    assert got is not None
    assert got.jti == "jti-1"


async def test_owner_uid_unknown_jti_returns_none(
    backend: TokenRegistryBackend,
) -> None:
    assert await backend.owner_uid("does-not-exist") is None


async def test_owner_uid_returns_owning_uid(backend: TokenRegistryBackend) -> None:
    await backend.add(_make_record(jti="jti-1", uid=42))
    assert await backend.owner_uid("jti-1") == 42


async def test_revoke_unknown_jti_returns_none(backend: TokenRegistryBackend) -> None:
    assert await backend.revoke(1000, "does-not-exist", revoked_at=123.0) is None


async def test_revoke_wrong_uid_returns_none(backend: TokenRegistryBackend) -> None:
    """revoke() is uid-scoped: a jti that exists under a *different* uid must
    not be revocable by passing the wrong uid -- API-layer ownership checks
    rely on this (see owner_uid(), used for the 403-vs-404 distinction)."""
    await backend.add(_make_record(jti="jti-1", uid=1000))

    assert await backend.revoke(9999, "jti-1", revoked_at=123.0) is None
    # ... and the record is untouched.
    assert (await backend.get(1000, "jti-1")).revoked_at is None  # type: ignore[union-attr]


async def test_revoke_sets_revoked_at_and_appears_in_list_revoked_jtis(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(_make_record(jti="jti-1", uid=1000))

    updated = await backend.revoke(1000, "jti-1", revoked_at=555.0)

    assert updated is not None
    assert updated.revoked_at == 555.0
    assert (await backend.get(1000, "jti-1")).revoked_at == 555.0  # type: ignore[union-attr]
    assert "jti-1" in await backend.list_revoked_jtis()


async def test_list_revoked_jtis_excludes_active_tokens(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(_make_record(jti="active-jti", uid=1000))
    await backend.add(_make_record(jti="revoked-jti", uid=1000))
    await backend.revoke(1000, "revoked-jti", revoked_at=1.0)

    revoked = await backend.list_revoked_jtis()

    assert revoked == frozenset({"revoked-jti"})


# ---------------------------------------------------------------------------
# Vault-specific: HA consistency across two independent backend instances
# sharing the same fake KV (simulating two broker replicas), and "survives
# restart" (a fresh instance against the same fake sees prior writes).
# ---------------------------------------------------------------------------


async def test_mint_on_one_replica_visible_on_another(sa_token_path: Path) -> None:
    fake = _FakeRegistryVault()
    replica_a = _make_vault_backend(fake, sa_token_path)
    replica_b = _make_vault_backend(fake, sa_token_path)

    await replica_a.add(_make_record(jti="jti-1", uid=1000))

    rows = await replica_b.list_for_uid(1000)
    assert [r.jti for r in rows] == ["jti-1"]


async def test_revoke_on_one_replica_visible_on_another(sa_token_path: Path) -> None:
    fake = _FakeRegistryVault()
    replica_a = _make_vault_backend(fake, sa_token_path)
    replica_b = _make_vault_backend(fake, sa_token_path)
    await replica_a.add(_make_record(jti="jti-1", uid=1000))

    await replica_b.revoke(1000, "jti-1", revoked_at=42.0)

    assert "jti-1" in await replica_a.list_revoked_jtis()
    got = await replica_a.get(1000, "jti-1")
    assert got is not None
    assert got.revoked_at == 42.0


async def test_records_survive_reconstructing_the_backend(sa_token_path: Path) -> None:
    """A fresh VaultTokenRegistryBackend pointed at the same fake KV models a
    broker pod restart -- the object is new, but persisted state is not."""
    fake = _FakeRegistryVault()
    backend_before = _make_vault_backend(fake, sa_token_path)
    await backend_before.add(_make_record(jti="jti-1", uid=1000))

    backend_after = _make_vault_backend(fake, sa_token_path)
    rows = await backend_after.list_for_uid(1000)

    assert [r.jti for r in rows] == ["jti-1"]


async def test_add_retries_on_concurrent_cas_conflict(sa_token_path: Path) -> None:
    """Two concurrent add() calls for the same uid (different jtis) must both
    succeed -- the read-modify-write CAS loop must retry on a version
    conflict rather than silently dropping one of the two writes."""
    fake = _FakeRegistryVault()
    replica_a = _make_vault_backend(fake, sa_token_path)
    replica_b = _make_vault_backend(fake, sa_token_path)

    await asyncio.gather(
        replica_a.add(_make_record(jti="jti-a", uid=1000)),
        replica_b.add(_make_record(jti="jti-b", uid=1000)),
    )

    rows = await replica_a.list_for_uid(1000)
    assert {r.jti for r in rows} == {"jti-a", "jti-b"}


async def test_vault_authenticates_once_and_caches_token(sa_token_path: Path) -> None:
    fake = _FakeRegistryVault()
    backend = _make_vault_backend(fake, sa_token_path)

    await backend.add(_make_record())
    await backend.list_for_uid(1000)

    assert len(fake.login_calls) == 1
    assert fake.login_calls[0] == {"role": AUTH_ROLE, "jwt": "fake-sa-jwt"}


# ---------------------------------------------------------------------------
# RevokedJtiCache
# ---------------------------------------------------------------------------


class _CountingBackend:
    """Wraps a real backend, counting list_revoked_jtis() calls and
    optionally raising on the next N calls -- for refresh-failure tests."""

    def __init__(self, inner: TokenRegistryBackend) -> None:
        self._inner = inner
        self.refresh_calls = 0
        self.fail_next = 0

    async def list_revoked_jtis(self) -> frozenset[str]:
        self.refresh_calls += 1
        if self.fail_next > 0:
            self.fail_next -= 1
            raise RuntimeError("vault unreachable")
        return await self._inner.list_revoked_jtis()


async def test_is_revoked_false_when_nothing_revoked() -> None:
    backend = InMemoryTokenRegistryBackend()
    cache = RevokedJtiCache(backend, refresh_interval_seconds=30.0)

    assert await cache.is_revoked("anything") is False


async def test_is_revoked_true_after_refresh_picks_up_revocation() -> None:
    backend = InMemoryTokenRegistryBackend()
    await backend.add(_make_record(jti="jti-1", uid=1000))
    await backend.revoke(1000, "jti-1", revoked_at=1.0)
    cache = RevokedJtiCache(backend, refresh_interval_seconds=30.0)

    assert await cache.is_revoked("jti-1") is True


async def test_unknown_jti_never_revoked_even_with_no_registry_entry() -> None:
    """Ordinary Keycloak session tokens carry a jti that was never minted
    through the registry at all -- they must never be treated as revoked."""
    backend = InMemoryTokenRegistryBackend()
    await backend.add(_make_record(jti="some-other-jti", uid=1000))
    cache = RevokedJtiCache(backend, refresh_interval_seconds=30.0)

    assert await cache.is_revoked("a-normal-keycloak-session-jti") is False


async def test_revocation_is_not_visible_until_next_refresh_interval() -> None:
    """Bounded staleness: a revocation that happens between refreshes is not
    picked up until the refresh interval has elapsed."""
    backend = InMemoryTokenRegistryBackend()
    await backend.add(_make_record(jti="jti-1", uid=1000))
    cache = RevokedJtiCache(backend, refresh_interval_seconds=1000.0)

    # Prime the cache before the revocation happens.
    assert await cache.is_revoked("jti-1") is False

    await backend.revoke(1000, "jti-1", revoked_at=1.0)

    # Still within the refresh window -- must keep serving the stale (empty) set.
    assert await cache.is_revoked("jti-1") is False


async def test_refresh_failure_serves_stale_set_instead_of_raising() -> None:
    backend = InMemoryTokenRegistryBackend()
    await backend.add(_make_record(jti="jti-1", uid=1000))
    await backend.revoke(1000, "jti-1", revoked_at=1.0)
    counting = _CountingBackend(backend)
    cache = RevokedJtiCache(counting, refresh_interval_seconds=0.0)

    assert await cache.is_revoked("jti-1") is True  # primes the cache

    counting.fail_next = 1
    # Force a refresh attempt (interval is 0, so every call tries to refresh);
    # the failure must not raise and must not erase the previously-cached set.
    assert await cache.is_revoked("jti-1") is True

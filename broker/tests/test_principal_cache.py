"""Tests for PrincipalCache's stale-while-revalidate behavior, and its persistence backends (issue #144 steps 2a/2b).

Fakes ``PrincipalDirectory`` directly (an ABC -- see principal_directory.py)
rather than hitting a real Keycloak; the point of these tests is the
cache's own refresh/staleness/fail-closed logic, not any directory
implementation. Similarly, ``PrincipalCacheBackend`` is exercised via its
two real implementations (parametrized, same technique
test_token_registry.py uses for ``TokenRegistryBackend``) rather than a
fake, since the point there is that both backends satisfy the same
contract.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from af_mcp_broker.principal_cache import (
    InMemoryPrincipalCacheBackend,
    PersistedPrincipalRecord,
    PrincipalCache,
    PrincipalCacheBackend,
    PrincipalUnavailableError,
    VaultPrincipalCacheBackend,
)
from af_mcp_broker.principal_directory import PrincipalAttributes, PrincipalDirectory
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from pathlib import Path


class _FakeDirectory(PrincipalDirectory):
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.responses: dict[str, PrincipalAttributes] = {}
        self.fail_next = 0

    async def resolve(self, principal_id: str) -> PrincipalAttributes:
        self.calls.append(principal_id)
        if self.fail_next > 0:
            self.fail_next -= 1
            raise RuntimeError("directory unreachable")
        return self.responses[principal_id]


class _CountingBackend(PrincipalCacheBackend):
    """Wraps an ``InMemoryPrincipalCacheBackend``, counting put() calls and optionally raising on the next N get()/put() calls -- for write-amplification and degrade-to-in-memory tests."""

    def __init__(self) -> None:
        self._inner = InMemoryPrincipalCacheBackend()
        self.put_calls = 0
        self.fail_get_next = 0
        self.fail_put_next = 0

    async def get(self, principal_id: str) -> PersistedPrincipalRecord | None:
        if self.fail_get_next > 0:
            self.fail_get_next -= 1
            raise RuntimeError("vault unreachable")
        return await self._inner.get(principal_id)

    async def put(self, principal_id: str, record: PersistedPrincipalRecord) -> None:
        self.put_calls += 1
        if self.fail_put_next > 0:
            self.fail_put_next -= 1
            raise RuntimeError("vault unreachable")
        await self._inner.put(principal_id, record)


def _attrs(**overrides) -> PrincipalAttributes:
    defaults = {
        "uid": 1000,
        "gid": 1000,
        "unixname": "auser",
        "groups": ["atlas"],
        "email": "auser@example.org",
    }
    defaults.update(overrides)
    return PrincipalAttributes(**defaults)


async def test_get_resolves_on_first_call() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs()
    cache = PrincipalCache(
        directory,
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=30.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    attrs = await cache.get("p1")

    assert attrs.uid == 1000
    assert directory.calls == ["p1"]


async def test_get_serves_cached_value_within_refresh_interval() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs()
    cache = PrincipalCache(
        directory,
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=1000.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    await cache.get("p1")
    await cache.get("p1")

    assert directory.calls == ["p1"]  # only resolved once


async def test_get_refreshes_after_interval_elapses() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])
    cache = PrincipalCache(
        directory,
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=0.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    await cache.get("p1")
    directory.responses["p1"] = _attrs(groups=["atlas", "af-admins"])
    attrs = await cache.get("p1")

    assert len(directory.calls) == 2
    assert attrs.groups == ["atlas", "af-admins"]


async def test_different_principals_cached_independently() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(uid=1)
    directory.responses["p2"] = _attrs(uid=2)
    cache = PrincipalCache(
        directory,
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=1000.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    a1 = await cache.get("p1")
    a2 = await cache.get("p2")

    assert a1.uid == 1
    assert a2.uid == 2


async def test_cold_start_failure_raises_principal_unavailable() -> None:
    directory = _FakeDirectory()
    directory.fail_next = 1
    cache = PrincipalCache(
        directory,
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=30.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    with pytest.raises(PrincipalUnavailableError):
        await cache.get("p1")


async def test_refresh_failure_serves_stale_value_within_max_staleness() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])
    cache = PrincipalCache(
        directory,
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=0.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )
    await cache.get("p1")  # primes the cache

    directory.fail_next = 1
    attrs = await cache.get("p1")  # refresh interval is 0 -> always attempts refresh

    assert attrs.groups == ["atlas"]  # served stale, not raised


async def test_fails_closed_once_max_staleness_exceeded(monkeypatch) -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs()
    cache = PrincipalCache(
        directory,
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=0.0,
        max_staleness_seconds=100.0,
        heartbeat_interval_seconds=3600.0,
    )
    await cache.get("p1")  # primes the cache

    # Simulate 200s having passed since the last successful refresh without
    # needing a real sleep.
    real_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + 200.0)

    directory.fail_next = 1
    with pytest.raises(PrincipalUnavailableError):
        await cache.get("p1")


# ---------------------------------------------------------------------------
# Fake Vault KV-v2 HTTP API for VaultPrincipalCacheBackend -- get/write_cas
# only, same technique as test_token_registry.py's _FakeRegistryVault, pared
# down since this backend needs no LIST/DELETE (no secondary indices).
# ---------------------------------------------------------------------------

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"
KV_PATH_PREFIX = "mcp/principal-cache"


class _FakePrincipalCacheVault:
    def __init__(self, *, login_lease_duration: int = 3600) -> None:
        self.entries: dict[str, dict[str, Any]] = {}
        self.login_lease_duration = login_lease_duration

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
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
        if not path.startswith(data_prefix):
            return httpx.Response(
                404, json={"errors": ["unknown path"]}, request=request
            )
        key = path[len(data_prefix) :]

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
    fake: _FakePrincipalCacheVault, sa_token_path: Path
) -> VaultPrincipalCacheBackend:
    vault_kv = VaultKV(
        addr=ADDR,
        auth_mount=AUTH_MOUNT,
        auth_role=AUTH_ROLE,
        kv_mount=KV_MOUNT,
        sa_token_path=str(sa_token_path),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)),
    )
    return VaultPrincipalCacheBackend(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)


# ---------------------------------------------------------------------------
# Shared PrincipalCacheBackend contract, parametrized across both backends
# (same technique test_token_registry.py uses for TokenRegistryBackend).
# ---------------------------------------------------------------------------


@pytest.fixture(params=["in_memory", "vault"])
def cache_backend(
    request: pytest.FixtureRequest, sa_token_path: Path
) -> PrincipalCacheBackend:
    if request.param == "in_memory":
        return InMemoryPrincipalCacheBackend()
    fake = _FakePrincipalCacheVault()
    return _make_vault_backend(fake, sa_token_path)


async def test_backend_get_unknown_principal_returns_none(
    cache_backend: PrincipalCacheBackend,
) -> None:
    assert await cache_backend.get("p1") is None


async def test_backend_put_then_get_roundtrips(
    cache_backend: PrincipalCacheBackend,
) -> None:
    record = PersistedPrincipalRecord(attributes=_attrs(), resolved_at=1000.0)

    await cache_backend.put("p1", record)
    got = await cache_backend.get("p1")

    assert got == record


async def test_backend_put_overwrites_previous_value(
    cache_backend: PrincipalCacheBackend,
) -> None:
    await cache_backend.put(
        "p1", PersistedPrincipalRecord(attributes=_attrs(uid=1), resolved_at=1.0)
    )
    await cache_backend.put(
        "p1", PersistedPrincipalRecord(attributes=_attrs(uid=2), resolved_at=2.0)
    )

    got = await cache_backend.get("p1")

    assert got is not None
    assert got.attributes.uid == 2
    assert got.resolved_at == 2.0


async def test_backend_different_principals_independent(
    cache_backend: PrincipalCacheBackend,
) -> None:
    await cache_backend.put(
        "p1", PersistedPrincipalRecord(attributes=_attrs(uid=1), resolved_at=1.0)
    )
    await cache_backend.put(
        "p2", PersistedPrincipalRecord(attributes=_attrs(uid=2), resolved_at=2.0)
    )

    got1 = await cache_backend.get("p1")
    got2 = await cache_backend.get("p2")

    assert got1 is not None
    assert got1.attributes.uid == 1
    assert got2 is not None
    assert got2.attributes.uid == 2


async def test_vault_backend_survives_reconstructing_the_backend(
    sa_token_path: Path,
) -> None:
    """A fresh VaultPrincipalCacheBackend pointed at the same fake KV models a
    broker pod restart -- the object is new, but persisted state is not."""
    fake = _FakePrincipalCacheVault()
    backend_before = _make_vault_backend(fake, sa_token_path)
    await backend_before.put(
        "p1", PersistedPrincipalRecord(attributes=_attrs(), resolved_at=42.0)
    )

    backend_after = _make_vault_backend(fake, sa_token_path)
    got = await backend_after.get("p1")

    assert got is not None
    assert got.resolved_at == 42.0


# ---------------------------------------------------------------------------
# PrincipalCache <-> PrincipalCacheBackend integration: cold start, write
# amplification, and degrade-to-in-memory-only on backend failure (issue
# #144 step 2b).
# ---------------------------------------------------------------------------


async def test_cold_start_serves_fresh_persisted_value_without_hitting_directory() -> (
    None
):
    """A persisted value still within the refresh window is served directly
    on a cold start -- the directory must not even be consulted (see this
    module's "Read layering" docstring)."""
    backend = InMemoryPrincipalCacheBackend()
    await backend.put(
        "p1",
        PersistedPrincipalRecord(attributes=_attrs(uid=42), resolved_at=time.time()),
    )
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(uid=999)  # would prove it was consulted
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=1000.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    attrs = await cache.get("p1")

    assert attrs.uid == 42
    assert directory.calls == []


async def test_cold_start_serves_persisted_value_when_directory_unreachable() -> None:
    """The core scenario this feature exists for: a broker restart during a
    Keycloak outage serves the last-known persisted value instead of
    failing closed."""
    backend = InMemoryPrincipalCacheBackend()
    await backend.put(
        "p1",
        PersistedPrincipalRecord(
            attributes=_attrs(groups=["atlas"]), resolved_at=time.time() - 3600.0
        ),
    )
    directory = _FakeDirectory()
    directory.fail_next = 1
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=30.0,
        max_staleness_seconds=6 * 3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    attrs = await cache.get("p1")

    assert attrs.groups == ["atlas"]


async def test_cold_start_rejects_persisted_value_beyond_max_staleness() -> None:
    """A record persisted three days ago must not be served when max
    staleness is six hours -- it is the same as no cached value at all."""
    backend = InMemoryPrincipalCacheBackend()
    await backend.put(
        "p1",
        PersistedPrincipalRecord(
            attributes=_attrs(), resolved_at=time.time() - 3 * 24 * 3600.0
        ),
    )
    directory = _FakeDirectory()
    directory.fail_next = 1
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=30.0,
        max_staleness_seconds=6 * 3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    with pytest.raises(PrincipalUnavailableError):
        await cache.get("p1")


async def test_no_write_when_unchanged_content_is_within_heartbeat_interval() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])
    backend = _CountingBackend()
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=0.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    await cache.get("p1")
    await cache.get("p1")
    await cache.get("p1")

    # Only the very first resolve persists (nothing to compare against yet);
    # every subsequent refresh confirms the same groups, well within the
    # heartbeat interval, and must not write.
    assert backend.put_calls == 1


async def test_write_occurs_when_content_changes() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])
    backend = _CountingBackend()
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=0.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )
    await cache.get("p1")

    directory.responses["p1"] = _attrs(groups=["atlas", "af-admins"])
    await cache.get("p1")

    assert backend.put_calls == 2


async def test_changed_content_writes_immediately_regardless_of_heartbeat_interval() -> (
    None
):
    """A changed value must persist on the very next refresh, never waiting
    for a heartbeat -- the heartbeat interval below is deliberately huge
    (far longer than this test can possibly run for) so any write it
    observes can only be explained by the content change."""
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])
    backend = _CountingBackend()
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=0.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=1_000_000.0,
    )
    await cache.get("p1")
    assert backend.put_calls == 1

    directory.responses["p1"] = _attrs(groups=["atlas", "af-admins"])
    await cache.get("p1")

    assert backend.put_calls == 2


async def test_write_occurs_when_unchanged_content_exceeds_heartbeat_interval(
    monkeypatch,
) -> None:
    """The write a pure content-diff would skip forever: unchanged content,
    but the last persisted write is older than the heartbeat interval, must
    still write -- refreshing the durability of that knowledge."""
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])
    backend = _CountingBackend()
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=0.0,
        max_staleness_seconds=24 * 3600.0,
        heartbeat_interval_seconds=100.0,
    )
    await cache.get("p1")  # first-ever resolve always persists
    assert backend.put_calls == 1

    await cache.get("p1")  # unchanged, still within the heartbeat interval
    assert backend.put_calls == 1

    # Simulate the heartbeat interval elapsing without needing a real sleep
    # -- same technique test_fails_closed_once_max_staleness_exceeded uses.
    real_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + 200.0)

    await cache.get("p1")  # still unchanged, but the heartbeat is now due

    assert backend.put_calls == 2


async def test_stable_principal_beyond_max_staleness_still_servable_at_cold_start(
    monkeypatch,
) -> None:
    """The scenario the heartbeat exists to fix, end to end: a principal
    whose attributes have been stable far longer than max_staleness_seconds
    must still be servable from the persisted cache at a cold start. A pure
    content-diff (write only when something changed) would leave the
    persisted record dated from this principal's last actual change --
    here, far beyond max_staleness_seconds in the past -- and this test
    would fail closed instead of passing.
    """
    backend = InMemoryPrincipalCacheBackend()
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])

    # Advance both clocks together -- time.time() for the wall-clock
    # resolved_at persisted records carry, time.monotonic() for this
    # process's own refresh/heartbeat bookkeeping -- same technique
    # test_fails_closed_once_max_staleness_exceeded uses for a single jump,
    # generalized here to many small jumps via a shared offset.
    offset = 0.0
    real_monotonic = time.monotonic
    real_time = time.time
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + offset)
    monkeypatch.setattr(time, "time", lambda: real_time() + offset)

    heartbeat = (
        3 * 3600.0
    )  # matches Settings.principal_cache_heartbeat_seconds' default
    max_staleness = (
        6 * 3600.0
    )  # matches Settings.principal_cache_max_staleness_seconds' default
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=0.0,
        max_staleness_seconds=max_staleness,
        heartbeat_interval_seconds=heartbeat,
    )

    await cache.get("p1")  # this principal's one and only real change

    # 10 days of this principal's groups never changing, refreshed roughly
    # once per heartbeat interval -- exactly the steady-state PrincipalCache's
    # own refresh cycle would produce in production.
    ten_days = 10 * 24 * 3600.0
    elapsed = 0.0
    while elapsed < ten_days:
        offset += heartbeat
        elapsed += heartbeat
        await cache.get("p1")

    # A fresh PrincipalCache against the same backend models a broker
    # restart 10 days after this principal's last actual change, with the
    # directory now unreachable -- the outage scenario.
    directory.fail_next = 1
    cache_after_restart = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=30.0,
        max_staleness_seconds=max_staleness,
        heartbeat_interval_seconds=heartbeat,
    )

    attrs = await cache_after_restart.get("p1")

    assert attrs.groups == ["atlas"]


async def test_backend_read_failure_at_cold_start_falls_through_to_directory() -> None:
    """Vault unreachable at cold start degrades to in-memory-only -- treated
    exactly like a cache miss, not an error."""
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(uid=7)
    backend = _CountingBackend()
    backend.fail_get_next = 1
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=1000.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    attrs = await cache.get("p1")

    assert attrs.uid == 7
    assert directory.calls == ["p1"]


async def test_backend_write_failure_does_not_fail_the_request() -> None:
    """Vault being down must not take down authentication when a perfectly
    good in-memory value (the one just resolved) exists."""
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(uid=7)
    backend = _CountingBackend()
    backend.fail_put_next = 1
    cache = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=1000.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    attrs = await cache.get("p1")  # must not raise despite the persist failure

    assert attrs.uid == 7


async def test_records_survive_reconstructing_the_cache() -> None:
    """A fresh PrincipalCache pointed at the same backend models a broker
    pod restart. Combined with the directory being unreachable, this is the
    end-to-end version of the outage scenario issue #144 step 2b exists
    for."""
    backend = InMemoryPrincipalCacheBackend()
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])
    cache_before = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=0.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )
    await cache_before.get("p1")  # resolves and persists

    directory.fail_next = 1
    cache_after = PrincipalCache(
        directory,
        backend=backend,
        refresh_interval_seconds=30.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    attrs = await cache_after.get("p1")

    assert attrs.groups == ["atlas"]

"""Tests for PrincipalCache's stale-while-revalidate behavior (issue #144 step 2a).

Fakes ``PrincipalDirectory`` directly (an ABC -- see principal_directory.py)
rather than hitting a real Keycloak; the point of these tests is the
cache's own refresh/staleness/fail-closed logic, not any directory
implementation.
"""

from __future__ import annotations

import time

import pytest

from af_mcp_broker.principal_cache import PrincipalCache, PrincipalUnavailableError
from af_mcp_broker.principal_directory import PrincipalAttributes, PrincipalDirectory


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
        directory, refresh_interval_seconds=30.0, max_staleness_seconds=3600.0
    )

    attrs = await cache.get("p1")

    assert attrs.uid == 1000
    assert directory.calls == ["p1"]


async def test_get_serves_cached_value_within_refresh_interval() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs()
    cache = PrincipalCache(
        directory, refresh_interval_seconds=1000.0, max_staleness_seconds=3600.0
    )

    await cache.get("p1")
    await cache.get("p1")

    assert directory.calls == ["p1"]  # only resolved once


async def test_get_refreshes_after_interval_elapses() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])
    cache = PrincipalCache(
        directory, refresh_interval_seconds=0.0, max_staleness_seconds=3600.0
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
        directory, refresh_interval_seconds=1000.0, max_staleness_seconds=3600.0
    )

    a1 = await cache.get("p1")
    a2 = await cache.get("p2")

    assert a1.uid == 1
    assert a2.uid == 2


async def test_cold_start_failure_raises_principal_unavailable() -> None:
    directory = _FakeDirectory()
    directory.fail_next = 1
    cache = PrincipalCache(
        directory, refresh_interval_seconds=30.0, max_staleness_seconds=3600.0
    )

    with pytest.raises(PrincipalUnavailableError):
        await cache.get("p1")


async def test_refresh_failure_serves_stale_value_within_max_staleness() -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs(groups=["atlas"])
    cache = PrincipalCache(
        directory, refresh_interval_seconds=0.0, max_staleness_seconds=3600.0
    )
    await cache.get("p1")  # primes the cache

    directory.fail_next = 1
    attrs = await cache.get("p1")  # refresh interval is 0 -> always attempts refresh

    assert attrs.groups == ["atlas"]  # served stale, not raised


async def test_fails_closed_once_max_staleness_exceeded(monkeypatch) -> None:
    directory = _FakeDirectory()
    directory.responses["p1"] = _attrs()
    cache = PrincipalCache(
        directory, refresh_interval_seconds=0.0, max_staleness_seconds=100.0
    )
    await cache.get("p1")  # primes the cache

    # Simulate 200s having passed since the last successful refresh without
    # needing a real sleep.
    real_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + 200.0)

    directory.fail_next = 1
    with pytest.raises(PrincipalUnavailableError):
        await cache.get("p1")

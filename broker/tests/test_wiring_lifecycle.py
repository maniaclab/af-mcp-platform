"""Unit tests for the lifetime-resource builders (``wiring/lifecycle.py``).

Each builder registers its close on the caller's ``AsyncExitStack``; the tests
check that closing the stack closes the resource, in reverse build order, and
that a failure after some builders ran still closes those.
"""

from __future__ import annotations

import socket
from contextlib import AsyncExitStack
from typing import Any

import httpx2
import pytest

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.credentials.stores import VaultLinkStores
from af_mcp_broker.maintenance import InMemoryMaintenanceModeStore
from af_mcp_broker.metering import InProcessMeteringBackend
from af_mcp_broker.shared_state import InMemorySharedState
from af_mcp_broker.usage import InMemoryUsageStore
from af_mcp_broker.vault_kv import VaultConnections
from af_mcp_broker.wiring import lifecycle
from af_mcp_broker.wiring.lifecycle import (
    open_shared_state,
    prime_jwks_cache,
    start_credmon_sync,
    start_maintenance_store,
    start_metering_pipeline,
    start_metrics_server,
    start_usage_store,
)
from af_mcp_broker.wiring.services import IdentityTargets


def _settings(**overrides: Any) -> Settings:
    return Settings(oidc_issuer="https://kc.invalid/realms/x", **overrides)


class _RecordingMaintenanceStore(InMemoryMaintenanceModeStore):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self._events = events

    async def start(self) -> None:
        self._events.append("maintenance.start")

    async def aclose(self) -> None:
        self._events.append("maintenance.aclose")


class _RecordingSharedState(InMemorySharedState):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self._events = events

    async def close(self) -> None:
        self._events.append("shared_state.close")


class TestOpenSharedState:
    async def test_closes_when_the_stack_closes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[str] = []
        monkeypatch.setattr(
            lifecycle,
            "build_shared_state",
            lambda url, *, key_prefix: _RecordingSharedState(events),
        )

        async with AsyncExitStack() as stack:
            shared_state = open_shared_state(_settings(), stack)
            assert isinstance(shared_state, _RecordingSharedState)
            assert events == []

        assert events == ["shared_state.close"]


class TestStartMaintenanceStore:
    async def test_starts_the_store_and_closes_it_with_the_stack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[str] = []
        monkeypatch.setattr(
            lifecycle,
            "build_maintenance_store",
            lambda settings, vaults: _RecordingMaintenanceStore(events),
        )

        async with AsyncExitStack() as stack:
            await start_maintenance_store(
                _settings(), VaultConnections(httpx2.AsyncClient()), stack
            )
            assert events == ["maintenance.start"]

        assert events == ["maintenance.start", "maintenance.aclose"]


class _RecordingUsageStore(InMemoryUsageStore):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self._events = events

    async def aclose(self) -> None:
        self._events.append("usage.close")


class _RecordingMetering(InProcessMeteringBackend):
    def __init__(self, events: list[str], usage_store: InMemoryUsageStore) -> None:
        super().__init__(_settings(), usage_store)
        self._events = events

    async def aclose(self) -> None:
        self._events.append("metering.drain")
        await super().aclose()


class TestUsageAndMetering:
    async def test_usage_store_is_returned_then_closed_with_the_stack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[str] = []
        built = _RecordingUsageStore(events)
        monkeypatch.setattr(lifecycle, "build_usage_store", lambda settings: built)

        async with AsyncExitStack() as stack:
            store = await start_usage_store(_settings(), stack)
            assert store is built
            assert events == []

        assert events == ["usage.close"]

    async def test_metering_pipeline_is_returned_running_then_drained(self) -> None:
        async with AsyncExitStack() as stack:
            backend = await start_metering_pipeline(
                _settings(), InMemoryUsageStore(), stack
            )
            assert isinstance(backend, InProcessMeteringBackend)
            assert backend.is_running

        assert not backend.is_running

    async def test_metering_feeds_the_usage_store_it_is_given(self) -> None:
        usage_store = InMemoryUsageStore()
        async with AsyncExitStack() as stack:
            backend = await start_metering_pipeline(_settings(), usage_store, stack)

        assert backend.usage_store is usage_store

    async def test_metering_drains_before_the_usage_store_closes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[str] = []
        usage_store = _RecordingUsageStore(events)
        monkeypatch.setattr(
            lifecycle, "build_usage_store", lambda settings: usage_store
        )
        monkeypatch.setattr(
            lifecycle,
            "build_metering_backend",
            lambda settings, store: _RecordingMetering(events, store),
        )

        async with AsyncExitStack() as stack:
            store = await start_usage_store(_settings(), stack)
            await start_metering_pipeline(_settings(), store, stack)

        assert events == ["metering.drain", "usage.close"]

    async def test_a_failure_after_both_started_closes_both(self) -> None:
        backends: list[InProcessMeteringBackend] = []

        async def _start_then_fail() -> None:
            async with AsyncExitStack() as stack:
                store = await start_usage_store(_settings(), stack)
                backends.append(
                    await start_metering_pipeline(_settings(), store, stack)
                )
                raise RuntimeError("later builder failed")

        with pytest.raises(RuntimeError, match="later builder failed"):
            await _start_then_fail()

        (backend,) = backends
        assert not backend.is_running


class TestStartMetricsServer:
    async def test_is_disabled_by_a_negative_port(self) -> None:
        async with AsyncExitStack() as stack:
            assert start_metrics_server(_settings(metrics_port=-1), stack) is None

    async def test_serves_on_the_returned_port_until_the_stack_closes(self) -> None:
        async with AsyncExitStack() as stack:
            port = start_metrics_server(_settings(metrics_port=0), stack)
            assert port is not None
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                pass

        with pytest.raises(OSError):  # noqa: PT011 -- connection refused, any OSError subclass
            socket.create_connection(("127.0.0.1", port), timeout=2)


class TestStartCredmonSync:
    async def test_is_none_when_credmon_is_disabled(self) -> None:
        targets = IdentityTargets([], [], [], {}, {}, {}, {})

        async with AsyncExitStack() as stack:
            result = await start_credmon_sync(
                _settings(),
                targets=targets,
                credential_registry=CredentialRegistry(),
                issuer=None,
                link_stores=VaultLinkStores(),
                vaults=VaultConnections(httpx2.AsyncClient()),
                principal_cache=None,
                http_client=httpx2.AsyncClient(),
                stack=stack,
            )

        assert result is None


class TestPrimeJwksCache:
    async def test_a_failed_fetch_is_not_fatal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _get_jwks(
            settings: Settings, http_client: httpx2.AsyncClient
        ) -> list[Any]:
            raise OSError("keycloak unreachable")

        monkeypatch.setattr(lifecycle, "get_jwks", _get_jwks)

        await prime_jwks_cache(_settings(), httpx2.AsyncClient())

    async def test_a_successful_fetch_primes_the_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[Settings] = []

        async def _get_jwks(
            settings: Settings, http_client: httpx2.AsyncClient
        ) -> list[Any]:
            calls.append(settings)
            return [{"kid": "k"}]

        monkeypatch.setattr(lifecycle, "get_jwks", _get_jwks)
        settings = _settings()

        await prime_jwks_cache(settings, httpx2.AsyncClient())

        assert calls == [settings]

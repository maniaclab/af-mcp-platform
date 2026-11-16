"""A failure partway through ``lifespan`` startup closes what was already built.

The lifespan registers each resource's close on one ``AsyncExitStack`` as it is
built, so a later builder raising still tears down the earlier ones, in reverse
build order, instead of leaking them (janitor tasks, the metrics server's
port, the usage store and metering worker).
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, Any

import pytest

import af_mcp_broker.app as app_module
from af_mcp_broker.credentials import CredentialCache
from af_mcp_broker.mcp.cache_invalidation import ListCacheInvalidator
from af_mcp_broker.metering import InProcessMeteringBackend
from af_mcp_broker.shared_state import InMemorySharedState
from af_mcp_broker.usage import InMemoryUsageStore

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture
def closed(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record, in order, the closes of the resources built before the failure point."""
    events: list[str] = []

    original_stop_janitor = CredentialCache.stop_janitor
    original_stop_invalidator = ListCacheInvalidator.stop
    original_close = InMemorySharedState.close
    original_drain = InProcessMeteringBackend.aclose
    original_close_usage = InMemoryUsageStore.aclose

    async def _stop_janitor(self: CredentialCache) -> None:
        events.append("credential_cache.janitor")
        await original_stop_janitor(self)

    async def _stop_invalidator(self: ListCacheInvalidator) -> None:
        events.append("list_cache_invalidator")
        await original_stop_invalidator(self)

    async def _close(self: InMemorySharedState) -> None:
        events.append("shared_state")
        await original_close(self)

    async def _drain(self: InProcessMeteringBackend) -> None:
        events.append("metering")
        await original_drain(self)

    async def _close_usage(self: InMemoryUsageStore) -> None:
        events.append("usage_store")
        await original_close_usage(self)

    monkeypatch.setattr(InProcessMeteringBackend, "aclose", _drain)
    monkeypatch.setattr(InMemoryUsageStore, "aclose", _close_usage)
    monkeypatch.setattr(CredentialCache, "stop_janitor", _stop_janitor)
    monkeypatch.setattr(ListCacheInvalidator, "stop", _stop_invalidator)
    monkeypatch.setattr(InMemorySharedState, "close", _close)
    return events


def _fail(message: str) -> Callable[..., Any]:
    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError(message)

    return _raise


def test_a_failure_before_the_stores_start_closes_the_credential_subsystem_in_reverse(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    closed: list[str],
) -> None:
    monkeypatch.setattr(app_module, "build_principal_cache", _fail("boom"))

    with pytest.raises(RuntimeError, match="boom"), app_client_factory():
        pass

    assert closed == [
        "credential_cache.janitor",
        "list_cache_invalidator",
        "shared_state",
    ]


def test_a_failure_after_every_builder_ran_closes_all_of_them(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    closed: list[str],
) -> None:
    monkeypatch.setattr(app_module, "prime_jwks_cache", _fail("late boom"))

    with pytest.raises(RuntimeError, match="late boom"), app_client_factory():
        pass

    assert closed == [
        "metering",
        "usage_store",
        "credential_cache.janitor",
        "list_cache_invalidator",
        "shared_state",
    ]
    port = app_module.app.state.broker.metrics_port
    assert port is not None
    with pytest.raises(OSError):  # noqa: PT011 -- connection refused, any OSError subclass
        socket.create_connection(("127.0.0.1", port), timeout=2)

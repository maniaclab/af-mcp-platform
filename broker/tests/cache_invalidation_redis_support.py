"""Fixtures and helpers shared by the unit and integration tests of ``test_cache_invalidation_redis``."""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING

import pytest
from conftest import AUDIENCE, ISSUER
from mcp_aggregator_support import (
    _build_namespaced_aggregator,
    _CountingListClient,
)

from af_mcp_broker.config import Settings
from af_mcp_broker.mcp import aggregator
from af_mcp_broker.mcp.cache_invalidation import ListCacheInvalidator
from af_mcp_broker.shared_state import RedisSharedState

if TYPE_CHECKING:
    from collections.abc import Callable

    from af_mcp_broker.principal import Principal


class _Replica:
    """One broker replica's listing cache, backend client and invalidator."""

    def __init__(self, store_url: str, client: _CountingListClient) -> None:
        self.client = client
        self.store = RedisSharedState(store_url)
        with pytest.MonkeyPatch.context() as monkeypatch:
            self.mcp, self.backend_providers = _build_namespaced_aggregator(
                monkeypatch,
                Settings(oidc_issuer=ISSUER, oidc_audience=AUDIENCE),
                {"example": client},
            )
        # Some tests need the raw listing error, which the aggregate swallows.
        self.provider = self.backend_providers.get("example")
        self.invalidator = ListCacheInvalidator(
            self.store,
            invalidate=lambda subject, target: aggregator.invalidate_subject_cache(
                self.backend_providers, subject, target
            ),
            invalidate_all=lambda: aggregator.invalidate_all_subject_caches(
                self.backend_providers
            ),
            retry_delays=(0.05, 0.2),
        )

    async def list_tools(self) -> list[str]:
        tools = await self.mcp._list_tools()
        return [
            t.name.removeprefix("example_")
            for t in tools
            if t.name.startswith("example_")
        ]

    async def stop(self) -> None:
        await self.invalidator.stop()
        await self.store.close()


async def _eventually(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.02)


@pytest.fixture(name="alice")
def alice_fixture(make_principal: Callable[..., Principal]) -> Principal:
    # The server outlives each test, so every test gets its own subject.
    return make_principal(subject=f"alice-{uuid.uuid4()}")

"""Unit tests for the area ``test_pat_mint_shared_state.py`` covers; the integration tests live in ``integration/test_pat_mint_shared_state.py``."""

from __future__ import annotations

import pytest
import structlog
from pat_mint_shared_state_support import (  # noqa: F401
    _MAX_MINTS,
    subject_fixture,
)

from af_mcp_broker.shared_state import RedisSharedState
from af_mcp_broker.token_registry import (
    InMemoryTokenRegistryBackend,
    PatMintRateLimitError,
    TokenRegistry,
)


async def test_store_outage_falls_back_to_a_per_replica_cap(
    unreachable_shared_state_url: str, subject: str
) -> None:
    store = RedisSharedState(unreachable_shared_state_url)
    registry = TokenRegistry(InMemoryTokenRegistryBackend(), store)
    try:
        with structlog.testing.capture_logs() as logs:
            for _ in range(_MAX_MINTS):
                await registry.record_mint(subject)
            with pytest.raises(PatMintRateLimitError):
                await registry.check_mint_rate_limit(subject)
    finally:
        await store.close()

    events = {entry["event"] for entry in logs}
    assert "token_registry.shared_state_unavailable" in events

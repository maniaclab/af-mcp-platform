"""Integration tests: the PAT mint window is shared across replicas.

Two ``TokenRegistry`` instances over one real redis server stand in for two
broker replicas (see the ``shared_state_url`` fixture); nothing is mocked.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Any

import pytest

from af_mcp_broker.shared_state import RedisSharedState
from af_mcp_broker.token_registry import (
    InMemoryTokenRegistryBackend,
    PatMintRateLimitError,
    TokenRegistry,
    pat_mint_key,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

_MAX_MINTS = 10


@pytest.fixture
def subject() -> str:
    # The server outlives each test, so every test gets its own subject.
    return f"sub-{uuid.uuid4()}"


@pytest.fixture
async def replicas(shared_state_url: str) -> AsyncIterator[list[TokenRegistry]]:
    stores = [RedisSharedState(shared_state_url) for _ in range(2)]
    yield [TokenRegistry(InMemoryTokenRegistryBackend(), store) for store in stores]
    for store in stores:
        await store.close()


async def test_mints_on_different_replicas_share_one_cap(
    replicas: list[TokenRegistry], subject: str
) -> None:
    replica_a, replica_b = replicas
    # Alternate replicas so neither sees more than half the cap.
    for i in range(_MAX_MINTS):
        await (replica_a, replica_b)[i % 2].record_mint(subject)

    for replica in replicas:
        with pytest.raises(PatMintRateLimitError, match="Try again in"):
            await replica.check_mint_rate_limit(subject)


async def test_below_the_cap_is_allowed_on_every_replica(
    replicas: list[TokenRegistry], subject: str
) -> None:
    replica_a, replica_b = replicas
    for _ in range(_MAX_MINTS - 1):
        await replica_a.record_mint(subject)

    await replica_b.check_mint_rate_limit(subject)

    # The cap is exactly _MAX_MINTS: one more mint reaches it.
    await replica_a.record_mint(subject)
    with pytest.raises(PatMintRateLimitError):
        await replica_b.check_mint_rate_limit(subject)


async def test_other_subjects_are_unaffected(
    replicas: list[TokenRegistry], subject: str
) -> None:
    for _ in range(_MAX_MINTS):
        await replicas[0].record_mint(subject)

    await replicas[1].check_mint_rate_limit(f"other-{subject}")
    with pytest.raises(PatMintRateLimitError):
        await replicas[1].check_mint_rate_limit(subject)


def test_app_enforces_the_cap_other_replicas_already_spent(
    app_client_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
    shared_state_url: str,
    make_principal: Callable[..., Any],
) -> None:
    """The real app reads ``SHARED_STATE_URL``: mints another replica counted trigger 429 here."""
    monkeypatch.setenv("SHARED_STATE_URL", shared_state_url)
    subject = make_principal().subject

    async def spend_cap_on_another_replica() -> None:
        other_replica = RedisSharedState(shared_state_url)
        try:
            for _ in range(_MAX_MINTS):
                await other_replica.incr_window(pat_mint_key(subject), 3600)
        finally:
            await other_replica.close()

    asyncio.run(spend_cap_on_another_replica())

    with app_client_factory() as (client, _):
        resp = client.post(
            "/v1/tokens", json={"name": "t"}, headers={"Authorization": "Bearer test"}
        )

    assert resp.status_code == 429, resp.text
    body = resp.json()
    assert body["retry_after_seconds"] == 3600
    assert body["detail"].startswith("Too many tokens minted")


def test_app_counts_mints_only_under_its_configured_key_prefix(
    app_client_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
    shared_state_url: str,
    make_principal: Callable[..., Any],
) -> None:
    """``SHARED_STATE_KEY_PREFIX`` scopes the window: mints another release counted under its own prefix do not count here."""
    monkeypatch.setenv("SHARED_STATE_URL", shared_state_url)
    # A prefix no other test uses, so nothing on the session-wide server counts.
    monkeypatch.setenv("SHARED_STATE_KEY_PREFIX", f"release-{uuid.uuid4()}:")
    subject = make_principal().subject

    async def spend_cap_under_the_default_prefix() -> None:
        other_release = RedisSharedState(shared_state_url)
        try:
            for _ in range(_MAX_MINTS):
                await other_release.incr_window(pat_mint_key(subject), 3600)
        finally:
            await other_release.close()

    asyncio.run(spend_cap_under_the_default_prefix())

    with app_client_factory() as (client, _):
        resp = client.post(
            "/v1/tokens", json={"name": "t"}, headers={"Authorization": "Bearer test"}
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "t"

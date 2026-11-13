"""Tests for ``usage/batcher.py`` -- the size/age-bounded usage record buffer.

Time is injected (a manual clock), so the interval rules are exercised
without sleeping.
"""

from __future__ import annotations

from typing import Any

import pytest

from af_mcp_broker.audit import AuditRecord
from af_mcp_broker.usage.batcher import UsageBatcher


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def _record(n: int) -> AuditRecord:
    fields: dict[str, Any] = {
        "principal_sub": "sub-abc",
        "principal_uid": 1000,
        "permission": "read_data",
        "target": "rucio",
        "action": "rucio_list_dids",
        "action_type": "read",
        "args_summary": "",
        "timestamp": 1.0,
        "request_id": f"req-{n}",
        "mcp_service": "rucio",
        "outcome": "success",
    }
    return AuditRecord(**fields)


@pytest.fixture
def flushed() -> list[list[AuditRecord]]:
    return []


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


@pytest.fixture
def batcher(flushed: list[list[AuditRecord]], clock: _Clock) -> UsageBatcher:
    async def _sink(records: list[AuditRecord]) -> None:
        flushed.append(records)

    return UsageBatcher(_sink, max_size=3, interval_seconds=1.0, clock=clock)


async def test_flushes_when_the_batch_reaches_max_size(
    batcher: UsageBatcher, flushed: list[list[AuditRecord]]
) -> None:
    records = [_record(i) for i in range(3)]
    await batcher.add(records[0])
    await batcher.add(records[1])
    assert flushed == []
    await batcher.add(records[2])
    assert flushed == [records]
    assert batcher.seconds_until_due() is None


async def test_is_due_once_the_interval_has_elapsed_since_the_first_record(
    batcher: UsageBatcher, flushed: list[list[AuditRecord]], clock: _Clock
) -> None:
    await batcher.add(_record(0))
    assert batcher.seconds_until_due() == pytest.approx(1.0)
    clock.now += 0.4
    await batcher.add(_record(1))
    # The deadline is anchored to the first buffered record, not the latest.
    assert batcher.seconds_until_due() == pytest.approx(0.6)
    await batcher.flush_if_due()
    assert flushed == []
    clock.now += 0.6
    assert batcher.seconds_until_due() == pytest.approx(0.0)
    await batcher.flush_if_due()
    assert len(flushed) == 1
    assert len(flushed[0]) == 2
    assert batcher.seconds_until_due() is None


async def test_the_interval_restarts_with_the_next_buffered_record(
    batcher: UsageBatcher, clock: _Clock
) -> None:
    await batcher.add(_record(0))
    await batcher.flush()
    clock.now += 5.0
    await batcher.add(_record(1))
    assert batcher.seconds_until_due() == pytest.approx(1.0)


async def test_flush_with_nothing_buffered_does_not_call_the_sink(
    batcher: UsageBatcher, flushed: list[list[AuditRecord]]
) -> None:
    await batcher.flush()
    await batcher.flush_if_due()
    assert flushed == []


async def test_flush_hands_over_the_buffer_and_starts_empty(
    batcher: UsageBatcher, flushed: list[list[AuditRecord]]
) -> None:
    await batcher.add(_record(0))
    await batcher.flush()
    await batcher.flush()
    assert len(flushed) == 1

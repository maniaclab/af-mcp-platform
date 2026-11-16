"""The ``rate_limit.exceeded`` log event every ``/v1`` 429 emits beside the generic ``http.exception`` line."""

from __future__ import annotations

from typing import TYPE_CHECKING

from test_request_logging import _capturing_info

from af_mcp_broker import retry_after as retry_after_module
from af_mcp_broker.retry_after import RateLimiter, log_rate_limited

if TYPE_CHECKING:
    import pytest


def test_log_rate_limited_emits_one_searchable_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _capturing_info(monkeypatch, retry_after_module.logger)

    log_rate_limited(
        subject="user-1",
        limiter=RateLimiter.TOOL_RATE_LIMIT,
        retry_after_seconds=40,
        rule="1/60s",
    )

    [event] = events
    assert event["event"] == "rate_limit.exceeded"
    assert event["subject"] == "user-1"
    assert event["limiter"] == "tool_rate_limit"
    assert event["rule"] == "1/60s"
    assert event["retry_after_seconds"] == 40

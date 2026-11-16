"""Fixtures and helpers shared by the unit and integration tests of ``test_request_logging``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    import pytest


def _capturing_info(
    monkeypatch: pytest.MonkeyPatch, logger: Any
) -> list[dict[str, Any]]:
    """Record every ``logger.info(...)``/``logger.error(...)`` call's level, event, explicit kwargs, and
    currently-bound structlog contextvars (request_id/subject) together
    -- the contextvar merge normally only happens inside structlog's
    processor chain on the way to output, which patching the method this way
    bypasses for the *recorded* copy (the original call still runs, so real
    output/processing is unaffected).
    """
    events: list[dict[str, Any]] = []

    def _patch(level: str) -> None:
        original = getattr(logger, level)

        def _capture(event: str, **kwargs: Any) -> Any:
            events.append(
                {
                    "event": event,
                    "level": level,
                    **structlog.contextvars.get_contextvars(),
                    **kwargs,
                }
            )
            return original(event, **kwargs)

        monkeypatch.setattr(logger, level, _capture)

    _patch("info")
    _patch("error")
    return events

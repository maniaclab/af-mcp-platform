"""Tests for logging.py's structlog contextvars helpers (issue #281).

``configure_logging`` already wires ``structlog.contextvars.merge_contextvars``
into the processor chain, but nothing previously called
``structlog.contextvars.bind_contextvars`` -- these two helpers are the single
place that now does, so every request-scoped log line can be tied back to a
``correlation_id`` and (once identity resolves) a ``subject``.
"""

from __future__ import annotations

import structlog

from af_mcp_broker.logging import bind_new_correlation_id, bind_subject


def test_bind_new_correlation_id_binds_a_nonempty_value() -> None:
    structlog.contextvars.clear_contextvars()

    bind_new_correlation_id()

    bound = structlog.contextvars.get_contextvars()
    assert bound["correlation_id"]


def test_bind_new_correlation_id_differs_across_calls() -> None:
    structlog.contextvars.clear_contextvars()
    bind_new_correlation_id()
    first = structlog.contextvars.get_contextvars()["correlation_id"]

    bind_new_correlation_id()
    second = structlog.contextvars.get_contextvars()["correlation_id"]

    assert first != second


def test_bind_new_correlation_id_clears_stale_contextvars_first() -> None:
    """A prior request's leftover bindings (e.g. ``subject``) must not survive
    into the next request reusing the same task."""
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(subject="stale-from-a-previous-request")

    bind_new_correlation_id()

    assert "subject" not in structlog.contextvars.get_contextvars()


def test_bind_subject_binds_the_given_value() -> None:
    structlog.contextvars.clear_contextvars()

    bind_subject("user-123")

    assert structlog.contextvars.get_contextvars()["subject"] == "user-123"

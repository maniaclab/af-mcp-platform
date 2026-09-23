"""Tests for logging.py's structlog contextvars helpers (issue #281).

``configure_logging`` already wires ``structlog.contextvars.merge_contextvars``
into the processor chain, but nothing previously called
``structlog.contextvars.bind_contextvars`` -- these two helpers are the single
place that now does, so every request-scoped log line can be tied back to a
``correlation_id`` and (once identity resolves) a ``subject``.
"""

from __future__ import annotations

import time

import structlog

from af_mcp_broker.logging import (
    bind_new_correlation_id,
    bind_subject,
    log_request_finished,
    log_request_received,
)


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


# ---------------------------------------------------------------------------
# log_request_received / log_request_finished (issue #322)
#
# Each test uses a logger name unique to itself so a prior test's real app
# boot elsewhere in the suite (which would cache that logger under
# structlog's cache_logger_on_first_use=True -- see test_identity.py's
# capture_logs() docstring) can never have already resolved it outside this
# test's own capture_logs() context.
# ---------------------------------------------------------------------------


def test_log_request_received_logs_method_and_path_and_returns_a_monotonic_start() -> (
    None
):
    logger = structlog.get_logger("test_logging.request_received")

    before = time.monotonic()
    with structlog.testing.capture_logs() as logs:
        start = log_request_received(logger, method="GET", path="/v1/ok")
    after = time.monotonic()

    assert before <= start <= after
    assert len(logs) == 1
    assert logs[0]["event"] == "http.request.received"
    assert logs[0]["method"] == "GET"
    assert logs[0]["path"] == "/v1/ok"


def test_log_request_finished_logs_status_and_duration() -> None:
    logger = structlog.get_logger("test_logging.request_finished_ok")
    start_time = time.monotonic() - 0.01  # pretend the request took ~10ms

    with structlog.testing.capture_logs() as logs:
        log_request_finished(logger, start_time=start_time, status_code=200)

    assert len(logs) == 1
    assert logs[0]["event"] == "http.request.finished"
    assert logs[0]["status_code"] == 200
    assert logs[0]["exc_type"] is None
    assert logs[0]["duration_ms"] >= 10


def test_log_request_finished_carries_exc_type_and_no_status_on_a_raised_request() -> (
    None
):
    logger = structlog.get_logger("test_logging.request_finished_exc")

    with structlog.testing.capture_logs() as logs:
        log_request_finished(
            logger,
            start_time=time.monotonic(),
            status_code=None,
            exc_type="RuntimeError",
        )

    assert logs[0]["status_code"] is None
    assert logs[0]["exc_type"] == "RuntimeError"

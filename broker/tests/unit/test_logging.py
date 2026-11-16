"""Tests for logging.py's structlog contextvars helpers (issue #281).

``configure_logging`` wires ``structlog.contextvars.merge_contextvars``
into the processor chain; these two helpers are the single place that calls
``structlog.contextvars.bind_contextvars``, so every request-scoped log line can be tied back to a
``request_id`` and (once identity resolves) a ``subject``.
"""

from __future__ import annotations

import json
import logging
import logging.config
import re
import time
from typing import TYPE_CHECKING

import httpcore2
import httpx2
import pytest
import structlog

from af_mcp_broker.logging import (
    bind_new_request_id,
    bind_subject,
    configure_logging,
    log_request_finished,
    log_request_received,
    request_id_headers,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


def test_bind_new_request_id_binds_a_nonempty_value() -> None:
    structlog.contextvars.clear_contextvars()

    bind_new_request_id()

    bound = structlog.contextvars.get_contextvars()
    assert re.fullmatch(r"[0-9a-f]{32}", bound["request_id"])


def test_bind_new_request_id_differs_across_calls() -> None:
    structlog.contextvars.clear_contextvars()
    bind_new_request_id()
    first = structlog.contextvars.get_contextvars()["request_id"]

    bind_new_request_id()
    second = structlog.contextvars.get_contextvars()["request_id"]

    assert first != second


def test_bind_new_request_id_clears_stale_contextvars_first() -> None:
    """A prior request's leftover bindings (e.g. ``subject``) must not survive
    into the next request reusing the same task."""
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(subject="stale-from-a-previous-request")

    bind_new_request_id()

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
        log_request_finished(
            logger, start_time=start_time, method="GET", path="/v1/x", status_code=200
        )

    assert len(logs) == 1
    assert logs[0]["event"] == "http.request.finished"
    assert logs[0]["status_code"] == 200
    assert logs[0]["exc_type"] is None
    assert logs[0]["duration_ms"] >= 10


def test_log_request_finished_logs_a_raised_request_at_error_with_status_500() -> None:
    logger = structlog.get_logger("test_logging.request_finished_exc")

    with structlog.testing.capture_logs() as logs:
        log_request_finished(
            logger,
            start_time=time.monotonic(),
            method="GET",
            path="/v1/x",
            status_code=None,
            exc_type="RuntimeError",
        )

    assert logs[0]["log_level"] == "error"
    assert logs[0]["status_code"] == 500
    assert logs[0]["exc_type"] == "RuntimeError"


def test_log_request_finished_keeps_the_status_already_sent_when_the_request_then_raised() -> (
    None
):
    logger = structlog.get_logger("test_logging.request_finished_exc_after_start")

    with structlog.testing.capture_logs() as logs:
        log_request_finished(
            logger,
            start_time=time.monotonic(),
            method="GET",
            path="/mcp",
            status_code=200,
            exc_type="RuntimeError",
        )

    assert logs[0]["log_level"] == "error"
    assert logs[0]["status_code"] == 200


# ---------------------------------------------------------------------------
# request_id_headers (issue #342)
# ---------------------------------------------------------------------------


def test_request_id_headers_carries_the_bound_request_id() -> None:
    structlog.contextvars.clear_contextvars()
    bind_new_request_id()

    headers = request_id_headers()

    assert headers == {
        "X-Request-ID": structlog.contextvars.get_contextvars()["request_id"]
    }


def test_request_id_headers_is_empty_without_a_bound_request_id() -> None:
    structlog.contextvars.clear_contextvars()

    assert request_id_headers() == {}


@pytest.fixture
def restore_logging() -> Iterator[None]:
    """Undo configure_logging's changes to the root and fastmcp loggers."""
    root = logging.getLogger()
    fastmcp_logger = logging.getLogger("fastmcp")
    saved = [
        (lg, lg.handlers[:], lg.level, lg.propagate) for lg in (root, fastmcp_logger)
    ]
    yield
    for lg, handlers, level, propagate in saved:
        lg.handlers = handlers
        lg.setLevel(level)
        lg.propagate = propagate


def test_configure_logging_emits_fastmcp_records_as_json(
    capsys: pytest.CaptureFixture[str], restore_logging: None
) -> None:
    """fastmcp installs its own rich handler on its logger and stops propagation; its records must go through the broker's JSON handler instead."""
    configure_logging("INFO")

    logging.getLogger("fastmcp.server.providers.aggregate").warning("provider failed")

    [line] = capsys.readouterr().out.splitlines()
    record = json.loads(line)
    assert record["event"] == "provider failed"
    assert record["level"] == "warning"
    assert record["logger"] == "fastmcp.server.providers.aggregate"


# The loggers each HTTP client library actually logs under, read from the
# installed libraries rather than spelled out here: httpx2 (and its httpcore2
# transport) log under "httpx2"/"httpcore2.*", not "httpx"/"httpcore".
_HTTP_CLIENT_LOGGERS = [
    pytest.param(httpx2._client.logger, id="httpx2"),
    pytest.param(httpcore2._async.http11.logger, id="httpcore2"),
]


@pytest.mark.parametrize("http_logger", _HTTP_CLIENT_LOGGERS)
def test_configure_logging_applies_the_third_party_level_to_http_client_loggers(
    http_logger: logging.Logger, restore_logging: None
) -> None:
    """INFO-level request lines from the HTTP client libraries are noise at the
    broker's default level; configure_logging holds them at WARNING."""
    # configure_logging sets the level on the library's top-level logger.
    top_level_logger = logging.getLogger(http_logger.name.split(".")[0])
    levels = [(lg, lg.level) for lg in (http_logger, top_level_logger)]
    try:
        configure_logging("INFO")

        assert http_logger.getEffectiveLevel() == logging.WARNING
    finally:
        for lg, level in levels:
            lg.setLevel(level)

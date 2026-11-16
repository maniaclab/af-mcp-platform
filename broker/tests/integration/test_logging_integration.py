"""Integration tests for the area ``test_logging.py`` covers; the unit tests live in ``unit/test_logging.py``."""

from __future__ import annotations

import json
import logging
import logging.config
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import af_mcp_broker

if TYPE_CHECKING:
    from collections.abc import Iterator


# ---------------------------------------------------------------------------
# uvicorn lifecycle lines
# ---------------------------------------------------------------------------

UVICORN_LOG_CONFIG = Path(af_mcp_broker.__file__).parent / "uvicorn_log_config.json"


@pytest.fixture
def restore_uvicorn_logging() -> Iterator[None]:
    """Undo ``uvicorn_log_config.json``'s changes to the uvicorn loggers."""
    names = ("uvicorn", "uvicorn.error", "uvicorn.access")
    saved = [
        (lg, lg.handlers[:], lg.level, lg.propagate)
        for lg in map(logging.getLogger, names)
    ]
    yield
    for lg, handlers, level, propagate in saved:
        lg.handlers = handlers
        lg.setLevel(level)
        lg.propagate = propagate


def test_uvicorn_lifecycle_lines_are_json_with_the_broker_line_shape(
    capsys: pytest.CaptureFixture[str], restore_uvicorn_logging: None
) -> None:
    logging.config.dictConfig(json.loads(UVICORN_LOG_CONFIG.read_text()))

    logging.getLogger("uvicorn.error").info("Application startup complete.")
    logging.getLogger("uvicorn.error").info("Started server process [%d]", 7)

    captured = capsys.readouterr()
    assert captured.err == ""
    records = [json.loads(line) for line in captured.out.splitlines()]
    assert [r["event"] for r in records] == [
        "Application startup complete.",
        "Started server process [7]",
    ]
    for record in records:
        assert record["logger"] == "uvicorn.error"
        assert record["level"] == "info"
        # ISO 8601 UTC, like every other broker line.
        assert record["timestamp"].endswith("Z")


def test_uvicorn_log_config_renders_exceptions_as_json(
    capsys: pytest.CaptureFixture[str], restore_uvicorn_logging: None
) -> None:
    logging.config.dictConfig(json.loads(UVICORN_LOG_CONFIG.read_text()))

    logging.getLogger("uvicorn.error").error(
        "Exception in ASGI application", exc_info=RuntimeError("boom")
    )

    [line] = capsys.readouterr().out.splitlines()
    record = json.loads(line)
    assert record["event"] == "Exception in ASGI application"
    assert "RuntimeError: boom" in record["exception"]


def test_uvicorn_log_config_keeps_access_lines_off(
    capsys: pytest.CaptureFixture[str], restore_uvicorn_logging: None
) -> None:
    """``configure_logging`` holds ``uvicorn.access`` at WARNING once the app is up (the broker's ``http.request.*`` lines carry the same facts and more); the config must not log them in the window before that."""
    logging.config.dictConfig(json.loads(UVICORN_LOG_CONFIG.read_text()))

    logging.getLogger("uvicorn.access").info(
        '%s - "%s %s HTTP/%s" %d', "127.0.0.1:1", "GET", "/", "1.1", 200
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""

"""Unit tests for ``audit/measure.py`` -- tool-result byte/token metering.

Deterministic by construction: every test that needs a tokenizer
monkeypatches a fake encoder (``encode`` returning a known-length list)
instead of loading a real tiktoken encoding, so the suite never depends on
a cached encoding file or network access.
"""

from __future__ import annotations

import json
from typing import Any

import mcp.types as mt
import pytest
from fastmcp.tools.base import ToolResult

from af_mcp_broker.audit import measure
from af_mcp_broker.config import Settings


class _FakeEncoding:
    """Stands in for a tiktoken Encoding: every call returns a fixed-length token list."""

    def __init__(self, n_tokens: int) -> None:
        self._n_tokens = n_tokens

    def encode(self, text: str, **kwargs: Any) -> list[int]:
        return [0] * self._n_tokens


# The module-level encoding cache is reset (and tiktoken's loader stubbed)
# for every test by conftest.py's autouse `stub_tiktoken` fixture; tests
# below re-patch the loader where they exercise it directly.


@pytest.fixture(autouse=True)
def default_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the encoding name so ambient env vars can't change test behavior."""
    monkeypatch.setattr(
        measure,
        "get_settings",
        lambda: Settings(token_estimate_encoding="o200k_base"),
    )


def _fake_loader(monkeypatch: pytest.MonkeyPatch, encoding: _FakeEncoding) -> list[str]:
    """Replace tiktoken.get_encoding with a recorder returning *encoding*."""
    calls: list[str] = []

    def _get_encoding(name: str) -> _FakeEncoding:
        calls.append(name)
        return encoding

    monkeypatch.setattr(measure.tiktoken, "get_encoding", _get_encoding)
    return calls


def test_text_content_measured_as_utf8_bytes_and_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_loader(monkeypatch, _FakeEncoding(7))
    result = ToolResult(
        content=[
            mt.TextContent(type="text", text="héllo "),
            mt.TextContent(type="text", text="wörld"),
        ]
    )

    result_bytes, result_tokens = measure.measure_tool_result(result)

    # UTF-8, not str length: the two umlauts are 2 bytes each.
    assert result_bytes == len("héllo wörld".encode())
    assert result_tokens == 7


def test_non_text_content_blocks_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only text blocks count -- an image's base64 payload is not text the
    LLM client injects verbatim into its context."""
    _fake_loader(monkeypatch, _FakeEncoding(3))
    result = ToolResult(
        content=[
            mt.TextContent(type="text", text="caption"),
            mt.ImageContent(type="image", data="aGVsbG8=", mimeType="image/png"),
        ]
    )

    result_bytes, result_tokens = measure.measure_tool_result(result)

    assert result_bytes == len(b"caption")
    assert result_tokens == 3


def test_structured_content_counted_via_json_dumps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_loader(monkeypatch, _FakeEncoding(4))
    structured = {"a": 1, "b": ["x", "y"]}
    result = ToolResult(
        content=[mt.TextContent(type="text", text="ok")],
        structured_content=structured,
    )

    result_bytes, result_tokens = measure.measure_tool_result(result)

    assert result_bytes == len(b"ok" + json.dumps(structured).encode())
    assert result_tokens == 4


def test_empty_result_is_zero_bytes_and_no_token_estimate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty text: 0 bytes measured, but no token estimate (there is
    nothing to tokenize) -- and the encoding is never even loaded."""
    calls = _fake_loader(monkeypatch, _FakeEncoding(99))
    result = ToolResult(content=[])

    result_bytes, result_tokens = measure.measure_tool_result(result)

    assert result_bytes == 0
    assert result_tokens is None
    assert calls == []


def test_estimation_disabled_via_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """token_estimate_encoding='' disables token estimation entirely;
    byte measurement is unaffected and tiktoken is never touched."""
    calls = _fake_loader(monkeypatch, _FakeEncoding(99))
    monkeypatch.setattr(
        measure, "get_settings", lambda: Settings(token_estimate_encoding="")
    )
    result = ToolResult(content=[mt.TextContent(type="text", text="hello")])

    result_bytes, result_tokens = measure.measure_tool_result(result)

    assert result_bytes == len(b"hello")
    assert result_tokens is None
    assert calls == []


def test_tiktoken_unavailable_degrades_and_never_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An encoding-load failure (no cached file, no network -- the broker
    pod has default-deny egress) must degrade to result_tokens_est=None
    without breaking the call, and must not retry the load per call."""
    calls: list[str] = []

    def _boom(name: str) -> Any:
        calls.append(name)
        raise RuntimeError("no network")

    monkeypatch.setattr(measure.tiktoken, "get_encoding", _boom)
    result = ToolResult(content=[mt.TextContent(type="text", text="hello")])

    assert measure.measure_tool_result(result) == (len(b"hello"), None)
    assert measure.measure_tool_result(result) == (len(b"hello"), None)
    # Loaded (and failed) exactly once; the failure is cached thereafter.
    assert calls == ["o200k_base"]


def test_measurement_blowup_degrades_to_nones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Metering must never break a tool call: any unexpected failure inside
    the measurement degrades to (None, None)."""

    def _boom(result: Any) -> str:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(measure, "_serialized_text", _boom)
    result = ToolResult(content=[mt.TextContent(type="text", text="hello")])

    assert measure.measure_tool_result(result) == (None, None)

"""Unit tests for ``audit/measure.py`` -- tool-result byte/token metering.

``measure_tool_result`` returns a per-content-type breakdown
(``ToolMeasurement.content``) whose sums are the result totals.

Deterministic by construction: every test that needs a tokenizer
monkeypatches a fake encoder (``encode`` returning a known-length list)
instead of loading a real tiktoken encoding, so the suite never depends on
a cached encoding file or network access.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

import mcp.types as mt
import structlog
from fastmcp.tools.base import ToolResult
from image_builders import png

from af_mcp_broker.audit import measure
from af_mcp_broker.audit.measure import ContentMeasure
from af_mcp_broker.config import Settings

if TYPE_CHECKING:
    import pytest


class _FakeEncoding:
    """Stands in for a tiktoken Encoding: every call returns a fixed-length token list."""

    def __init__(self, n_tokens: int) -> None:
        self._n_tokens = n_tokens

    def encode(self, text: str, **kwargs: Any) -> list[int]:
        return [0] * self._n_tokens


# The module-level encoding cache is reset (and tiktoken's loader stubbed)
# for every test by conftest.py's autouse `stub_tiktoken` fixture; tests
# below re-patch the loader where they exercise it directly.


# Pins the encoding name so ambient env vars can't change test behavior.
_SETTINGS = Settings(token_estimate_encoding="o200k_base")


def _fake_loader(monkeypatch: pytest.MonkeyPatch, encoding: _FakeEncoding) -> list[str]:
    """Replace tiktoken.get_encoding with a recorder returning *encoding*."""
    calls: list[str] = []

    def _get_encoding(name: str) -> _FakeEncoding:
        calls.append(name)
        return encoding

    monkeypatch.setattr(measure.tiktoken, "get_encoding", _get_encoding)
    return calls


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _png_block(width: int, height: int) -> mt.ImageContent:
    return mt.ImageContent(
        type="image", data=_b64(png(width, height)), mimeType="image/png"
    )


def _measure(result: ToolResult) -> measure.ToolMeasurement:
    measurement = measure.measure_tool_result(result, _SETTINGS)
    assert measurement is not None
    return measurement


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

    m = _measure(result)

    # UTF-8, not str length: the two umlauts are 2 bytes each.
    assert m.content == {
        "text": ContentMeasure(
            blocks=2, bytes=len("héllo wörld".encode()), tokens_est=7
        )
    }
    assert m.result_bytes == len("héllo wörld".encode())
    assert m.result_tokens_est == 7


def test_image_block_measured_as_base64_wire_bytes_and_vision_tokens() -> None:
    """The production case: a 640x480 PNG returned as ImageContent was
    recorded as 29 bytes / 14 tokens because only text was measured."""
    block = _png_block(640, 480)

    m = _measure(ToolResult(content=[block]))

    assert m.content == {
        "image": ContentMeasure(blocks=1, bytes=len(block.data), tokens_est=414)
    }
    assert m.result_bytes == len(block.data)
    assert m.result_tokens_est == 414


def test_mixed_text_and_image_totals_are_the_sum_of_the_breakdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_loader(monkeypatch, _FakeEncoding(3))
    image = _png_block(1000, 1000)
    result = ToolResult(content=[mt.TextContent(type="text", text="caption"), image])

    m = _measure(result)

    assert m.content == {
        "text": ContentMeasure(blocks=1, bytes=len(b"caption"), tokens_est=3),
        "image": ContentMeasure(blocks=1, bytes=len(image.data), tokens_est=1296),
    }
    assert m.result_bytes == len(b"caption") + len(image.data)
    assert m.result_tokens_est == 3 + 1296
    assert m.result_bytes == sum(c.bytes for c in m.content.values())
    assert m.result_tokens_est == sum(c.tokens_est for c in m.content.values())


def test_image_over_the_cap_is_priced_at_the_resized_dimensions() -> None:
    m = _measure(ToolResult(content=[_png_block(3840, 2160)]))

    assert m.content["image"].tokens_est == 4784


def test_several_images_are_summed_under_one_content_type() -> None:
    m = _measure(ToolResult(content=[_png_block(200, 200), _png_block(200, 200)]))

    assert m.content["image"].blocks == 2
    assert m.content["image"].tokens_est == 128


def test_unreadable_image_costs_the_tier_maximum_and_warns() -> None:
    block = mt.ImageContent(
        type="image", data=_b64(b"not an image"), mimeType="image/png"
    )

    with structlog.testing.capture_logs() as logs:
        m = _measure(ToolResult(content=[block]))

    assert m.content["image"].tokens_est == 4784
    assert m.content["image"].bytes == len(block.data)
    assert [e["event"] for e in logs] == ["image_dimensions_unreadable"]
    assert logs[0]["log_level"] == "warning"


def test_audio_is_measured_in_bytes_and_costs_no_tokens() -> None:
    block = mt.AudioContent(type="audio", data=_b64(b"\x00" * 90), mimeType="audio/wav")

    m = _measure(ToolResult(content=[block]))

    assert m.content == {
        "audio": ContentMeasure(blocks=1, bytes=len(block.data), tokens_est=0)
    }


def test_text_resource_counts_as_tokens_and_blob_resource_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_loader(monkeypatch, _FakeEncoding(5))
    text_res = mt.EmbeddedResource(
        type="resource",
        resource=mt.TextResourceContents(uri="file:///a.txt", text="hello"),
    )
    blob_res = mt.EmbeddedResource(
        type="resource",
        resource=mt.BlobResourceContents(uri="file:///b.bin", blob=_b64(b"\x00" * 30)),
    )

    m = _measure(ToolResult(content=[text_res, blob_res]))

    assert m.content["resource"] == ContentMeasure(
        blocks=2, bytes=len(b"hello") + len(_b64(b"\x00" * 30)), tokens_est=5
    )


def test_resource_link_is_measured_as_its_wire_json_with_no_tokens() -> None:
    block = mt.ResourceLink(type="resource_link", name="r", uri="file:///x")

    m = _measure(ToolResult(content=[block]))

    wire = block.model_dump_json(by_alias=True, exclude_none=True)
    assert m.content == {
        "resource_link": ContentMeasure(
            blocks=1, bytes=len(wire.encode()), tokens_est=0
        )
    }


def test_unknown_block_type_is_measured_under_its_own_type_and_warns() -> None:
    class _Hologram:
        type = "hologram"

        def model_dump_json(self, **kwargs: Any) -> str:
            return '{"type":"hologram","data":"xyz"}'

    result = ToolResult(content=[mt.TextContent(type="text", text="")])
    result.content.append(_Hologram())  # type: ignore[arg-type]

    with structlog.testing.capture_logs() as logs:
        m = _measure(result)

    assert m.content["hologram"] == ContentMeasure(
        blocks=1, bytes=len(b'{"type":"hologram","data":"xyz"}'), tokens_est=0
    )
    assert [(e["event"], e["content_type"]) for e in logs] == [
        ("unknown_content_type", "hologram")
    ]


def test_structured_content_ignored_when_text_blocks_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A backend that mirrors its text into structured output must not be
    counted twice (issue #241): with text blocks present, only they are
    measured -- that is the representation a client feeds the model."""
    _fake_loader(monkeypatch, _FakeEncoding(4))
    structured = {"a": 1, "b": ["x", "y"]}
    result = ToolResult(
        content=[mt.TextContent(type="text", text="ok")],
        structured_content=structured,
    )

    m = _measure(result)

    assert m.content == {
        "text": ContentMeasure(blocks=1, bytes=len(b"ok"), tokens_est=4)
    }


def test_structured_only_result_is_its_own_content_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no text blocks, the structured content IS the payload."""
    _fake_loader(monkeypatch, _FakeEncoding(4))
    structured = {"a": 1, "b": ["x", "y"]}
    result = ToolResult(content=[], structured_content=structured)

    m = _measure(result)

    assert m.content == {
        "structured": ContentMeasure(
            blocks=1, bytes=len(json.dumps(structured).encode()), tokens_est=4
        )
    }


def test_empty_result_has_an_empty_breakdown_and_never_loads_the_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _fake_loader(monkeypatch, _FakeEncoding(99))

    m = _measure(ToolResult(content=[]))

    assert m.content == {}
    assert m.result_bytes == 0
    assert m.result_tokens_est == 0
    assert calls == []


def test_estimation_disabled_via_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """token_estimate_encoding='' disables token estimation entirely (images
    included); byte measurement is unaffected and tiktoken is never touched."""
    calls = _fake_loader(monkeypatch, _FakeEncoding(99))
    result = ToolResult(
        content=[mt.TextContent(type="text", text="hello"), _png_block(640, 480)]
    )

    m = measure.measure_tool_result(result, Settings(token_estimate_encoding=""))

    assert m is not None
    assert m.result_tokens_est is None
    assert m.result_bytes == len(b"hello") + len(_png_block(640, 480).data)
    assert {c.tokens_est for c in m.content.values()} == {0}
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

    for _ in range(2):
        m = _measure(result)
        assert m.result_bytes == len(b"hello")
        assert m.result_tokens_est is None
    # Loaded (and failed) exactly once; the failure is cached thereafter.
    assert calls == ["o200k_base"]


def test_measurement_blowup_degrades_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Metering must never break a tool call: any unexpected failure inside
    the measurement degrades to no measurement."""

    def _boom(result: Any) -> Any:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(measure, "_collect_items", _boom)
    result = ToolResult(content=[mt.TextContent(type="text", text="hello")])

    assert measure.measure_tool_result(result, _SETTINGS) is None

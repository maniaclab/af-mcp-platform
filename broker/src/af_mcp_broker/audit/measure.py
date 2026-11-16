"""Tool-result metering for the audit log (observability roadmap PR B).

``measure_tool_result`` turns a FastMCP ``ToolResult`` into a
:class:`ToolMeasurement`: a breakdown ``content_type -> ContentMeasure(blocks,
bytes, tokens_est)`` and the totals, which are the sums of that breakdown
(computed in one place, :class:`ToolMeasurement`). The authorization
middleware's metering worker records it on every successful call.

The breakdown is keyed by an open set so a new MCP content type never needs a
schema change. A ``content_type`` is the MCP block's own ``type`` discriminator
(``text``, ``image``, ``audio``, ``resource``, ``resource_link``, ...), plus
``structured`` for the result's ``structuredContent``. A block type this module
does not know is still measured under its own ``type`` string and logged once
per call as ``measure.unknown_content_type`` -- never dropped.

Bytes are the size of the payload as sent on the wire: text is its UTF-8
length, and base64 payloads (image and audio ``data``, a blob resource's
``blob``) are counted at their base64 length, not their decoded length. A
block with no payload field of its own (``resource_link``, an unknown type) is
its serialized JSON.

Tokens are an ESTIMATE of what the content costs the LLM client's context,
chosen per content type by ``_TOKEN_RULES`` (adding a rule is one entry):

- ``text``, ``structured`` and text ``resource``: tiktoken (see
  ``Settings.token_estimate_encoding``).
- ``image``: Claude's vision estimate (``image_tokens.py``), with dimensions
  read from the image header (``image_header.py``). An unreadable image is
  logged and charged the tier maximum, never 0.
- everything else (audio, blob ``resource``, ``resource_link``, unknown):
  0 -- the model does not consume it as tokens.

``structuredContent`` is measured only when the result has no text blocks:
fastmcp mirrors a typed tool's text into structured output, and a client feeds
the model ONE representation, so summing both double-counts such backends
(issue #241).

The tiktoken encoding is loaded once, lazily: tiktoken downloads encoding
files from a CDN on first use, and the broker pod has default-deny egress, so
the container image pre-seeds ``TIKTOKEN_CACHE_DIR`` at build time (see
``Containerfile.broker``). If the load fails (e.g. local dev with no cache and
no network), the failure is warned about once and token estimation is off
thereafter: every ``tokens_est`` is 0 and the total is ``None``. The same
happens when ``token_estimate_encoding`` is empty. Metering must never break a
tool call, so the whole measurement likewise degrades to ``None`` on any
unexpected error.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import mcp.types as mt
import structlog
import tiktoken

from af_mcp_broker.audit.image_header import image_dimensions
from af_mcp_broker.audit.image_tokens import (
    ASSUMED_TIER,
    estimate_image_tokens,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastmcp.tools.base import ToolResult

    from af_mcp_broker.config import Settings

logger = structlog.get_logger(__name__)

# Module-level encoding cache: the loaded encoding, and whether a load has
# already failed (so the warning fires once, not per tool call).
_encoding: tiktoken.Encoding | None = None
_encoding_load_failed = False


def _get_encoding(encoding_name: str) -> tiktoken.Encoding | None:
    """Return the cached tiktoken encoding, loading it on first use.

    A load failure is remembered: every later call returns None without
    retrying, so a broker without the pre-seeded cache (and without egress
    -- see the module docstring) logs one warning instead of re-attempting
    an unreachable CDN download on every tool call.
    """
    global _encoding, _encoding_load_failed
    if _encoding is not None:
        return _encoding
    if _encoding_load_failed:
        return None
    try:
        _encoding = tiktoken.get_encoding(encoding_name)
    except Exception as exc:  # noqa: BLE001 -- degrade to no estimate, see docstring
        _encoding_load_failed = True
        logger.warning(
            "measure.token_encoding_unavailable",
            encoding=encoding_name,
            error=str(exc),
        )
        return None
    return _encoding


# The content types this module recognizes. Anything else is still measured
# (see the module docstring); metrics labels collapse the rest to "other" so
# a misbehaving backend cannot mint label values.
KNOWN_CONTENT_TYPES = frozenset(
    {"text", "structured", "image", "audio", "resource", "resource_link"}
)
OTHER_CONTENT_TYPE = "other"


def metric_content_type(content_type: str) -> str:
    """Return the metrics-label value for *content_type*: itself if known, else ``other``."""
    return content_type if content_type in KNOWN_CONTENT_TYPES else OTHER_CONTENT_TYPE


@dataclass(frozen=True)
class ContentMeasure:
    """What one content type contributed to a tool result."""

    blocks: int
    bytes: int
    tokens_est: int


@dataclass(frozen=True)
class ToolMeasurement:
    """A tool result's per-content-type breakdown and its totals.

    The totals are derived from ``content`` so they can never disagree with
    it. ``tokens_estimated`` is False when token estimation is off (disabled
    or tiktoken unavailable): every ``tokens_est`` is then 0 and
    ``result_tokens_est`` is None, not 0.
    """

    content: dict[str, ContentMeasure] = field(default_factory=dict)
    tokens_estimated: bool = True

    @property
    def result_bytes(self) -> int:
        """Total wire bytes over all content."""
        return sum(c.bytes for c in self.content.values())

    @property
    def result_tokens_est(self) -> int | None:
        """Total estimated tokens over all content; None when estimation is off."""
        if not self.tokens_estimated:
            return None
        return sum(c.tokens_est for c in self.content.values())


@dataclass(frozen=True)
class _Item:
    """One measurable payload: a content block, or the structured content."""

    wire_bytes: int
    text: str | None = None  # text the model reads verbatim, if any
    base64_data: str | None = None  # base64 image payload, if any


def _wire_json_bytes(block: object) -> int:
    dump = getattr(block, "model_dump_json", None)
    wire = (
        dump(by_alias=True, exclude_none=True)
        if dump is not None
        else json.dumps(block, default=str)
    )
    return len(wire.encode("utf-8"))


def _collect_items(result: ToolResult) -> dict[str, list[_Item]]:
    """Group *result*'s payloads by content type."""
    items: dict[str, list[_Item]] = {}
    unknown: set[str] = set()
    for block in result.content:
        content_type: str
        item: _Item
        if isinstance(block, mt.TextContent):
            content_type = "text"
            item = _Item(len(block.text.encode("utf-8")), text=block.text)
        elif isinstance(block, mt.ImageContent):
            content_type = "image"
            item = _Item(len(block.data.encode("ascii")), base64_data=block.data)
        elif isinstance(block, mt.AudioContent):
            content_type = "audio"
            item = _Item(len(block.data.encode("ascii")))
        elif isinstance(block, mt.EmbeddedResource):
            content_type = "resource"
            contents = block.resource
            if isinstance(contents, mt.TextResourceContents):
                item = _Item(len(contents.text.encode("utf-8")), text=contents.text)
            else:
                item = _Item(len(contents.blob.encode("ascii")))
        elif isinstance(block, mt.ResourceLink):
            content_type = "resource_link"
            item = _Item(_wire_json_bytes(block))
        else:
            content_type = str(getattr(block, "type", "unknown"))
            item = _Item(_wire_json_bytes(block))
            unknown.add(content_type)
        items.setdefault(content_type, []).append(item)
    for content_type in sorted(unknown):
        logger.warning("measure.unknown_content_type", content_type=content_type)
    # Text blocks and structured content are alternatives, not additive; see
    # the module docstring (issue #241).
    if "text" not in items and result.structured_content is not None:
        payload = json.dumps(result.structured_content, default=str)
        items["structured"] = [_Item(len(payload.encode("utf-8")), text=payload)]
    return items


def _text_tokens(items: list[_Item], encoding_name: str) -> int | None:
    """tiktoken estimate of the items' text, tokenized as one string.

    None when the encoding is unavailable (token estimation is then off).
    """
    text = "".join(item.text for item in items if item.text is not None)
    if not text:
        return 0
    encoding = _get_encoding(encoding_name)
    if encoding is None:
        return None
    # disallowed_special=(): a tool result may legitimately contain a
    # tokenizer's special-token spelling (e.g. "<|endoftext|>"), which
    # encode() would otherwise raise on.
    return len(encoding.encode(text, disallowed_special=()))


def _image_tokens(items: list[_Item], _encoding_name: str) -> int:
    """Claude vision estimate summed over the images (see image_tokens.py)."""
    total = 0
    for item in items:
        try:
            width, height = image_dimensions(base64.b64decode(item.base64_data or ""))
        except ValueError as exc:  # includes binascii.Error
            logger.warning("measure.image_dimensions_unreadable", error=str(exc))
            total += ASSUMED_TIER.max_tokens
        else:
            total += estimate_image_tokens(width, height)
    return total


# content_type -> estimator over every item of that type (None: estimation
# unavailable). A type with no entry
# costs 0 tokens: the model does not consume it as tokens. Adding a rule for
# a new content type is one entry here.
_TOKEN_RULES: dict[str, Callable[[list[_Item], str], int | None]] = {
    "text": _text_tokens,
    "structured": _text_tokens,
    "resource": _text_tokens,
    "image": _image_tokens,
}


def measure_tool_result(
    result: ToolResult, settings: Settings
) -> ToolMeasurement | None:
    """Measure *result* per content type; see the module docstring.

    Any unexpected failure degrades to None with a warning -- a tool call
    must succeed even if its measurement blows up.
    """
    try:
        items = _collect_items(result)
        encoding_name = settings.token_estimate_encoding
        tokens: dict[str, int] = dict.fromkeys(items, 0)
        tokens_estimated = bool(encoding_name)
        if tokens_estimated:
            for content_type, group in items.items():
                rule = _TOKEN_RULES.get(content_type)
                estimate = rule(group, encoding_name) if rule is not None else 0
                if estimate is None:  # a rule reported estimation unavailable
                    tokens = dict.fromkeys(items, 0)
                    tokens_estimated = False
                    break
                tokens[content_type] = estimate
        return ToolMeasurement(
            content={
                content_type: ContentMeasure(
                    blocks=len(group),
                    bytes=sum(item.wire_bytes for item in group),
                    tokens_est=tokens[content_type],
                )
                for content_type, group in items.items()
            },
            tokens_estimated=tokens_estimated,
        )
    except Exception as exc:  # noqa: BLE001 -- metering must never break a tool call
        logger.warning("measure.tool_result_failed", error=str(exc))
        return None

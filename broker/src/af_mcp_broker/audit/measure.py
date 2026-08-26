"""Tool-result metering for the audit log (observability roadmap PR B).

``measure_tool_result`` turns a FastMCP ``ToolResult`` into the
``(result_bytes, result_tokens_est)`` pair the authorization middleware
records on every successful call. Both numbers estimate what the call
injects into the LLM client's context -- NOT wire size: what is measured
is the result's serialized text, defined as the concatenated text of its
text-content blocks plus, when structured content is present, its
``json.dumps``. Non-text blocks (images, audio, resource links) are
ignored -- their payloads are not text the client feeds back into its
context verbatim.

Token counts come from tiktoken and are an ESTIMATE (see
``Settings.token_estimate_encoding``). The encoding is loaded once,
lazily: tiktoken downloads encoding files from a CDN on first use, and the
broker pod has default-deny egress, so the container image pre-seeds
``TIKTOKEN_CACHE_DIR`` at build time (see ``Containerfile.broker``). If
the load still fails (e.g. local dev with no cache and no network), the
failure is warned about once and token estimation degrades to ``None``
thereafter -- metering must never break a tool call, so the whole
measurement likewise degrades to ``(None, None)`` on any unexpected error.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import mcp.types as mt
import structlog
import tiktoken

from af_mcp_broker.config import get_settings

if TYPE_CHECKING:
    from fastmcp.tools.base import ToolResult

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
            "token_estimate_encoding_unavailable",
            encoding=encoding_name,
            error=str(exc),
        )
        return None
    return _encoding


def _serialized_text(result: ToolResult) -> str:
    """Return serialized text of tool result.

    See the module docstring for exactly what is (and is not) counted.
    """
    parts = [
        block.text for block in result.content if isinstance(block, mt.TextContent)
    ]
    if result.structured_content is not None:
        parts.append(json.dumps(result.structured_content, default=str))
    return "".join(parts)


def measure_tool_result(result: ToolResult) -> tuple[int | None, int | None]:
    """``(result_bytes, result_tokens_est)`` for *result*.

    ``result_bytes`` is the UTF-8 byte length of the serialized text;
    ``result_tokens_est`` is the tiktoken estimate of the same text, None
    when estimation is disabled (``token_estimate_encoding`` empty), the
    text is empty, or the encoding could not be loaded. Any unexpected
    failure degrades to ``(None, None)`` with a warning -- a tool call
    must succeed even if its measurement blows up.
    """
    try:
        text = _serialized_text(result)
        result_bytes = len(text.encode("utf-8"))
        encoding_name = get_settings().token_estimate_encoding
        if not encoding_name or not text:
            return result_bytes, None
        encoding = _get_encoding(encoding_name)
        if encoding is None:
            return result_bytes, None
        # disallowed_special=(): a tool result may legitimately contain a
        # tokenizer's special-token spelling (e.g. "<|endoftext|>"), which
        # encode() would otherwise raise on.
        return result_bytes, len(encoding.encode(text, disallowed_special=()))
    except Exception as exc:  # noqa: BLE001 -- metering must never break a tool call
        logger.warning("tool_result_measurement_failed", error=str(exc))
        return None, None

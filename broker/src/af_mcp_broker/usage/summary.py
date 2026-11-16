"""Assemble a caller's usage summary.

The single implementation behind both ``GET /v1/usage`` (``api/usage.py``)
and the ``af_usage`` MCP tool (``mcp/diagnostics.py``): store query and
aggregation shaping live here so the two surfaces can never drift apart.

Honesty caveats (repeated in both surfaces' descriptions): the token
numbers are a tiktoken (o200k) ESTIMATE of what each tool result would
inject into an LLM client's context -- not provider-reported usage, and not
the user's full token volume (their prompts, the model's own output, and
every non-tool token are invisible to the broker). Image tokens follow
Anthropic's documented 28 px-patch rule on an assumed high-resolution tier
(``audit/image_tokens.py``).
"""

from __future__ import annotations

from collections import defaultdict

# Runtime import (not TYPE_CHECKING): pydantic must resolve UsageByDay.date's
# annotation when the model class is built.
from datetime import date  # noqa: TC003
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from af_mcp_broker.usage.store import add_content

if TYPE_CHECKING:
    from af_mcp_broker.audit.measure import ContentMeasure
    from af_mcp_broker.usage.store import UsageAggregate, UsageStore

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class UsageTotals(BaseModel):
    model_config = ConfigDict(frozen=True)

    calls: int
    errors: int
    duration_ms: float
    result_bytes: int
    result_tokens_est: int


class UsageByService(BaseModel):
    model_config = ConfigDict(frozen=True)

    service: str
    calls: int
    errors: int
    result_bytes: int
    result_tokens_est: int


class UsageByDay(BaseModel):
    model_config = ConfigDict(frozen=True)

    date: date
    calls: int
    result_tokens_est: int


class UsageByContentType(BaseModel):
    """One MCP content type's share of the window's tool results.

    ``content_type`` is an open set (``text``, ``image``, ``audio``,
    ``resource``, ``resource_link``, ``structured``, and whatever MCP adds).
    Calls recorded without a breakdown appear in ``totals`` but in no entry
    here, so the entries can sum to less than ``totals``.
    """

    model_config = ConfigDict(frozen=True)

    content_type: str
    blocks: int
    bytes: int
    tokens_est: int


class UsageResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    window_days: int
    totals: UsageTotals
    by_service: list[UsageByService]
    by_day: list[UsageByDay]
    by_content_type: list[UsageByContentType]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


async def build_usage_summary(
    store: UsageStore,
    subject: str,
    days: int,
) -> UsageResponse:
    """Return *subject*'s usage over the trailing *days*-day window."""
    aggregates: list[UsageAggregate] = await store.query(subject, days)

    totals = UsageTotals(
        calls=sum(a.calls for a in aggregates),
        errors=sum(a.calls for a in aggregates if a.outcome == "error"),
        duration_ms=sum(a.duration_ms for a in aggregates),
        result_bytes=sum(a.result_bytes for a in aggregates),
        result_tokens_est=sum(a.result_tokens_est for a in aggregates),
    )

    # Roll the (day, service, method, outcome) aggregates up along each axis.
    by_service_acc: dict[str, dict[str, int]] = defaultdict(
        lambda: {"calls": 0, "errors": 0, "result_bytes": 0, "result_tokens_est": 0}
    )
    by_day_acc: dict[date, dict[str, int]] = defaultdict(
        lambda: {"calls": 0, "result_tokens_est": 0}
    )
    by_content_acc: dict[str, ContentMeasure] = {}
    for a in aggregates:
        for content_type, measure in a.content.items():
            by_content_acc[content_type] = add_content(
                by_content_acc.get(content_type), measure
            )
        svc = by_service_acc[a.service]
        svc["calls"] += a.calls
        svc["errors"] += a.calls if a.outcome == "error" else 0
        svc["result_bytes"] += a.result_bytes
        svc["result_tokens_est"] += a.result_tokens_est
        day = by_day_acc[a.day]
        day["calls"] += a.calls
        day["result_tokens_est"] += a.result_tokens_est

    return UsageResponse(
        subject=subject,
        window_days=days,
        totals=totals,
        by_service=[
            UsageByService(service=service, **acc)
            for service, acc in sorted(by_service_acc.items())
        ],
        by_day=[UsageByDay(date=day, **acc) for day, acc in sorted(by_day_acc.items())],
        by_content_type=[
            UsageByContentType(
                content_type=content_type,
                blocks=m.blocks,
                bytes=m.bytes,
                tokens_est=m.tokens_est,
            )
            for content_type, m in sorted(by_content_acc.items())
        ],
    )

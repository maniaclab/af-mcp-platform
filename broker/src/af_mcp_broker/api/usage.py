"""GET /v1/usage -- self-service usage accounting with read-time cost.

Serves the calling user their own tool-call usage (and nobody else's --
the subject comes from the authenticated principal, never a parameter)
aggregated by the UsageStore (``usage/``), plus a dollar figure derived AT
READ TIME from tokencost's bundled static price table. Dollars are never
stored; only tokens are, so repricing is a query away.

Honesty caveats (also in the route's OpenAPI description): the token
numbers are a tiktoken (o200k) ESTIMATE of what each tool result would
inject into an LLM client's context -- not provider-reported usage, and not
the user's full LLM spend (their prompts, the model's own output, and every
non-tool token are invisible to the broker). The cost is that estimate
priced at the chosen model's *input* rate.

tokencost is used strictly offline: only ``calculate_cost_by_tokens`` and
the ``TOKEN_COSTS`` table, both backed by the JSON bundled in the package.
``update_token_costs``/``refresh_prices`` fetch prices from the network and
must never be called -- the broker pod is egress-deny.
"""

from __future__ import annotations

from collections import defaultdict

# Runtime import (not TYPE_CHECKING): pydantic must resolve UsageByDay.date's
# annotation when the model class is built.
from datetime import date  # noqa: TC003
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from tokencost import (  # type: ignore[import-untyped]
    TOKEN_COSTS,
    calculate_cost_by_tokens,
)

from af_mcp_broker.config import get_settings
from af_mcp_broker.identity import Principal, keycloak_dependency

if TYPE_CHECKING:
    from af_mcp_broker.usage import UsageAggregate, UsageStore

router = APIRouter(prefix="/usage", tags=["usage"])

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

# estimated_cost_usd fields are floats: tokencost's Decimal is exact, but
# there is no money/Decimal serialization precedent in this API and the value
# is an ESTIMATE of an estimate -- float round-trip error is far below its
# honesty bar. Revisit if anything ever bills from this endpoint.


class UsageTotals(BaseModel):
    model_config = ConfigDict(frozen=True)

    calls: int
    errors: int
    duration_ms: float
    result_bytes: int
    result_tokens_est: int
    estimated_cost_usd: float


class UsageByService(BaseModel):
    model_config = ConfigDict(frozen=True)

    service: str
    calls: int
    errors: int
    result_bytes: int
    result_tokens_est: int
    estimated_cost_usd: float


class UsageByDay(BaseModel):
    model_config = ConfigDict(frozen=True)

    date: date
    calls: int
    result_tokens_est: int


class UsageResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    window_days: int
    # The TOKEN_COSTS key whose input price produced every
    # estimated_cost_usd in this response.
    cost_model: str
    totals: UsageTotals
    by_service: list[UsageByService]
    by_day: list[UsageByDay]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _estimated_cost_usd(tokens: int, model: str) -> float:
    """*tokens* priced at *model*'s input rate, from the bundled table."""
    return float(calculate_cost_by_tokens(tokens, model, token_type="input"))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=UsageResponse,
    summary="Get the caller's own usage",
    description=(
        "Per-service and per-day aggregates of the caller's tool calls over "
        "a trailing window, with an estimated cost. Honesty caveats: token "
        "counts are a tiktoken (o200k) ESTIMATE of the tool-result text "
        "injected into the LLM client's context -- not provider-reported "
        "usage, and not the user's full LLM spend -- and estimated_cost_usd "
        "is that estimate priced at the chosen model's input rate."
    ),
)
async def get_usage(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    days: Annotated[int, Query(ge=1, le=365)] = 30,
    model: str | None = None,
) -> UsageResponse:
    """Return the caller's own usage -- scoped strictly to ``principal.subject``.

    Token counts are a tiktoken (o200k) ESTIMATE of tool-result context
    injection only (see the module docstring's honesty caveats);
    ``estimated_cost_usd`` prices them at the input rate of ``?model=`` (or
    the configured ``cost_reference_model``).
    """
    settings = getattr(request.app.state, "settings", None) or get_settings()
    cost_model = model or settings.cost_reference_model
    if cost_model not in TOKEN_COSTS:
        # Deliberately does not enumerate the table -- it has thousands of
        # keys and would drown the actual message.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"Model '{cost_model}' is not in the bundled token price "
                "table; pick a key tokencost knows."
            ),
        )

    # None only outside the lifespan (unit tests hitting the router bare) --
    # degrade to an empty window rather than 500ing a self-service page.
    store: UsageStore | None = getattr(request.app.state, "usage_store", None)
    aggregates: list[UsageAggregate] = (
        await store.query(principal.subject, days) if store is not None else []
    )

    totals = UsageTotals(
        calls=sum(a.calls for a in aggregates),
        errors=sum(a.calls for a in aggregates if a.outcome == "error"),
        duration_ms=sum(a.duration_ms for a in aggregates),
        result_bytes=sum(a.result_bytes for a in aggregates),
        result_tokens_est=sum(a.result_tokens_est for a in aggregates),
        estimated_cost_usd=_estimated_cost_usd(
            sum(a.result_tokens_est for a in aggregates), cost_model
        ),
    )

    # Roll the (day, service, tool, outcome) aggregates up along each axis.
    by_service_acc: dict[str, dict[str, int]] = defaultdict(
        lambda: {"calls": 0, "errors": 0, "result_bytes": 0, "result_tokens_est": 0}
    )
    by_day_acc: dict[date, dict[str, int]] = defaultdict(
        lambda: {"calls": 0, "result_tokens_est": 0}
    )
    for a in aggregates:
        svc = by_service_acc[a.service]
        svc["calls"] += a.calls
        svc["errors"] += a.calls if a.outcome == "error" else 0
        svc["result_bytes"] += a.result_bytes
        svc["result_tokens_est"] += a.result_tokens_est
        day = by_day_acc[a.day]
        day["calls"] += a.calls
        day["result_tokens_est"] += a.result_tokens_est

    return UsageResponse(
        subject=principal.subject,
        window_days=days,
        cost_model=cost_model,
        totals=totals,
        by_service=[
            UsageByService(
                service=service,
                estimated_cost_usd=_estimated_cost_usd(
                    acc["result_tokens_est"], cost_model
                ),
                **acc,
            )
            for service, acc in sorted(by_service_acc.items())
        ],
        by_day=[UsageByDay(date=day, **acc) for day, acc in sorted(by_day_acc.items())],
    )

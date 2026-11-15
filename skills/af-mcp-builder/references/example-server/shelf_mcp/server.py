"""Tools, the ASGI app and the entry point."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Annotated

import httpx2
import uvicorn
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field
from starlette.middleware import Middleware as ASGIMiddleware
from starlette.responses import PlainTextResponse, Response

from shelf_mcp.auth import BrokerTokenVerifier, JwksCache
from shelf_mcp.data import ShelfClient, ShelfNotFoundError, ShelfUnavailableError
from shelf_mcp.observability import (
    HEALTH_PATH,
    RequestLogMiddleware,
    ToolCallMiddleware,
    configure_logging,
    configure_tracing,
)

if TYPE_CHECKING:
    from starlette.applications import Starlette
    from starlette.requests import Request

MAX_ROWS = 100
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)


class Dataset(BaseModel):
    """One catalogue entry, with the fields an analyst picks (O3)."""

    name: str
    status: str
    size_gb: float
    events: int


class ListResult(BaseModel):
    """Result of shelf_list_datasets."""

    datasets: list[Dataset]
    truncated: bool
    next_step: str | None  # how to continue after an empty or truncated page


class DatasetResult(BaseModel):
    """Result of shelf_get_dataset."""

    dataset: Dataset


def build_server(verifier: BrokerTokenVerifier, client: ShelfClient) -> FastMCP:
    """Register the tools. Names carry the service prefix (N1, P1)."""
    mcp = FastMCP(
        "shelf",
        auth=verifier,
        middleware=[ToolCallMiddleware()],
        instructions="Read-only catalogue of facility datasets.",
    )

    @mcp.tool(annotations=READ_ONLY)
    def shelf_list_datasets(
        pattern: Annotated[
            str, Field(description="Wildcard on the dataset name, e.g. 'mc23_*'.")
        ] = "*",
        limit: Annotated[
            int, Field(description="Maximum rows to return.", ge=1, le=MAX_ROWS)
        ] = 20,
    ) -> ListResult:
        """List catalogue datasets matching a wildcard, at most `limit` of them.

        Sizes are in GB. Use shelf_get_dataset for one entry's detail.
        """
        try:
            # Lazy iterator: only `limit + 1` rows are fetched (B1).
            rows = [
                r
                for _, r in zip(
                    range(limit + 1), client.iter_datasets(pattern), strict=False
                )
            ]
        except ShelfUnavailableError as exc:
            raise _unavailable() from exc
        truncated = len(rows) > limit
        hint = None
        if not rows:
            hint = f"No datasets match {pattern!r}. Try a broader wildcard such as '*'."
        elif truncated:
            hint = f"Showing {limit} datasets. Narrow `pattern` or raise `limit` (maximum {MAX_ROWS}) to see others."
        return ListResult(
            datasets=[Dataset(**r) for r in rows[:limit]],
            truncated=truncated,
            next_step=hint,
        )

    @mcp.tool(annotations=READ_ONLY)
    def shelf_get_dataset(
        name: Annotated[str, Field(description="Full dataset name.")],
    ) -> DatasetResult:
        """Return one catalogue dataset by its full name.

        The caller is the identity in the broker token; there is no owner argument (U6).
        """
        try:
            return DatasetResult(dataset=Dataset(**client.get_dataset(name)))
        except ShelfNotFoundError as exc:
            # A failure the caller can act on is a tool error with a next step (E1, E2, E4).
            msg = (
                f"Dataset {name!r} not found. Use shelf_list_datasets with a wildcard "
                "pattern to search for it."
            )
            raise ToolError(msg) from exc
        except ShelfUnavailableError as exc:
            raise _unavailable() from exc

    @mcp.custom_route(HEALTH_PATH, methods=["GET"])
    async def healthz(_request: Request) -> Response:
        """Answer readiness from this process's own health only (X5)."""
        return PlainTextResponse("ok")

    return mcp


def _unavailable() -> ToolError:
    return ToolError(
        "The shelf service is unreachable. This is transient: retry the call (E3)."
    )


def create_app(
    jwks_uri: str,
    issuer: str,
    audience: str,
    http: httpx2.AsyncClient | None = None,
) -> Starlette:
    """Build the stateless streamable-HTTP app (X1) behind broker-token auth (X2)."""
    http = http or httpx2.AsyncClient(timeout=5.0)  # explicit timeout (X5)
    verifier = BrokerTokenVerifier(JwksCache(jwks_uri, http), issuer, audience)
    mcp = build_server(verifier, ShelfClient())
    return mcp.http_app(
        stateless_http=True, middleware=[ASGIMiddleware(RequestLogMiddleware)]
    )


def main() -> None:
    """Serve on ``SHELF_HOST:SHELF_PORT``, configured from ``SHELF_*`` variables."""
    configure_logging()
    configure_tracing()
    app = create_app(
        jwks_uri=os.environ["SHELF_JWKS_URI"],
        issuer=os.environ["SHELF_ISSUER"],
        audience=os.environ["SHELF_AUDIENCE"],
    )
    uvicorn.run(
        app,
        host=os.environ.get("SHELF_HOST", "127.0.0.1"),
        port=int(os.environ.get("SHELF_PORT", "8000")),
        access_log=False,  # RequestLogMiddleware writes the access line (L3)
        log_config=None,  # uvicorn's own lines go through configure_logging (L2)
    )


if __name__ == "__main__":
    main()

"""shelf-mcp: an MCP server over a facility dataset catalogue (eval fixture)."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import JWTVerifier
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from shelf_client import ShelfClient, ShelfNotFoundError

# Signature, issuer, audience and expiry are all checked by the verifier; the
# audience is this service's registered audience in services.yaml.
verifier = JWTVerifier(
    jwks_uri="https://broker.example.org/.well-known/jwks.json",
    issuer="https://broker.example.org",
    audience="shelf-mcp",
)
mcp = FastMCP("shelf", auth=verifier)
client = ShelfClient()  # wraps the native shelf client library, no CLI

MAX_ROWS = 100


class Dataset(BaseModel):
    """One catalogue entry, with the fields an analyst picks."""

    name: str
    status: str
    size_gb: float
    events: int


class ListResult(BaseModel):
    """Result of shelf_list_datasets."""

    datasets: list[Dataset]
    truncated: bool
    next_step: str | None  # how to continue after a truncated or empty page


class DatasetResult(BaseModel):
    """Result of shelf_get_dataset."""

    dataset: Dataset


READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)


@mcp.tool(annotations=READ_ONLY)
def shelf_list_datasets(
    pattern: Annotated[str, Field(description="Wildcard on the dataset name, e.g. 'mc23_*'.")] = "*",
    limit: Annotated[int, Field(description="Maximum rows to return.", ge=1, le=MAX_ROWS)] = 20,
) -> ListResult:
    """List catalogue datasets matching a wildcard, at most `limit` of them.

    Sizes are in GB. Use shelf_get_dataset for one entry's detail.
    """
    rows = client.iter_datasets(pattern)  # lazy iterator: only `limit + 1` rows are fetched
    page = [Dataset(**r) for _, r in zip(range(limit + 1), rows, strict=False)]
    truncated = len(page) > limit
    if not page:
        hint = f"No datasets match {pattern!r}. Try a broader wildcard such as '*'."
    elif truncated:
        hint = f"Showing {limit} datasets. Narrow `pattern` or raise `limit` (maximum {MAX_ROWS}) to see others."
    else:
        hint = None
    return ListResult(datasets=page[:limit], truncated=truncated, next_step=hint)


@mcp.tool(annotations=READ_ONLY)
def shelf_get_dataset(
    name: Annotated[str, Field(description="Full dataset name.")],
) -> DatasetResult:
    """Return one catalogue dataset by its full name.

    The caller's own access is checked by the backend; there is no owner argument.
    """
    try:
        return DatasetResult(dataset=Dataset(**client.get_dataset(name)))
    except ShelfNotFoundError as exc:
        msg = (
            f"Dataset {name!r} not found. Use shelf_list_datasets with a wildcard "
            "pattern to search for it."
        )
        raise ToolError(msg) from exc


if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8000, stateless_http=True)

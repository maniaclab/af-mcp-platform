"""tapestore-mcp: an MCP server over a tape-archive catalogue (eval fixture).

Compliant apart from one defect: the verifier's audience does not match the
service's audience in services.yaml, so it refuses every broker token.
"""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import JWTVerifier
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from tapestore_client import TapeClient, TapeNotFoundError

# The signature, issuer and expiry checks are correct. The audience is a
# hard-coded string chosen when the server was written.
verifier = JWTVerifier(
    jwks_uri="https://broker.example.org/.well-known/jwks.json",
    issuer="https://broker.example.org",
    audience="tapestore-mcp",
)
mcp = FastMCP("tapestore", auth=verifier)
client = TapeClient()

MAX_ROWS = 100


class Tape(BaseModel):
    """One tape in the archive catalogue."""

    label: str
    state: str
    files: int


class TapeList(BaseModel):
    """Result of tapestore_list_tapes."""

    tapes: list[Tape]
    truncated: bool
    note: str


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
def tapestore_list_tapes(
    pattern: Annotated[str, Field(description="Glob over tape labels, e.g. 'ATL*'")],
    limit: Annotated[
        int, Field(description="Maximum rows to return", ge=1, le=MAX_ROWS)
    ] = 20,
) -> TapeList:
    """List tapes whose label matches a pattern.

    Returns at most `limit` rows. Call tapestore_get_tape for one tape's detail.
    """
    rows = list(client.iter_tapes(pattern, limit + 1))
    truncated = len(rows) > limit
    note = (
        f"Showing {limit} tapes. Narrow the pattern to see others."
        if truncated
        else "All matching tapes shown."
    )
    return TapeList(
        tapes=[Tape(label=r.label, state=r.state, files=r.files) for r in rows[:limit]],
        truncated=truncated,
        note=note,
    )


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
def tapestore_get_tape(
    label: Annotated[str, Field(description="Tape label from tapestore_list_tapes")],
) -> Tape:
    """Return one tape's state and file count."""
    try:
        r = client.get_tape(label)
    except TapeNotFoundError as exc:
        msg = f"No tape '{label}'. Call tapestore_list_tapes to find labels."
        raise ToolError(msg) from exc
    return Tape(label=r.label, state=r.state, files=r.files)


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000, stateless_http=True)  # noqa: S104

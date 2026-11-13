"""Real fastmcp servers used by the audit_tools integration tests.

`compliant` satisfies every wire-visible guide item (`compliant-auth` adds
transport bearer auth); `violating` breaks a known, fixed set of them. Run as a script:

    python fixture_servers.py <compliant|compliant-auth|violating> stdio
    python fixture_servers.py <compliant|compliant-auth|violating> <http|stateless> <port>
    python fixture_servers.py status <401|200> <port>   # bare HTTP status stub
"""

from __future__ import annotations

import sys
from typing import Annotated

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

PREFIX = "fx"


class ThingResult(BaseModel):
    """Structured result of fx_get_thing."""

    thing_id: str
    size: int


class ListResult(BaseModel):
    """Structured result of fx_list_things."""

    things: list[str]


GOOD_TOKEN = "fixture-good-token"


def build_compliant(*, auth: bool = False) -> FastMCP:
    """Return a server with no wire-visible findings.

    With ``auth=True`` the transport rejects any bearer other than
    ``GOOD_TOKEN`` with HTTP 401 before a tool runs.
    """
    verifier = (
        StaticTokenVerifier(tokens={GOOD_TOKEN: {"client_id": "audit", "scopes": []}})
        if auth
        else None
    )
    mcp = FastMCP("fx-compliant", auth=verifier)

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Get a thing", read_only_hint=True, open_world_hint=False
        )
    )
    def fx_get_thing(
        thing_id: Annotated[str, Field(description="Identifier of the thing.")],
    ) -> ThingResult:
        """Return the size of one thing.

        Fails with a next step when the identifier is unknown.
        """
        if thing_id != "known":
            raise ToolError(
                f"No thing {thing_id!r}. Next step: call fx_list_things to see valid ids."
            )
        return ThingResult(thing_id=thing_id, size=3)

    @mcp.tool(
        annotations=ToolAnnotations(
            title="List things", read_only_hint=True, open_world_hint=False
        )
    )
    def fx_list_things(
        limit: Annotated[
            int, Field(description="Maximum rows to return.", ge=1, le=100)
        ] = 10,
    ) -> ListResult:
        """List thing identifiers, at most `limit` of them."""
        return ListResult(things=[f"t{i}" for i in range(min(limit, 100))])

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Delete a thing",
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        )
    )
    def fx_delete_thing(
        thing_id: Annotated[
            str, Field(description="Identifier of the thing to delete.")
        ],
    ) -> ThingResult:
        """Delete one thing."""
        return ThingResult(thing_id=thing_id, size=0)

    return mcp


def build_violating() -> FastMCP:
    """Return a server that breaks N1, N2, N3, S1, O1, A1, A2, B1, U3 and U6."""
    mcp = FastMCP("fx-violating")

    # N1 (no prefix), N2 (no description), S1 (undescribed arg), O1 (no
    # outputSchema), A1 (no annotations)
    @mcp.tool(name="bare_tool", output_schema=None)
    def bare_tool(x: str) -> str:
        return x

    # N2 (first line too long), A2 (write tool missing hints), N3
    @mcp.tool(
        name="fx_write_thing",
        description="W" * 150,
        annotations=ToolAnnotations(read_only_hint=False),
    )
    def fx_write_thing(
        a: Annotated[str, Field(description="a")],
        b: Annotated[str, Field(description="b")],
        c: Annotated[str, Field(description="c")],
    ) -> str:
        return a + b + c

    # B1 (listing without limit), U3 (credential-like arg), U6 (identity arg)
    @mcp.tool(
        name="fx_list_things",
        description="List things.",
        annotations=ToolAnnotations(read_only_hint=True),
    )
    def fx_list_things(
        api_token: Annotated[str, Field(description="Token for the backend.")],
        owner: Annotated[str, Field(description="Whose things to list.")],
    ) -> ListResult:
        return ListResult(things=[api_token])

    # E1: a failing input that reports success instead of isError
    @mcp.tool(
        name="fx_get_thing",
        description="Get a thing.",
        annotations=ToolAnnotations(read_only_hint=True),
    )
    def fx_get_thing(
        thing_id: Annotated[str, Field(description="Identifier.")],
    ) -> str:
        return f"error: no such thing {thing_id}"

    return mcp


BUILDERS = {
    "compliant": build_compliant,
    "compliant-auth": lambda: build_compliant(auth=True),
    "violating": build_violating,
}


def _serve_status(code: int, port: int) -> None:
    """Serve a bare HTTP endpoint that answers every POST with *code*."""
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    kind, mode = sys.argv[1], sys.argv[2]
    if kind == "status":
        _serve_status(int(mode), int(sys.argv[3]))
    elif mode == "stdio":
        BUILDERS[kind]().run(transport="stdio", show_banner=False)
    else:
        BUILDERS[kind]().run(
            transport="http",
            host="127.0.0.1",
            port=int(sys.argv[3]),
            show_banner=False,
            stateless_http=(mode == "stateless"),
        )

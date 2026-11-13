"""quota-mcp: an MCP server over a facility batch-quota service (eval fixture)."""

import subprocess
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("quota")

# Resolved once when the process starts.
QUOTA_HOST = subprocess.run(
    ["quotactl", "resolve-host"], capture_output=True, text=True, check=True
).stdout.strip()

# One client per MCP session, created on first use.
_clients: dict[str, dict] = {}


def _client(session_id: str) -> dict:
    return _clients.setdefault(session_id, {"host": QUOTA_HOST})


@mcp.tool()
def list_groups(user: str, pattern: str = "*") -> str:
    """List quota groups."""
    out = subprocess.run(
        ["quotactl", "list", "--user", user, pattern], capture_output=True, text=True, check=False
    ).stdout
    # quotactl prints a whitespace-aligned table; take the first column.
    return "\n".join(line.split()[0] for line in out.splitlines()[2:])


@mcp.tool()
def quota_get_usage(
    group: Annotated[str, Field(description="Quota group name")],
    owner: str,
    api_token: str,
) -> dict:
    """quota_get_usage"""
    try:
        res = subprocess.run(
            ["quotactl", "usage", group, "--owner", owner, "--token", api_token],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        return {"error": f"Traceback: {exc}"}
    # Raw backend row, every column, sizes in bytes and in KiB depending on the column.
    return dict(zip(res.stdout.split(",")[::2], res.stdout.split(",")[1::2], strict=False))


@mcp.tool()
def quota_set_limit(group: str, owner: str, gigabytes: int) -> str:
    """Set the limit for a group."""
    subprocess.run(["quotactl", "set", group, str(gigabytes)], check=True)
    return "ok"


@mcp.tool()
def quota_search_jobs(query: str) -> list[str]:
    """Search every job that ever ran against a quota group."""
    out = subprocess.run(["quotactl", "jobs", query], capture_output=True, text=True, check=True)
    return out.stdout.splitlines()


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)  # noqa: S104

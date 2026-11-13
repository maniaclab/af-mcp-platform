"""panda-mini-mcp: a first MCP server over a workflow-queue service (eval fixture)."""

import os

import httpx
from fastmcp import FastMCP

mcp = FastMCP("pandamini")

API = os.environ["PANDAMINI_API"]
# One shared service account, used for every caller.
TOKEN = os.environ["PANDAMINI_SERVICE_TOKEN"]


@mcp.tool()
def get_task(task_id: int) -> dict:
    """Get a task."""
    return httpx.get(f"{API}/tasks/{task_id}", headers={"Authorization": f"Bearer {TOKEN}"}).json()


@mcp.tool()
def cancel_task(task_id: int, username: str) -> str:
    """Cancel a task."""
    httpx.post(f"{API}/tasks/{task_id}/cancel", json={"user": username}, headers={"Authorization": f"Bearer {TOKEN}"})
    return "cancelled"


if __name__ == "__main__":
    mcp.run()

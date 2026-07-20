from __future__ import annotations

# Aggregator entry point — the FastMCP application that proxies tool calls to
# downstream MCP backends after the broker has validated identity and issued
# credentials.
#
# This module is imported by app.py and mounted at /mcp. It is intentionally
# minimal at this stage: the full aggregation logic (backend discovery, per-call
# credential injection, audit emission) will be layered in here once the
# credential subsystem is complete.

from fastapi import FastAPI

from af_mcp_broker._version import version as __version__

# Placeholder ASGI app so that app.py can mount something at /mcp today.
# Replace with the real FastMCP aggregator instance once the backend routing
# layer is implemented.
aggregator_app = FastAPI(
    title="AF MCP Aggregator",
    description=(
        "Internal ASGI sub-application that proxies MCP tool calls to "
        "downstream backends. Mounted at /mcp by the broker application."
    ),
    version=__version__,
)

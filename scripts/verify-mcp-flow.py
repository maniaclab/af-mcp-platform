#!/usr/bin/env python3
"""End-to-end verification of the FastMCP aggregator mounted at /mcp.

Exercises a *deployed* broker exactly the way a real MCP client would: over
the wire, via the fastmcp Client, with a real AF Keycloak bearer token. No
mocks -- every step is a real MCP-over-HTTP round trip to whatever service(s)
the broker is actually wired to.

Sibling of the /v1-surface verification this issue's design doc refers to as
`verify-rucio-flow.py` (identity, is_linked, catalog, authorize, credential --
a local, unversioned operator script per .gitignore's `scripts/` entry). This
script is the /mcp equivalent: it exercises the aggregator's MCP protocol
surface (initialize -> tools/list -> optional tools/call) rather than /v1
directly, and unlike its sibling it IS versioned -- see the .gitignore
comment next to the `!scripts/verify-mcp-flow.py` exception for why.

Steps:
    1. Connect (MCP initialize handshake).
    2. tools/list -- prints every visible tool, grouped by inferred service
       prefix. What's visible reflects entitlement filtering: a principal
       only sees tools for services its Keycloak groups grant a permission
       for (see docs/architecture.md's Authorization subsystem).
    3. (optional, --call) tools/call one real tool against a real service.

Usage:
    # Read the token with -s so it never lands in shell history or a file.
    read -s -p "Bearer token: " MCP_BEARER_TOKEN
    export MCP_BEARER_TOKEN
    pixi run -e dev python scripts/verify-mcp-flow.py
    pixi run -e dev python scripts/verify-mcp-flow.py \\
        --call rucio_whoami --args-json '{}'

    # Local dev-bypass broker (see docs/local-development.md) -- no token
    # needed; BROKER_DEV_INSECURE_PRINCIPAL short-circuits identity checks
    # broker-side regardless of what the client sends.
    pixi run -e bypass broker  # separate terminal
    pixi run -e dev python scripts/verify-mcp-flow.py --local

Never pass the bearer token as a --flag: it would land in shell history and
in `ps` output for the duration of the process. MCP_BEARER_TOKEN is read
from the environment only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import McpError

DEFAULT_BROKER_URL = "https://mcp.af.uchicago.edu"
LOCAL_BROKER_URL = "http://localhost:8080"
TOKEN_ENV_VAR = "MCP_BEARER_TOKEN"

# Friendly, ToolError-message-substring -> extra hint printed under a FAIL.
# Mirrors the exact strings af_mcp_broker.mcp.aggregator's _make_client_factory
# and mcp.middleware.authorization_mw raise, so the hint only fires for the
# error path it actually names.
_HINTS: dict[str, str] = {
    "not linked": (
        "The credential provider for this service has no linked account "
        "for you yet. Visit the portal's Identities page and click "
        "'Link', then re-run this script."
    ),
    "Credential unlock required": (
        "Your x509/VOMS proxy needs a passphrase unlock. Visit the portal "
        "URL in the error above."
    ),
    "Authorization denied": (
        "Your Keycloak groups don't grant the permission this service "
        "requires. Check `GET /v1/permissions` for what you currently have."
    ),
    "requires an x509/VOMS proxy, which needs a POSIX": (
        "x509 services are callable via /mcp (issue #112), but this "
        "account has no POSIX/grid identity for the legacy ephemeral-Job "
        "mint path. If a voms-token-service identity_providers entry "
        "covers this service, that path doesn't need POSIX at all -- see "
        "docs/x509-deployment-notes.md. Otherwise contact your Analysis "
        "Facility operator to request a grid identity."
    ),
    "No service registered for tool": (
        "The tool name doesn't match any configured service's prefix. "
        "Check the exact name printed by the tools/list step above."
    ),
}


def _print_step(n: int, total: int, label: str) -> None:
    print(f"\n[{n}/{total}] {label}")


def _print_result(ok: bool, message: str) -> None:
    status = "PASS" if ok else "FAIL"
    print(f"  {status}: {message}")


def _hint_for(error_text: str) -> str | None:
    for substring, hint in _HINTS.items():
        if substring in error_text:
            return hint
    return None


def _group_tools_by_service(tool_names: list[str]) -> dict[str, list[str]]:
    """Groups tool names by inferred service prefix (the segment before the
    first underscore). This is a display heuristic, not authoritative: it
    works because every service in services.yaml either namespaces its
    tools as "<prefix>_<name>" or (like rucio-mcp) already self-prefixes
    the same way -- see ServiceSpec.apply_namespace in mcp/registry.py.
    """
    grouped: dict[str, list[str]] = {}
    for name in tool_names:
        prefix = name.split("_", 1)[0] if "_" in name else name
        grouped.setdefault(prefix, []).append(name)
    return grouped


async def run(args: argparse.Namespace) -> bool:
    total_steps = 3 if args.call else 2
    mcp_url = f"{args.broker_url.rstrip('/')}/mcp/"

    headers: dict[str, str] = {}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    client = Client(StreamableHttpTransport(mcp_url, headers=headers))

    _print_step(1, total_steps, f"Connecting to {mcp_url} (MCP initialize)")
    try:
        await client.__aenter__()
    except Exception as exc:  # noqa: BLE001 - report whatever the transport raises
        _print_result(False, f"{type(exc).__name__}: {exc}")
        return False
    _print_result(True, "connected")

    try:
        _print_step(2, total_steps, "tools/list")
        try:
            tools = await client.list_tools()
        except Exception as exc:  # noqa: BLE001
            _print_result(False, f"{type(exc).__name__}: {exc}")
            return False

        tool_names = sorted(t.name for t in tools)
        grouped = _group_tools_by_service(tool_names)
        _print_result(
            True, f"{len(tool_names)} tool(s) across {len(grouped)} service(s)"
        )
        for prefix in sorted(grouped):
            print(f"    {prefix}:")
            for name in grouped[prefix]:
                print(f"      - {name}")

        if not args.call:
            return True

        call_args: dict[str, Any] = json.loads(args.args_json)
        _print_step(3, total_steps, f"tools/call {args.call} {call_args!r}")
        try:
            result = await client.call_tool(args.call, call_args)
        except (ToolError, McpError) as exc:
            error_text = str(exc)
            _print_result(False, f"{type(exc).__name__}: {error_text}")
            hint = _hint_for(error_text)
            if hint:
                print(f"    hint: {hint}")
            return False
        except Exception as exc:  # noqa: BLE001
            _print_result(False, f"{type(exc).__name__}: {exc}")
            return False

        _print_result(True, f"result: {result.data!r}")
        return True
    finally:
        await client.__aexit__(None, None, None)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--broker-url",
        default=None,
        help=(
            "Broker base URL (default: "
            f"{DEFAULT_BROKER_URL}, or {LOCAL_BROKER_URL} with --local)."
        ),
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help=(
            "Target a local broker running the dev-bypass workflow "
            "(see docs/local-development.md, `pixi run -e bypass broker`). "
            f"Changes the default broker URL to {LOCAL_BROKER_URL} and does "
            "not require MCP_BEARER_TOKEN -- the bypass ignores whatever "
            "Authorization header the client sends."
        ),
    )
    parser.add_argument(
        "--call",
        metavar="TOOL_NAME",
        default=None,
        help="Invoke one real tool (e.g. rucio_whoami) after listing tools.",
    )
    parser.add_argument(
        "--args-json",
        default="{}",
        help="JSON object of arguments for --call (default: '{}').",
    )
    args = parser.parse_args(argv)

    args.broker_url = args.broker_url or (
        LOCAL_BROKER_URL if args.local else DEFAULT_BROKER_URL
    )

    try:
        json.loads(args.args_json)
    except json.JSONDecodeError as exc:
        parser.error(f"--args-json is not valid JSON: {exc}")

    args.token = os.environ.get(TOKEN_ENV_VAR)
    if not args.token and not args.local:
        parser.error(
            f"{TOKEN_ENV_VAR} is not set. Read a real AF Keycloak bearer "
            "token without it touching disk or shell history, e.g.:\n\n"
            f"    read -s -p 'Bearer token: ' {TOKEN_ENV_VAR}\n"
            f"    export {TOKEN_ENV_VAR}\n\n"
            "or pass --local to target a dev-bypass broker instead."
        )

    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ok = asyncio.run(run(args))
    print(f"\n{'PASS' if ok else 'FAIL'}: verify-mcp-flow.py")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

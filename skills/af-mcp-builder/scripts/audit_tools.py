#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["fastmcp>=4.0.4,<5", "jsonschema>=4"]
# ///
"""Audit a running MCP server's tools against the AF MCP design guide.

Connects with an MCP client, lists the tools, and reports the checklist items
that can be read off the wire. Item IDs match references/mcp-design.md.
Items that need the source or the deployment (E3, B2, X1, U1, U2, U4, U5,
P2-P5) are not checked here.

Usage:
    # Streamable HTTP server; token read from the environment, never argv
    export MCP_BEARER_TOKEN=...
    uv run audit_tools.py --url http://localhost:8000/mcp --prefix rucio

    # stdio server
    uv run audit_tools.py --stdio "python -m my_server" --prefix my

    # Also exercise one tool with an input that must fail (E1, E2)
    uv run audit_tools.py --url ... --call my_get_thing \\
        --args-json '{"id": "does-not-exist"}' --expect-error

    # Check that a bad bearer gets HTTP 401 (X2)
    uv run audit_tools.py --url ... --check-401

Exit status is 1 when any MUST finding is reported, 0 otherwise.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shlex
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

import jsonschema
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
SUMMARY_MAX_CHARS = 120
LISTING_VERBS = ("list_", "search_", "query_", "find_", "get_all")
LIMIT_PARAMS = {
    "limit",
    "max_results",
    "page_size",
    "cursor",
    "offset",
    "top",
    "max",
    "count",
    "n",
}
SECRET_PARAM_RE = re.compile(
    r"(password|passwd|secret|token|proxy|private_key|api_key|credential)", re.I
)
WRITE_HINTS = ("destructiveHint", "idempotentHint", "openWorldHint")


@dataclass(frozen=True)
class Finding:
    """One audit result row."""

    item: str
    level: str
    tool: str
    message: str


def _field(obj: Any, snake: str, camel: str) -> Any:
    """Read a tool field under either SDK naming (fastmcp 4 snake_case, older camelCase)."""
    value = getattr(obj, snake, None)
    return value if value is not None else getattr(obj, camel, None)


def _strip_prefix(name: str, prefix: str | None) -> str:
    """Return the tool name without its service prefix."""
    if prefix and name.startswith(f"{prefix}_"):
        return name[len(prefix) + 1 :]
    return name


def audit_tool(tool: Any, prefix: str | None) -> list[Finding]:
    """Check one listed tool against the wire-visible guide items."""
    out: list[Finding] = []
    name = tool.name

    def add(item: str, level: str, message: str) -> None:
        out.append(Finding(item, level, name, message))

    # N1: name shape and prefix
    if not NAME_RE.match(name):
        add("N1", "MUST", "name has characters outside A-Za-z0-9_.- or is too long")
    if prefix and not name.startswith(f"{prefix}_"):
        add("N1", "MUST", f"name does not start with the prefix '{prefix}_' (P1)")

    # N2/N3: description
    desc = (tool.description or "").strip()
    first = desc.splitlines()[0].strip() if desc else ""
    if not first:
        add("N2", "MUST", "no description")
    else:
        if len(first) > SUMMARY_MAX_CHARS:
            add(
                "N2",
                "MUST",
                f"first line is {len(first)} chars; lead with a one-line summary "
                f"of at most {SUMMARY_MAX_CHARS}",
            )
        if first.lower().replace(" ", "_").rstrip(".") == name.lower():
            add("N2", "MUST", "first line only restates the tool name")

    schema = _field(tool, "input_schema", "inputSchema") or {}
    props = schema.get("properties") or {}
    if first and len(desc.splitlines()) == 1 and len(props) > 2:
        add("N3", "SHOULD", f"one-line description for a tool with {len(props)} arguments")

    # S1: input schema
    if schema.get("type") != "object":
        add("S1", "MUST", "inputSchema is not a JSON object schema")
    for pname, pschema in props.items():
        if not (pschema.get("description") or "").strip():
            add("S1", "MUST", f"argument '{pname}' has no description")
        if SECRET_PARAM_RE.search(pname):
            add("U3", "MUST", f"argument '{pname}' looks like a credential (heuristic)")

    # O1: output schema
    out_schema = _field(tool, "output_schema", "outputSchema")
    if not out_schema:
        add("O1", "MUST", "no outputSchema")
    elif out_schema.get("type") != "object":
        add("O1", "MUST", "outputSchema is not a JSON object schema")

    # A1/A2: annotations
    ann = getattr(tool, "annotations", None)
    ann_d = ann.model_dump(by_alias=True, exclude_none=True) if ann is not None else {}
    if "readOnlyHint" not in ann_d:
        add("A1", "MUST", "readOnlyHint is not set")
    elif ann_d["readOnlyHint"] is False:
        missing = [h for h in WRITE_HINTS if h not in ann_d]
        if missing:
            add("A2", "SHOULD", f"write tool does not set {', '.join(missing)}")
    elif ann_d["readOnlyHint"] is True and (
        "destructiveHint" in ann_d or "idempotentHint" in ann_d
    ):
        add("A1", "SHOULD", "destructive/idempotent hint set on a read-only tool")

    # B1: listings need a bound
    bare = _strip_prefix(name, prefix)
    if bare.startswith(LISTING_VERBS):
        limit_names = [p for p in props if p in LIMIT_PARAMS]
        if not limit_names:
            add("B1", "MUST", "listing/search tool has no limit-like argument (heuristic)")
        else:
            for p in limit_names:
                if props[p].get("type") in ("integer", "number") and "maximum" not in props[p]:
                    add("B1", "SHOULD", f"argument '{p}' has no maximum in the schema")
    return out


def _result_text(result: Any) -> str:
    """Join the text blocks of a call result."""
    return "\n".join(
        getattr(block, "text", "") for block in (result.content or []) if getattr(block, "text", None)
    )


def audit_call(
    tool: Any, result: Any, *, expect_error: bool, max_bytes: int
) -> list[Finding]:
    """Check the result of one real call (E1, E2, O1, O2, B1)."""
    out: list[Finding] = []
    name = tool.name
    text = _result_text(result)
    size = len(text.encode()) + len(json.dumps(result.structured_content or {}).encode())

    if size > max_bytes:
        out.append(Finding("B1", "MUST", name, f"result is {size} bytes (limit {max_bytes})"))
    if expect_error:
        if not result.is_error:
            out.append(Finding("E1", "MUST", name, "failing input did not set isError"))
        elif not text.strip():
            out.append(Finding("E2", "MUST", name, "error result has no text"))
        elif re.search(r"Traceback \(most recent call last\)|goroutine \d+ \[", text):
            out.append(Finding("E2", "MUST", name, "error text contains a stack trace"))
        return out
    if result.is_error:
        out.append(Finding("E1", "SHOULD", name, f"call returned isError: {text[:120]!r}"))
        return out
    out_schema = _field(tool, "output_schema", "outputSchema")
    if out_schema:
        if result.structured_content is None:
            out.append(Finding("O1", "MUST", name, "outputSchema declared but no structuredContent"))
        else:
            try:
                jsonschema.validate(result.structured_content, out_schema)
            except jsonschema.ValidationError as exc:
                out.append(Finding("O1", "MUST", name, f"structuredContent invalid: {exc.message}"))
    if result.structured_content is not None and text.strip():
        try:
            if json.loads(text) == result.structured_content:
                out.append(Finding("O2", "SHOULD", name, "text block is a JSON dump of structuredContent"))
        except ValueError:
            pass
    return out


def check_401(url: str) -> list[Finding]:
    """POST a bare tools/list with an invalid bearer; expect HTTP 401 (X2)."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()
    req = urllib.request.Request(  # noqa: S310 - URL is operator-supplied
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer invalid-audit-token",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    if status != 401:
        return [Finding("X2", "MUST", "(transport)", f"bad bearer got HTTP {status}, expected 401")]
    return []


def render(findings: list[Finding], n_tools: int) -> str:
    """Render the findings table in the skill's output format."""
    lines = [f"Audited {n_tools} tools.", ""]
    if not findings:
        return "\n".join([*lines, "No findings."])
    lines += ["| Item | Level | Tool | Finding |", "|------|-------|------|---------|"]
    order = {"MUST": 0, "SHOULD": 1}
    for f in sorted(findings, key=lambda f: (order[f.level], f.item, f.tool)):
        lines.append(f"| {f.item} | {f.level} | `{f.tool}` | {f.message} |")
    must = sum(f.level == "MUST" for f in findings)
    lines += ["", f"{must} MUST, {len(findings) - must} SHOULD."]
    return "\n".join(lines)


def _transport(args: argparse.Namespace) -> Any:
    """Build the client transport from the CLI arguments."""
    if args.stdio:
        parts = shlex.split(args.stdio)
        return StdioTransport(command=parts[0], args=parts[1:])
    return args.url


async def run(args: argparse.Namespace) -> tuple[int, list[Finding]]:
    """Connect, list tools, audit, and optionally call one tool."""
    token = os.environ.get(args.token_env)
    auth = token if (args.url and token) else None
    findings: list[Finding] = []
    async with Client(_transport(args), auth=auth) as client:
        tools = await client.list_tools()
        for tool in tools:
            findings += audit_tool(tool, args.prefix)
        if args.call:
            by_name = {t.name: t for t in tools}
            if args.call not in by_name:
                sys.exit(f"--call: no tool named {args.call!r}")
            result = await client.call_tool(
                args.call, json.loads(args.args_json), raise_on_error=False
            )
            findings += audit_call(
                by_name[args.call], result, expect_error=args.expect_error, max_bytes=args.max_bytes
            )
    if args.check_401 and args.url:
        findings += check_401(args.url)
    return len(tools), findings


def main() -> None:
    """CLI entry point."""
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--url", help="streamable HTTP endpoint, e.g. http://localhost:8000/mcp")
    target.add_argument("--stdio", help="command that starts a stdio server")
    p.add_argument("--prefix", help="service prefix every tool name must carry (N1/P1)")
    p.add_argument(
        "--token-env",
        default="MCP_BEARER_TOKEN",
        help="environment variable holding a bearer token (never pass a token as an argument)",
    )
    p.add_argument("--call", help="also call this tool once")
    p.add_argument("--args-json", default="{}", help="JSON arguments for --call")
    p.add_argument("--expect-error", action="store_true", help="the --call input must fail")
    p.add_argument("--max-bytes", type=int, default=50_000, help="result size ceiling for --call")
    p.add_argument("--check-401", action="store_true", help="check a bad bearer gets HTTP 401 (needs --url)")
    args = p.parse_args()

    n_tools, findings = asyncio.run(run(args))
    print(render(findings, n_tools))
    sys.exit(1 if any(f.level == "MUST" for f in findings) else 0)


if __name__ == "__main__":
    main()

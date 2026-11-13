---
name: af-mcp-builder
license: MIT
description: Audit, review or onboard an MCP server for the AF MCP platform (the credential-brokering MCP gateway at maniaclab/af-mcp-platform). Use when someone is building a new MCP server for the analysis facility, reviewing an existing one (Python fastmcp or mcp SDK, Go mcp-go or golang-htcondor style), or asking what must change for a backend to sit behind the gateway. Checks tool naming and descriptions, input and output schemas, annotations, isError and error text, pagination and output size, stateless HTTP, broker identity token handling, and the services.yaml fields (prefix, agent_policy, trust_tier, exclude_tools).
---

# AF MCP Builder

Audit an MCP server's codebase against the AF MCP design guide and report what
must change for the server to fit the platform. The platform adds nothing
special: a backend fits if it follows the MCP specification plus the
conventions in the guide.

The rules live in [references/mcp-design.md](references/mcp-design.md). Read it
before auditing; every finding cites an item ID from it (N1, S1, O1, A1, E1, ...)
and its MUST or SHOULD level. Do not restate or reinterpret the rules here or in
the report. The guide pins MCP spec revision 2026-07-28.

## Procedure

1. **Identify the server.** Language (Python or Go), SDK, transport (stdio,
   streamable HTTP), and the service prefix it will be registered under. Ask the
   user for the prefix if the code does not make it obvious; N1 and P1 depend on
   it.
2. **Locate the tools.** See [references/locating-tools.md](references/locating-tools.md)
   for the registration patterns in each SDK. Produce the full list of tool names
   with `file:line` before checking anything. If the list from the source and the
   list from the running server (step 3) differ, report the difference.
3. **Run the mechanical audit** when the server can be started. It reads the
   wire-visible items and is faster and more reliable than reading:

   ```bash
   # HTTP server; the token is read from $MCP_BEARER_TOKEN, never passed as an argument
   uv run scripts/audit_tools.py --url http://localhost:8000/mcp --prefix <prefix> --check-401

   # stdio server
   uv run scripts/audit_tools.py --stdio "<command that starts it>" --prefix <prefix>

   # one real call with an input that must fail, for E1 and E2
   uv run scripts/audit_tools.py --url ... --prefix <prefix> \
       --call <tool> --args-json '{"id": "does-not-exist"}' --expect-error
   ```

   `uv run` reads the script's inline dependencies (`fastmcp>=4.0.4,<5`,
   `jsonschema`). With pixi, use `pixi exec --spec "fastmcp>=4.0.4,<5" --spec jsonschema python scripts/audit_tools.py ...`.
   Exit status: 1 when any MUST finding is reported, 0 when there are none, 2
   when the audit could not run (cannot connect, unknown `--call` tool); on 2,
   fix the connection and rerun rather than reporting a finding.
   Only call tools that are read-only (check `readOnlyHint`) with `--call`; do not
   call a write tool against a real backend to test E1.

   The script covers N1, N2, N3, S1, O1, A1, A2, B1 (as a heuristic), U3 (as a
   heuristic), and with the flags above E1, E2, O1 (payload validation), O2, B1
   (size) and X2. Treat its heuristic rows as leads and confirm them in the
   source. If the server cannot be started (missing credentials, a facility-only
   dependency), say so in the report and do those items by reading.
4. **Read the source for what the wire cannot show.** For each item below, find
   the code and decide; do not infer from the absence of a grep hit.

   | Items | Where to look |
   |-------|---------------|
   | E1, E2, E4 | The error path of each tool: does a failure return a tool-error result or raise the SDK's tool-error exception, or return a string? Do empty and error results name a next step? Is a JSON-RPC error used for a domain failure? |
   | E3 | The downstream client calls: is a connection failure classified and hinted? Is a retry bounded, and limited to idempotent tools? |
   | B1, B2 | Listing and search tools: default and maximum limit, a truncation note, a cursor. Long calls: progress notifications, cancellation, a handle for work that outlives the call. |
   | X1, X2 | How the HTTP app is built: stateless option, module-level state keyed by session or connection. The auth verifier: does it run at the transport and answer 401? |
   | U1, U2, U5 | Token verification: JWKS source, `iss`, `exp`, and an exact `aud` check; any use of groups or permissions claims; any second way in (shared secret, a PAT) enabled in the deployment. |
   | U3, U4 | Tool arguments and results for credentials; where the server gets a proxy or ticket (the broker's redeem routes, or something else). |
   | P1 to P5 | The server's name handling (`apply_namespace`), and the service's `services.yaml` entry if the user has it: `agent_policy`, `trust_tier`, `exclude_tools`, a read-only mode. |
5. **Report** in the format below. Fix nothing unless the user asks; findings
   come first.

## Report format

Start with one line: server, language and SDK, how many tools, which spec
revision, and what was and was not run (mechanical audit yes or no, why).

Then one table, MUST rows first, ordered by item ID:

| Item | Level | Location | Finding | Suggested change |
|------|-------|----------|---------|------------------|
| A1 | MUST | `src/server/tools/jobs.py:42` (`my_submit_job`) | `readOnlyHint` not set | Add `ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)` |
| S1 | MUST | `src/server/tools/jobs.py:57` | argument `queue` has no description | Add `Field(description="Queue name, e.g. 'short'")` |

Rules for the table:

- One row per distinct problem. When the same problem affects many tools, give
  one row with the count and the first location, and list the tool names under
  the table.
- `Location` is `file:line` for source findings and the tool name for findings
  read off the wire. A finding without a location is a finding you did not check.
- `Suggested change` is concrete: the code or the setting, in the server's own
  SDK. Quote the guide's rule by ID rather than copying it.
- After the table, list the items that passed, as a line of IDs, and the items
  you could not check with the reason.
- Mark an item **Not exercised by the platform** when the guide says so (B2
  cancellation). Do not report it as a failure.
- Do not file issues or open pull requests on the audited repository unless the
  user asks.

## Things that look like findings and are not

- A `readOnlyHint` that disagrees with the platform's `policy.yaml` is a lint
  row on the gateway's admin page, not a protocol failure. Report it as a
  question for the operator.
- Tools returning a curated text block that is not the JSON dump of
  `structuredContent` is what the guide asks for (O2), though the spec's
  backwards-compatibility SHOULD says otherwise. Report only the opposite case.
- A listing tool with a limit but no cursor can be fine when the result set is
  small by construction. Say why in the row instead of dropping it.

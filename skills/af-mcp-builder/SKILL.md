---
name: af-mcp-builder
license: MIT
description: Use this skill whenever someone is building, designing, extending, reviewing, auditing or onboarding an MCP server (Python fastmcp or mcp SDK, Go mcp-go or golang-htcondor) that will run behind an AF MCP gateway, the credential-brokering MCP platform from maniaclab/af-mcp-platform, deployed at mcp.af.uchicago.edu or at any other analysis facility. Trigger even when the user never says "audit", and for design questions asked before any code exists. Examples are a new backend or architecture for Rucio, PanDA, AMI, HTCondor, ServiceX or JupyterHub; what a server must change to sit behind the gateway; adding a service to services.yaml (prefix, agent_policy, trust_tier, exclude_tools); or checking tool names, schemas, annotations, error results, pagination, stateless HTTP, 401 handling and broker identity tokens against docs/mcp-design.md or with audit_tools.py. Not for generic MCP questions, servers for other gateways, or code inside af-mcp-platform itself (broker, portal, chart).
---

# AF MCP Builder

Audit an MCP server's codebase against the AF MCP design guide and report what
must change for the server to fit the platform. The platform adds nothing
special: a backend fits if it follows the MCP specification plus the
conventions in the guide.

## The guide

The rules live in one canonical file, `docs/mcp-design.md` in
maniaclab/af-mcp-platform. Read it before auditing; every finding cites an item
ID from it (N1, S1, O1, A1, E1, ...) and its MUST or SHOULD level. Do not
restate or reinterpret the rules in the report. The guide pins MCP spec revision
2026-07-28.

- Inside an af-mcp-platform checkout (`docs/mcp-design.md` exists): read that
  file.
- Anywhere else: fetch
  `https://raw.githubusercontent.com/maniaclab/af-mcp-platform/main/docs/mcp-design.md`
  (WebFetch, or `curl -fsSL`).
- If the fetch fails, say so in the report and audit from the index below. The
  index is a reminder of each rule's headline, not the rule: the guide's
  Why, Verify and In-this-repo parts are not here, and the report must say the
  guide was not read.

### Index of items

MUST items block onboarding. SHOULD items are expected, and a deviation needs a
stated reason.

| ID | Level | Rule |
|----|-------|------|
| G1 | SHOULD | Build a server only for a service assistants need repeatedly, with bounded output and recoverable errors, never one that hands the model a credential |
| N1 | MUST | Tool names are `<prefix>_<verb_noun>`, stable, letters/digits/`_-.`, under 128 characters |
| N2 | MUST | First line of each description is a one-line summary |
| N3 | SHOULD | Description adds arguments, preconditions, domain quirks and the tool to call instead |
| N4 | SHOULD | The tool surface is small enough to choose from; split tools along observed confusion |
| S1 | MUST | `inputSchema` is an object schema, every property described |
| S2 | SHOULD | Enums, bounds and defaults live in the schema, not in prose |
| O1 | MUST | Object `outputSchema`, with matching `structuredContent` |
| O2 | SHOULD | `structuredContent` is the contract; a text block carries the same information (serialized JSON, or a rendering of it) |
| O3 | SHOULD | Curated fields, units converted in the open, duplicates removed, stable identifiers, follow-up tools named |
| A1 | MUST | `readOnlyHint` set on every tool |
| A2 | SHOULD | Write tools also set `destructiveHint`, `idempotentHint`, `openWorldHint` |
| E1 | MUST | Tool failure sets `isError: true` |
| E2 | MUST | Error and empty results name a next step; errors graded by audience, with a stable category |
| E3 | SHOULD | Transient errors are classified and hinted, or retried boundedly (idempotent tools only) |
| E4 | MUST | JSON-RPC errors only for protocol problems |
| B1 | MUST | Every result bounded; listings take a limit and paginate; truncation announced with how to continue; upstream work capped too |
| B2 | SHOULD | Long calls report progress and honour cancellation |
| B3 | SHOULD | Per-caller concurrency or rate bound in front of a shared backend |
| X1 | MUST | Stateless streamable HTTP; no session or per-connection state; per-caller caches keyed by verified identity |
| X2 | MUST | A bad bearer gets HTTP 401 before any tool runs |
| X3 | SHOULD | `tools/list` answered from registration, with no downstream call |
| X4 | SHOULD | Standard transport and auth only; nothing client-specific |
| X5 | SHOULD | Explicit timeouts; downstream endpoints re-resolved after failure; readiness reflects own health |
| U1 | MUST | Authenticate callers with the broker identity token only; never forward the received token |
| U2 | MUST | Check signature, `iss`, `aud` and `exp`; reject any other `aud` |
| U3 | MUST | No credentials in tool arguments, results or errors |
| U4 | MUST | Fetch x509/krb5 credentials from the broker's redeem routes, per call, deleted after; no secrets stored |
| U5 | MUST | Read no permissions or groups from the token |
| U6 | MUST | No tool takes a username or owner; derive it from the verified identity |
| P1 | MUST | Tool names carry the service prefix the registry routes on |
| P2 | SHOULD | The service entry carries an `agent_policy`; facility know-how goes in `instructions` or a skill |
| P3 | MUST | The service entry declares `trust_tier` |
| P4 | SHOULD | Infrastructure-facing tools are in `exclude_tools` |
| P5 | SHOULD | A server with write tools can be started read-only |
| I1 | SHOULD | Wrap the native client library; parse artifacts, never CLI prose |
| T1 | SHOULD | Descriptions, examples, caps and error strings are tested against the real service |

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
   uv run scripts/audit_tools.py --url http://localhost:8000/mcp --prefix <prefix> \
       --check-401 --check-stateless

   # stdio server
   uv run scripts/audit_tools.py --stdio "<command that starts it>" --prefix <prefix>

   # one real call with an input that must fail, for E1 and E2
   uv run scripts/audit_tools.py --url ... --prefix <prefix> \
       --call <tool> --args-json '{"id": "does-not-exist"}' --expect-error

   # one real call that succeeds, for O1, O2, O3, U3 and the result size
   uv run scripts/audit_tools.py --url ... --prefix <prefix> \
       --call <tool> --args-json '{"id": "a-real-id"}'
   ```

   `uv run` reads the script's inline dependencies (`fastmcp>=4.0.4,<5`,
   `jsonschema`). With pixi, use `pixi exec --spec "fastmcp>=4.0.4,<5" --spec jsonschema python scripts/audit_tools.py ...`.
   Exit status: 1 when any MUST finding is reported, 0 when there are none, 2
   when the audit could not run (cannot connect, unknown `--call` tool); on 2,
   fix the connection and rerun rather than reporting a finding.
   Only call tools that are read-only (check `readOnlyHint`) with `--call`; do not
   call a write tool against a real backend to test E1.

   The script covers N1, N2, N3, N4, S1, O1, A1, A2, B1 (as a heuristic), U3 and
   U6 (as heuristics), and with the flags above E1, E2, O1 (payload validation),
   O2, O3, U3 (results), B1 (size), X1 and X2. Treat its heuristic rows as leads
   and confirm them in the source. If the server cannot be started (missing
   credentials, a facility-only dependency), say so in the report and do those
   items by reading.
4. **Read the source for what the wire cannot show.** For each item below, find
   the code and decide; do not infer from the absence of a grep hit.

   | Items | Where to look |
   |-------|---------------|
   | E1, E2, E4 | The error path of each tool: does a failure return a tool-error result or raise the SDK's tool-error exception, or return a string? Do empty and error results name a next step? Is a JSON-RPC error used for a domain failure? |
   | E3, X5 | The downstream client calls: is a connection failure classified and hinted? Is a retry bounded, and limited to idempotent tools? Is every call timed, and is an address resolved once at startup and pinned? |
   | B1, B2, B3 | Listing and search tools: default and maximum limit, a truncation note, a cursor, whether the upstream iterator is paged or fully fetched. Long calls: progress, cancellation, a handle. Shared backends: a per-caller limit. |
   | X1, X2, X3 | How the HTTP app is built: stateless option, module-level state keyed by session or connection, caches keyed by identity. The auth verifier: does it run at the transport and answer 401? Does `tools/list` call downstream? |
   | U1, U2, U5 | Token verification: JWKS source, `iss`, `exp`, and an exact `aud` check; any use of groups or permissions claims; any second way in; any outbound call that forwards the incoming `Authorization` header. |
   | U3, U4, U6 | Tool arguments and results for credentials and for owner or username parameters; where the server gets a proxy or ticket (the broker's redeem routes, or something else); whether the temporary file is deleted on failure too. |
   | N3, N4, O3, I1, T1 | Descriptions for domain quirks and examples that were never run; the tool count and UI-only tools; raw backend rows and unconverted units; `subprocess` output parsed as text; tests that run against a real service. |
   | P1 to P5, X4 | The server's name handling (`apply_namespace`), and the service's `services.yaml` entry if the user has it: `agent_policy`, `trust_tier`, `exclude_tools`, a read-only mode. Client-specific behaviour. |
5. **Report** in the format below. Fix nothing unless the user asks; findings
   come first.

## Report format

Start with one line: server, language and SDK, how many tools, which spec
revision, which copy of the guide was read (local file, fetched, or none), and
what was and was not run (mechanical audit yes or no, why).

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
- A table row is a violation you saw, in the source or on the wire. A lead you
  could not confirm (identity wiring that lives in a library you cannot read, an
  item only the mechanical audit can settle) is not a MUST row, even for a MUST
  item: list it after the table under "Needs confirmation" with the item ID and
  what would settle it. MUST items block onboarding, so a MUST row you cannot
  stand behind sends the user chasing a problem that may not exist.
- After the table, list the items that passed, as a line of IDs, and the items
  you could not check with the reason.
- Mark an item **Not exercised by the platform** when the guide says so (B2
  cancellation). Do not report it as a failure.
- Do not file issues or open pull requests on the audited repository unless the
  user asks.

## When a backend misbehaves behind the gateway

Use this when the server works on its own but fails or looks wrong through the
broker. Start from the symptom, run the matching check, and report what you find
in the usual table with the item ID. Gateway-side state (the drift page,
`af_list_mcp_servers`) belongs to the operator, so ask the user for its output
instead of assuming it. Every flag below is an `audit_tools.py` flag from step 3.

| Symptom | Items to check | Run |
|---------|----------------|-----|
| 401 or 403 through the gateway, fine locally | **U2**: the token's `aud` must equal the service's `audience` in `services.yaml`, which defaults to `name` (renaming a service without setting `audience` 401'd every backend). **U1**: accept only the broker identity token, verified against the broker's `/.well-known/jwks.json` by `kid`, with `iss` and `exp` checked (it lives 600 s by default). **X2**: a bad bearer must be a transport 401, not a tool error inside a 200, or the broker never learns an `oauth21-direct` token was revoked. | `--check-401`. Then, with a real broker token in `$MCP_BEARER_TOKEN`, a plain run; a validly signed token with another `aud` must also be refused (U2). |
| A tool is missing from `tools/list` | **N1/P1**: a name without the registered prefix is unroutable and hidden while the backend looks healthy. With the default `apply_namespace: true` the aggregator adds the prefix, so the backend advertises bare names; with `false` it must advertise `<prefix>_<tool>`. **P4**: `exclude_tools` and per-tool `required_permission` keys are native, pre-namespace names. For a credentialed service (`bearer`, `x509`, `krb5`, `servicex`) a caller who has not linked the credential is not listed at all: `af_list_mcp_servers` shows `link_state`, `af_link_identity` fixes it. Operator: `GET /v1/admin/tool-mapping-drift` (portal Admin page) lists unroutable names, and the service reads `misconfigured` when none route. | `--prefix <prefix>`, then compare its tool list with the one the user sees. |
| "Session terminated", 404s across replicas, or a hang | **X1**: the stateful default breaks when consecutive calls reach different replicas, so serve stateless. **X5**: every downstream call needs an explicit timeout, and a downstream address resolved once at startup stops working after the downstream restarts. | `--check-stateless`. Read the downstream calls for timeouts. |
| A result is unparseable or empty | **O1**: an object `outputSchema` with matching `structuredContent`. **O2**: a text block with the same information. **O3**: curated fields, not raw backend rows. **E2**: an empty result names a next step. | `--call <read-only tool> --args-json '...'` (payload validation against the schema, O2, O3). |
| Huge outputs or timeouts | **B1**: `limit` with a default and a maximum enforced in code, truncation announced, the upstream paged. **B3**: a per-caller concurrency bound in front of a shared backend. **X5**: timeouts. | `--call <listing tool>`, which checks the result size against `--max-bytes`. |

If none of the checks explains it, say so and list what you could not observe;
do not guess at gateway internals.

## Things that look like findings and are not

- A `readOnlyHint` that disagrees with the platform's `policy.yaml` is a lint
  row on the gateway's admin page, not a protocol failure. Report it as a
  question for the operator.
- A text block that is exactly the JSON of `structuredContent` is what the SDKs
  produce and what the spec asks for (O2); a curated text block beside the full
  `structuredContent` is also fine. Report only `structuredContent` with no text,
  or text that drops data the structure has.
- A listing tool with a limit but no cursor can be fine when the result set is
  small by construction. Say why in the row instead of dropping it.
- A `user`-like parameter that names a resource (a Rucio `account` on a read),
  not the caller, is a case to confirm in the source, not an automatic U6 row.

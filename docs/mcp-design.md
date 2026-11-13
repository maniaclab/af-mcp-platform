# MCP Design Guide

This is the checklist a backend MCP server is held to before it sits behind
the AF MCP platform. The platform does nothing special for a backend: a server
fits if it follows the MCP specification and the conventions below. The broker
forwards what the backend advertises verbatim, so the quality of every tool
description, schema and error message is set at the source, and every agent
that calls the tool pays for a gap there.

The same checklist is available as an installable agent skill,
`af-mcp-builder`, which audits an MCP codebase against it and reports what has
to change. See [Auditing with the skill](#auditing-with-the-skill). Wiring a
server into a deployment (the `services.yaml` side) is a separate, config-only
procedure covered by [Adding a Service](adding-a-service.md).

## Spec revision

The guide is written against MCP specification revision **2026-07-28**
([specification](https://modelcontextprotocol.io/specification/2026-07-28)).
That is the latest protocol version of the `mcp` SDK the broker pins
(`mcp` 2.2.0 via `fastmcp>=4.0.4,<5` in `pixi.toml`; `mcp.types.LATEST_PROTOCOL_VERSION`
is `2026-07-28`). Section links below point at that revision. Where a rule
exists only because of this platform and not the spec, the item says so.

## How to read the checklist

Each item has an ID, a level, and four parts.

- **MUST** items are required for a backend to be onboarded. A server that
  fails one either breaks callers, breaks the broker's routing or audit, or
  weakens the credential boundary.
- **SHOULD** items are expected. A deviation needs a stated reason in the
  server's own documentation.
- **Rule** is the requirement. **Why** is the agent-facing cost of skipping it.
  **Verify** is how to check it, mechanically where possible. **Spec** links the
  specification section, or says the item is platform-specific. **In this
  repo** gives the file or setting that implements or documents the rule.
- Anything the specification defines that the platform does not yet exercise
  is marked **Not exercised by the platform**.

| ID | Level | Rule |
|----|-------|------|
| [N1](#n1-tool-names-are-prefixed-stable-verb_noun-identifiers) | MUST | Tool names are `<prefix>_<verb_noun>`, stable, in the spec's character set |
| [N2](#n2-the-first-line-of-a-description-is-a-one-line-summary) | MUST | First line of each description is a one-line summary |
| [N3](#n3-descriptions-say-when-to-call-the-tool-and-what-it-needs) | SHOULD | Description adds arguments, caveats and when to call it |
| [S1](#s1-every-tool-has-an-object-inputschema-with-described-properties) | MUST | `inputSchema` is an object schema, every property described |
| [S2](#s2-constrain-arguments-in-the-schema-not-in-prose) | SHOULD | Types, enums, bounds and defaults live in the schema |
| [O1](#o1-declare-an-object-outputschema-and-return-structuredcontent) | MUST | Object `outputSchema`, with matching `structuredContent` |
| [O2](#o2-keep-curated-text-alongside-structuredcontent) | SHOULD | Readable text content alongside the structured payload |
| [A1](#a1-declare-annotations-on-every-tool) | MUST | `readOnlyHint` set on every tool |
| [A2](#a2-state-destructive-idempotent-and-open-world-hints-for-writes) | SHOULD | Writes also state `destructiveHint`, `idempotentHint`, `openWorldHint` |
| [E1](#e1-report-tool-failures-with-iserror-true) | MUST | Tool failure sets `isError: true` |
| [E2](#e2-error-and-empty-results-name-the-next-step) | MUST | Error and empty results name a next step |
| [E3](#e3-classify-transient-errors-and-hint-at-a-retry) | SHOULD | Transient errors are classified and hinted, or retried boundedly |
| [E4](#e4-use-protocol-errors-only-for-protocol-problems) | MUST | JSON-RPC errors only for protocol problems |
| [B1](#b1-bound-every-result-and-paginate-listings) | MUST | Every result is bounded; listings take a limit and paginate |
| [B2](#b2-report-progress-and-honour-cancellation-on-long-calls) | SHOULD | Long calls report progress and honour cancellation |
| [X1](#x1-serve-streamable-http-statelessly) | SHOULD | Streamable HTTP, no reliance on per-connection session state |
| [X2](#x2-reject-a-bad-bearer-with-http-401-at-the-transport) | MUST | A bad bearer gets HTTP 401 before any tool runs |
| [U1](#u1-trust-only-the-broker-identity-token) | MUST | Authenticate callers with the broker identity token only |
| [U2](#u2-validate-signature-issuer-audience-and-expiry) | MUST | Check signature, `iss`, `aud` and `exp`; reject any other `aud` |
| [U3](#u3-never-accept-raw-user-credentials-as-tool-arguments) | MUST | No credentials in tool arguments or results |
| [U4](#u4-redeem-credentials-through-the-broker) | MUST | Fetch x509/krb5 credentials from the broker's redeem routes |
| [U5](#u5-take-no-authorization-decision-from-the-token) | MUST | Read no permissions or groups from the token |
| [P1](#p1-the-prefix-rule) | MUST | Tool names carry the service prefix the registry routes on |
| [P2](#p2-write-an-agent_policy-for-the-service) | SHOULD | A service entry carries an `agent_policy` |
| [P3](#p3-declare-a-trust_tier) | MUST | A service entry declares `trust_tier` |
| [P4](#p4-hide-infrastructure-tools-with-exclude_tools) | SHOULD | Infrastructure-facing tools are excluded, not left reachable |
| [P5](#p5-offer-a-read-only-mode) | SHOULD | A server with write tools can be started read-only |

---

## Tools

### N1: Tool names are prefixed, stable `verb_noun` identifiers

**MUST.**

- **Rule.** Name each tool `<prefix>_<verb_noun>` (`rucio_list_dids`,
  `jhub_create_jupyter_server`). Use only letters, digits, `_`, `-` and `.`,
  stay under 128 characters, and treat names as case-sensitive. Do not rename a
  published tool without changing the deployment in the same release.
- **Why.** The broker routes, authorizes and audits a call from the name's
  prefix. A tool without the prefix belongs to no service: callers never see
  it, and the backend still looks healthy. A backend-side rename took every
  tool of a service away from every caller twice (`atlas_opensearch_*` to
  `aos_*`) while the backend answered `tools/list` without error.
- **Verify.** List tools with an MCP client and check every name against
  `^<prefix>_[a-z][a-z0-9_]*$`. The skill's `audit_tools.py --prefix <prefix>`
  does this. On a deployed gateway, `GET /v1/admin/tool-mapping-drift` lists
  unroutable names.
- **Spec.** [Tool names](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool-names)
  (length and character set are SHOULD there; the prefix is a platform rule, see P1).
- **In this repo.** [Adding a Service](adding-a-service.md#apply_namespace-tool-naming)
  covers `apply_namespace` and the drift reporting.

### N2: The first line of a description is a one-line summary

**MUST.**

- **Rule.** Start each tool's `description` with a single line that says what
  the tool does, in the imperative ("Return the caller's own subject, groups,
  and effective permissions."). Put arguments, caveats and when to call it
  below that line.
- **Why.** Clients show the first line in a compact tool list and rank on it.
  Clients that move from loading every schema up front to progressive
  tool search see only summaries. A tool whose first line does not say what it
  does is never picked.
- **Verify.** Mechanical: the first line is non-empty, fits in about 120
  characters, and is not a bare restatement of the tool name. Reading is
  needed to judge whether it says what the tool does.
- **Spec.** The spec defines `description` as "human-readable description of
  functionality" ([Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool)).
  The one-line-first rule is a platform convention.
- **In this repo.** `af_whoami` in `broker/src/af_mcp_broker/mcp/diagnostics.py`
  leads with its summary ahead of its usage notes. maniaclab/af-mcp-platform#216
  recorded the frictions that came from skipping this.

### N3: Descriptions say when to call the tool and what it needs

**SHOULD.**

- **Rule.** After the summary, state each argument's meaning where the
  schema cannot, preconditions (a linked credential, a running server), and
  the tool to call instead when this one is the wrong choice.
- **Why.** An agent that guesses burns a diagnostic call or several.
- **Verify.** Reading. Mechanical proxy: descriptions with a single line and
  more than two parameters are flagged.
- **Spec.** [Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool).
- **In this repo.** rucio-mcp's tools point container DIDs at
  `rucio_list_container_replicas` when a dataset query comes back empty.

### S1: Every tool has an object `inputSchema` with described properties

**MUST.**

- **Rule.** Declare `inputSchema` as a JSON Schema object, even for a tool
  with no arguments (`{"type": "object", "additionalProperties": false}`).
  Give every property a `description`. Mark required properties in `required`.
- **Why.** The schema is what the model fills in. An undescribed property is
  filled by guesswork from its name.
- **Verify.** Mechanical: `type == "object"`, and every property has a
  non-empty `description`. `audit_tools.py` reports each undescribed property.
- **Spec.** [Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool),
  [Tool with no parameters](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool-with-no-parameters).
- **In this repo.** SDK-derived schemas (fastmcp, the `mcp` SDK, mcp-go) take
  descriptions from docstrings, `Field(description=...)` or `WithDescription`.
  Check the generated schema, not the source.

### S2: Constrain arguments in the schema, not in prose

**SHOULD.**

- **Rule.** Use `enum` for closed sets, `minimum`/`maximum` for numeric
  bounds, `default` for optional values, and typed fields instead of free
  strings that carry a format.
- **Why.** The schema is validated before the tool runs. A constraint in prose
  is learned from a failed call.
- **Verify.** Mechanical for the presence of constraints on `limit`-like
  parameters (see B1); the rest by reading.
- **Spec.** [Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool).
- **In this repo.** ami-mcp caps a batch with `_MAX_BATCH_DATASETS = 50`
  (`src/ami_mcp/tools/datasets.py`), a bound the schema could state as
  `maxItems`.

### O1: Declare an object `outputSchema` and return `structuredContent`

**MUST.**

- **Rule.** Give every tool an `outputSchema` that is a JSON *object*
  schema, and return `structuredContent` that validates against it. A tool that
  returns a list wraps it in an object with a named field
  (`ListIdentitiesResult.identities`).
- **Why.** Without it a client cannot type-check a result or compose one
  tool's output into another's input. It parses prose. A bare list gets no
  usable schema, or a synthetic wrapper with a meaningless field name.
- **Verify.** Mechanical: `outputSchema` present with `type == "object"`;
  with `--call`, the result's `structuredContent` validates against it.
- **Spec.** [Output schema](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#output-schema),
  [Structured content](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#structured-content).
- **In this repo.** All five `gateway_service` tools declare one
  (`broker/src/af_mcp_broker/mcp/diagnostics.py`). As of 2026-11-12 all six
  fleet backends (rucio-mcp, ami-mcp, af-jupyterlab-mcp, af-filesystem-mcp,
  servicex-mcp, and condor via golang-htcondor `webapi/mcpserver`) implement
  `outputSchema` (closing audit on maniaclab/af-mcp-platform#216). That audit
  confirmed the mechanism in each repo, not every tool.

### O2: Keep curated text alongside `structuredContent`

**SHOULD.**

- **Rule.** Return readable text content as well as the structured payload,
  and do not let the SDK replace your curated text with a JSON dump of the
  model.
- **Why.** The model reads the text block. Curated markdown (tables, the
  "Next steps" hints of E2) serves it better than a JSON dump of the same
  fields. This departs from the spec's backwards-compatibility SHOULD, which
  asks for the serialized JSON in a text block so that older clients that parse
  it keep working. The platform prefers the curated text; a server that must
  serve such clients returns the JSON text instead.
- **Verify.** With `--call`, compare the text block to the JSON. Identical
  text on a tool that has hints or tables means the curated text was lost.
- **Spec.** [Structured content](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#structured-content)
  (the SHOULD on a serialized-JSON text block).
- **In this repo.** In the Python `mcp` SDK, annotating a tool `-> MyModel`
  yields `outputSchema` and `structuredContent` but renders the text block as the
  raw JSON. The escape hatch is `Annotated[CallToolResult, ResultModel]`:
  return an ordinary `CallToolResult` with your own `TextContent` and
  `structured_content=payload.model_dump(mode="json")`. The SDK still publishes
  `ResultModel`'s schema and validates the payload against it; the annotation
  is metadata, never evaluated as the literal return type. `Context`,
  `CallToolResult`, `TextContent`, `ToolAnnotations` and every model used in a
  return annotation must be runtime imports, never `TYPE_CHECKING`-only: the
  SDK resolves live annotations with `inspect.signature(func, eval_str=True)`,
  and a `TYPE_CHECKING`-only name raises `InvalidSignature` at registration.
  ami-mcp uses this form (`src/ami_mcp/tools/datasets.py`). The `gateway_service`
  tools return plain pydantic models and have no curated text to keep, so they
  are the reference for the schema but not for this pattern.

### A1: Declare annotations on every tool

**MUST.**

- **Rule.** Set `ToolAnnotations` on every tool, with at least
  `readOnlyHint`. Set `readOnlyHint: true` for anything that only reads.
  Leave `destructiveHint` and `idempotentHint` unset on a read-only tool; they
  are meaningful only when `readOnlyHint` is false.
- **Why.** Clients use the hints to decide which tools are safe to call
  speculatively and which need confirmation, without guessing from the name.
- **Verify.** Mechanical: `annotations.readOnlyHint` is present on every
  listed tool. On a deployed gateway, a disagreement between a backend's
  `readOnlyHint` and `policy.yaml`'s action type shows at
  `GET /v1/admin/annotation-mismatches` and in the
  `af_mcp_annotation_policy_mismatches_total` counter.
- **Spec.** [ToolAnnotations](https://modelcontextprotocol.io/specification/2026-07-28/schema#toolannotations).
  The spec treats annotations as untrusted hints from the server.
- **In this repo.** The broker forwards annotations verbatim and lints them
  against `policy.yaml` (maniaclab/af-mcp-platform#238 B.8). A disagreement does
  not block anything: the gateway never takes an authorization decision from a
  backend's annotation, and `required_permission` stays authoritative. The five
  `gateway_service` tools are all read-only, including `af_link_identity`, which
  returns a portal link but mutates nothing. golang-htcondor keeps the table in
  `webapi/mcpserver/annotations.go`. All six backends implement annotations as
  of 2026-11-12.

### A2: State destructive, idempotent and open-world hints for writes

**SHOULD.**

- **Rule.** On a tool with `readOnlyHint: false`, set `destructiveHint`
  (true when it deletes or overwrites), `idempotentHint` (true when a repeat
  with the same arguments has no further effect) and `openWorldHint` (true when
  it reaches outside the server's own system), and set `title` for display.
- **Why.** The spec's defaults for an unset write tool are
  `destructiveHint: true`, `idempotentHint: false`, `openWorldHint: true`, the
  most cautious reading. Stating them lets a client confirm only what needs it.
- **Verify.** Mechanical: every tool with `readOnlyHint` false sets the other
  two explicitly.
- **Spec.** [ToolAnnotations](https://modelcontextprotocol.io/specification/2026-07-28/schema#toolannotations).
- **In this repo.** `title` is set on the `gateway_service` tools
  (`broker/src/af_mcp_broker/mcp/diagnostics.py`).

---

## Errors

### E1: Report tool failures with `isError: true`

**MUST.**

- **Rule.** When a tool call fails, return a result with `isError: true` (or
  raise your SDK's tool-error exception, which does the same). Do not return an
  error-shaped string as ordinary text.
- **Why.** A failure reported only in prose is indistinguishable from success to
  anything that reads the wire result. The broker's audit counted such calls as
  successes until it was fixed (`9034858`); only results with `isError` are
  audited `outcome=error` with `error_class=tool_reported`. A backend that
  adopts this will show a step up in its error rate in dashboards the day it
  ships. That is the fix working.
- **Verify.** Call a tool with an input that must fail (a missing DID, an
  invalid path) and check `isError` on the result. `audit_tools.py --call`
  reports it.
- **Spec.** [Error handling](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#error-handling),
  [CallToolResult.isError](https://modelcontextprotocol.io/specification/2026-07-28/schema#calltoolresult-iserror).
- **In this repo.** `docs/observability.md` describes the audit side. All six
  fleet backends implement `isError` as of 2026-11-12.

### E2: Error and empty results name the next step

**MUST.**

- **Rule.** An empty result or an error says what to do next, naming the
  specific tool or argument when there is one. "No replicas found" is not
  enough: add "if this is a container DID, use `rucio_list_container_replicas`
  instead". Return it as a tool error (E1) with the hint in the message, not as
  raw backend exception text.
- **Why.** The model guesses otherwise, and usually spends a diagnostic call
  or several. This was the root of the frictions in maniaclab/af-mcp-platform#216.
- **Verify.** Reading. Mechanical proxy: with `--call` on a failing input, the
  error text is not empty and does not contain a Python traceback or a Go panic
  trace.
- **Spec.** [Error handling](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#error-handling).
  The "next step" content is a platform convention.
- **In this repo.** rucio-mcp is the model. Several of its empty and error
  results end with a "Next steps" hint. ami-mcp builds the same through
  `append_next_actions` and `format_error` (`src/ami_mcp/tools/_helpers.py`).

### E3: Classify transient errors and hint at a retry

**SHOULD.**

- **Rule.** When a downstream call fails in a way that is likely to succeed on
  a repeat (connection reset, socket closed, connect timeout), say so in the
  error text and tell the caller it is safe to retry. If the tool is idempotent
  (A2), retry boundedly inside the server before failing: a fixed small number
  of attempts with backoff, and no retry of a non-idempotent write.
- **Why.** An agent cannot tell a flapping connection from a real failure
  without that sentence. It either gives up on a recoverable call or retries
  an unrecoverable one.
- **Verify.** Reading, plus a test that injects a connection failure into the
  server's downstream client and checks the result text and `isError`.
- **Spec.** Platform-specific. The spec leaves retry policy to implementations.
- **In this repo.** The broker classifies its own broker-to-backend dial
  failures as `error_class=transient_connection`
  (`broker/src/af_mcp_broker/mcp/errors.py`), scoped to connect failures,
  mid-exchange socket errors and closed connections. An HTTP 5xx or a read
  timeout on an established connection stays `backend_error`. As of 2026-11-12
  only ami-mcp retries transient errors automatically (a bounded retry,
  kratsg/ami-mcp#27). rucio-mcp and servicex-mcp classify the error and hint at
  a retry. filesystem, jupyterlab and condor do neither.

### E4: Use protocol errors only for protocol problems

**MUST.**

- **Rule.** Return a JSON-RPC error for an unknown tool or a malformed request.
  Return a tool result with `isError: true` for everything the tool itself can
  report: a failed lookup, a refused operation, a downstream outage, bad
  argument values that passed schema validation.
- **Why.** The spec's own split is that protocol errors are ones the model is
  unlikely to fix, and tool errors are ones it can act on. A JSON-RPC error for
  a recoverable failure hides the hint (E2) from the model, since clients
  surface it differently.
- **Verify.** Call a tool with a well-formed request that fails for a domain
  reason and confirm the response is a result, not a JSON-RPC `error`.
- **Spec.** [Error handling](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#error-handling).
- **In this repo.** No platform-specific implementation; the broker propagates
  both forms.

---

## Output size and long calls

### B1: Bound every result and paginate listings

**MUST.**

- **Rule.** A tool must have a ceiling on what it returns, whatever the
  caller asked for. A listing or search tool takes a `limit` (with a default
  and a maximum) and, where the result set can exceed it, a cursor or offset,
  and says in the result when it truncated. `tools/list` itself paginates with
  `nextCursor` if the tool count warrants.
- **Why.** Tool output goes into the model's context window, which is the
  real budget, not the server's willingness to send. An unbounded answer
  crowds out the reasoning that was meant to follow it, and the model reads a
  thousand rows no better than fifty. Past a few hundred rows the honest
  answer is a smaller question.
- **Verify.** Mechanical: tools whose names begin `list_`, `search_`,
  `query_` or `get_all` have a `limit`-like parameter (`limit`, `max_results`,
  `page_size`, `cursor`, `offset`). With `--call --max-bytes N`, the result
  size is checked. Reading for the truncation note.
- **Spec.** [Pagination](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination)
  covers `nextCursor` on list operations. A tool result ceiling is not
  specified.
- **In this repo.** ServiceX's facility-wide transform listing is the
  reference case: `GET /servicex/transformation` returns every user's full
  records with no pagination, about 1.5 GB per call (ssl-hep/ServiceX#1634).
  Until that is fixed upstream, the reference deployment excludes the tool at
  the gateway (see P4), and servicex-mcp runs `--read-only` by design. golang-htcondor clamps every listing to a
  maximum in `webapi/mcpserver/tool_limits.go` and appends a truncation note.

### B2: Report progress and honour cancellation on long calls

**SHOULD.**

- **Rule.** A call that can run for more than a few seconds sends progress
  notifications when the request carries a `progressToken`, stops work when a
  cancellation notification arrives, and does not leave a half-done
  side effect when cancelled. For work that outlives a request, return a handle
  from a start tool and accept it in a status tool, as `servicex_submit_query`
  and `servicex_get_transform_status` do.
- **Why.** A client with no progress cannot tell a slow call from a stuck one
  and will time out or retry. Work that keeps running after a cancel burns
  facility resources for a caller that has gone.
- **Verify.** Reading for the `progressToken` handling and the cancellation
  path. With a streaming client, call the slowest read-only tool and watch for
  progress.
- **Spec.** [Progress](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/progress),
  [Cancellation](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation),
  [Stateful tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#stateful-tools)
  (non-normative guidance on explicit handles).
- **In this repo.** In stateless mode progress and log notifications sent
  during a tool call are still delivered on that call's own response stream
  (`docs/architecture.md`, "`/mcp` transport mode"). **Not exercised by the
  platform:** cancellation forwarding from client through the broker to a
  backend has no test in this repo, so a backend's cancel handling is verified
  against the backend alone.

---

## Transport

### X1: Serve streamable HTTP statelessly

**SHOULD.**

- **Rule.** Expose the MCP endpoint over streamable HTTP and make every request
  self-contained. Do not rely on a session id, on the `initialize` call having
  reached this process, or on state held between calls in process memory.
  Where a feature needs state across calls (a transform, a server), return an
  explicit handle from a creation tool and accept it as an argument, as
  `servicex_submit_query` and `servicex_get_transform_status` do.
- **Why.** The broker's own `/mcp` runs stateless by default
  (`broker.mcpStatelessHttp: true`), and its chart load-balances requests across
  replicas with no session pinning. A backend that keeps per-connection state
  fails the same way when consecutive calls reach different replicas, or when a
  proxy opens a fresh connection per call. This repo does not pin down which of
  those the aggregator does on the broker-to-backend hop, so a backend should
  depend on neither. In stateless mode the standalone GET SSE stream is not
  available, so `notifications/tools/list_changed` and server-initiated sampling
  or elicitation do not reach the client; a backend that needs them is the
  exception, and then needs session affinity in front of it.
- **Verify.** Run the server with the transport's stateless option (for the
  Python SDKs, `stateless_http=True`), or run two replicas, then send a bare
  `tools/call` with `curl` without a prior `initialize` or session header and
  confirm it succeeds. Reading for module-level dicts keyed by session or
  connection.
- **Spec.** [Transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports),
  [Stateful tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#stateful-tools):
  at this revision the protocol has no session, so a server cannot rely on
  implicit per-connection state.
- **In this repo.** `docs/architecture.md` ("`/mcp` transport mode and replica
  safety", issue #128) and `broker.mcpStatelessHttp` in
  `charts/af-mcp-platform/values.yaml`. The broker warns at startup on a stateful
  aggregator with more than one replica (`broker/src/af_mcp_broker/app.py`).

### X2: Reject a bad bearer with HTTP 401 at the transport

**MUST.**

- **Rule.** Verify the bearer on every request before any tool runs, and answer
  an invalid or revoked token with HTTP 401. Do not return a rejection as a tool
  error inside a 200 response.
- **Why.** The broker learns that an `oauth21-direct` token was revoked only from
  a 401. A rejection hidden in a 200 keeps the broker serving the token, and the
  caller's catalog entry never shows `link_state: "rejected"`.
- **Verify.** Send a `tools/list` with `Authorization: Bearer invalid` and
  check the status code is 401. `audit_tools.py --url ... --token invalid`
  reports the status.
- **Spec.** [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#error-handling)
  (error handling).
- **In this repo.** [Backends must reject a bad bearer with HTTP 401](adding-a-service.md#backends-must-reject-a-bad-bearer-with-http-401)
  and [Rejected `oauth21-direct` tokens](auth.md#rejected-oauth21-direct-tokens).
  af-jupyterhub-mcp's `HubTokenVerifier` is the worked example.

---

## Authentication and credentials

The platform's trust boundary: the broker authenticates the human, checks
authorization, and either forwards a credential for an external system or
issues an identity assertion for an AF-native backend. A backend is told "who
is this and did the broker send them", and nothing else. The full design is in
[Authentication](auth.md#af-broker-identity-token-issue-162).

### U1: Trust only the broker identity token

**MUST.**

- **Rule.** An AF-native backend authenticates a caller only by the AF Broker
  Identity Token the broker sends in `Authorization: Bearer`. It does not
  accept a Keycloak JWT, a personal access token, a username or a shared secret
  from a caller it has not placed behind the broker.
- **Why.** The broker is the sole authorization decision point. A second way in
  is a way around entitlement and audit.
- **Verify.** Reading the auth wiring; then a request carrying a token signed by
  another key, or none, must fail with 401 (see X2).
- **Spec.** [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  (the MCP server as an OAuth resource server).
- **In this repo.** `docs/auth.md`, "AF Broker Identity Token". A static shared
  secret gating the server (ami-mcp's `--auth shared-secret`) is for running
  the server outside the broker, not for a deployment behind it.

### U2: Validate signature, issuer, audience and expiry

**MUST.**

- **Rule.** Verify the token against the broker's JWKS at
  `GET /.well-known/jwks.json` (select the key by `kid`) and check signature,
  `iss`, `exp` and `aud`. Reject any token whose `aud` is not exactly this
  server's audience.
- **Why.** Without the `aud` check, a token minted for one backend is accepted
  by another. The `aud` is the service's `audience` field in `services.yaml`,
  which defaults to `name`. Renaming a service without setting `audience` 401'd
  every AF-native backend on 2026-08-26.
- **Verify.** Present a validly signed token with a different `aud` and confirm
  401 or 403. Present an expired one and confirm the same.
- **Spec.** [Token handling](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#token-handling)
  and [Token requirements](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#token-requirements)
  (a server MUST validate that a token was issued for it).
- **In this repo.** The claim table is in `docs/auth.md` ("The token format").
  The token TTL is `BROKER_TOKEN_TTL_SECONDS`, 600 s by default.

### U3: Never accept raw user credentials as tool arguments

**MUST.**

- **Rule.** No tool takes a password, token, proxy or key as an argument,
  and no tool returns one in its result or in error text.
- **Why.** Tool arguments and results pass through the model, the client's
  logs and the audit trail. A credential there has left the credential boundary.
  LLM clients never hold raw credentials on this platform.
- **Verify.** Mechanical: flag parameters named like `password`, `token`,
  `secret`, `proxy`, `key`, `credential`. Reading for results.
- **Spec.** [Security considerations](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#security-considerations)
  and [Token handling](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#token-handling).
- **In this repo.** Users link credentials through the portal or
  `af_link_identity`, which returns a link and takes no secret.

### U4: Redeem credentials through the broker

**MUST.**

- **Rule.** A backend that needs a grid or Kerberos credential on the caller's
  behalf calls back to the broker with its identity token: `POST
  /v1/credentials/x509/redeem` for a VOMS proxy, `POST
  /v1/credentials/krb5/redeem` for a ticket. Hold the result for the one call,
  in a per-call temporary file, and delete it when the call finishes. Do not
  persist it or log it.
- **Why.** The broker is where credentials are minted, renewed, stored and
  audited. The redeem routes are the deliberate, audited exception to "the PEM
  never leaves the broker", scoped to authenticated backend targets and released
  once per request. The krb5 route never mints or renews, because a synchronous
  backend call cannot prompt a user.
- **Verify.** Reading for any other credential source (environment variables,
  files in the user's home, shared service accounts). A deployment's audit log
  shows `x509_proxy_release` and `krb5_ticket_release` events for each call.
- **Spec.** Platform-specific.
- **In this repo.** `docs/auth.md` (the x509 redeem flow and "Redeeming the
  ticket"), `broker/src/af_mcp_broker/api/credentials.py`. ami-mcp is the
  example: its `BrokerProxyClientFactory` (`src/ami_mcp/auth/broker.py`)
  redeems per call.

### U5: Take no authorization decision from the token

**MUST.**

- **Rule.** Do not read permissions, groups or roles from the broker token, and
  do not add them. Use the token for subject, audience, expiry and, when the
  service declares `requires_posix`, the POSIX identity claims.
- **Why.** The token carries no authorization claim by design. Authorization is
  an attribute of the principal, decided per call by the broker. A backend that
  tests `token.permissions` has broken the design.
- **Verify.** Reading for any use of `groups`, `permissions` or `roles` claims
  after validation.
- **Spec.** Platform-specific.
- **In this repo.** `docs/auth.md`, "Authorization is an attribute of the
  principal, not the token".

---

## Platform integration

These items are properties of the service's registry entry or of how the
backend is run. They are config, not protocol, but they are checked in the same
audit because a backend that cannot meet them cannot be registered.

### P1: The prefix rule

**MUST.**

- **Rule.** Tools reach callers as `<prefix>_toolname`. With the default
  `apply_namespace: true` the aggregator adds the prefix, so the backend
  advertises bare names. With `apply_namespace: false` the backend must
  advertise names already prefixed with exactly the registered `prefix`, and
  every per-tool `required_permission` and `exclude_tools` key uses the
  backend's names. Upgrade the backend and the service entry together.
- **Why.** Routing, entitlement and audit all find a tool's service from
  `<prefix>_`. See N1. `apply_namespace: false` is safe only while no other
  service can advertise an overlapping name.
- **Verify.** `audit_tools.py --prefix <prefix>` against the backend. On a
  deployed gateway, `af_mcp_service_tools_advertised` against
  `af_mcp_service_tools_routable`, and the `aggregator.tool_prefix_mismatch`
  log line.
- **Spec.** Platform-specific.
- **In this repo.** [Adding a Service](adding-a-service.md#apply_namespace-tool-naming)
  and its subsection on coupling `prefix` to the backend's names.
  rucio-mcp is the shipped `apply_namespace: false` example.

### P2: Write an `agent_policy` for the service

**SHOULD.**

- **Rule.** Set `agent_policy` on the service entry: one to three imperative
  sentences for the agent, saying which operations are safe reads and which
  change real facility state and should be confirmed with the user first. Keep
  it separate from `description`, which is user-facing catalog text.
- **Why.** The aggregator composes every service's `agent_policy` into the MCP
  server `instructions` the model reads before calling anything. It is the
  model-facing half of dual enforcement (`docs/architecture.md`). It is
  guidance, not an access-control boundary: `required_permission` stays
  authoritative.
- **Verify.** Reading `services.yaml`. On a deployment, `af_list_mcp_servers`
  and the gateway's server `instructions` show the composed text.
- **Spec.** Platform-specific. The spec's `instructions` field on `initialize`
  is the carrier.
- **In this repo.** `broker/src/af_mcp_broker/mcp/services.yaml` carries one for
  every reference service. Rucio's says queries are safe and rule changes need
  confirmation.

### P3: Declare a `trust_tier`

**MUST.**

- **Rule.** Set `trust_tier` on the service entry to `user-tier` (acts only with
  the caller's own credentials), `service-tier` (touches shared facility
  infrastructure or acts with a facility credential) or `infrastructure-tier`
  (holds platform-wide secrets). Choose `required_permission` to match.
  `required_permission: __none__` is only for user-tier read-only services.
- **Why.** The tier sets the governance bar the service is reviewed against
  (runbook, policy, named reviewer for service-tier and above), and tells the
  model how much caution the service warrants.
- **Verify.** Reading `services.yaml`. A backend that forwards the caller's own
  token or proxy is user-tier. One that acts with its own credential is not.
- **Spec.** Platform-specific.
- **In this repo.** `docs/architecture.md`, "Trust tiers". The declaration in
  `services.yaml` is posture only; the authoritative per-deployment assignment
  lives with each app's manifests in the GitOps repo (maniaclab/flux_apps#32).

### P4: Hide infrastructure tools with `exclude_tools`

**SHOULD.**

- **Rule.** A tool with no user story behind the broker (infrastructure-facing,
  or unsafe at facility scale, as in B1) is listed in the service's
  `exclude_tools` by its native, pre-namespace name, so it is absent from
  `tools/list` and refused on `tools/call`. Better still, do not ship it in the
  server's default configuration.
- **Why.** `exclude_tools` is removal, not gating. For a tool you merely want
  fewer callers to reach, use per-tool `required_permission`.
- **Verify.** After deploy, the name does not appear in `tools/list` and a
  mistyped entry shows an `aggregator.exclude_tools_not_found` warning.
- **Spec.** Platform-specific.
- **In this repo.** [Adding a Service](adding-a-service.md#exclude_tools-hiding-backend-tools-entirely).
  The shipped example is condor-mcp's `advertise_to_collector`.

### P5: Offer a read-only mode

**SHOULD.**

- **Rule.** A server that has write or destructive tools can be started in a
  mode that withholds them, as a server-wide setting that applies on every
  transport, not only through the caller's scopes.
- **Why.** An operator who wants agents without the ability to submit, remove or
  edit has to say so once about the server, instead of relying on every path
  that reaches it to carry the right scopes. Annotations (A1) make the withheld
  set derivable from the server's own tool list.
- **Verify.** Start the server in read-only mode and check that every listed
  tool has `readOnlyHint: true`.
- **Spec.** Platform-specific.
- **In this repo.** servicex-mcp is `--read-only` by design. golang-htcondor
  implements it in `webapi/mcpserver/read_only.go`, withholding the same set that
  the `mcp:read`-without-`mcp:write` scope sees. The registry's own filesystem
  service is read-only by construction, and its `agent_policy` says so.

---

## Auditing with the skill

The `af-mcp-builder` skill walks an agent through this checklist against a
backend's source and, where it can, against the running server.

### Install

The repo is a source for both mechanisms below. Both were exercised against a
checkout of this repo; see the [README](https://github.com/maniaclab/af-mcp-platform#mcp-server-authors-the-af-mcp-builder-skill)
for the exact commands and the checks behind them.

With the GitHub CLI's skill installer (`gh skill`, in preview):

```bash
gh skill install maniaclab/af-mcp-platform af-mcp-builder
```

As a Claude Code plugin, from the repo's marketplace manifest
(`.claude-plugin/marketplace.json`):

```text
/plugin marketplace add maniaclab/af-mcp-platform
/plugin install af-mcp-builder@af-mcp-platform
```

### What it checks

`skills/af-mcp-builder/scripts/audit_tools.py` connects to a server with an MCP
client, lists its tools, and reports the items that can be read off the wire:
N1, N2, S1, O1, A1, A2, B1 (the `limit` parameter), U3 (parameter names),
and with `--call` E1 and the output size. The remaining items need the source
and the deployment and are checked by reading, following the skill's procedure.
The skill reports findings as a table of ID, level, location (`file:line`), and
suggested change.

### One source of truth

This page is the canonical text. The skill installs as a directory, and an
installed skill cannot reach `docs/`, so `skills/af-mcp-builder/references/mcp-design.md`
carries a generated copy. `scripts/sync-skill-guide.py` writes the copy from this
page, rewriting the relative links to sibling docs into absolute GitHub URLs so
they resolve outside the repo. A pre-commit hook, `sync-skill-guide`, runs the
script with `--check` and fails when the copy differs from what the script would
write. Edit this page, then run `python3 scripts/sync-skill-guide.py` to refresh
the copy.

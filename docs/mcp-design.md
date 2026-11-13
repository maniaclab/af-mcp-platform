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

## Sources

The spec items follow the MCP specification. The platform items and most of the
agent-facing ones come from operating the reference deployment: the
maniaclab/af-mcp-platform#216 audit and the production incidents cited in
individual items, and Giordon Stark's HTCondor Workshop talk
[The Facility Is the Context](https://kratsg.github.io/2026-10-01-htcondor-eu/)
(2026-10-01), whose lessons are folded into the items below with the evidence
in its research notes
([`mcp-design-talk.md`](https://github.com/kratsg/2026-10-01-htcondor-eu/blob/main/mcp-design-talk.md)).

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
| [G1](#g1-build-a-server-only-where-it-fits) | SHOULD | Build a server only for a service assistants need repeatedly, with bounded output and recoverable errors, never one that hands the model a credential |
| [N1](#n1-tool-names-are-prefixed-stable-verb_noun-identifiers) | MUST | Tool names are `<prefix>_<verb_noun>`, stable, in the spec's character set |
| [N2](#n2-the-first-line-of-a-description-is-a-one-line-summary) | MUST | First line of each description is a one-line summary |
| [N3](#n3-descriptions-say-when-to-call-the-tool-and-what-it-needs) | SHOULD | Description adds arguments, caveats and when to call it |
| [N4](#n4-keep-the-tool-surface-proportional-and-split-along-observed-confusion) | SHOULD | The tool surface is small enough to choose from; split tools along observed confusion |
| [S1](#s1-every-tool-has-an-object-inputschema-with-described-properties) | MUST | `inputSchema` is an object schema, every property described |
| [S2](#s2-constrain-arguments-in-the-schema-not-in-prose) | SHOULD | Types, enums, bounds and defaults live in the schema |
| [O1](#o1-declare-an-object-outputschema-and-return-structuredcontent) | MUST | Object `outputSchema`, with matching `structuredContent` |
| [O2](#o2-send-a-text-block-with-the-same-information-as-structuredcontent) | SHOULD | `structuredContent` is the contract; a text block carries the same information |
| [O3](#o3-curate-results-for-the-model) | SHOULD | Curated fields, units converted in the open, duplicates removed, stable identifiers |
| [A1](#a1-declare-annotations-on-every-tool) | MUST | `readOnlyHint` set on every tool |
| [A2](#a2-state-destructive-idempotent-and-open-world-hints-for-writes) | SHOULD | Writes also state `destructiveHint`, `idempotentHint`, `openWorldHint` |
| [E1](#e1-report-tool-failures-with-iserror-true) | MUST | Tool failure sets `isError: true` |
| [E2](#e2-error-and-empty-results-name-the-next-step) | MUST | Error and empty results name a next step |
| [E3](#e3-classify-transient-errors-and-hint-at-a-retry) | SHOULD | Transient errors are classified and hinted, or retried boundedly |
| [E4](#e4-use-protocol-errors-only-for-protocol-problems) | MUST | JSON-RPC errors only for protocol problems |
| [B1](#b1-bound-every-result-and-paginate-listings) | MUST | Every result is bounded; listings take a limit and paginate |
| [B2](#b2-report-progress-and-honour-cancellation-on-long-calls) | SHOULD | Long calls report progress and honour cancellation |
| [B3](#b3-protect-shared-backends-from-one-caller) | SHOULD | Per-caller concurrency or rate bound in front of a shared backend |
| [X1](#x1-serve-streamable-http-statelessly) | MUST | Stateless streamable HTTP, no reliance on per-connection session state |
| [X2](#x2-reject-a-bad-bearer-with-http-401-at-the-transport) | MUST | A bad bearer gets HTTP 401 before any tool runs |
| [X3](#x3-answer-toolslist-without-a-downstream-call) | SHOULD | `tools/list` is answered from registration, with no downstream call |
| [X4](#x4-design-for-the-least-capable-client) | SHOULD | Standard transport and auth only; nothing client-specific |
| [X5](#x5-treat-downstream-endpoints-as-changing) | SHOULD | Explicit timeouts, endpoints re-resolved after failure, readiness reflects own health |
| [U1](#u1-trust-only-the-broker-identity-token) | MUST | Authenticate callers with the broker identity token only |
| [U2](#u2-validate-signature-issuer-audience-and-expiry) | MUST | Check signature, `iss`, `aud` and `exp`; reject any other `aud` |
| [U3](#u3-never-accept-raw-user-credentials-as-tool-arguments) | MUST | No credentials in tool arguments or results |
| [U4](#u4-redeem-credentials-through-the-broker) | MUST | Fetch x509/krb5 credentials from the broker's redeem routes |
| [U5](#u5-take-no-authorization-decision-from-the-token) | MUST | Read no permissions or groups from the token |
| [U6](#u6-identity-is-ambient-never-an-argument) | MUST | No tool takes a username or owner; derive it from the verified identity |
| [P1](#p1-the-prefix-rule) | MUST | Tool names carry the service prefix the registry routes on |
| [P2](#p2-write-an-agent_policy-for-the-service) | SHOULD | A service entry carries an `agent_policy` |
| [P3](#p3-declare-a-trust_tier) | MUST | A service entry declares `trust_tier` |
| [P4](#p4-hide-infrastructure-tools-with-exclude_tools) | SHOULD | Infrastructure-facing tools are excluded, not left reachable |
| [P5](#p5-offer-a-read-only-mode) | SHOULD | A server with write tools can be started read-only |
| [I1](#i1-wrap-the-client-library-not-the-cli) | SHOULD | Wrap the native client library; parse artifacts, never CLI prose |
| [T1](#t1-test-the-agent-facing-contract-against-the-live-service) | SHOULD | Descriptions, examples, caps and error strings are tested against the real service |

---

## Scope

### G1: Build a server only where it fits

**SHOULD.**

- **Rule.** Put a service behind an MCP server when assistants will need it
  repeatedly and from more than one client, scientists already use it, you want
  to control the context the agent is given, and you can bound its output (B1)
  and make its errors recoverable (E2). Do not build one for a one-off that a
  script covers, for a backend whose API is still churning, or when the honest
  implementation would hand the model a credential (U3): fix that boundary
  first.
- **Why.** The model experiences exactly two things directly, the size of
  results and the text of errors. A server that cannot control either gives the
  agent worse results than the script it replaced, and a tool that returns a
  credential has left the credential boundary.
- **Verify.** Reading, as a gate before onboarding: the server's README states
  the repeat use, the worst-case output of each tool, and what each error tells
  the caller to do next.
- **Spec.** Platform-specific.
- **In this repo.** The talk's "When is an MCP server appropriate?" slide. The
  brokered x509 and krb5 redeem routes (U4) exist so that no tool has to return
  a proxy or ticket.

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
  Call out the quirks of the domain the model cannot infer. In condor-mcp,
  `$(...)` in a job's `arguments` is expanded by HTCondor's submit parser before
  the shell sees it, and a system path as `executable` needs
  `transfer_executable = False`; each cost a failed submission until the
  description said so.
- **Why.** An agent that guesses burns a diagnostic call or several.
- **Verify.** Reading. Mechanical proxy: descriptions with a single line and
  more than two parameters are flagged.
- **Spec.** [Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool).
- **In this repo.** rucio-mcp's tools point container DIDs at
  `rucio_list_container_replicas` when a dataset query comes back empty.

### N4: Keep the tool surface proportional, and split along observed confusion

**SHOULD.**

- **Rule.** Expose the tools a caller would pick between without guessing, and
  no more. Split one tool into two when callers have been seen to confuse its
  cases (one replica tool became one per DID type, each redirecting to the
  other). Keep UI-plumbing, per-widget and infrastructure-facing operations out
  of the default server, or behind `exclude_tools` (P4). Past about 60 tools a
  server should say why, or offer a smaller default set.
- **Why.** Every tool's name, description and schema sits in the model's context
  for the whole session, and a long list makes the right tool harder to pick.
  Fewer tools with sharper boundaries beat many overlapping ones. The reference
  fleet runs from 4 (filesystem, read-only) to 45 (rucio) tools per backend.
- **Verify.** Mechanical lead: `audit_tools.py` reports a tool count above 60.
  Reading for overlapping tools and for UI-only tools.
- **Spec.** Platform-specific.
- **In this repo.** rucio-mcp's 9f4caed split. The gateway lists only the tools a
  caller may use, so a backend's surface is also bounded by `required_permission`
  and `exclude_tools`.

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

### O2: Send a text block with the same information as `structuredContent`

**SHOULD.**

- **Rule.** `structuredContent` is the contract (O1). Also return a text block
  that carries the same information: the serialized JSON, which is what the spec
  asks for and what the SDKs produce for a typed tool, or a readable rendering of
  the same fields. A text block must not drop data that is in
  `structuredContent`, and `structuredContent` must not be dropped to make room
  for prose.
- **Why.** Clients differ in which representation they feed the model, so each
  has to be complete on its own. The broker measures what a call puts in the
  model's context as the text blocks, falling back to the JSON of
  `structuredContent` only when there are none, because backends commonly mirror
  one into the other (counting both double-counted every typed tool,
  `c1c9518`). A server that returns only prose gives the platform nothing to
  type-check or compose: the markdown-only fleet was the cost behind the
  `outputSchema` convention (`35591cf`).
- **Verify.** With `--call`, a tool that declares an `outputSchema` returns
  `structuredContent` and a non-empty text block. A text block identical to the
  JSON is conformant, not a finding.
- **Spec.** [Structured content](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#structured-content)
  (a tool that returns `structuredContent` SHOULD also return the serialized JSON
  in a text block).
- **In this repo.** The five `gateway_service` tools return plain pydantic
  models, so fastmcp supplies both: `structuredContent` and a JSON text block
  (`broker/src/af_mcp_broker/mcp/diagnostics.py`). The talk's checklist says
  "`outputSchema` + serialized text". Backends that also want curated markdown
  with "Next steps" hints (E2) keep it in the text block beside the full
  `structuredContent`. In the Python `mcp` SDK, annotating a tool `-> MyModel`
  gives `outputSchema`, `structuredContent` and a JSON text block; to supply your
  own text, annotate `Annotated[CallToolResult, ResultModel]` and return a
  `CallToolResult` with your `TextContent` and
  `structured_content=payload.model_dump(mode="json")`. The SDK still publishes
  `ResultModel`'s schema and validates the payload; the annotation is metadata,
  never evaluated as the literal return type. `Context`, `CallToolResult`,
  `TextContent`, `ToolAnnotations` and every model used in a return annotation
  must be runtime imports, never `TYPE_CHECKING`-only: the SDK resolves live
  annotations with `inspect.signature(func, eval_str=True)`, and a
  `TYPE_CHECKING`-only name raises `InvalidSignature` at registration. ami-mcp
  uses this form (`src/ami_mcp/tools/datasets.py`).

### O3: Curate results for the model

**SHOULD.**

- **Rule.** A result carries the fields an analyst would pick, not the backend's
  full row: about fifteen, not a hundred. Convert units where the value is
  returned and say so in the field name or value (`729 pb`, not a bare `0.729`
  in nb), remove duplicate rows, and use the community's own identifiers (DIDs,
  dataset names, paths) verbatim, so that one tool's output is another's input.
  End a result with the follow-up tools to call when there is an obvious next
  step (E2).
- **Why.** An existing API is not an agent interface. Raw AMI rows were a
  hundred fields per dataset, cross-sections in nanobarn with no hint, and
  duplicate rows, multiplied by every dataset in the answer. The model cannot
  silently mix units it was never told differ, and it reads a hundred columns no
  better than fifteen.
- **Verify.** Mechanical lead: with `--call`, a result record with more than 30
  fields is reported. Reading for units, duplicates and identifiers.
- **Spec.** Platform-specific.
- **In this repo.** ami-mcp's curation commit 901f339 ("optimize MCP tools for LLM
  usefulness"); rucio-mcp's DIDs are returned in the form the next tool accepts.

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
  raw backend exception text. Grade errors by audience: say what the caller can
  fix specifically, and keep security-adjacent detail (internal paths, hostnames,
  why an authorization check failed) in the server log. Give each error a stable
  category so that monitoring can chart which tools confuse the agent.
- **Why.** The model guesses otherwise, and usually spends a diagnostic call
  or several. This was the root of the frictions in maniaclab/af-mcp-platform#216.
- **Verify.** Reading. Mechanical proxy: with `--call` on a failing input, the
  error text is not empty and does not contain a Python traceback or a Go panic
  trace. The same call reports a credential-shaped string in any result (U3).
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
  and says in the result when it truncated and how to get the rest (`Showing 50
  results (offset=0). Pass offset=50 to see more.`). Cap the work as well as the
  output: paginate the upstream iterator, so that a 50-row page of a
  500,000-file container does not download the container. Enforce the cap in
  code and test it; a limit that is only documented is not a limit.
  `tools/list` itself paginates with `nextCursor` if the tool count warrants.
- **Why.** Truncation the model cannot see distorts what it believes;
  truncation it can see is the next tool call. Tool output goes into the model's
  context window, which is the real budget, not the server's willingness to send. An unbounded answer
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
  rucio-mcp's `paginate_iter` pages the upstream iterator, after a version that
  paginated the output but still fetched the whole container per page.

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

### B3: Protect shared backends from one caller

**SHOULD.**

- **Rule.** Bound how much one caller can ask of a shared downstream system at
  once: a per-caller concurrency limit (a semaphore) or rate limit in front of
  anything whose latency or lockout counters other users share (NFS, a Kerberos
  KDC, a schedd, an upstream with account lockout). Answer a refused call with a
  tool error that says to retry later (E3).
- **Why.** Agents loop and fan out. One caller's burst against a shared
  filesystem or a third party's lockout counter is felt by every other user.
- **Verify.** Reading for the limit, and a test that issues more concurrent calls
  than the bound and checks the excess waits or is refused.
- **Spec.** Platform-specific.
- **In this repo.** af-filesystem-mcp's per-user semaphore protects other tenants'
  NFS latency; krb5-token-service's rate limiter protects CERN's lockout counter,
  not itself.

---

## Transport

### X1: Serve streamable HTTP statelessly

**MUST.**

- **Rule.** Expose the MCP endpoint over streamable HTTP and make every request
  self-contained. The gateway reaches backends over streamable HTTP only: the
  deprecated HTTP+SSE transport (replaced by streamable HTTP in spec revision
  2025-03-26) is refused at broker startup (#389), so a server that exposes only
  a legacy `/sse` endpoint does not fit. Do not rely on a session id, on the `initialize` call having
  reached this process, or on state held between calls in process memory. A
  cache of per-caller data (a client, a result) is keyed by the verified
  identity, never by a session or connection alone.
  Where a feature needs state across calls (a transform, a server), return an
  explicit handle from a creation tool and accept it as an argument, as
  `servicex_submit_query` and `servicex_get_transform_status` do.
- **Why.** Stateless backends simplify the platform's logic and its upkeep: no
  session routing, no affinity, no session-lifetime handling, and any replica can
  serve any call. The broker's own `/mcp` runs stateless by default
  (`broker.mcpStatelessHttp: true`), and its chart load-balances requests across
  replicas with no session pinning. A backend that keeps per-connection state
  fails when consecutive calls reach different replicas, or when a proxy opens a
  fresh connection per call: the SDK default (stateful) with two replicas gave
  cross-replica "Session terminated" and 404s until `stateless_http=True`
  (af-filesystem-mcp `149b63d`, af-jupyterlab-mcp `92ff9cc`, platform #128). A
  session-keyed client cache once risked serving one user's client to another.
  The MCP 2026-07-28 revision removed protocol sessions, so stateless is also
  the spec's default. The standalone GET SSE stream named next is a different thing
  from the legacy transport: it is an SSE response stream inside streamable HTTP.
  In stateless mode that stream is not available, so `notifications/tools/list_changed` and server-initiated sampling
  or elicitation do not reach the client. A backend that needs them cannot be
  onboarded as it is; redesign the feature around an explicit handle.
- **Verify.** Run the server with the transport's stateless option (for the
  Python SDKs, `stateless_http=True`), or run two replicas, then send a bare
  `tools/call` with `curl` without a prior `initialize` or session header and
  confirm it succeeds. `audit_tools.py --url ... --check-stateless` sends that
  request and reports a non-200 answer. With `--url`, the audit also reports an
  endpoint that speaks only the legacy HTTP+SSE transport. Reading for
  module-level dicts keyed by session or connection, and for a legacy SSE app
  (`sse_app()`, `transport="sse"`, a `/sse` route, mcp-go `NewSSEServer`).
- **Spec.** [Transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports),
  [2025-03-26 changelog](https://modelcontextprotocol.io/specification/2025-03-26/changelog)
  (streamable HTTP replaces HTTP+SSE),
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

### X3: Answer `tools/list` without a downstream call

**SHOULD.**

- **Rule.** `tools/list` is answered from the server's own registration, needs
  nothing but the broker identity token, and does not call the downstream service
  or depend on the caller's linked credentials. The list does not vary with
  hidden state.
- **Why.** The gateway has to enumerate a backend's tools before any user call,
  and some backends demanded per-user authentication just to list, so the gateway
  minted a credential for the listing. Fixing that naively poisoned a schema cache
  shared with other callers (#121). A backend that is down should disappear from
  the list at the gateway, not fail inside `tools/list`.
- **Verify.** Stop the downstream service and call `tools/list` with a valid
  broker token: it must still return the full list.
- **Spec.** [Listing tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#listing-tools).
- **In this repo.** The aggregator's per-(user, service) tool-list cache and its
  handling of an unavailable backend (`docs/architecture.md`, #121, #323).

### X4: Design for the least capable client

**SHOULD.**

- **Rule.** Use standard transports (stdio for local use, which the gateway cannot
  reach, and streamable HTTP for anything it fronts) and standard OAuth
  or bearer auth, with no behaviour that depends on one client or provider. Do
  not add a fallback that only one client needs, and remove one when a different
  client breaks on it.
- **Why.** Clients differ: one had no OAuth discovery, so personal access tokens
  were added; another choked on an OAuth metadata fallback, which was deleted. A
  design that needs a particular client does not travel across providers or
  facilities.
- **Verify.** Run the audit script, then connect with at least one client other
  than the one you developed against and list and call a tool.
- **Spec.** [Transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports),
  [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
- **In this repo.** The root OAuth-metadata fallback was removed after it
  produced a phantom issuer for non-first sites (`89e66cf`); PATs exist for
  clients without OAuth discovery.

### X5: Treat downstream endpoints as changing

**SHOULD.**

- **Rule.** Set an explicit timeout on every downstream call. Re-resolve a
  downstream address after a connection failure rather than pinning the one
  found at startup, or fail the readiness probe so the orchestrator restarts the
  pod. Readiness reflects the server's own health, never the upstream's.
- **Why.** condor-mcp resolved its schedd address once and kept it. When the
  schedd restarted on a new socket, every call failed until the pod was
  restarted, because its refresh loop logged the new address and kept the old
  one (bbockelm/golang-htcondor#308). An upstream outage that fails readiness
  takes the whole backend, including calls that still work, out of rotation.
- **Verify.** Restart the downstream service under a running server and check the
  next call succeeds without a pod restart.
- **Spec.** Platform-specific.
- **In this repo.** E3 covers what the caller sees; this item covers whether the
  server recovers by itself.

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
  from a caller it has not placed behind the broker. Never forward the received
  token to another service: exchange it for a credential minted for that
  service, or redeem one (U4).
- **Why.** The broker is the sole authorization decision point. A second way in
  is a way around entitlement and audit, and the MCP specification forbids a
  server from passing the token it received on to a downstream API.
- **Verify.** Reading the auth wiring and every outbound HTTP call for the
  incoming `Authorization` header; then a request carrying a token signed by
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
  `secret`, `proxy`, `key`, `credential`; with `--call`, flag a result or error
  containing a PEM block or a JWT. Reading for the rest of the results.
- **Spec.** [Security considerations](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#security-considerations)
  and [Token handling](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#token-handling).
- **In this repo.** Users link credentials through the portal or
  `af_link_identity`, which returns a link and takes no secret. A token-returning
  argument was deleted as soon as brokered execution made possessing the token
  unnecessary (`4ea435f`): brokered execution beats redacted disclosure.

### U4: Redeem credentials through the broker

**MUST.**

- **Rule.** A backend that needs a grid or Kerberos credential on the caller's
  behalf calls back to the broker with its identity token: `POST
  /v1/credentials/x509/redeem` for a VOMS proxy, `POST
  /v1/credentials/krb5/redeem` for a ticket. Hold the result for the one call,
  in a per-call temporary file, and delete it when the call finishes. Do not
  persist it or log it. A server holds no secrets of its own; long-lived
  secrets live in a vault behind the broker, and each root secret has one
  service that touches it.
- **Why.** The broker is where credentials are minted, renewed, stored and
  audited. The redeem routes are the deliberate, audited exception to "the PEM
  never leaves the broker", scoped to authenticated backend targets and released
  once per request. The krb5 route never mints or renews, because a synchronous
  backend call cannot prompt a user.
- **Verify.** Reading for any other credential source (environment variables,
  files in the user's home, shared service accounts). A test that the temporary
  file is deleted after a successful call and after a failed one. A deployment's audit log
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

### U6: Identity is ambient, never an argument

**MUST.**

- **Rule.** No tool takes a username, owner, uid or account that the caller
  could set to someone else. Derive the acting identity from the verified broker
  token (and the POSIX claims when `requires_posix`), and enforce it where the
  backend can: owner labels on a Kubernetes object, a kernel uid/gid on a
  subprocess, the nickname inside a redeemed proxy. State in the description
  that the caller is always the owner.
- **Why.** A model-supplied value can be hallucinated or injected. A schema with
  no owner parameter cannot express "read bob's files", so the whole class of
  mistake is unrepresentable. Do not expose dangerous parameters; derive them
  from verified identity.
- **Verify.** Mechanical lead: parameters named `user`, `username`, `owner`,
  `uid`, `gid` or `unixname` are reported. Reading for any parameter that selects
  whose data a tool touches.
- **Spec.** Platform-specific.
- **In this repo.** `create_jupyter_server` in af-jupyterlab-mcp takes no owner and
  reads it from `get_broker_claims`; af-filesystem-mcp runs a setuid subprocess
  so the kernel enforces it. A resource name that is not the caller (a Rucio
  `account` on a read) is a case for the reader to confirm, not an automatic
  pass.

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
  Put facility know-how that does not fit one tool (how storage and queues
  actually work) in the server's `instructions`, a resource or a published
  skill, not in every tool description: MCP gives the agent hands, skills give it
  expertise.
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

## Implementation and testing

### I1: Wrap the client library, not the CLI

**SHOULD.**

- **Rule.** Build a tool on the service's native client library so that the
  server handles structured objects and returns curated text (O3). Where only a
  CLI exists, run the native binary and parse artifacts it produces (a ccache,
  a PEM, JSON output), never its human-readable text. Start on stdio from the
  user's own environment; add HTTP when a facility hosts it.
- **Why.** Parsing text tables is fragile, and CLI prose is locale-dependent. A
  Rust CLI wrapper that parsed tables was replaced by the Python client for that
  reason.
- **Verify.** Reading for `subprocess` calls whose output is split or matched as
  text, and for the locale the child runs under.
- **Spec.** Platform-specific.
- **In this repo.** rucio-mcp wraps `rucio.client`; the three token services
  orchestrate the native binary and parse artifacts.

### T1: Test the agent-facing contract against the live service

**SHOULD.**

- **Rule.** Test what the model sees against the real service: that each
  example in a description runs and returns what the description says, that
  result caps hold, that errors carry their next step and category. Fix a
  description as you fix code, against the live behaviour. Run the audit script
  against a running instance in CI.
- **Why.** The model reproduces an example verbatim, so a documentation bug is a
  behaviour bug: ami-mcp's documented query examples were wrong four times in
  one day and the model copied the wrong syntax. Mock-green tools shipped real
  API misuse, and green CI proves nothing about credential plumbing.
- **Verify.** A test that extracts and runs the examples in descriptions; a
  test for each cap and error string. `audit_tools.py --call` against a live
  instance covers E1, E2, O1, O2 and the result size.
- **Spec.** Platform-specific.
- **In this repo.** The closing remark of the talk: "testing against the live
  services, not mocks". No linter checks that a description agrees with its
  schema.

---

## Auditing with the skill

The `af-mcp-builder` skill walks an agent through this checklist against a
backend's source and, where it can, against the running server.

### Install

The repo is a source for both mechanisms below; see the
[README](https://github.com/maniaclab/af-mcp-platform#mcp-server-authors-the-af-mcp-builder-skill)
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
N1, N2, N3, N4, S1, O1, A1, A2, B1 (the `limit` parameter), U3 and U6 (parameter
names), and with `--call` E1, E2, O1, O2, O3, U3 (results) and the output size.
`--check-401` checks X2 and `--check-stateless` checks X1; with `--url` it also
flags a legacy HTTP+SSE-only endpoint as X1. The remaining items
need the source and the deployment and are checked by reading, following the
skill's procedure. The skill reports findings as a table of ID, level, location
(`file:line`), and suggested change.

### Where the skill reads the guide

This page is the only copy of the guide. The skill installs as a bare
directory, which cannot reach `docs/`, and a symlink does not fix that:
`gh skill install` drops a symlink, and the plugin install turns it into a
frozen copy. So the skill carries an index of item IDs and one-line rules
(enough to audit when it cannot fetch the guide) and points at this page:
inside an af-mcp-platform checkout it reads `docs/mcp-design.md`, and elsewhere
it fetches
`https://raw.githubusercontent.com/maniaclab/af-mcp-platform/main/docs/mcp-design.md`.
When you add, rename or re-level an item, update the index in
`skills/af-mcp-builder/SKILL.md` in the same change.

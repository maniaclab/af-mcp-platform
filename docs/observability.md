# Observability

How to operate and use the broker's metering, usage accounting, metrics,
and tracing. This page is the how-to half; the design — why the pipeline
is asynchronous, what the cardinality policy forbids and why, how spans
join audit lines — lives in
[Architecture § Audit](architecture.md#4-audit) and its
[Distributed tracing subsection](architecture.md#distributed-tracing-opentelemetry),
and is not repeated here.

The one contract everything below hangs off: **metering is best-effort;
audit records are authoritative.** Four surfaces divide the work:

- **Prometheus metrics** — aggregate facility health, never per-user
  (see the [cardinality policy](architecture.md#4-audit)).
- **Audit log** — the per-user source of truth: one structured JSON line
  per tool invocation, identity attached, behind access control.
- **Usage store** — queryable per-user aggregates derived from audit
  records, served back to each user by `GET /v1/usage`.
- **Traces** — opt-in OpenTelemetry emission; off by default, and the
  broker is an emitter only (no trace backend is shipped or assumed).

## What gets measured per tool call

The metering worker fills these measurements into each success/error audit
record (and the usage store accumulates them):

| Field | What it is |
|---|---|
| `duration_ms` | Wall time of the downstream tool call — credential resolution plus the backend call itself. |
| `result_bytes` | Wire size of the whole tool result: the **sum** of the per-content-type bytes in `result_content` below. |
| `result_tokens_est` | An **estimate** of what the result costs the LLM client's context: the sum of the per-content-type token estimates below. `null` when token estimation is off (see below). |
| `result_content` | The breakdown behind those two totals, keyed by MCP content type (see below). |

#### Per-content-type breakdown

`result_content` maps a content type to `{blocks, bytes, tokens_est}`. The
key is the MCP block's own `type` (`text`, `image`, `audio`, `resource`,
`resource_link`, …) plus `structured` for the result's `structuredContent`.
It is an open set: a new MCP content type shows up as a new key, with no
schema change anywhere. A block type the broker does not recognize is still
measured under its own type string (bytes = its serialized JSON, tokens 0) and
logged once per call as `unknown_content_type` — never dropped.

- **Bytes** are wire size as sent: text is its UTF-8 length; base64 payloads
  (image and audio `data`, a blob resource's `blob`) are counted at their
  **base64** length; a `resource_link` or unknown block is its serialized JSON.
- **Tokens** come from a per-type rule table
  (`broker/src/af_mcp_broker/audit/measure.py`, `_TOKEN_RULES`; a new rule is
  one entry):
  - `text`, `structured` and text `resource`: a tiktoken estimate, using the
    `o200k_base` encoding by default (`TOKEN_ESTIMATE_ENCODING`; an empty
    string disables token estimation: every `tokens_est` is then 0 and
    `result_tokens_est` is `null`, byte measurement is unaffected).
  - `image`: Anthropic's vision rule — `ceil(width/28) × ceil(height/28)`
    visual tokens after downscaling to the tier's limits
    ([Vision](https://platform.claude.com/docs/en/build-with-claude/vision),
    [How Claude resizes and pads images](https://platform.claude.com/docs/en/build-with-claude/vision-coordinates)).
    The broker cannot know the client's model, so the tier is a fixed
    assumption: the high-resolution tier (2,576 px long edge, 4,784 visual
    tokens; Claude 4.7 and later), `audit/image_tokens.py`'s `ASSUMED_TIER`.
    Dimensions are read from the PNG/JPEG/GIF/WebP header; an unreadable image
    is logged (`image_dimensions_unreadable`) and charged the tier maximum,
    never 0. Example: a 640×480 PNG is 23 × 18 = 414 tokens.
  - everything else (audio, blob `resource`, `resource_link`, unknown): 0 —
    the model does not consume it as tokens.
- `structuredContent` is measured only when the result has no text blocks (the
  two are alternatives, never summed, since backends commonly mirror one into
  the other).

Be clear about what the token number is: an estimate of what each tool
result would inject into an LLM client's context — **not**
provider-reported usage, and **not** the user's full token volume (their
prompts, the model's own output, and every non-tool token are invisible to
the broker). The broker reports token counts only and attaches no monetary
figure to them.

A record whose measurement failed (or that arrived via the queue-overflow
inline fallback) is still written and still counts as a call — its
measurement fields are just `null`, contributing 0 to usage sums. Nothing
is ever dropped.

**Error-rate step change to expect as backends adopt `isError`**
(`maniaclab/af-mcp-platform#238` A.2): the broker already audits a result
that sets `isError` as `outcome=error` / `error_class=tool_reported`
(fixed in `9034858`) — a call that "failed" only in plain text, with no
`isError`, was silently counted as a success before that fix, and still
is for any backend that hasn't adopted the convention yet (see
[MCP Design Guide](mcp-design.md#e1-report-tool-failures-with-iserror-true)). Expect a
visible step up in a given backend's error rate the day it starts
setting `isError` correctly; that's the fix finally seeing what was
always failing, not a new regression to chase.

## How token counts are estimated

Every token figure the broker reports (`result_tokens_est` in usage, `af_usage`,
OTel and the portal's Usage page) is an **estimate** of what a tool result adds
to the LLM client's context. It is not provider-reported usage, and it covers
only tool results: prompts and the model's own output are invisible to the
broker. The portal shows these rules in a tooltip next to its token figures.

| Content | Tokens |
|---|---|
| Text (and the text of an embedded `resource`) | Counted with [tiktoken](https://github.com/openai/tiktoken) using the `o200k_base` encoding (`TOKEN_ESTIMATE_ENCODING`). |
| Image | One token per 28x28 px patch: `ceil(width/28) x ceil(height/28)`, after downscaling to the high-resolution tier's limits: 2,576 px long edge and at most 4,784 tokens per image. A 640x480 image is 23 x 18 = 414 tokens. An image whose size cannot be read is charged the 4,784 maximum, never 0. |
| Audio, binary blob resources, resource links, unknown types | Bytes are recorded; tokens are 0, because the model does not consume them as tokens. |
| Structured content | Counted (as text) only when the result has no text block, since backends commonly mirror one into the other. |

**Why the high-resolution tier.** Claude's image cost depends on the model:
standard-resolution models cap an image at 1,568 px and 1,568 tokens, newer
models at 2,576 px and 4,784 tokens
([Vision](https://platform.claude.com/docs/en/build-with-claude/vision)). The
broker sits between many clients and cannot know which model any of them runs,
so it assumes the high-resolution tier. That errs toward overestimating: a
standard-tier model would count less for large images. Small images (the
640x480 example) cost the same on both tiers. The assumption is the single
constant `ASSUMED_TIER` in `broker/src/af_mcp_broker/audit/image_tokens.py`.

`broker/tests/test_token_explainer_docs.py` fails if these numbers and the
portal tooltip (`portal/src/lib/tokenExplainer.ts`) drift from the code.

## Self-service usage: `GET /v1/usage`

Every user can query their own usage — and nobody else's: the subject
comes from the authenticated principal, never from a parameter. Like all
of `/v1`, the endpoint takes a Keycloak JWT (`aud=mcp-gateway`), not a
PAT.

Query parameters:

- `days` — trailing window in UTC calendar days, today inclusive
  (`1..365`, default `30`; `days=1` is just today).

```bash
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN

curl -sS "https://mcp.example.org/v1/usage?days=7" \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN"
```

Trimmed response:

```json
{
  "subject": "f1b0…",
  "window_days": 7,
  "totals": {
    "calls": 42,
    "errors": 1,
    "duration_ms": 91834.2,
    "result_bytes": 1048576,
    "result_tokens_est": 262144
  },
  "by_service": [
    {
      "service": "rucio-mcp",
      "calls": 30,
      "errors": 0,
      "result_bytes": 917504,
      "result_tokens_est": 229376
    }
  ],
  "by_day": [
    { "date": "2026-08-24", "calls": 42, "result_tokens_est": 262144 }
  ],
  "by_content_type": [
    { "content_type": "image", "blocks": 3, "bytes": 786432, "tokens_est": 1242 },
    { "content_type": "text", "blocks": 39, "bytes": 262144, "tokens_est": 260902 }
  ]
}
```

**Honesty caveats**: token counts are ESTIMATES of what tool results add to
the LLM client's context, not provider-reported usage and not the user's full
token volume. Text is counted with tiktoken `o200k_base`; images by Claude's
vision rule (28x28 px patches on the high-resolution tier). The full rules
are in [How token counts are estimated](#how-token-counts-are-estimated); the
endpoint's own description and the `af_usage` tool description state the same
rules.

`by_content_type` is the same sums split per content type. Calls recorded
without a breakdown (unmeasured, or written by a replica older than the
breakdown) are in `totals` but in no `by_content_type` entry, so the entries
can sum to less than the totals, never to more.

An MCP client doesn't need to leave the MCP surface for this: the
broker-native `af_usage` method (alongside `af_whoami` and the builtin
`gateway_service` service's other methods) returns the same payload — totals,
`by_service`, `by_day` — for the calling principal, with the same
`days` parameter and the same honesty caveats in its tool
description, so the LLM can relay them.

`af_*` calls are themselves audited and metered like every other call
(service `gateway_service` in audit lines, usage rows, and metric labels — issue
maniaclab/af-mcp-platform#240), so they show up in this data too. In particular `af_usage` meters
itself: each call to it appears as one `gateway_service` call in the next usage
window it reports — accepted and deliberately visible.

The portal shows the same numbers as a usage card on its overview page
(`mcp-portal.example.org/overview/`), labeled with the same estimate
caveat, and in full — window selector, per-service table, daily activity —
on its Usage page (`mcp-portal.example.org/usage/`), which also splits tokens
by content type (`by_content_type`) and shows calls recorded without a
breakdown as an "Unattributed" row, so the rows always add up to the totals.

## Operator: the usage store

`USAGE_STORE_BACKEND` (chart: `broker.usage.backend`) selects where the
aggregates behind `GET /v1/usage` live:

- **`in_memory`** (default) — single-replica, lost on restart. Fine for
  dev and small facilities that treat usage as a convenience view; the
  audit log stays authoritative either way.
- **`postgres`** — persists one raw event row per tool-call audit record
  via asyncpg. Postgres itself is BYO: the chart only consumes an existing
  instance, it does not deploy one.

### Batched usage writes

The metering worker does not write each usage record as it arrives: it
buffers them and hands the store one batch (`UsageStore.record_many`; the
Postgres store runs a single `executemany` of the idempotent insert), so
the database sees one round trip per batch instead of one per tool call.

| Setting | Default | Meaning |
|---|---|---|
| `USAGE_BATCH_MAX` (chart: `broker.usage.batchMax`) | `100` | Flush as soon as this many records are buffered. |
| `USAGE_BATCH_INTERVAL_MS` (chart: `broker.usage.batchIntervalMs`) | `1000` | Flush once the oldest buffered record has waited this long, even if the batch is not full. |

Both must be at least 1. Remaining records are also flushed when the
broker shuts down gracefully, and the audit line for a record is always
written before the record is buffered.

- **Crash trade-off.** Buffered rows live only in memory, so a hard crash
  (SIGKILL, OOM) can lose up to `USAGE_BATCH_INTERVAL_MS` worth of usage
  rows (at most `USAGE_BATCH_MAX` records). Their audit lines were already
  written, so the audit log stays complete and the rows can be rebuilt
  from it.
- **Failed batches.** A batch that fails to write is logged as
  `usage_record_batch_failed` (with `batch_size` and the `audit_ids`) and
  counted on `af_mcp_metering_worker_errors_total` once per record, the
  same unit a failed single insert used. The Postgres batch is
  all-or-nothing, so one rejected row fails every row in its batch; the
  logged `audit_ids` identify exactly which rows to rebuild. Nothing about
  a failure reaches the tool call or the audit write.
- **Unbatched paths.** The queue-overflow fallback and the inline path
  used when no pipeline is running still write each record immediately.
- **Fresher reads.** `GET /v1/usage` can lag a call by up to the interval.

### Token and trace columns

Each raw row also carries `token_id` (the calling PAT's public `lookup_id`;
`NULL` for a session JWT) and `trace_id` (the OTel trace; `NULL` when the
call was not traced), and both are `NULL` on rows written before the columns
existed. They let you join
usage to a token or to a trace from SQL. The columns are added at startup by
an idempotent `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`; they are not
indexed, because nothing reads by them yet and an index adds write load.

### Retention and daily rollup (Postgres)

Raw rows would otherwise accumulate forever. The broker folds raw rows older
than the retention window into `af_mcp_usage_daily`, keyed `(day,
principal_sub, service, method, outcome)` with the summed calls, duration,
bytes and tokens, and deletes them in the same statement. The per-content-type
rows are folded in that same statement into `af_mcp_usage_daily_content`,
keyed `(day, principal_sub, service, method, outcome, content_type)`, before
the delete cascades them away.

| Setting | Default | Meaning |
|---|---|---|
| `USAGE_RETENTION_DAYS` (chart: `broker.usage.retentionDays`) | `365` | Raw rows older than this many UTC days are rolled up and deleted. `0` keeps raw rows forever and runs no job. |
| `USAGE_ROLLUP_INTERVAL_SECONDS` (chart: `broker.usage.rollupIntervalSeconds`) | `3600` | How often each replica attempts the job. |

- **Reads do not change.** `GET /v1/usage` and `af_usage` sum raw rows and
  rollup rows, so a window answers the same before and after a row moves.
  What ages out is per-call detail (`audit_id`, `token_id`, `trace_id`);
  the audit log keeps that.
- **One replica at a time.** Every replica runs the loop; a Postgres
  advisory lock (`pg_try_advisory_xact_lock`) lets one proceed and the rest
  skip until the next interval. The lock lives in the database the job
  works on, so it needs no second dependency, is released if the replica
  dies, and is not weakened by the optional shared-state store's in-memory
  fallback. Correctness does not depend on it: the `DELETE ... RETURNING`
  that feeds the rollup is a single statement, so two racing replicas would
  still count each row once.
- **First run.** The first pass on a large existing table moves everything
  older than the window in one statement; expect a one-time burst of
  Postgres work.
- **Window edges.** The raw-row window is a plain range on `ts`, so the
  `ts` indexes are used (wrapping `ts` in `(ts AT TIME ZONE 'UTC')::date`
  would force a full index scan).

### Postgres via Crunchy PGO

The reference deployment uses [Crunchy PGO](https://access.crunchydata.com/documentation/postgres-operator/latest).
The recipe:

1. Create a `PostgresCluster` CR with a user and a database for the
   broker, e.g.:

    ```yaml
    apiVersion: postgres-operator.crunchydata.com/v1beta1
    kind: PostgresCluster
    metadata:
      name: af-mcp-usage
    spec:
      users:
        - name: broker
          databases: ["usage"]
      # instances, storage, postgresVersion, … per your facility's PGO defaults
    ```

    **Give the user a writable schema** (learned in production): PGO can
    create a schema owned by the user automatically via the
    `postgres-operator.crunchydata.com/autoCreateUserSchema: "true"`
    annotation on the `PostgresCluster`, but that annotation requires
    **PGO ≥ 5.6**. On older operators (this facility runs 5.5.0) with
    Postgres ≥ 15 — where `public` is no longer world-writable — the user
    ends up with no writable schema at all, and the broker's startup DDL
    fails with `permission denied for schema public`. The fix is to create
    the user-owned schema yourself, in the user's database:

    ```sql
    CREATE SCHEMA IF NOT EXISTS broker AUTHORIZATION broker;
    ```

    ideally declaratively at cluster bootstrap via `spec.databaseInitSQL`
    (a ConfigMap of SQL PGO runs once at cluster creation), or as a single
    manual `psql` against an already-running cluster.

2. PGO generates a secret named `<cluster>-pguser-<user>`
   (here `af-mcp-usage-pguser-broker`) whose `uri` key is exactly the
   asyncpg-compatible DSN the broker needs. Point the chart at it:

    ```yaml
    broker:
      usage:
        backend: "postgres"
        postgres:
          existingSecret:
            name: "af-mcp-usage-pguser-broker"
            key: "uri"          # the default
          networkPolicy:
            namespace: ""       # empty = the release namespace
            clusterName: "af-mcp-usage"
    ```

    The `existingSecret` is rendered as `USAGE_POSTGRES_DSN` via
    `secretKeyRef`; the broker fails closed at startup if the backend is
    `postgres` but the DSN is empty.

3. `broker.usage.postgres.networkPolicy` renders an egress rule (only
   when `backend: postgres` and the chart's NetworkPolicy is enabled)
   allowing the broker to reach pods labeled
   `postgres-operator.crunchydata.com/cluster: <clusterName>` and
   `postgres-operator.crunchydata.com/data: postgres` on port 5432 —
   exactly the labels PGO puts on the cluster's postgres pods.

### Schema

Four idempotent tables: `af_mcp_usage_events` (raw rows), keyed by
`audit_id` (primary key) with indexes on `(principal_sub, ts)` and `ts`,
`af_mcp_usage_event_content` (one child row per content type of an event:
`audit_id` → `af_mcp_usage_events ON DELETE CASCADE`, `content_type`,
`blocks`, `bytes`, `tokens_est`, primary key `(audit_id, content_type)`),
`af_mcp_usage_daily` (the rollup, see
[Retention and daily rollup](#retention-and-daily-rollup-postgres)) and
`af_mcp_usage_daily_content` (its per-content-type counterpart). The parent's
`result_bytes` / `result_tokens_est` are the totals over its children, and
`content_type` is an open set, so a new MCP content type or token rule needs
no schema change. Parent and children are written in one transaction. Inserts use
`ON CONFLICT (audit_id) DO NOTHING`, so redelivery of the same record —
which best-effort metering permits — is safe by construction. The DDL is
`CREATE ... IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS` and runs at broker
startup (replicas racing each other are fine); there is deliberately **no
migration framework** yet — idempotent DDL does not justify one. Raw
rows are bounded by the retention window described above.

**Upgrading from a release without the breakdown.** Starting the broker
creates the two content tables and backfills them once: each existing event
row with `result_bytes > 0` and no child rows gets one `text` child row from
its totals, and each daily row without content rows gets one `text` content
row. Only text was measured before the breakdown, so `text` is what those
totals were; the real block count is unknown, so `blocks` is an approximation
(1 per event row, `calls` per daily row). The backfill uses `NOT EXISTS` and
`ON CONFLICT DO NOTHING`, so it runs once per row no matter how often or from
how many replicas the DDL runs. During a rolling deploy, replicas of the
previous release keep inserting event rows without children; that does not
fail, readers treat such a row as "breakdown unknown", and the next start
adopts them as `text` (which is exactly what that release measured).

## Operator: metrics

Prometheus metrics are served on a dedicated port (9090, `METRICS_PORT`)
so the chart's NetworkPolicy can allow scraping without opening the API
port; the API port has no `/metrics`. Beyond the generic HTTP metrics
from `prometheus-fastapi-instrumentator`, the broker defines these
(`broker/src/af_mcp_broker/metrics.py`):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `af_mcp_tool_invocations_total` | counter | `service`, `tool`, `action_type` | Tool invocations attempted via `/mcp`, once per call regardless of outcome. |
| `af_mcp_tool_invocations_denied_total` | counter | `service`, `action_type` | Invocations denied by authorization for a known service. |
| `af_mcp_tool_duration_seconds` | histogram | `service`, `tool`, `action_type`, `outcome` | Wall time of the downstream call (credential resolution + backend call); buckets sized up to 300 s for calls that mint credentials via ephemeral k8s Jobs. `outcome` is the audit record's value, `success` or `error`; denied and rate-limited calls never execute, so they are not observed (see their own counters). |
| `af_mcp_tool_invocation_errors_total` | counter | `service`, `error_class` | Calls whose audit record has `outcome=error`, by the audit record's `error_class` (`transient_connection`, `backend_error`, `tool_reported`). Error rate per service: `sum by (service) (rate(af_mcp_tool_invocation_errors_total[5m])) / sum by (service) (rate(af_mcp_tool_invocations_total[5m]))`. |
| `af_mcp_tool_invocations_rate_limited_total` | counter | `service`, `action_type` | Tool calls refused by a `rate_limits` rule in `policy.yaml` (see [auth](auth.md#tool-rate-limits)). Also counted in `tool_invocations_total`. |
| `af_mcp_tool_invocations_unmapped_total` | counter | *(none)* | Tool names matching no registered service prefix (client-supplied, so never a label). |
| `af_mcp_metering_queue_overflow_total` | counter | *(none)* | Records that found the metering queue full and were written inline without measurement — nothing dropped, but tool calls are paying for audit I/O again. |
| `af_mcp_metering_queue_depth` | gauge | *(none)* | Records currently waiting in the metering queue. |
| `af_mcp_metering_queue_delay_seconds` | gauge | *(none)* | Time-in-queue of the most recently dequeued item; rising means the worker is falling behind. |
| `af_mcp_metering_worker_processed_total` | counter | *(none)* | Records fully processed by the metering worker (measured or not). |
| `af_mcp_metering_worker_errors_total` | counter | *(none)* | Measurement or audit-write failures in the pipeline — the record is still written unmeasured where possible. Also counts usage-store write failures, once per record (every record of a failed batch). |
| `af_mcp_metering_records_missing_measurements_total` | counter | *(none)* | Success-path records written without measurements despite a result being present (overflow fallback + measurement failure). |
| `af_mcp_credential_cache_hits_total` / `..._misses_total` | counter | `target` | Credential cache lookups that did / did not find a valid cached credential. |
| `af_mcp_x509_proxy_mints_total` | counter | *(none)* | Successful x509/VOMS proxy mints. |
| `af_mcp_broker_identity_tokens_issued_total` | counter | `target` | AF Broker Identity Tokens actually minted (cache hits not counted). |
| `af_mcp_condor_tokens_issued_total` | counter | `target` | HTCondor IDTOKENs actually obtained from condor-token-service (cache hits not counted). |
| `af_mcp_krb5_tickets_issued_total` | counter | `target` | Kerberos tickets actually obtained from krb5-token-service (cache hits not counted). |
| `af_mcp_annotation_policy_mismatches_total` | counter | `service`, `tool` | A tool's declared `read_only_hint` disagreed with `policy.yaml`'s resolved `action_type` (issue #238 B.8's "forward + lint" decision — visibility only, `policy.yaml` stays authoritative for enforcement). Incremented once per newly observed disagreement; see `GET /v1/admin/annotation-mismatches` for the current set. |
| `af_mcp_tool_mapping_drift_total` | counter | `service`, `kind` | Tools where a service's dict-form `required_permission` and its backend's advertised tools disagree (issue #330). `kind` is `unmapped` (advertised, no key and no `__default__`, so implicitly disabled), `stale` (a mapped key the backend no longer advertises, typically a rename) or `unroutable` (advertised without the service's prefix by an `apply_namespace: false` backend, for any `required_permission` form). Incremented once per newly observed tool; see `GET /v1/admin/tool-mapping-drift` for the current set. |
| `af_mcp_service_tools_advertised` | gauge | `service` | Tools the service's backend advertised on its last successful upstream `tools/list` (after `exclude_tools`). |
| `af_mcp_service_tools_routable` | gauge | `service` | Of those, the tools that carry the service's prefix and so can be routed. `routable == 0` with `advertised > 0` means callers see none of the service's tools; the chart's optional `prometheusRule` alerts on it (`AfMcpServiceNoRoutableTools`). See [Adding a Service](adding-a-service.md). |
| `af_mcp_service_tools_unmapped` | gauge | `service` | Routable tools implicitly disabled by a dict-form `required_permission` (no key, no `__default__`), as of the last observed listing — the current-state counterpart of `af_mcp_tool_mapping_drift_total{kind="unmapped"}`. |

The six `af_mcp_metering_*` metrics are the pipeline's health signal, and
three of them are also its scaling trigger: a rising
`metering_queue_depth`, `metering_queue_delay_seconds`, or
`metering_queue_overflow_total` is the empirical signal to move metering
off the in-process queue onto a distributed backend. The seam already
exists — `MeteringBackend` in `metering.py`, selected by
`METERING_BACKEND` (chart: `broker.metering.backend`) — but only
`in_process` and the synchronous `inline` (tests, local dev) are implemented
today (the broker fails closed on any other value); a future taskiq-style transport is one new backend entry, not a
redesign.

Cardinality policy in one sentence: no metric above ever carries a
per-user label (or a raw token, jti, request ID, or tool argument) —
per-identity questions are answered from the audit log, and the full
reasoning is the module docstring of
`broker/src/af_mcp_broker/metrics.py`.

### Which signal carries what

Each signal has a cardinality budget, and identity only appears where the
signal is access-controlled and unbounded by design:

| Signal | Carries identity | Attributes | Cardinality |
|---|---|---|---|
| Prometheus metrics (`:9090`) | No | `service`, `tool`, `action_type`, `outcome`, `error_class`, `target` (per metric) | Bounded by `services.yaml` / `policy.yaml` |
| OTel metrics (OTLP) | No | `service`, `method`, `action_type`, `outcome`; plus `content_type` on the two size counters | Same bound; `content_type` is MCP's small type set, unknown types become `other` |
| Audit log (JSON lines) | Yes: `principal_sub`, `token_id`, `request_id`, `audit_id`, `trace_id` | One record per tool call | Unbounded by design; authoritative, behind access control |
| OTel usage events (OTLP logs, opt-in) | Yes: `principal_sub`, `token_id`, `audit_id`, `trace_id` | `service`, `method`, `outcome`, `duration_ms`, `result_bytes`, `result_tokens_est`, and `result_content.<type>.{blocks,bytes,tokens_est}`; never arguments or results | One per tool call; access control is the log backend's |
| Spans (OTLP, sampled) | Yes: `user.id` | Identity, outcome and timing; never arguments or results | Sampled; joins to the audit log by `trace_id` |

Rule of thumb: a question about *a user* is answered from the audit log
(or a trace); a question about *the facility* is answered from metrics.

## Operator: OTLP transport shared by every signal

Traces, OTel metrics and OTel usage events export to one collector,
configured once under `broker.otlp`; `broker.tracing.enabled`,
`broker.metrics.otlp.enabled` and `broker.usageEvents.otlp.enabled` are
only the per-signal switches. With every signal off, nothing OTel is
rendered.

```yaml
broker:
  otlp:
    endpoint: "http://otel-collector.observability.svc:4318"
    headers:
      existingSecret: { name: otlp-collector-auth, key: headers }
```

- `endpoint` renders `OTEL_EXPORTER_OTLP_ENDPOINT` once, whenever any
  signal is enabled, and is **transport only**: it switches nothing on.
  It is required when any signal is enabled (the chart refuses to render
  otherwise, and the broker refuses to start with an enabled signal and no
  endpoint, naming the signal's setting). Each signal appends its own
  `/v1/<signal>` path.
- Each signal has its own switch: `TRACING_ENABLED` (chart
  `broker.tracing.enabled`), `OTEL_METRICS_ENABLED` (chart
  `broker.metrics.otlp.enabled`) and `USAGE_EVENTS_OTLP_ENABLED` (chart
  `broker.usageEvents.otlp.enabled`). Enabling one does not enable the others.
- `headers` renders `OTEL_EXPORTER_OTLP_HEADERS` (`k1=v1,k2=v2`) for every
  signal. `existingSecret` holds the whole string behind a `secretKeyRef`,
  so credentials never sit in values; `value` is a literal for non-secret
  headers such as an MLflow `x-mlflow-experiment-id=3`. Set at most one.
- The chart's NetworkPolicy allows egress to `endpoint` while any signal is
  enabled, like every other URL in the values
  ([Adding a Service, Step 4](adding-a-service.md#step-4-declare-the-pods-behind-the-service-for-the-networkpolicy)).
  An in-cluster collector needs the `<service>.<namespace>.svc` host form and
  a `networkPolicy.egress.endpoints.<host>.podSelector` naming its pods.
- **Breaking rename.** `broker.tracing.endpoint` and
  `broker.tracing.networkPolicy` no longer exist, with no alias. Setting
  either makes the chart fail with a message naming `broker.otlp.endpoint` /
  `networkPolicy.egress.endpoints`. `broker.otlp.networkPolicy` was removed as well:
  the collector rule is generated from `broker.otlp.endpoint`. Tracing with an empty endpoint used to render
  silently as "off"; it now fails, because an enabled signal with no
  collector is a misconfiguration. **Setting `OTEL_EXPORTER_OTLP_ENDPOINT`
  alone no longer turns tracing on:** the broker now needs
  `TRACING_ENABLED=true` too (the chart renders both from
  `broker.tracing.enabled` and `broker.otlp.endpoint`). A deployment that
  set the endpoint by hand to get traces must add `TRACING_ENABLED=true`.

## Operator: OTel metrics (OTLP)

OTel metrics are **off by default** and the broker is an emitter only.
Prometheus on `:9090` is unchanged and is all a facility without an OTel
collector needs; turn this on to feed your own dashboards from a collector.
In the chart:

```yaml
broker:
  otlp:                      # shared collector, see "OTLP transport" below
    endpoint: "http://otel-collector.observability.svc:4318"
  metrics:
    otlp:
      enabled: true
```

- `broker.metrics.otlp.enabled` renders `OTEL_METRICS_ENABLED`. Unset,
  nothing is installed and recording is a no-op.
- The collector is shared with tracing through `broker.otlp` (see
  [OTLP transport](#operator-otlp-transport-shared-by-every-signal)): the
  endpoint, headers, timeout and TLS come from the standard
  `OTEL_EXPORTER_OTLP_*` variables, which the SDK exporter reads natively
  (appending `/v1/metrics`). Enabling metrics does not enable tracing:
  the endpoint is transport only.
- An unreachable collector never fails startup or a tool call; export
  failures are the periodic reader's background problem.

| Metric | Type | Unit | Meaning |
|---|---|---|---|
| `af_mcp.tool.calls` | counter | `{call}` | Tool calls that reached a backend. |
| `af_mcp.tool.errors` | counter | `{call}` | Of those, the ones that ended in error. |
| `af_mcp.tool.duration` | histogram | `s` | Wall time of the downstream call; same buckets as `af_mcp_tool_duration_seconds`. |
| `af_mcp.tool.result_bytes` | counter | `By` | Wire size of tool results, per `content_type`. |
| `af_mcp.tool.result_tokens_est` | counter | `{token}` | Estimated tokens of those results, per `content_type`. |

Every instrument carries exactly `service`, `method`, `action_type` and
`outcome`, and no other attribute — except that the two size counters also
carry `content_type`, bounded by MCP's type set (`text`, `structured`,
`image`, `audio`, `resource`, `resource_link`); any other type a backend
sends is labelled `other` here (Postgres and the audit log keep the real
string): a test fails if any metric gains a user,
token, jti or request-id attribute. Like usage accounting, these cover
success and error calls only; denied and unmapped calls never reach the
metering worker.

## Operator: per-call usage as OTel log events (opt-in)

To receive every tool call's usage record over OTLP (for example into Loki
or ClickHouse), alongside the usage store that backs `/v1/usage`,
`af_usage` and the portal:

```yaml
broker:
  otlp:
    endpoint: "http://otel-collector.observability.svc:4318"   # shared collector
  usageEvents:
    otlp:
      enabled: true
```

- `broker.usageEvents.otlp.enabled` renders `USAGE_EVENTS_OTLP_ENABLED`,
  off by default; off, the usage store is not wrapped and nothing changes.
- The collector is shared with tracing and OTel metrics through `broker.otlp`
  (same endpoint, headers and NetworkPolicy egress rule). Enabling this
  does not enable tracing: the endpoint is transport only.
- One log record (event name `af_mcp.usage`) is emitted for each usage
  record the store records, with exactly these attributes: `audit_id`,
  `trace_id`, `principal_sub`, `token_id`, `service`, `method`, `outcome`,
  `duration_ms`, `result_bytes`, `result_tokens_est`; a measured call also
  carries `result_content.<content_type>.blocks`, `.bytes` and `.tokens_est`
  for each content type of the result (the real type string). Unset optional
  values (no token for a session JWT, no trace when untraced, nothing
  measured) are omitted. Tool arguments and results are never included.
- Postgres stays authoritative and the audit log stays authoritative
  overall. Emission is a wrapper around the usage store, so every record
  path (batched, overflow, inline) is covered with no second call site, and
  it adds no Postgres load.
- A collector outage or overflow never affects a tool call or the Postgres
  write: the emitter only enqueues onto the SDK's batch processor, which
  exports on its own thread and drops on overflow. Delivery is
  at-least-once (a record redelivered to the store is emitted again), so
  receivers dedupe on `audit_id`. Events are emitted even when the Postgres
  write fails; the two sinks are independent.
- These records carry the caller's identity, so the receiving log backend
  holds per-user data and needs its own access control (out of scope for
  the broker, as for traces).

## Operator: enabling trace emission

Tracing is **off by default** and the broker is an emitter only — point
it at any OTLP/HTTP collector (Grafana Tempo, Jaeger, an OTel Collector,
…). In the chart:

```yaml
broker:
  otlp:
    endpoint: "http://otel-collector.observability.svc:4318"   # see OTLP transport
  tracing:
    enabled: true
    sampleRatio: ""          # empty = keep every trace
```

- `broker.tracing.enabled` renders `TRACING_ENABLED`, the broker's on/off
  switch for tracing: off, no tracer provider is installed and every OTel
  call — fastmcp's native spans included — no-ops, even if
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set for another signal.
  `broker.otlp.endpoint` renders as `OTEL_EXPORTER_OTLP_ENDPOINT` — the
  standard OTel env var, which the SDK's exporter reads natively (appending
  the `/v1/traces` signal path itself); it is transport only.
- `sampleRatio` (a head-sampling ratio in `[0, 1]`) renders as
  `OTEL_TRACES_SAMPLER=parentbased_traceidratio` plus
  `OTEL_TRACES_SAMPLER_ARG=<ratio>`; empty means the SDK default
  `parentbased_always_on` — every trace, fine at tool-call volumes.

An unreachable collector never fails startup or a tool call — export
failures are the batch exporter's background problem.

**Access-control the trace backend.** Spans carry `user.id` (the
principal's Keycloak subject) on every tool-call span — that is the point
of the trace ↔ audit join — so whatever backend receives them holds
per-user data and needs real access control. Concretely at this facility:
Grafana allows anonymous viewers, so do not expose a trace datasource
there unfiltered. Tool arguments and results never become span attributes
(see [payload privacy](architecture.md#distributed-tracing-opentelemetry)),
which bounds the damage but does not excuse an open trace UI.

## Users: joining your own traces

If your client instruments itself with OpenTelemetry, its trace does not
stop at the broker: a W3C `traceparent` sent inside the MCP request's
`_meta` (SEP-414 — see
[the tracing design](architecture.md#distributed-tracing-opentelemetry))
becomes the remote parent of the broker's `tools/call` span, and an
instrumented backend MCP server continues the same trace.

With the fastmcp Python client (3.4.4+) this is automatic — no manual
`_meta` plumbing. `Client.call_tool` injects the current span context into
`_meta` whenever a span is active and an OTel SDK is configured
(`fastmcp.telemetry.inject_trace_context`; with no SDK installed it
no-ops). A minimal traced script:

```python
import asyncio
import os

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Exports to your own collector -- reads OTEL_EXPORTER_OTLP_ENDPOINT.
provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("my-agent")

async def main() -> None:
    transport = StreamableHttpTransport(
        "https://mcp.example.org/mcp/",
        headers={"Authorization": f"Bearer {os.environ['MCP_BEARER_TOKEN']}"},
    )
    async with Client(transport) as client:
        with tracer.start_as_current_span("my-analysis-step"):
            # The client injects the active span's traceparent into _meta;
            # the broker's spans (and an instrumented backend's) join this trace.
            await client.call_tool("rucio_whoami", {})

asyncio.run(main())
```

Every `AuditRecord` also carries the span's `trace_id` (32-hex, `null`
when tracing is off). That is the join key for operators: given a trace
ID from a user's report (or a trace found in the collector), the audit
log's `trace_id` field finds the exact invocations — and their
measurements, which live only in the audit log and usage store, never on
spans.

## Audit log line shape

Audit records are emitted through structlog, so an audit line has the same
shape as every other broker log line. Each is one JSON object with
`event: "audit"`:

| Field | Meaning |
|---|---|
| `timestamp` | ISO 8601 UTC time the line was **written**. |
| `level` | Always `info`. |
| `logger` | `af_mcp_broker.audit.logger`. |
| `correlation_id`, `subject` | The request's correlation id and caller, when the record was written inside a request. A queued tool-call record carries the ids of the request that submitted it. |
| `recorded_at` | ISO 8601 UTC time the record was **created**; for a record the metering worker wrote later, earlier than `timestamp`. |
| `request_id` | For tool calls, the request's `correlation_id`, so the audit, `http.request.*` and usage lines of one call share one id. Other record types keep their own identifier (a token `jti`, a PAT `lookup_id`). |
| everything else | The `AuditRecord` fields: `audit_id`, `principal_sub`, `principal_uid`, `permission`, `target`, `action`, `action_type`, `args_summary`, `outcome`, `error`, and the metering and attribution fields above. |

Where the lines go: `AUDIT_LOG_FILE` is `-` (stdout, the default) or a file
path opened for appending. Either way the line is written through the audit
handler, never through the root handler, so the audit destination does not
change what other log lines look like. The stdout destination resolves
`sys.stdout` at each write rather than holding the stream it saw at startup.

Audit writes fail loudly. A failure to write a line raises to the code that
produced the record: the denial path, the inline fallback (no pipeline
running, or a full metering queue) and the credential and token endpoints
all surface it to the request. The metering worker has no caller to raise
to, so it logs `metering_audit_write_failed` at `error` level with the
traceback and the lost record's `audit_id`, `principal_sub`, `target`,
`action` and `outcome`, increments `af_mcp_metering_worker_errors_total`, and
keeps processing the queue.

Admin state changes are audited like tool calls: toggling maintenance mode
writes a `maintenance_enable` or `maintenance_disable` record (caller,
enabled or disabled, the reason given) and logs `maintenance_mode_changed`
at `info`. A toggle that loses the compare-and-set race changed nothing and
writes neither.

## HTTP request lines

Every request except the kubelet probes (`/v1/healthz`, `/v1/readyz`) logs
exactly one `http.request.received` and one `http.request.finished` line,
both under one `correlation_id`. A `/mcp` request is logged by
`AsgiAuthMiddleware` and a `/v1` request by the FastAPI request middleware;
neither logs the other's requests.

| Field | On | Meaning |
|---|---|---|
| `method`, `path` | `received`, `finished` | HTTP method and path. Never the query string, which may carry secrets. On `finished` each matched path parameter is shown as `{name}` (`/v1/admin/tokens/{lookup_id}`) so lines group by endpoint. |
| `status_code`, `duration_ms`, `exc_type` | `finished` | Response status (`null` when the request raised or the client disconnected first), wall time since `received`, and the exception class if one escaped. |
| `subject` | `finished` | The caller, once known. `received` never has it: it logs before identity resolves. Backend credential redeems (`/v1/credentials/*/redeem`) authenticate with a broker-issued token, and their `subject` is that token's `sub`. |
| `parent_request_id` | `finished` | Only on a backend credential redeem whose token was minted for a tool call: that call's `correlation_id`, so the redeem's request lines join to the call. The redeem's own id stays in `correlation_id`. Absent on every other request. |

## Process and portal log lines

Every line a broker pod writes is a JSON object. That includes uvicorn's own
lifecycle lines (`Started server process`, `Waiting for application startup.`,
`Application startup complete.`, `Uvicorn running on ...`, and the shutdown
counterparts), which are `event` lines on logger `uvicorn.error` at `info`.
uvicorn configures its loggers before the broker's code is imported, so the
image starts it with `--log-config
broker/src/af_mcp_broker/uvicorn_log_config.json` (`Containerfile.broker`), and
`python -m af_mcp_broker` (the `af-mcp-broker` script) loads the same file.
`pixi run -e dev broker` does not pass it and keeps uvicorn's plain-text lines
(see [Local development](local-development.md#uvicorn-lifecycle-lines)).
`uvicorn.access` stays at `warning`: the `http.request.received` /
`http.request.finished` lines carry the method, path, status and duration of
every request, with the correlation id.

The portal's nginx writes its standard access log. Two sources of lines with
no signal are left out of it: a successful kubelet probe (user agent
`kube-probe/*` answered 2xx or 3xx; a failing probe is still logged), and the
`[error] open() failed` line for the favicon the portal does not ship (the
request still answers 404 and is access-logged).

## Following one call end to end

Every `/v1` and `/mcp` request gets a broker-generated `correlation_id`; a
client cannot choose it. An `X-Request-ID` the client sent is logged on the
request as `client_request_id` (truncated to 128 characters) so the client
can find its call, and is never forwarded.

| Where | Field | Value |
|---|---|---|
| Broker request lines (`http.request.received`/`finished`), every other broker line of the request | `correlation_id` | The request's id. `subject` names the caller once known. |
| Audit record of a tool call | `request_id` and `correlation_id` | The same id. `audit_id` is unique to the record. |
| Usage row (`af_mcp_usage_events`) | `request_id` | The same id, joined to the audit line by `request_id` or `audit_id`. |
| Backend MCP server | `X-Request-ID` request header | The same id, on every HTTP request the broker makes to the backend for that call. A backend that logs the header shares the id with the broker. |
| Token services (servicex, voms, krb5, condor) | `X-Request-ID` request header | The same id. |
| Broker identity token minted for the call | `rid` claim | The same id (see [Auth § AF Broker Identity Token](auth.md)). |
| Credential release when the backend redeems (`krb5_ticket_release`, x509 and servicex equivalents) | `parent_request_id` | The `rid` of the token, so the release joins to the tool call. |
| Same credential-release line | `correlation_id`, `request_id` | The redeem request's own id, and the token's `jti`. These identify the redeem, not the tool call. |

To follow one call, take its `correlation_id` (from a 5xx or error body, an
audit line, or a client-side `X-Request-ID` found through `client_request_id`):

1. `correlation_id=<id>` finds the request lines, the audit record and any
   other broker line of the call.
2. `request_id=<id>` in the usage store finds its usage row.
3. `parent_request_id=<id>` finds every credential release the backend
   redeemed for it. One tool call can produce several, one per backend HTTP
   request that redeems; each is a real release and has its own `audit_id`.
4. The backend's logs, where it logs `X-Request-ID`, carry the same id.

`trace_id` joins the same lines to a trace when tracing is on. The W3C
`traceparent` rides inside the MCP request's `_meta`, not an HTTP header, so
it and `X-Request-ID` do not interact. 5xx bodies carry `correlation_id`, as
does the ServiceX link rejection (400); other 4xx bodies do not.

## `/v1` error responses in the log

Each error response from `/v1` logs one `http_exception` line with
`status_code`, `detail` and `path`. A 5xx logs at `error`, so an alert on
error-level lines sees a `/v1` outage; a 4xx (authentication, validation,
rate limit, conflict) logs at `info`, because it is the caller's request being
refused as designed, not a broker failure.

## Finding rate-limit refusals

Every 429, on `/v1` and on `/mcp`, also logs one `rate_limit_exceeded` line at
`info`, so a single search (`event=rate_limit_exceeded`) lists every lockout
and rate-limit refusal. On `/v1` it comes beside the generic `http_exception`
line; on `/mcp` it is the only line for the refusal besides the audit record.

| Field | Value |
|---|---|
| `subject` | The caller, or `null` when no identity was bound yet. |
| `limiter` | Which limiter refused: `x509_unlock` (too many failed passphrase attempts), `pat_mint` (PAT mint budget), `krb5_service` (krb5-token-service answered 429), `credential_service` (a credential service such as condor-token-service answered 429), `tool_rate_limit` (a `rate_limits` rule in `policy.yaml`). |
| `rule` | For `tool_rate_limit`, the exceeded rule as `<limit>/<window_seconds>s`. `null` for a limiter with one budget. |
| `retry_after_seconds` | The wait returned to the caller, the same value as the `Retry-After` header. |

## See also

- [Architecture § Audit](architecture.md#4-audit) — the metering
  pipeline's design, the cardinality policy, and the tracing subsection
  this page operationalizes.
- [Connecting a Client](connecting-a-client.md) — getting the bearer
  token the `curl` and Python examples above need.

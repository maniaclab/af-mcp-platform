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

The metering worker fills three measurements into each success/error audit
record (and the usage store accumulates them):

| Field | What it is |
|---|---|
| `duration_ms` | Wall time of the downstream tool call — credential resolution plus the backend call itself. |
| `result_bytes` | Size of the tool result's serialized text content — its text blocks, or the JSON of its structured content only when no text blocks are present (the two are alternatives, never summed, since backends commonly mirror one into the other). |
| `result_tokens_est` | A tiktoken **estimate** of the same text, using the `o200k_base` encoding by default (`TOKEN_ESTIMATE_ENCODING`; empty string disables token estimation, byte measurement is unaffected). |

Be clear about what the token number is: an estimate of what each tool
result would inject into an LLM client's context — **not**
provider-reported usage, and **not** the user's full LLM spend (their
prompts, the model's own output, and every non-tool token are invisible to
the broker). Dollars are never stored — only tokens — so cost is derived
at read time from a price table (see the next section) and repricing is a
config change, not a migration.

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

## Self-service usage: `GET /v1/usage`

Every user can query their own usage — and nobody else's: the subject
comes from the authenticated principal, never from a parameter. Like all
of `/v1`, the endpoint takes a Keycloak JWT (`aud=mcp-gateway`), not a
PAT.

Query parameters:

- `days` — trailing window in UTC calendar days, today inclusive
  (`1..365`, default `30`; `days=1` is just today).
- `model` — the [tokencost](https://github.com/AgentOps-AI/tokencost)
  price-table key whose *input* rate turns token estimates into
  `estimated_cost_usd`. Defaults to the broker's `cost_reference_model`
  (currently `claude-sonnet-4-20250514`); an unknown key is a 422.

```bash
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN

curl -sS "https://mcp.af.uchicago.edu/v1/usage?days=7" \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN"
```

Trimmed response:

```json
{
  "subject": "f1b0…",
  "window_days": 7,
  "cost_model": "claude-sonnet-4-20250514",
  "totals": {
    "calls": 42,
    "errors": 1,
    "duration_ms": 91834.2,
    "result_bytes": 1048576,
    "result_tokens_est": 262144,
    "estimated_cost_usd": 0.786432
  },
  "by_service": [
    {
      "service": "rucio-mcp",
      "calls": 30,
      "errors": 0,
      "result_bytes": 917504,
      "result_tokens_est": 229376,
      "estimated_cost_usd": 0.688128
    }
  ],
  "by_day": [
    { "date": "2026-08-24", "calls": 42, "result_tokens_est": 262144 }
  ]
}
```

**Honesty caveats** (verbatim from the endpoint's own description): token
counts are a tiktoken (o200k) ESTIMATE of the tool-result text injected
into the LLM client's context — not provider-reported usage, and not the
user's full LLM spend — and `estimated_cost_usd` is that estimate priced
at the chosen model's input rate.

An MCP client doesn't need to leave the MCP surface for this: the
broker-native `af_usage` method (alongside `af_whoami` and the builtin
`gateway_service` service's other methods) returns the same payload — totals,
`by_service`, `by_day` — for the calling principal, with the same
`days`/`model` parameters and the same honesty caveats in its tool
description, so the LLM can relay them.

`af_*` calls are themselves audited and metered like every other call
(service `gateway_service` in audit lines, usage rows, and metric labels — issue
maniaclab/af-mcp-platform#240), so they show up in this data too. In particular `af_usage` meters
itself: each call to it appears as one `gateway_service` call in the next usage
window it reports — accepted and deliberately visible.

The portal shows the same numbers as a usage card on its overview page
(`mcp-portal.af.uchicago.edu/overview/`), labeled with the same estimate
caveat, and in full — window selector, per-service table, daily activity —
on its Usage page (`mcp-portal.af.uchicago.edu/usage/`).

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

One idempotent table, `af_mcp_usage_events`, keyed by `audit_id`
(primary key) with an index on `(principal_sub, ts)`. Inserts use
`ON CONFLICT (audit_id) DO NOTHING`, so redelivery of the same record —
which best-effort metering permits — is safe by construction. The DDL is
`CREATE ... IF NOT EXISTS` and runs at broker startup (replicas racing
each other are fine); there is deliberately **no migration framework**
yet — one table plus one index does not justify one. There is also no
retention policy yet: rows are small (one per tool call), so revisit at
scale rather than up front.

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
| `af_mcp_tool_duration_seconds` | histogram | `service`, `tool`, `action_type` | Wall time of the downstream call (credential resolution + backend call); buckets sized up to 300 s for calls that mint credentials via ephemeral k8s Jobs. |
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
exists — `MeteringBackend` in `audit/pipeline.py`, selected by
`METERING_BACKEND` (chart: `broker.metering.backend`) — but only
`in_process` is implemented today (the broker fails closed on any other
value); a future taskiq-style transport is one new backend entry, not a
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
| Prometheus metrics (`:9090`) | No | `service`, `tool`, `action_type`, `target` (per metric) | Bounded by `services.yaml` / `policy.yaml` |
| OTel metrics (OTLP) | No | `service`, `method`, `action_type`, `outcome` | Same bound |
| Audit log (JSON lines) | Yes: `principal_sub`, `token_id`, `request_id`, `audit_id`, `trace_id` | One record per tool call | Unbounded by design; authoritative, behind access control |
| Spans (OTLP, sampled) | Yes: `user.id` | Identity, outcome and timing; never arguments or results | Sampled; joins to the audit log by `trace_id` |

Rule of thumb: a question about *a user* is answered from the audit log
(or a trace); a question about *the facility* is answered from metrics.

## Operator: OTLP transport shared by every signal

Traces and OTel metrics export to one collector, configured once under
`broker.otlp`; `broker.tracing.enabled` and `broker.metrics.otlp.enabled`
are only the per-signal switches. With every signal off, nothing OTel is
rendered.

```yaml
broker:
  otlp:
    endpoint: "http://otel-collector.observability:4318"
    headers:
      existingSecret: { name: otlp-collector-auth, key: headers }
    networkPolicy:
      namespaceSelector: { kubernetes.io/metadata.name: observability }
      podSelector: { app.kubernetes.io/name: otel-collector }
      port: 4318
```

- `endpoint` renders `OTEL_EXPORTER_OTLP_ENDPOINT` once, whenever any
  signal is enabled, and is **transport only**: it switches nothing on.
  It is required when any signal is enabled (the chart refuses to render
  otherwise, and the broker refuses to start with an enabled signal and no
  endpoint, naming the signal's setting). Each signal appends its own
  `/v1/<signal>` path.
- Each signal has its own switch: `TRACING_ENABLED` (chart
  `broker.tracing.enabled`), `OTEL_METRICS_ENABLED` (chart
  `broker.metrics.otlp.enabled`). Enabling one does not enable the other.
- `headers` renders `OTEL_EXPORTER_OTLP_HEADERS` (`k1=v1,k2=v2`) for every
  signal. `existingSecret` holds the whole string behind a `secretKeyRef`,
  so credentials never sit in values; `value` is a literal for non-secret
  headers such as an MLflow `x-mlflow-experiment-id=3`. Set at most one.
- `networkPolicy` renders one egress rule to the collector when any signal
  is enabled and the chart's NetworkPolicy is on; an empty
  `namespaceSelector` selects the release namespace, an empty
  `podSelector` allows any pod there.
- **Breaking rename.** `broker.tracing.endpoint` and
  `broker.tracing.networkPolicy` no longer exist, with no alias. Setting
  either makes the chart fail with a message naming `broker.otlp.endpoint` /
  `broker.otlp.networkPolicy`. Tracing with an empty endpoint used to render
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
    endpoint: "http://otel-collector.observability:4318"
    networkPolicy:
      namespaceSelector: { kubernetes.io/metadata.name: observability }
      podSelector: { app.kubernetes.io/name: otel-collector }
      port: 4318
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
| `af_mcp.tool.result_bytes` | counter | `By` | Serialized size of tool results (an estimate of what enters the LLM client's context). |
| `af_mcp.tool.result_tokens_est` | counter | `{token}` | Estimated tokens of those results. |

Every instrument carries exactly `service`, `method`, `action_type` and
`outcome`, and no other attribute: a test fails if any metric gains a user,
token, jti or request-id attribute. Like usage accounting, these cover
success and error calls only; denied and unmapped calls never reach the
metering worker.

## Operator: enabling trace emission

Tracing is **off by default** and the broker is an emitter only — point
it at any OTLP/HTTP collector (Grafana Tempo, Jaeger, an OTel Collector,
…). In the chart:

```yaml
broker:
  otlp:
    endpoint: "http://otel-collector.observability:4318"   # see OTLP transport
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
        "https://mcp.af.uchicago.edu/mcp/",
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

## Correlation ids on calls to token services

Every `/v1` request binds a `correlation_id` into the broker's log lines.
Calls to the AF-internal token services (servicex, voms, krb5, condor) send
it as `X-Request-ID`, so a token service that logs that header shares the id
with the broker's line. 5xx bodies carry `correlation_id`, as does the
ServiceX link rejection (400); other 4xx bodies do not.

## See also

- [Architecture § Audit](architecture.md#4-audit) — the metering
  pipeline's design, the cardinality policy, and the tracing subsection
  this page operationalizes.
- [Connecting a Client](connecting-a-client.md) — getting the bearer
  token the `curl` and Python examples above need.

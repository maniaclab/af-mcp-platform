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
broker-native `af_usage` tool (alongside `af_whoami` and the other `af_*`
tools) returns the same payload — totals, `by_service`, `by_day` — for the
calling principal, with the same `days`/`model` parameters and the same
honesty caveats in its tool description, so the LLM can relay them.

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
| `af_mcp_tool_invocations_unmapped_total` | counter | *(none)* | Tool names matching no registered service prefix (client-supplied, so never a label). |
| `af_mcp_metering_queue_overflow_total` | counter | *(none)* | Records that found the metering queue full and were written inline without measurement — nothing dropped, but tool calls are paying for audit I/O again. |
| `af_mcp_metering_queue_depth` | gauge | *(none)* | Records currently waiting in the metering queue. |
| `af_mcp_metering_queue_delay_seconds` | gauge | *(none)* | Time-in-queue of the most recently dequeued item; rising means the worker is falling behind. |
| `af_mcp_metering_worker_processed_total` | counter | *(none)* | Records fully processed by the metering worker (measured or not). |
| `af_mcp_metering_worker_errors_total` | counter | *(none)* | Measurement or audit-write failures in the pipeline — the record is still written unmeasured where possible. |
| `af_mcp_metering_records_missing_measurements_total` | counter | *(none)* | Success-path records written without measurements despite a result being present (overflow fallback + measurement failure). |
| `af_mcp_credential_cache_hits_total` / `..._misses_total` | counter | `target` | Credential cache lookups that did / did not find a valid cached credential. |
| `af_mcp_x509_proxy_mints_total` | counter | *(none)* | Successful x509/VOMS proxy mints. |
| `af_mcp_broker_identity_tokens_issued_total` | counter | `target` | AF Broker Identity Tokens actually minted (cache hits not counted). |
| `af_mcp_condor_tokens_issued_total` | counter | `target` | HTCondor IDTOKENs actually obtained from condor-token-service (cache hits not counted). |

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

## Operator: enabling trace emission

Tracing is **off by default** and the broker is an emitter only — point
it at any OTLP/HTTP collector (Grafana Tempo, Jaeger, an OTel Collector,
…). In the chart:

```yaml
broker:
  tracing:
    enabled: true
    endpoint: "http://otel-collector.observability:4318"
    sampleRatio: ""          # empty = keep every trace
    networkPolicy:
      namespaceSelector: { kubernetes.io/metadata.name: observability }
      podSelector: { app.kubernetes.io/name: otel-collector }
      port: 4318
```

- `endpoint` renders as `OTEL_EXPORTER_OTLP_ENDPOINT` — the standard OTel
  env var, which the SDK's exporter reads natively (appending the
  `/v1/traces` signal path itself). This is also the broker's on/off
  gate: unset, no tracer provider is installed and every OTel call —
  fastmcp's native spans included — no-ops.
- `sampleRatio` (a head-sampling ratio in `[0, 1]`) renders as
  `OTEL_TRACES_SAMPLER=parentbased_traceidratio` plus
  `OTEL_TRACES_SAMPLER_ARG=<ratio>`; empty means the SDK default
  `parentbased_always_on` — every trace, fine at tool-call volumes.
- `networkPolicy` renders an egress rule to the collector (only when
  tracing and the chart's NetworkPolicy are both enabled); an empty
  `namespaceSelector` selects the release namespace, an empty
  `podSelector` allows any pod there.

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

## See also

- [Architecture § Audit](architecture.md#4-audit) — the metering
  pipeline's design, the cardinality policy, and the tracing subsection
  this page operationalizes.
- [Connecting a Client](connecting-a-client.md) — getting the bearer
  token the `curl` and Python examples above need.

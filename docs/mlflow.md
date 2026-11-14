# MLflow and the AF MCP Platform

[MLflow](https://mlflow.org/) is an open-source platform for tracking machine
learning experiments, versioning models, and tracing and evaluating GenAI
applications. This page says what each tool is for, where they do not overlap,
why the broker meters usage itself instead of delegating to MLflow, and which
integrations between them are possible. Each integration is marked as
**verified against documentation**, **untested here**, or **not currently
possible**. None of them has been deployed at the facility.

MLflow facts on this page come from the MLflow documentation (links inline and
under [Sources](#sources)); the current PyPI release at the time of writing is
3.18.0. Where the MLflow documentation is silent, the page says so rather than
filling the gap.

## What each tool is for

| | MLflow | AF MCP platform |
|---|---|---|
| Core job | Record and compare ML work: runs, parameters, metrics, artifacts, models, GenAI traces, evaluations | Let an AI agent call facility services (Rucio, PanDA, HTCondor, ...) as the user, without the agent holding raw credentials |
| Who is the actor | A training script, an experiment, or an instrumented agent application that logs to a tracking server | The broker, between an MCP client and backend MCP servers |
| Identity | A tracking-server login (the optional basic-auth app) or a hosted-platform token | The caller's Keycloak identity; per-user credentials minted or fetched per call |
| Source of truth for | What an experiment or agent run did, how a model scored | Who called which tool, with what outcome ([audit log](observability.md)) |

In MLflow's own terms:

- **Tracking** records parameters, code versions, metrics and output files from
  ML code, organized into runs and experiments, optionally behind a tracking
  server that provides a REST API and UI
  ([Tracking](https://mlflow.org/docs/latest/ml/tracking/)).
- **Model Registry** is a central store that versions models, links each
  version to the run that produced it, and supports aliases such as "champion"
  ([Model Registry](https://mlflow.org/docs/latest/ml/model-registry/)).
- **GenAI tracing and evaluation** captures inputs, outputs and metadata for
  each step of an agent or LLM application, and scores applications with
  `mlflow.genai.evaluate` against datasets and scorers
  ([Tracing](https://mlflow.org/docs/latest/genai/tracing/),
  [Evaluation](https://mlflow.org/docs/latest/genai/eval-monitor/)).

The platform is described in [Architecture](architecture.md). It does not train
or register models, run evaluations, or store experiment results.

## Where they do not overlap

- **Model and experiment management.** The platform has no equivalent of
  runs, the model registry or evaluation datasets. If a facility user wants
  those, MLflow is the tool; nothing in the platform replaces or conflicts
  with it.
- **Credential brokering and authorization.** MLflow does not mint or hold
  facility credentials (IAM tokens, VOMS proxies, Kerberos tickets) and has no
  group-to-permission policy over tool calls. That is the platform's reason to
  exist.

## Why the broker meters usage itself

The question of using MLflow as the metering system came up in an alignment
review in 2026, and the decision was that it would not be. The broker meters
usage on its own, for these reasons:

- **The audit log is authoritative.** Each tool invocation produces one
  structured audit record with identity attached, written at the point where
  authorization is decided. The usage store, `GET /v1/usage`, the `af_usage`
  method and the portal usage page are all derived from those records and are
  best-effort ([Observability](observability.md)).
- **The broker sits at the trust boundary.** It sees every call, including
  denied and rate-limited ones, and it knows the caller's identity from the
  validated token and the directory, not from anything the client reports.
  Telemetry sent by an agent-side library is client-reported, so it can be
  missing, partial or wrong. It is useful, but it cannot be the record of what
  a user was allowed to do.
- **What is measured differs.** The broker measures the size of each tool
  result and a token estimate of it (`result_bytes`, `result_tokens_est`).
  It cannot see the user's prompts or model output, so it does not report LLM
  spend. An agent-side tracer sees the model calls but not the broker's
  authorization decisions.
- **Dependency direction.** The audit and usage path works with no tracking
  server deployed. MLflow's OTLP trace ingest requires the server to run with
  a SQL-based backend store
  ([ingest docs](https://mlflow.org/docs/latest/genai/tracing/opentelemetry/ingest/)),
  so making MLflow the record would tie each tool-call record to an external
  service's availability.

MLflow is therefore a place to *view* broker traces next to agent-side traces,
not a place the broker's records live.

## Integrations

### 1. Broker traces into an MLflow tracking server

**Status: verified against documentation; untested here.**

The broker already emits OpenTelemetry traces over OTLP/HTTP when tracing is
enabled ([Observability](observability.md#operator-enabling-trace-emission)).
Per the MLflow documentation, an MLflow server exposes an OTLP endpoint at
`/v1/traces`, supported from MLflow 3.6.0, and accepts OTLP/HTTP only (the
OTLP/gRPC endpoint is not supported). Every request must carry an
`x-mlflow-experiment-id` header naming the target experiment
([ingest docs](https://mlflow.org/docs/latest/genai/tracing/opentelemetry/ingest/)).

The chart renders only `OTEL_EXPORTER_OTLP_ENDPOINT` (plus the sampler
variables) for the broker; it has no value for exporter headers. Pointing
`broker.tracing.endpoint` straight at MLflow would therefore send no
experiment header. Route through an OpenTelemetry Collector instead, which
also lets the same spans go to a second backend. A Collector configuration
based on the one in MLflow's documentation:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  otlphttp/mlflow:
    endpoint: http://mlflow.mlflow:5000   # MLflow tracking server base URL
    headers:
      x-mlflow-experiment-id: "<experiment id>"
    compression: gzip                     # gzip/deflate accepted from MLflow 3.7.0
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp/mlflow]
```

The chart values are the same ones already documented for any collector:

```yaml
broker:
  tracing:
    enabled: true
    endpoint: "http://otel-collector.observability:4318"
    networkPolicy:
      namespaceSelector: { kubernetes.io/metadata.name: observability }
      podSelector: { app.kubernetes.io/name: otel-collector }
      port: 4318
```

What an operator needs:

- **Endpoint.** `<mlflow base URL>/v1/traces`, OTLP/HTTP. The Collector's
  `otlphttp` exporter appends the path.
- **Experiment.** Create an experiment for the broker and put its ID in the
  exporter header. MLflow's page names an optional `X-MLFLOW-WORKSPACE` header
  that applies only when workspaces are enabled on the server.
- **NetworkPolicy egress.** The broker's chart rule covers broker to
  Collector only. The Collector's egress to MLflow is outside this chart and
  must be allowed in the Collector's own namespace.
- **Auth.** The MLflow ingest page does not document authentication. MLflow
  ships an optional basic-auth app (`mlflow server --app-name basic-auth`)
  whose REST clients send an HTTP `Authorization` header
  ([basic auth docs](https://mlflow.org/docs/latest/self-hosting/security/basic-http-auth/)).
  Whether the `/v1/traces` endpoint is covered by that app, and whether the
  Collector's `otlphttp` `headers` can carry the credential, was not verified.
  The basic-auth page does not describe OIDC for the tracking server.
- **Access control.** Broker spans carry `user.id`, the principal's Keycloak
  subject. The access-control warning in
  [Observability](observability.md#operator-enabling-trace-emission) applies
  to MLflow exactly as to any trace backend: anyone who can open the
  experiment sees per-user data. Tool arguments and results are never span
  attributes, so they do not appear in MLflow either.
- **Not verified.** How MLflow renders spans that carry no GenAI semantic
  convention attributes (the broker's spans use `user.id` and `af.*`
  attributes, not `gen_ai.*`). MLflow documents an
  [attribute mapping](https://mlflow.org/docs/latest/genai/tracing/opentelemetry/attribute-mapping/)
  page that was not read in detail.

### 2. Joining agent-side and broker-side traces

**Status: each half verified against documentation; the join across both is
untested.**

The aim is one trace in MLflow that contains the agent's own steps and the
broker's `tools/call` spans.

- **Broker side (existing behavior).** A W3C `traceparent` sent in the MCP
  request's `_meta` becomes the remote parent of the broker's span, and the
  broker injects its own context toward instrumented backends
  ([Architecture](architecture.md#distributed-tracing-opentelemetry)). The
  fastmcp Python client does this automatically when an OpenTelemetry SDK is
  configured ([Observability](observability.md#users-joining-your-own-traces)).
- **MLflow side.** MLflow Tracing is documented as OpenTelemetry compatible.
  Its distributed-tracing guide propagates context over HTTP using the W3C
  `traceparent` header, through
  `get_tracing_context_headers_for_http_request()` and
  `set_tracing_context_from_http_request_headers()`, and requires both
  services to log to the same tracking server and experiment
  ([distributed tracing](https://mlflow.org/docs/latest/genai/tracing/app-instrumentation/distributed-tracing/)).

Both sides use the same `traceparent` format, so in principle a user whose
agent is traced by MLflow and calls the gateway with the fastmcp client would
get broker spans under the agent's span, provided the broker's spans reach the
same MLflow experiment (integration 1) and the active OpenTelemetry span is the
one MLflow created. That last condition has not been checked. The MLflow
documentation read for this page describes header propagation between HTTP
services, not the `_meta` field MCP uses, so the user's code may need to make
the span the fastmcp client sees active. Treat this as untested.

Even if the trace does not nest cleanly, the `trace_id` join still works at
the operator level: every audit record carries the span's 32-hex `trace_id`,
so a trace ID found in MLflow identifies the exact audited invocations and
their measurements ([Observability](observability.md#users-joining-your-own-traces)).

Nothing in the broker needs to change for this, and no per-user MLflow
credential is involved: the agent writes its own spans to MLflow with the
user's own MLflow access.

### 3. An MLflow MCP server behind the gateway

**Status: not currently possible as documented; untested.**

MLflow documents an experimental MCP server for managing traces, installed
with `pip install 'mlflow[mcp]>=3.5.1'` and launched with `mlflow mcp run`. It
exposes trace tools (`search_traces`, `get_trace`, `delete_traces`,
`set_trace_tag`, `delete_trace_tag`) and assessment tools (`log_feedback`,
`log_expectation`, `get_assessment`, `update_assessment`,
`delete_assessment`). It reaches the tracking server through
`MLFLOW_TRACKING_URI`. The page calls the server "experimental and may change
in future releases" ([MLflow MCP server](https://mlflow.org/docs/latest/genai/mcp/)).

The blocker is transport. The gateway registers backends by URL in
`services.yaml` (`url: http://.../mcp`; see
[Adding a Service](adding-a-service.md#step-1-add-the-service-to-the-aggregator-service-list)),
which requires an HTTP MCP endpoint. The MLflow page shows only a local
command launch and does not say whether `mlflow mcp run` can serve HTTP. Until
that is confirmed, or the server is wrapped by a stdio-to-HTTP bridge, it
cannot be registered. If an HTTP endpoint exists, the wiring would be:

- **Registration.** One entry under `aggregator.services` with a `name` that
  becomes the tool prefix (for example `mlflow`), a `url`, and a
  `required_permission`. Tools would be exposed as `mlflow_search_traces` and
  so on, following the prefix rule in
  [Adding a Service](adding-a-service.md#apply_namespace-tool-naming).
- **Auth type.** MLflow's documented authentication is basic auth with a
  username and password, and the broker has no provider that supplies that
  per user. With `auth_type: none` the MLflow server would run with one shared
  credential held by the backend pod. Every caller would then act as the same
  MLflow user, which makes the service **service-tier** under
  [Trust tiers](architecture.md#trust-tiers), not user-tier, and it needs the
  runbook, policy and named reviewer that tier requires. A per-user mode would
  need a new identity-provider type, which is a code change and outside
  "adding a service requires no code".
- **Permission and tool exposure.** The MLflow server has no documented
  read-only mode, and several of its tools delete or modify data
  (`delete_traces`, `delete_assessment`, `log_feedback`, ...). Use a dict-form
  `required_permission` to gate writes separately from reads, and
  `exclude_tools` to hide the deletion tools
  ([`exclude_tools`](adding-a-service.md#exclude_tools-hiding-backend-tools-entirely)).
  The [MCP Design Guide](mcp-design.md) asks every tool to declare
  `readOnlyHint`; whether MLflow's server does was not checked.
- **NetworkPolicy.** If the MLflow MCP pod is in the broker's namespace on
  port 8000 or 8080, no change is needed. Another port goes in
  `networkPolicy.broker.servicePorts`. A pod in another namespace is not
  supported by the chart today
  ([Adding a Service, Step 4](adding-a-service.md#step-4-allow-egress-to-the-service-in-networkpolicy-if-needed)).
  The MCP pod's own egress to the tracking server is outside this chart.

The use case would be an agent asking the gateway for traces of its own
earlier runs. The shared credential also means the permission is the only
thing limiting which traces a caller can read, so its scope matters.

### 4. Not planned or not possible

- **OTLP metrics or usage events into MLflow.** Broker OTel metrics (#375) and
  per-call OTel usage events (#376) are open and not merged. The MLflow pages
  read for this page document MLflow *exporting* a span-duration metric over
  OTLP; they say nothing about ingesting OTLP metrics or logs. Do not assume
  MLflow can be a sink for either. Revisit once #375 and #376 land and the
  signal formats are known.
- **MLflow as a metering backend.** Decided against; see
  [above](#why-the-broker-meters-usage-itself).
- **Model registry or evaluation integration.** There is no connection point
  between those MLflow features and the broker. A user's notebook that calls
  both is just two clients.

## Summary

| Integration | Broker change | Status |
|---|---|---|
| Broker traces to MLflow via a Collector | None | Verified against documentation; untested here |
| Joined agent and broker traces | None | Each half documented; the join is untested |
| MLflow MCP server as a backend | None, if it serves HTTP | Not possible as documented (transport); untested |
| OTLP metrics or usage events into MLflow | Depends on #375, #376 | Not documented by MLflow; not possible today |

## Sources

All pages read in November 2026. MLflow's `latest` documentation does not show
a version on most pages; the versions below are those the pages state.

- [OTLP trace ingestion](https://mlflow.org/docs/latest/genai/tracing/opentelemetry/ingest/):
  `/v1/traces`, OTLP/HTTP only, `x-mlflow-experiment-id` header, MLflow 3.6.0
  and later, gzip/deflate from 3.7.0, SQL backend store required.
- [OpenTelemetry overview](https://mlflow.org/docs/latest/genai/tracing/opentelemetry/)
  and [export via OTLP](https://mlflow.org/docs/latest/genai/tracing/opentelemetry/export/):
  MLflow exports traces and a span-duration metric; nothing on metric ingest.
- [Distributed tracing](https://mlflow.org/docs/latest/genai/tracing/app-instrumentation/distributed-tracing/):
  `traceparent` propagation, same tracking server and experiment.
- [MLflow MCP server](https://mlflow.org/docs/latest/genai/mcp/):
  `mlflow[mcp]>=3.5.1`, tool list, experimental, no transport stated.
- [Basic HTTP auth](https://mlflow.org/docs/latest/self-hosting/security/basic-http-auth/).
- [Tracking](https://mlflow.org/docs/latest/ml/tracking/),
  [Model Registry](https://mlflow.org/docs/latest/ml/model-registry/),
  [GenAI tracing](https://mlflow.org/docs/latest/genai/tracing/),
  [GenAI evaluation](https://mlflow.org/docs/latest/genai/eval-monitor/).
- [mlflow on PyPI](https://pypi.org/project/mlflow/): latest release 3.18.0.

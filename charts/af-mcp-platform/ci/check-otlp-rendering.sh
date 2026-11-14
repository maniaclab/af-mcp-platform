#!/usr/bin/env bash
# Content assertions for the shared OTLP transport (broker.otlp.*) and the
# per-signal switches (broker.tracing.enabled, broker.metrics.otlp.enabled).
# `helm lint` only proves these values files render; this proves what lands in
# the output. Run from the repository root.
set -euo pipefail

chart=charts/af-mcp-platform
ci=$chart/ci
common=(--set image.broker.tag=sha-test --set image.portal.tag=sha-test)

render() {
  helm template af-mcp-platform "$chart" "${common[@]}" "$@"
}

# expect_has <description> <needle> <rendered>
expect_has() {
  grep -qF -- "$2" <<<"$3" || {
    echo "FAIL ($1): missing '$2'" >&2
    exit 1
  }
}

# expect_lacks <description> <needle> <rendered>
expect_lacks() {
  if grep -qF -- "$2" <<<"$3"; then
    echo "FAIL ($1): unexpected '$2'" >&2
    exit 1
  fi
}

# expect_fails <description> <message fragment> <helm args...>
expect_fails() {
  local description=$1 fragment=$2
  shift 2
  local out
  if out=$(render "$@" 2>&1); then
    echo "FAIL ($description): chart rendered but should have failed" >&2
    exit 1
  fi
  grep -qF -- "$fragment" <<<"$out" || {
    echo "FAIL ($description): error did not mention '$fragment'" >&2
    echo "$out" >&2
    exit 1
  }
}

# Neither signal: nothing OTel-related is rendered.
neither=$(render -f "$ci/test-values.yaml")
for needle in OTEL_ USAGE_EVENTS 4318; do
  expect_lacks "neither" "$needle" "$neither"
done

# Tracing only: the generic endpoint (the broker's tracing gate), the sampler,
# and the egress rule; no metrics switch.
tracing=$(render -f "$ci/tracing-values.yaml")
expect_has "tracing only" "name: OTEL_EXPORTER_OTLP_ENDPOINT" "$tracing"
expect_has "tracing only" "http://otel-collector.observability:4318" "$tracing"
expect_has "tracing only" "name: OTEL_TRACES_SAMPLER_ARG" "$tracing"
expect_has "tracing only" "port: 4318" "$tracing"
expect_lacks "tracing only" "OTEL_METRICS_ENABLED" "$tracing"

# Metrics only: the per-signal endpoint, so tracing is NOT switched on.
metrics=$(render -f "$ci/otel-metrics-values.yaml")
expect_has "metrics only" "name: OTEL_METRICS_ENABLED" "$metrics"
expect_has "metrics only" "name: OTEL_EXPORTER_OTLP_METRICS_ENDPOINT" "$metrics"
expect_has "metrics only" "http://otel-collector.observability:4318/v1/metrics" "$metrics"
expect_has "metrics only" "port: 4318" "$metrics"
expect_lacks "metrics only" "name: OTEL_EXPORTER_OTLP_ENDPOINT" "$metrics"
expect_lacks "metrics only" "OTEL_TRACES_SAMPLER" "$metrics"

# Both signals, with headers from a Secret: one generic endpoint covers both,
# and the Secret is a secretKeyRef (the token never appears in the output).
both=$(render -f "$ci/otel-both-headers-values.yaml")
expect_has "both" "name: OTEL_EXPORTER_OTLP_ENDPOINT" "$both"
expect_has "both" "name: OTEL_METRICS_ENABLED" "$both"
expect_lacks "both" "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT" "$both"
expect_has "both" "name: OTEL_EXPORTER_OTLP_HEADERS" "$both"
expect_has "both" 'name: "otlp-collector-auth"' "$both"
expect_has "both" 'key: "headers"' "$both"
expect_has "both" "secretKeyRef" "$both"

# Usage events only: per-signal logs endpoint (tracing stays off), the
# switch, and the shared egress rule.
events=$(render -f "$ci/otel-usage-events-values.yaml")
expect_has "usage events only" "name: USAGE_EVENTS_OTLP_ENABLED" "$events"
expect_has "usage events only" "http://otel-collector.observability:4318/v1/logs" "$events"
expect_has "usage events only" "port: 4318" "$events"
expect_lacks "usage events only" "name: OTEL_EXPORTER_OTLP_ENDPOINT" "$events"
expect_lacks "usage events only" "OTEL_METRICS_ENABLED" "$events"

# A literal (non-secret) header renders as a plain value.
literal=$(render -f "$ci/otel-metrics-values.yaml" \
  --set broker.otlp.headers.value=x-mlflow-experiment-id=3)
expect_has "literal header" "name: OTEL_EXPORTER_OTLP_HEADERS" "$literal"
expect_has "literal header" 'value: "x-mlflow-experiment-id=3"' "$literal"

# The renamed keys fail with a message naming the new ones.
expect_fails "old broker.tracing.endpoint" "set broker.otlp.endpoint" \
  -f "$ci/test-values.yaml" --set broker.tracing.endpoint=http://x:4318
expect_fails "old broker.tracing.networkPolicy" "set broker.otlp.networkPolicy" \
  -f "$ci/test-values.yaml" --set broker.tracing.networkPolicy.port=4318

# A signal with no collector, or two header sources, is refused.
expect_fails "signal without endpoint" "broker.otlp.endpoint is required" \
  -f "$ci/test-values.yaml" --set broker.metrics.otlp.enabled=true
expect_fails "usage events without endpoint" "broker.otlp.endpoint is required" \
  -f "$ci/test-values.yaml" --set broker.usageEvents.otlp.enabled=true
expect_fails "both header sources" "only one of broker.otlp.headers.value" \
  -f "$ci/otel-both-headers-values.yaml" --set broker.otlp.headers.value=a=b

echo "OTLP rendering assertions passed"

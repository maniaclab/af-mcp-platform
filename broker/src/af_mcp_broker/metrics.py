"""Custom Prometheus metrics for the broker.

All custom metrics are defined here, once, against ``prometheus_client``'s
default registry -- the same registry ``app.py``'s lifespan serves via
``start_http_server()`` on ``METRICS_PORT`` (see ``app.py``). Defining
``Counter``/``Histogram``/``Gauge`` instances anywhere else risks
double-registration on module re-import (``prometheus_client`` raises
``ValueError`` the second time the same name is registered against the
same registry), so every call site imports the module-level instances below
rather than constructing its own.

Cardinality policy -- read this before adding a label or a new metric:

- No metric here may carry a per-user label (username, unixname, subject,
  or any other user identifier) -- not because the set is unbounded, but
  because the audit log (``audit/logger.py``) already records every
  invocation with the caller's identity attached, at full fidelity and
  behind access control, while these Prometheus series are long-retained
  and broadly readable via Grafana. A per-user label here would duplicate
  the audit log at worse fidelity while adding storage cost and a privacy
  surface. Per-identity questions are answered from the audit log, never
  from these counters.
- NEVER label a metric with a raw token, jti, request ID, or tool argument
  either -- those are attacker-influenced or session-scoped and unbounded,
  and will exhaust Prometheus memory.
- ``service`` and ``action_type`` are drawn from the operator-configured
  ``services.yaml`` / ``policy.yaml`` (single/low-digit cardinality at
  facility scale) -- safe on every counter that carries them.
- ``tool`` is also configuration-bound (a service's own fixed schema, on
  the order of dozens of names) -- safe on ``tool_invocations_total``.
- ``target`` on the credential-cache counters is the configured service
  target set (``services.yaml``), not user input.
- A tool call whose name matches no registered service prefix is audited
  (see ``audit/logger.py``) but deliberately NOT counted by tool name here
  -- an unmapped tool name is client-supplied and unbounded (a buggy or
  hostile client can send an arbitrary string per call).
  ``tool_invocations_unmapped_total`` carries no labels at all, so a burst
  of these is still visible without any cardinality risk.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

tool_invocations_total = Counter(
    "af_mcp_tool_invocations_total",
    "Tool invocations attempted via the /mcp aggregator, by service, tool, "
    "and action_type. Incremented once per call regardless of outcome "
    "(success, denied, or error) -- see tool_invocations_denied_total to "
    "isolate denials. No identity label -- see module docstring.",
    ["service", "tool", "action_type"],
)

tool_invocations_denied_total = Counter(
    "af_mcp_tool_invocations_denied_total",
    "Tool invocations denied by AuthorizationMiddleware for a known service.",
    ["service", "action_type"],
)

tool_duration_seconds = Histogram(
    "af_mcp_tool_duration_seconds",
    "Wall time of the downstream tool call (credential resolution plus the "
    "backend call itself), by service, tool, and action_type. Observed on "
    "success and error alike -- outcome is deliberately not a label; the "
    "audit log is the per-outcome source of truth. No identity label -- "
    "see module docstring. Buckets are sized for tool calls that can "
    "include credential minting via ephemeral k8s Jobs (tens of seconds "
    "to minutes), not just fast HTTP proxying.",
    ["service", "tool", "action_type"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0),
)

tool_invocations_unmapped_total = Counter(
    "af_mcp_tool_invocations_unmapped_total",
    "Tool invocations whose name matched no registered service prefix. "
    "No labels -- see module docstring.",
)

metering_queue_overflow_total = Counter(
    "af_mcp_metering_queue_overflow_total",
    "Audit records that found the metering pipeline's queue full and were "
    "written inline without measurement instead (audit/pipeline.py) -- "
    "nothing is dropped, but a nonzero rate means tool calls are paying "
    "for audit I/O again. No labels -- see module docstring.",
)

metering_queue_depth = Gauge(
    "af_mcp_metering_queue_depth",
    "Audit records currently waiting in the metering pipeline's queue "
    "(audit/pipeline.py), updated after every enqueue and dequeue. No "
    "labels -- see module docstring.",
)

metering_queue_delay_seconds = Gauge(
    "af_mcp_metering_queue_delay_seconds",
    "Time-in-queue (seconds) of the item the metering worker most recently "
    "dequeued. A rising value means the worker is falling behind the "
    "enqueue rate; together with metering_queue_depth and "
    "metering_queue_overflow_total this is the empirical trigger for "
    "introducing a distributed metering backend (audit/pipeline.py's "
    "MeteringBackend seam). No labels -- see module docstring.",
)

metering_worker_processed_total = Counter(
    "af_mcp_metering_worker_processed_total",
    "Audit records fully processed by the metering worker -- written, "
    "measured or not. No labels -- see module docstring.",
)

metering_worker_errors_total = Counter(
    "af_mcp_metering_worker_errors_total",
    "Measurement or audit-write failures in the metering pipeline's "
    "processing path (audit/pipeline.py's warning sites) -- the record is "
    "still written unmeasured where possible, never dropped. No labels -- "
    "see module docstring.",
)

metering_records_missing_measurements_total = Counter(
    "af_mcp_metering_records_missing_measurements_total",
    "Success-path audit records written WITHOUT result measurements even "
    "though a result was present to measure: the queue-overflow inline "
    "fallback and the measurement-failure path (audit/pipeline.py). No "
    "labels -- see module docstring.",
)

credential_cache_hits_total = Counter(
    "af_mcp_credential_cache_hits_total",
    "Credential cache lookups that returned a still-valid cached credential.",
    ["target"],
)

credential_cache_misses_total = Counter(
    "af_mcp_credential_cache_misses_total",
    "Credential cache lookups that found no valid cached credential.",
    ["target"],
)

x509_proxy_mints_total = Counter(
    "af_mcp_x509_proxy_mints_total",
    "Successful x509/VOMS proxy mints. No labels -- see module docstring.",
)

broker_identity_tokens_issued_total = Counter(
    "af_mcp_broker_identity_tokens_issued_total",
    "AF Broker Identity Tokens actually minted (issue #162) -- cache hits "
    "are not counted (see credential_cache_hits_total). `target` is the "
    "configured service target set, not user input; no identity label -- "
    "see module docstring.",
    ["target"],
)

condor_tokens_issued_total = Counter(
    "af_mcp_condor_tokens_issued_total",
    "HTCondor IDTOKENs actually obtained from condor-token-service (issue "
    "#169) -- cache hits are not counted (see credential_cache_hits_total). "
    "`target` is the configured service target set, not user input; no "
    "identity label -- see module docstring.",
    ["target"],
)

maintenance_store_unavailable_total = Counter(
    "af_mcp_maintenance_store_unavailable_total",
    "require_not_in_maintenance (identity.py) failed to reach the "
    "maintenance-mode store and fell open, letting the non-admin request "
    "through as if maintenance mode were disabled -- see that function's "
    "docstring for why this fails open rather than closed, and for the "
    "resulting limitation: maintenance mode cannot be relied on as an "
    "incident-containment control if the store itself is within the "
    "incident's blast radius. A nonzero rate means maintenance mode has "
    "silently stopped enforcing and needs operator attention. No labels "
    "-- see module docstring.",
)

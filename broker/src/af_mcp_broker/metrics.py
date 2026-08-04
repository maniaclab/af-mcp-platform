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

- ``identity`` (``principal.unixname``) is the only per-user label anywhere
  in this module, and it appears on exactly one counter
  (``tool_invocations_total``). NEVER label a metric with a raw token, jti,
  request ID, or tool argument -- those are attacker-influenced or
  session-scoped and unbounded, and will exhaust Prometheus memory.
- ``backend`` and ``action_type`` are drawn from the operator-configured
  ``backends.yaml`` / ``policy.yaml`` (single/low-digit cardinality at
  facility scale) -- safe on every counter that carries them.
- ``tool`` is also configuration-bound (a backend's own fixed schema, on
  the order of dozens of names) but is deliberately kept OFF the
  identity-bearing counter: ``identity x backend x action_type`` already
  covers per-user rate dashboards, and multiplying that by ~50 tools per
  backend would buy little dashboard value for a large increase in series.
- ``username`` on the x509 mint counter is the same bounded set as
  ``identity`` above -- kept because the dashboard already keys the
  "mints per hour" panel by user, and x509 mints are inherently rare and
  expensive (one Kubernetes Job each), so the series count stays small even
  at full facility scale.
- ``target`` on the credential-cache counters is the configured backend
  target set (``backends.yaml``), not user input.
- A tool call whose name matches no registered backend prefix is audited
  (see ``audit/logger.py``) but deliberately NOT counted by tool name here
  -- an unmapped tool name is client-supplied and unbounded (a buggy or
  hostile client can send an arbitrary string per call).
  ``tool_invocations_unmapped_total`` carries no labels at all, so a burst
  of these is still visible without any cardinality risk.
"""

from __future__ import annotations

from prometheus_client import Counter

tool_invocations_total = Counter(
    "af_mcp_tool_invocations_total",
    "Tool invocations attempted via the /mcp aggregator, by identity. "
    "Incremented once per call regardless of outcome (success, denied, or "
    "error) -- see tool_invocations_denied_total to isolate denials.",
    ["identity", "backend", "action_type"],
)

tool_invocations_by_tool_total = Counter(
    "af_mcp_tool_invocations_by_tool_total",
    "Tool invocations attempted via the /mcp aggregator, by tool. "
    "Deliberately has no identity label -- see module docstring.",
    ["backend", "tool", "action_type"],
)

tool_invocations_denied_total = Counter(
    "af_mcp_tool_invocations_denied_total",
    "Tool invocations denied by AuthorizationMiddleware for a known backend.",
    ["backend", "action_type"],
)

tool_invocations_unmapped_total = Counter(
    "af_mcp_tool_invocations_unmapped_total",
    "Tool invocations whose name matched no registered backend prefix. "
    "No labels -- see module docstring.",
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
    "Successful x509/VOMS proxy mints, by username.",
    ["username"],
)

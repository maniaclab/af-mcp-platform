from __future__ import annotations

# Deliberately does NOT re-export from mcp.aggregator here (as it used to):
# aggregator.py now imports mcp.diagnostics, which imports api.permissions
# for ServiceStatus/_service_status reuse (issue #153) -- api.permissions in
# turn imports from mcp.registry, and importing any submodule of this
# package runs this __init__.py first. Eagerly pulling in aggregator.py here
# would make importing mcp.registry alone (as api.permissions does) trigger
# aggregator.py -> mcp.diagnostics -> api.permissions while api.permissions
# is itself still mid-import -- a real circular-import failure, not a lazy-
# import inconvenience to work around. Every caller already imports directly
# from the submodule it needs (mcp.aggregator's build_aggregator/
# populate_aggregator, mcp.registry's ServiceRegistry/ServiceSpec), so this
# package-level re-export was never load-bearing.
from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec

__all__ = [
    "ServiceRegistry",
    "ServiceSpec",
]

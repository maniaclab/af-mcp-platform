from __future__ import annotations

# Deliberately does NOT re-export from mcp.aggregator here (as it used to):
# aggregator.py now imports mcp.diagnostics, which imports api.capabilities
# for BackendStatus/_backend_status reuse (issue #153) -- api.capabilities in
# turn imports from mcp.registry, and importing any submodule of this
# package runs this __init__.py first. Eagerly pulling in aggregator.py here
# would make importing mcp.registry alone (as api.capabilities does) trigger
# aggregator.py -> mcp.diagnostics -> api.capabilities while api.capabilities
# is itself still mid-import -- a real circular-import failure, not a lazy-
# import inconvenience to work around. Every caller already imports directly
# from the submodule it needs (mcp.aggregator's build_aggregator/
# populate_aggregator, mcp.registry's BackendRegistry/BackendSpec), so this
# package-level re-export was never load-bearing.
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec

__all__ = [
    "BackendRegistry",
    "BackendSpec",
]

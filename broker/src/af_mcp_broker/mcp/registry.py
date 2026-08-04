from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml  # type: ignore[import-untyped]


@dataclass
class BackendSpec:
    name: str
    prefix: str
    url: str
    transport: str  # "http" | "sse"
    # The capability a caller must hold to invoke this backend's tools:
    #   - a capability name (e.g. "read_data") -> gated on that capability.
    #   - "__none__" -> open to any authenticated user (deliberate opt-in).
    #   - None (omitted) -> no capability gate; the credential layer is the
    #     gate instead (the caller must have a linked identity / mintable
    #     credential for this target). app.py's lifespan refuses to start if
    #     a backend omits this AND has no resolvable credential provider,
    #     since that would mean no gate at all -- see issue #60.
    required_capability: str | None = None
    auth_type: str = "bearer"  # "bearer" | "x509" | "none"
    description: str = ""
    display_name: str = ""
    # Whether the aggregator namespaces this backend's tools as
    # "<prefix>_<toolname>". Defaults to True because that's what prevents
    # two backends from advertising the same tool name and one silently
    # shadowing the other. Backends whose tools are already self-prefixed
    # (e.g. rucio-mcp ships "rucio_list_dids") must set this False, or
    # namespacing would double up into "rucio_rucio_list_dids" -- see
    # docs/adding-a-backend.md's apply_namespace section and #113 for when
    # False stops being safe.
    apply_namespace: bool = True
    # Per-call read timeout (seconds) applied to this backend's Client, so a
    # slow/unresponsive backend fails that one call cleanly instead of
    # hanging the aggregator. 30s is a generous default for a synchronous
    # tool call; docs/adding-a-backend.md's example already assumes this
    # value, so it doubles as an operator-visible default.
    timeout_seconds: float = 30.0
    # How long (seconds) ProxyProvider's _get_tool() may serve a cached
    # component list for this backend before refreshing -- see aggregator.py's
    # _make_client_factory docstring for the cross-user cache assumption this
    # relies on (tool schemas, not credentials, are what's cached). 300s
    # matches fastmcp's own ProxyProvider default; set 0 to disable caching
    # entirely for a backend whose tool list personalizes per caller.
    tools_cache_ttl: float = 300.0


class BackendRegistry:
    """Config-driven backend registry. Adding a backend = one YAML entry, no code change."""

    def __init__(self) -> None:
        self._backends: dict[str, BackendSpec] = {}

    def load(self, path: str) -> None:
        with Path(path).open() as fh:
            raw = yaml.safe_load(fh) or {}
        for entry in raw.get("backends", []):
            spec = BackendSpec(
                name=entry["name"],
                prefix=entry.get("prefix", entry["name"]),
                url=entry["url"],
                transport=entry.get("transport", "http"),
                required_capability=entry.get("required_capability"),
                auth_type=entry.get("auth_type", "bearer"),
                description=entry.get("description", ""),
                display_name=entry.get("display_name", ""),
                apply_namespace=entry.get("apply_namespace", True),
                timeout_seconds=entry.get("timeout_seconds", 30.0),
                tools_cache_ttl=entry.get("tools_cache_ttl", 300.0),
            )
            self._backends[spec.name] = spec

    def register(self, backend: BackendSpec) -> None:
        self._backends[backend.name] = backend

    def all_backends(self) -> list[BackendSpec]:
        return list(self._backends.values())

    def get(self, name: str) -> BackendSpec | None:
        return self._backends.get(name)

    def get_by_tool_prefix(self, tool_name: str) -> BackendSpec | None:
        """Find the backend that owns a tool by matching its prefix."""
        for spec in self._backends.values():
            if tool_name == spec.prefix or tool_name.startswith(f"{spec.prefix}_"):
                return spec
        return None

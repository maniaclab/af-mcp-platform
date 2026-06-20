from __future__ import annotations

from dataclasses import dataclass, field

import yaml


@dataclass
class BackendSpec:
    name: str
    prefix: str
    url: str
    transport: str  # "http" | "sse"
    required_capability: str
    entitlement_groups: list[str] = field(default_factory=list)
    auth_type: str = "bearer"  # "bearer" | "x509" | "none"


class BackendRegistry:
    """Config-driven backend registry. Adding a backend = one YAML entry, no code change."""

    def __init__(self) -> None:
        self._backends: dict[str, BackendSpec] = {}

    def load(self, path: str) -> None:
        with open(path) as fh:
            raw = yaml.safe_load(fh)
        for entry in raw.get("backends", []):
            spec = BackendSpec(
                name=entry["name"],
                prefix=entry.get("prefix", entry["name"]),
                url=entry["url"],
                transport=entry.get("transport", "http"),
                required_capability=entry.get("required_capability", "__none__"),
                entitlement_groups=entry.get("entitlement_groups", []),
                auth_type=entry.get("auth_type", "bearer"),
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

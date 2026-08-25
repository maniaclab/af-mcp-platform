from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings

# Reserved for the broker-native diagnostic tools registered directly on the
# aggregator (mcp/diagnostics.py, issue #153): af_whoami, af_list_identities,
# af_list_mcp_servers. No service may configure this prefix -- doing so would
# let a service's own tools ("af_<toolname>", once namespaced) shadow the
# diagnostic tools' names in a caller's tools/list, defeating the "always
# visible, never proxied" guarantee those tools exist to provide. Enforced by
# ServiceRegistry.register() below.
#
# These names live here rather than in mcp/diagnostics.py itself so that
# EntitlementMiddleware/AuthorizationMiddleware (which need DIAGNOSTIC_TOOL_NAMES
# to bypass entitlement/authorization for these tools) and api/capabilities.py
# (which names them in a status_detail sentence -- see _STATUS_DETAILS) can
# both import them without either importing mcp/diagnostics.py itself, which
# in turn imports api/capabilities.py's _service_status -- that would be a
# straight import cycle.
RESERVED_PREFIX = "af"
WHOAMI_TOOL_NAME = f"{RESERVED_PREFIX}_whoami"
LIST_IDENTITIES_TOOL_NAME = f"{RESERVED_PREFIX}_list_identities"
LIST_MCP_SERVERS_TOOL_NAME = f"{RESERVED_PREFIX}_list_mcp_servers"
LINK_IDENTITY_TOOL_NAME = f"{RESERVED_PREFIX}_link_identity"
DIAGNOSTIC_TOOL_NAMES = frozenset(
    {
        WHOAMI_TOOL_NAME,
        LIST_IDENTITIES_TOOL_NAME,
        LIST_MCP_SERVERS_TOOL_NAME,
        LINK_IDENTITY_TOOL_NAME,
    }
)


def identity_provider_url(settings: Settings, alias: str) -> str:
    """Build the portal Identities page's deep link for one identity-provider alias.

    Shared by the not-linked ``ToolError`` aggregator.py's ``_bearer_factory``/
    ``_x509_factory`` raise and ``af_link_identity`` (mcp/diagnostics.py) so
    the URL format can never drift between "here's why you're blocked" and
    "here's the link you asked for" (stage 1 of the elicitation/link-identity
    design -- see the af-mcp-platform issue tracker). Lives here rather than
    in aggregator.py or diagnostics.py because both of those modules already
    import from this one, and diagnostics.py is itself imported by
    aggregator.py -- a shared helper in either of them would risk an import
    cycle the other way.
    """
    portal = settings.portal_url.rstrip("/")
    return f"{portal}/identities#identity-card-{alias}"


@dataclass
class ServiceSpec:
    name: str
    prefix: str
    url: str
    transport: str  # "http" | "sse"
    # The capability a caller must hold to invoke this service's tools:
    #   - a capability name (e.g. "read_data") -> gated on that capability.
    #   - "__none__" -> open to any authenticated user (deliberate opt-in).
    #   - None (omitted) -> no capability gate; the credential layer is the
    #     gate instead (the caller must have a linked identity / mintable
    #     credential for this target). app.py's lifespan refuses to start if
    #     a service omits this AND has no resolvable credential provider,
    #     since that would mean no gate at all -- see issue #60.
    required_capability: str | None = None
    auth_type: str = "bearer"  # "bearer" | "x509" | "none"
    description: str = ""
    display_name: str = ""
    # Whether the aggregator namespaces this service's tools as
    # "<prefix>_<toolname>". Defaults to True because that's what prevents
    # two services from advertising the same tool name and one silently
    # shadowing the other. Services whose tools are already self-prefixed
    # (e.g. rucio-mcp ships "rucio_list_dids") must set this False, or
    # namespacing would double up into "rucio_rucio_list_dids" -- see
    # docs/adding-a-service.md's apply_namespace section and #113 for when
    # False stops being safe.
    apply_namespace: bool = True
    # Per-call read timeout (seconds) applied to this service's Client, so a
    # slow/unresponsive service fails that one call cleanly instead of
    # hanging the aggregator. 30s is a generous default for a synchronous
    # tool call; docs/adding-a-service.md's example already assumes this
    # value, so it doubles as an operator-visible default.
    timeout_seconds: float = 30.0
    # How long (seconds) ProxyProvider's _get_tool() may serve a cached
    # component list for this service before refreshing -- see aggregator.py's
    # _make_client_factory docstring for the cross-user cache assumption this
    # relies on (tool schemas, not credentials, are what's cached). 300s
    # matches fastmcp's own ProxyProvider default; set 0 to disable caching
    # entirely for a service whose tool list personalizes per caller.
    tools_cache_ttl: float = 300.0


class ServiceRegistry:
    """Config-driven service registry. Adding a service = one YAML entry, no code change."""

    def __init__(self) -> None:
        self._services: dict[str, ServiceSpec] = {}
        # service name -> most recently classified tools/list failure reason
        # ("not_linked" | "unauthorized" | "unavailable", see aggregator.py's
        # _classify_list_failure). Best-effort, last-write-wins, no history --
        # lets /v1/catalog's status derivation (issue #123) factor in a recent
        # listing failure without an extra live probe of its own.
        self._recent_list_failures: dict[str, str] = {}

    def load(self, path: str) -> None:
        with Path(path).open() as fh:
            raw = yaml.safe_load(fh) or {}
        for entry in raw.get("services", []):
            spec = ServiceSpec(
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
            self.register(spec)

    def register(self, service: ServiceSpec) -> None:
        if service.prefix == RESERVED_PREFIX:
            msg = (
                f"service '{service.name}' cannot use prefix "
                f"'{RESERVED_PREFIX}' -- reserved for the broker's own "
                f"af_* diagnostic tools ({sorted(DIAGNOSTIC_TOOL_NAMES)}, "
                "issue #153). Choose a different prefix."
            )
            raise ValueError(msg)
        self._services[service.name] = service

    def all_services(self) -> list[ServiceSpec]:
        return list(self._services.values())

    def get(self, name: str) -> ServiceSpec | None:
        return self._services.get(name)

    def get_by_tool_prefix(self, tool_name: str) -> ServiceSpec | None:
        """Find the service that owns a tool by matching its prefix."""
        for spec in self._services.values():
            if tool_name == spec.prefix or tool_name.startswith(f"{spec.prefix}_"):
                return spec
        return None

    def record_list_failure(self, name: str, reason: str) -> None:
        """Record the most recent classified tools/list failure *reason* for service *name*. Called by aggregator.py's _ObservableProxyProvider when a tools/list request fails -- see _classify_list_failure."""
        self._recent_list_failures[name] = reason

    def clear_list_failure(self, name: str) -> None:
        """Clear any recorded tools/list failure reason for *name*. Called by aggregator.py's _ObservableProxyProvider on a successful tools/list, so a service that recovers stops being reported "unavailable" -- record_list_failure() has last-write-wins semantics but nothing previously cleared a stale reason on success, so it otherwise persisted for the life of the process. No-op if nothing was recorded."""
        self._recent_list_failures.pop(name, None)

    def recent_list_failure(self, name: str) -> str | None:
        """Return the most recently recorded tools/list failure reason for *name*, or None if none has been recorded (the healthy default)."""
        return self._recent_list_failures.get(name)

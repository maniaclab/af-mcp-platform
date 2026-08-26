from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings

# Reserved for the broker's own methods, registered directly on the
# aggregator (mcp/diagnostics.py, issue #153): af_whoami, af_list_identities,
# af_list_mcp_servers, af_link_identity, af_usage. The prefix belongs to the
# builtin BUILTIN_SERVICE_NAME entry ServiceRegistry self-registers below
# (issue #240) -- no operator service may configure it: doing so would let a
# service's own tools ("af_<toolname>", once namespaced) shadow these methods'
# names in a caller's tools/list, defeating the "always visible, never
# proxied" guarantee they exist to provide. Enforced by
# ServiceRegistry.register() below.
#
# These names live here rather than in mcp/diagnostics.py itself so that
# api/permissions.py (which names them in a status_detail sentence -- see
# _STATUS_DETAILS) and mcp/aggregator.py (which names them in the not-linked
# ToolError text) can import them without importing mcp/diagnostics.py
# itself, which in turn imports api/permissions.py's _service_status -- that
# would be a straight import cycle.
RESERVED_PREFIX = "af"
# The registry's self-registered entry for the broker's own af_* methods --
# see _builtin_service_spec() below.
BUILTIN_SERVICE_NAME = "af-mcp"
WHOAMI_TOOL_NAME = f"{RESERVED_PREFIX}_whoami"
LIST_IDENTITIES_TOOL_NAME = f"{RESERVED_PREFIX}_list_identities"
LIST_MCP_SERVERS_TOOL_NAME = f"{RESERVED_PREFIX}_list_mcp_servers"
LINK_IDENTITY_TOOL_NAME = f"{RESERVED_PREFIX}_link_identity"
USAGE_TOOL_NAME = f"{RESERVED_PREFIX}_usage"
DIAGNOSTIC_TOOL_NAMES = frozenset(
    {
        WHOAMI_TOOL_NAME,
        LIST_IDENTITIES_TOOL_NAME,
        LIST_MCP_SERVERS_TOOL_NAME,
        LINK_IDENTITY_TOOL_NAME,
        USAGE_TOOL_NAME,
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
    # The permission a caller must hold to invoke this service's tools:
    #   - a permission name (e.g. "read_data") -> gated on that permission.
    #   - "__none__" -> open to any authenticated user (deliberate opt-in).
    #   - None (omitted) -> no permission gate; the credential layer is the
    #     gate instead (the caller must have a linked identity / mintable
    #     credential for this target). app.py's lifespan refuses to start if
    #     a service omits this AND has no resolvable credential provider,
    #     since that would mean no gate at all -- see issue #60.
    required_permission: str | None = None
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
    # True only for the registry's self-registered BUILTIN_SERVICE_NAME entry
    # (issue #240) -- the broker's own af_* methods, dispatched by the
    # aggregator's local provider rather than proxied anywhere. Not a
    # services.yaml key: load() never reads it, and register() refuses the
    # builtin name/prefix outright, so an operator entry can never be builtin.
    builtin: bool = False


def _builtin_service_spec() -> ServiceSpec:
    """Build the broker's own ``af-mcp`` service entry (issue #240).

    Self-registered by every ``ServiceRegistry`` so the broker-native af_*
    methods (mcp/diagnostics.py) are a first-class service: visible in
    /v1/catalog and ``af_list_mcp_servers``, and routed through the normal
    entitlement/authorization/audit path by prefix like every other service.
    There is no backend to dial -- the aggregator's own FastMCP instance
    serves these methods from its local provider, so ``url``/``transport``
    are inert placeholders and aggregator.py's ``_register_services`` skips
    building a ProxyProvider for a builtin spec.
    """
    return ServiceSpec(
        name=BUILTIN_SERVICE_NAME,
        prefix=RESERVED_PREFIX,
        url="",
        transport="http",
        # Open to any authenticated principal: af_whoami/af_link_identity are
        # exactly the bootstrap methods a caller with zero permissions needs.
        required_permission="__none__",
        # No per-user credential concept at all -- which also makes
        # api/permissions.py's _service_status report it "available"
        # unconditionally (it is the thing serving the status).
        auth_type="none",
        description=(
            "The gateway's own identity, catalog, and usage methods -- "
            "always available to any authenticated caller."
        ),
        display_name="AF Gateway",
        builtin=True,
    )


class ServiceRegistry:
    """Config-driven service registry. Adding a service = one YAML entry, no code change."""

    def __init__(self) -> None:
        self._services: dict[str, ServiceSpec] = {}
        # The broker's own af-mcp service is always present (issue #240) --
        # inserted directly rather than via register(), which refuses its
        # name/prefix precisely so services.yaml can never define, replace,
        # or unregister the broker from itself.
        self._services[BUILTIN_SERVICE_NAME] = _builtin_service_spec()
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
                required_permission=entry.get("required_permission"),
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
                f"'{RESERVED_PREFIX}' -- it belongs to the builtin "
                f"'{BUILTIN_SERVICE_NAME}' service serving the broker's own "
                f"af_* methods ({sorted(DIAGNOSTIC_TOOL_NAMES)}, issues "
                "#153/#240). Choose a different prefix."
            )
            raise ValueError(msg)
        if service.name == BUILTIN_SERVICE_NAME:
            # A same-name entry would silently replace the builtin spec in
            # _services (dict keyed by name) -- the config-file equivalent of
            # unregistering the broker from itself.
            msg = (
                f"service name '{BUILTIN_SERVICE_NAME}' is reserved for the "
                "builtin service serving the broker's own af_* methods "
                "(issue #240) and cannot be configured in services.yaml. "
                "Choose a different name."
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

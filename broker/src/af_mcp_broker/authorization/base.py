from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.identity import Principal


# Sentinel a per-tool required_permission resolution can produce
# (mcp/registry.py's ServiceRegistry.required_permission_for) when a
# service's required_permission is a dict, the tool being called isn't one of
# its explicit keys, and no "__default__" was declared: opt-in-only per-tool
# gating means an unlisted tool is disabled, never silently open. Distinct
# from both a real permission name and "__none__" (open to any authenticated
# user) -- check_entitlement/get_action_type below deny it unconditionally,
# the mirror image of how they already special-case "__none__".
DISABLED_PERMISSION = "__disabled__"


ACTION_TYPES = frozenset({"read", "state_change"})

# A bracket expression must be closed: fnmatch silently treats an unclosed
# "[" as a literal character, which turns a typo into a rule matching nothing.
_BALANCED_BRACKETS = re.compile(r"[^\[\]]*(?:\[[^\[\]]+\][^\[\]]*)*")

_RATE_LIMIT_RULE_KEYS = frozenset({"action_type", "tool", "limit", "window_seconds"})


@dataclass(frozen=True)
class RateLimitRule:
    """One ``rate_limits`` entry: at most *limit* matching calls per principal per *window_seconds*.

    A rule matches a call when every selector it sets matches: *action_type*
    equals the call's resolved action type, and *tool* (an fnmatch glob over
    the wire tool name, like ``target_action_types``) matches its name.
    """

    limit: int
    window_seconds: int
    action_type: str | None = None
    tool: str | None = None

    def matches(self, tool_name: str, action_type: str) -> bool:
        if self.action_type is not None and self.action_type != action_type:
            return False
        return self.tool is None or fnmatch.fnmatch(tool_name, self.tool)


@dataclass(frozen=True)
class Permission:
    name: str
    action_type: str  # "read" | "state_change"
    description: str


PERMISSIONS: dict[str, Permission] = {
    "read_data": Permission("read_data", "read", "Read datasets from data stores"),
    "read_metadata": Permission("read_metadata", "read", "Read metadata catalogs"),
    "read_monitoring": Permission(
        "read_monitoring", "read", "Read monitoring dashboards and metrics"
    ),
    "read_gitlab": Permission(
        "read_gitlab", "read", "Browse GitLab repos, issues, MRs, and pipelines"
    ),
    "read_files": Permission(
        "read_files", "read", "Browse and read files in a POSIX home directory"
    ),
    "submit_jobs": Permission("submit_jobs", "state_change", "Submit compute jobs"),
    "manage_jobs": Permission(
        "manage_jobs", "state_change", "Cancel or modify compute jobs"
    ),
    "launch_compute": Permission(
        "launch_compute", "state_change", "Launch interactive compute sessions"
    ),
    "manage_jupyter": Permission(
        "manage_jupyter", "state_change", "Start, stop, and configure Jupyter servers"
    ),
    "manage_gitlab": Permission(
        "manage_gitlab", "state_change", "Create MRs, open issues, retry CI"
    ),
    "manage_data": Permission(
        "manage_data", "state_change", "Write or delete data (gated)"
    ),
    "admin": Permission("admin", "state_change", "Platform administration"),
}


@dataclass
class EntitlementPolicy:
    # group_name -> list[permission_name]
    group_permissions: dict[str, list[str]] = field(default_factory=dict)
    # target_name -> {tool_glob_pattern -> "read"|"state_change"}
    target_action_types: dict[str, dict[str, str]] = field(default_factory=dict)
    # Site-defined permission name -> "read"|"state_change", for permissions
    # a services.yaml required_permission uses that PERMISSIONS doesn't
    # know. Without an entry, get_action_type could only guess "read".
    custom_permissions: dict[str, str] = field(default_factory=dict)
    # Per-principal call budgets; empty means no rate limiting at all.
    rate_limits: list[RateLimitRule] = field(default_factory=list)


def _positive_int(value: object, where: str, key: str) -> int:
    # bool is an int subclass, so `true` would otherwise pass as 1.
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        msg = f"{where}: {key} must be a positive integer, got {value!r}"
        raise ValueError(msg)
    return value


def _parse_rate_limit_rule(raw: object, where: str) -> RateLimitRule:
    if not isinstance(raw, dict):
        msg = f"{where} must be a mapping, got {raw!r}"
        raise ValueError(msg)  # noqa: TRY004 -- config validation reports ValueError
    unknown = sorted(set(raw) - _RATE_LIMIT_RULE_KEYS)
    if unknown:
        msg = f"{where} has unknown key(s) {unknown}; allowed: {sorted(_RATE_LIMIT_RULE_KEYS)}"
        raise ValueError(msg)
    action_type = raw.get("action_type")
    tool = raw.get("tool")
    if action_type is None and tool is None:
        msg = f"{where} needs an action_type and/or a tool glob to match on"
        raise ValueError(msg)
    if action_type is not None and action_type not in ACTION_TYPES:
        msg = (
            f"{where}: action_type '{action_type}' must be one of "
            f"{sorted(ACTION_TYPES)}"
        )
        raise ValueError(msg)
    if tool is not None and (
        not isinstance(tool, str) or not tool or not _BALANCED_BRACKETS.fullmatch(tool)
    ):
        msg = f"{where}: tool must be a non-empty glob with balanced brackets, got {tool!r}"
        raise ValueError(msg)
    return RateLimitRule(
        limit=_positive_int(raw.get("limit"), where, "limit"),
        window_seconds=_positive_int(
            raw.get("window_seconds"), where, "window_seconds"
        ),
        action_type=action_type,
        tool=tool,
    )


def _parse_rate_limits(raw: object) -> list[RateLimitRule]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        msg = f"rate_limits must be a list of rules, got {raw!r}"
        raise ValueError(msg)  # noqa: TRY004 -- config validation reports ValueError
    return [
        _parse_rate_limit_rule(rule, f"rate_limits[{index}]")
        for index, rule in enumerate(raw)
    ]


def load_policy(path: str) -> EntitlementPolicy:
    with Path(path).open() as fh:
        raw = yaml.safe_load(fh) or {}
    policy = EntitlementPolicy()
    policy.group_permissions = raw.get("group_permissions", {})
    policy.target_action_types = raw.get("target_action_types", {})
    policy.custom_permissions = raw.get("custom_permissions", {})
    policy.rate_limits = _parse_rate_limits(raw.get("rate_limits"))
    for name, action_type in policy.custom_permissions.items():
        if name in PERMISSIONS:
            msg = f"custom_permissions '{name}' shadows a built-in permission"
            raise ValueError(msg)
        if action_type not in ACTION_TYPES:
            msg = (
                f"custom_permissions '{name}' has action_type "
                f"'{action_type}'; must be one of {sorted(ACTION_TYPES)}"
            )
            raise ValueError(msg)
    return policy


def get_principal_permissions(
    principal: Principal,
    policy: EntitlementPolicy,
) -> set[str]:
    """Return the permissions *principal* currently holds.

    Derived from ``principal.groups`` exactly as before permission PATs
    existed (issue #144 step 4). The one addition is the final
    ``permission_grant`` intersection below: ``None`` for a JWT or an
    identity PAT (the overwhelming majority), in which case this returns
    exactly what it always has. For a **permission PAT**,
    ``principal.permission_grant`` is an explicit RESTRICTION, not a
    substitute for the group-derived set above -- intersecting means a
    grant can never hand out more than the group-derived set already
    allows, however it got into the grant (see ``Principal
    .permission_grant`` and ``token_registry.TokenRecord.permission_grant``
    for why that must hold even if a record is somehow constructed with an
    over-broad grant), and it means losing a group shrinks a permission
    PAT's effective set on the very next call, exactly like it already does
    for every other credential -- there is no separate code path for a
    permission PAT to go stale in.
    """
    caps: set[str] = set()
    # Any authenticated user gets __authenticated__ caps
    for cap in policy.group_permissions.get("__authenticated__", []):
        caps.add(cap)
    for group in principal.groups:
        for cap in policy.group_permissions.get(group, []):
            caps.add(cap)
    if principal.permission_grant is not None:
        caps &= principal.permission_grant
    return caps


def groups_granting_any(policy: EntitlementPolicy, permissions: set[str]) -> list[str]:
    """Return the sorted groups whose ``group_permissions`` entry grants at least one of *permissions*.

    Answers "which group memberships would unlock this?" for a caller who
    lacks a permission. ``__authenticated__`` is excluded: it is a policy
    pseudo-group every caller already belongs to, not a membership anyone can
    request.
    """
    return sorted(
        group
        for group, granted in policy.group_permissions.items()
        if group != "__authenticated__" and permissions.intersection(granted)
    )


def is_admin(principal: Principal, settings: Settings) -> bool:
    """Return True when *principal* belongs to the configured admin group.

    Deliberately separate from the permission engine's ``group_permissions``
    -- "can this principal manage the platform" is a different axis than "can
    this principal call this tool", and maintenance mode (see maintenance.py)
    needs this same check to bypass an otherwise-universal gate, which
    doesn't fit the permission model. An empty ``admin_group`` (the default)
    means no admin surface is reachable by anyone.
    """
    return bool(settings.admin_group) and settings.admin_group in principal.groups


def resolve_action_type(
    target: str,
    tool_name: str,
    permission: str | None,
    policy: EntitlementPolicy,
) -> tuple[str, str]:
    """Resolve the action type for a specific tool on a target, and say how.

    ``permission`` is the target's required permission as declared by the
    service registry (``ServiceSpec.required_permission``) -- the fallback
    below a tool-glob override, same as before this took the permission as a
    parameter instead of looking it up in ``policy.target_permissions``
    (deleted; the service registry is now the sole source for what permission
    a target requires -- see issue #60).

    Returns ``(action_type, via)`` where ``via`` is ``"target_action_types"``
    (a tool-glob override), ``"permission"`` (the built-in or custom
    permission's action type), or ``"default"`` (nothing applied; ``"read"``).
    """
    overrides = policy.target_action_types.get(target, {})
    for pattern, action_type in overrides.items():
        if fnmatch.fnmatch(tool_name, pattern):
            return action_type, "target_action_types"
    # Default: look up from the permission
    if permission in PERMISSIONS:
        return PERMISSIONS[permission].action_type, "permission"
    if permission in policy.custom_permissions:
        return policy.custom_permissions[permission], "permission"
    return "read", "default"


def get_action_type(
    target: str,
    tool_name: str,
    permission: str | None,
    policy: EntitlementPolicy,
) -> str:
    """Return the action type half of resolve_action_type, for callers that don't need to know how it was resolved."""
    return resolve_action_type(target, tool_name, permission, policy)[0]


def annotation_disagrees_with_policy(
    read_only_hint: bool | None, action_type: str
) -> bool:
    """Whether a tool's declared ``read_only_hint`` disagrees with the policy-resolved ``action_type`` (issue #238 B.8's "forward + lint" decision: warn on disagreement, never trust the backend's own self-declared annotation for an authorization decision -- policy.yaml stays authoritative for that; see get_action_type above).

    ``None`` (the tool declared no annotation at all) is never a
    disagreement -- there is nothing to check against. Otherwise
    ``read_only_hint=True`` should mean ``action_type == "read"`` and
    ``read_only_hint=False`` should mean ``action_type == "state_change"``.
    """
    if read_only_hint is None:
        return False
    is_read = action_type == "read"
    return read_only_hint != is_read


def check_entitlement(
    principal: Principal,
    permission: str | None,
    target: str,
    policy: EntitlementPolicy,
) -> tuple[bool, str]:
    """Return (allow, reason).

    ``permission`` is the target's required permission, resolved per-tool by
    ``ServiceRegistry.required_permission_for`` from ``ServiceSpec.
    required_permission`` (services.yaml is the sole source of truth for what
    a target requires; policy.yaml no longer duplicates it):
      - a permission name (e.g. "read_data") -> principal must hold it.
      - "__none__" -> open to any authenticated user (deliberate opt-in).
      - None (omitted) -> no permission gate; the credential layer is the
        gate instead (enforced at startup -- see app.py's lifespan), so any
        authenticated principal is allowed through here.
      - DISABLED_PERMISSION -> a dict-form required_permission declared this
        tool isn't reachable (not one of its explicit keys, no "__default__"
        to fall back to) -- denied unconditionally, for every principal.
    """
    if permission is None or permission == "__none__":
        return True, ""
    if permission == DISABLED_PERMISSION:
        return False, f"target '{target}' has no permission mapping for this tool"

    principal_caps = get_principal_permissions(principal, policy)
    if permission not in principal_caps:
        return False, f"target '{target}' requires permission '{permission}'"

    return True, ""

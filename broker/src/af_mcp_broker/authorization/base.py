from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.identity import Principal


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


def load_policy(path: str) -> EntitlementPolicy:
    with Path(path).open() as fh:
        raw = yaml.safe_load(fh) or {}
    policy = EntitlementPolicy()
    policy.group_permissions = raw.get("group_permissions", {})
    policy.target_action_types = raw.get("target_action_types", {})
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


def get_action_type(
    target: str,
    tool_name: str,
    permission: str | None,
    policy: EntitlementPolicy,
) -> str:
    """Resolve the action type for a specific tool on a target.

    ``permission`` is the target's required permission as declared by the
    service registry (``ServiceSpec.required_permission``) -- the fallback
    below a tool-glob override, same as before this took the permission as a
    parameter instead of looking it up in ``policy.target_permissions``
    (deleted; the service registry is now the sole source for what permission
    a target requires -- see issue #60).
    """
    overrides = policy.target_action_types.get(target, {})
    for pattern, action_type in overrides.items():
        if fnmatch.fnmatch(tool_name, pattern):
            return action_type
    # Default: look up from the permission
    if permission in PERMISSIONS:
        return PERMISSIONS[permission].action_type
    return "read"


def check_entitlement(
    principal: Principal,
    permission: str | None,
    target: str,
    policy: EntitlementPolicy,
) -> tuple[bool, str]:
    """Return (allow, reason).

    ``permission`` is the target's required permission as declared by the
    service registry (``ServiceSpec.required_permission`` -- services.yaml is
    the sole source of truth for what a target requires; policy.yaml no
    longer duplicates it):
      - a permission name (e.g. "read_data") -> principal must hold it.
      - "__none__" -> open to any authenticated user (deliberate opt-in).
      - None (omitted) -> no permission gate; the credential layer is the
        gate instead (enforced at startup -- see app.py's lifespan), so any
        authenticated principal is allowed through here.
    """
    if permission is None or permission == "__none__":
        return True, ""

    principal_caps = get_principal_permissions(principal, policy)
    if permission not in principal_caps:
        return False, f"target '{target}' requires permission '{permission}'"

    return True, ""

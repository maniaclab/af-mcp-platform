from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from af_mcp_broker.identity import Principal


@dataclass(frozen=True)
class Capability:
    name: str
    action_type: str  # "read" | "state_change"
    description: str


CAPABILITIES: dict[str, Capability] = {
    "read_data": Capability("read_data", "read", "Read datasets from data stores"),
    "read_metadata": Capability("read_metadata", "read", "Read metadata catalogs"),
    "read_monitoring": Capability(
        "read_monitoring", "read", "Read monitoring dashboards and metrics"
    ),
    "read_gitlab": Capability(
        "read_gitlab", "read", "Browse GitLab repos, issues, MRs, and pipelines"
    ),
    "submit_jobs": Capability("submit_jobs", "state_change", "Submit compute jobs"),
    "manage_jobs": Capability(
        "manage_jobs", "state_change", "Cancel or modify compute jobs"
    ),
    "launch_compute": Capability(
        "launch_compute", "state_change", "Launch interactive compute sessions"
    ),
    "manage_jupyter": Capability(
        "manage_jupyter", "state_change", "Start, stop, and configure Jupyter servers"
    ),
    "manage_gitlab": Capability(
        "manage_gitlab", "state_change", "Create MRs, open issues, retry CI"
    ),
    "manage_data": Capability(
        "manage_data", "state_change", "Write or delete data (gated)"
    ),
    "admin": Capability("admin", "state_change", "Platform administration"),
}


@dataclass
class EntitlementPolicy:
    # group_name -> list[capability_name]
    group_capabilities: dict[str, list[str]] = field(default_factory=dict)
    # target_name -> required capability_name (or "__none__" for open access)
    target_capabilities: dict[str, str] = field(default_factory=dict)
    # target_name -> {tool_glob_pattern -> "read"|"state_change"}
    target_action_types: dict[str, dict[str, str]] = field(default_factory=dict)


def load_policy(path: str) -> EntitlementPolicy:
    with Path(path).open() as fh:
        raw = yaml.safe_load(fh) or {}
    policy = EntitlementPolicy()
    policy.group_capabilities = raw.get("group_capabilities", {})
    policy.target_capabilities = raw.get("target_capabilities", {})
    policy.target_action_types = raw.get("target_action_types", {})
    return policy


def get_principal_capabilities(
    principal: Principal,
    policy: EntitlementPolicy,
) -> set[str]:
    caps: set[str] = set()
    # Any authenticated user gets __authenticated__ caps
    for cap in policy.group_capabilities.get("__authenticated__", []):
        caps.add(cap)
    for group in principal.groups:
        for cap in policy.group_capabilities.get(group, []):
            caps.add(cap)
    return caps


def get_action_type(target: str, tool_name: str, policy: EntitlementPolicy) -> str:
    """Resolve the action type for a specific tool on a target."""
    overrides = policy.target_action_types.get(target, {})
    for pattern, action_type in overrides.items():
        if fnmatch.fnmatch(tool_name, pattern):
            return action_type
    # Default: look up from the capability
    required_cap = policy.target_capabilities.get(target, "__none__")
    if required_cap in CAPABILITIES:
        return CAPABILITIES[required_cap].action_type
    return "read"


def check_entitlement(
    principal: Principal,
    capability: str,
    target: str,
    policy: EntitlementPolicy,
) -> tuple[bool, str]:
    """Returns (allow, reason)."""
    # Open-access targets require no capability
    required_cap = policy.target_capabilities.get(target)
    if required_cap == "__none__":
        return True, ""

    if required_cap is None:
        return False, f"target '{target}' is not registered in policy"

    if capability != required_cap:
        return (
            False,
            f"target '{target}' requires capability '{required_cap}', got '{capability}'",
        )

    principal_caps = get_principal_capabilities(principal, policy)
    if required_cap not in principal_caps:
        return False, (
            f"principal lacks capability '{required_cap}'. "
            f"Granted capabilities: {sorted(principal_caps)}"
        )

    return True, ""

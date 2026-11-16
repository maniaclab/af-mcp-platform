from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from authorization_support import (
    _write_policy,
)

from af_mcp_broker.authorization import (
    DISABLED_PERMISSION,
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
    get_principal_permissions,
    groups_granting_any,
    is_admin,
    is_platform_member,
    load_policy,
    resolve_action_type,
)
from af_mcp_broker.config import Settings

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def test_atlas_allowed_rucio_read_data(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    principal = make_principal(groups=["atlas"])
    allow, reason = check_entitlement(principal, "read_data", "rucio", policy)
    assert allow, reason


def test_authenticated_only_gets_read_metadata(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    principal = make_principal(groups=[])
    caps = get_principal_permissions(principal, policy)
    # __authenticated__ grants read_metadata + read_monitoring, nothing more.
    assert caps == {"read_metadata", "read_monitoring"}

    # ami requires read_metadata -> allowed for any authenticated user.
    allow, reason = check_entitlement(principal, "read_metadata", "ami", policy)
    assert allow, reason


def test_no_groups_denied_rucio(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    principal = make_principal(groups=[])
    # rucio requires read_data, which __authenticated__ does not grant.
    allow, reason = check_entitlement(principal, "read_data", "rucio", policy)
    assert not allow
    assert "read_data" in reason


def test_open_sentinel_requires_no_permission(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    """ "__none__" is a deliberate open-access opt-in: no permission, not even
    __authenticated__'s, is required."""
    principal = make_principal(groups=[])
    allow, reason = check_entitlement(principal, "__none__", "docs", policy)
    assert allow, reason


def test_omitted_permission_is_allowed(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    """Omitted required_permission (None) means the credential layer is the
    gate instead of a permission check (issue #60) -- enforced at startup
    (see test_app.py's fail-closed test), not here. check_entitlement itself
    must allow any authenticated principal straight through."""
    principal = make_principal(groups=[])
    allow, reason = check_entitlement(principal, None, "some-target", policy)
    assert allow, reason


# ---------------------------------------------------------------------------
# Permission PATs (issue #144 step 4): Principal.permission_grant is a
# RESTRICTION intersected with the group-derived set above, never a
# substitute for it -- see get_principal_permissions's docstring.
# ---------------------------------------------------------------------------


def test_permission_grant_intersects_with_group_derived_permissions(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    """A permission PAT scoped to a subset of the owner's group-derived
    permissions is narrowed to exactly that subset."""
    principal = make_principal(
        groups=["atlas"], permission_grant=frozenset({"read_data"})
    )
    caps = get_principal_permissions(principal, policy)
    assert caps == {"read_data"}


def test_permission_grant_cannot_exceed_group_derived_permissions(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    """A grant naming a permission the owner's CURRENT groups don't grant
    must never widen the effective set -- intersection, not union. This
    proves enforcement doesn't trust the grant's contents, independent of
    whether mint-time validation ever ran (it's exercised directly here via
    make_principal, not through the mint endpoint)."""
    principal = make_principal(
        groups=[], permission_grant=frozenset({"read_data", "admin"})
    )
    caps = get_principal_permissions(principal, policy)
    # __authenticated__ grants read_metadata/read_monitoring; neither
    # read_data nor admin is in the group-derived set for an empty groups
    # list, so both are dropped by the intersection regardless of the grant.
    assert caps == set()


def test_identity_pat_permission_grant_none_behaves_exactly_as_before(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    """permission_grant=None (every JWT, every identity PAT) must skip the
    intersection entirely, not intersect with an empty set."""
    principal = make_principal(groups=["atlas"], permission_grant=None)
    caps = get_principal_permissions(principal, policy)
    assert caps == {
        "read_data",
        "read_metadata",
        "read_monitoring",
        "submit_jobs",
        "manage_jobs",
        "launch_compute",
        "manage_jupyter",
        "read_files",
    }


def test_losing_a_group_shrinks_a_permission_pats_effective_set(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    """The property the whole design turns on: a permission PAT's grant is
    re-intersected against CURRENT groups on every call, so removing the
    owner from the group that grants a permission kills that
    permission for the PAT too -- not just for fresh JWTs."""
    grant = frozenset({"read_data", "submit_jobs"})
    still_in_group = make_principal(groups=["atlas"], permission_grant=grant)
    assert get_principal_permissions(still_in_group, policy) == grant

    removed_from_group = make_principal(groups=[], permission_grant=grant)
    # __authenticated__ grants neither read_data nor submit_jobs, so the
    # intersection is now empty -- the grant itself never changed.
    assert get_principal_permissions(removed_from_group, policy) == set()


def test_action_type_resolution(policy: EntitlementPolicy) -> None:
    # af-jupyterlab-mcp create_* is a state_change override. The glob must
    # win regardless of the permission's own action type, so pass a
    # read-typed permission here to prove it's the override deciding (the
    # target's real permission, manage_jupyter, is itself state_change,
    # which couldn't tell the override apart from the fallback).
    assert (
        get_action_type(
            "af-jupyterlab-mcp", "create_jupyter_server", "read_files", policy
        )
        == "state_change"
    )
    # A non-override tool falls back to the permission's action type
    # (af-jupyterlab-mcp's declared permission is manage_jupyter -> state_change).
    assert (
        get_action_type(
            "af-jupyterlab-mcp", "list_jupyter_servers", "manage_jupyter", policy
        )
        == "state_change"
    )
    # rucio -> read_data -> read.
    assert get_action_type("rucio", "list_dids", "read_data", policy) == "read"


def test_action_type_resolution_omitted_permission_defaults_to_read(
    policy: EntitlementPolicy,
) -> None:
    """A target with no glob override and no declared permission (None) has
    no action-type signal to derive from, so it defaults to "read"."""
    assert get_action_type("mystery", "list_things", None, policy) == "read"


def test_action_type_resolution_uses_custom_permission() -> None:
    """A site-defined permission carries its action_type via
    ``custom_permissions`` instead of silently defaulting to "read"."""
    policy = EntitlementPolicy(custom_permissions={"exec_jobs": "state_change"})
    assert (
        get_action_type("condor_service", "condor_exec_in_job", "exec_jobs", policy)
        == "state_change"
    )


def test_action_type_glob_override_beats_custom_permission() -> None:
    policy = EntitlementPolicy(
        custom_permissions={"exec_jobs": "state_change"},
        target_action_types={"condor_service": {"condor_peek_*": "read"}},
    )
    assert (
        get_action_type("condor_service", "condor_peek_job", "exec_jobs", policy)
        == "read"
    )


@pytest.mark.parametrize(
    ("tool", "permission", "expected"),
    [
        ("condor_peek_job", "exec_jobs", ("read", "target_action_types")),
        ("condor_exec_in_job", "exec_jobs", ("state_change", "permission")),
        ("condor_query_jobs", "read_data", ("read", "permission")),
        ("condor_x", None, ("read", "default")),
        ("condor_x", DISABLED_PERMISSION, ("read", "default")),
        ("condor_x", "unknown_perm", ("read", "default")),
    ],
)
def test_resolve_action_type_reports_how_it_resolved(
    tool: str, permission: str | None, expected: tuple[str, str]
) -> None:
    policy = EntitlementPolicy(
        custom_permissions={"exec_jobs": "state_change"},
        target_action_types={"condor_service": {"condor_peek_*": "read"}},
    )
    assert resolve_action_type("condor_service", tool, permission, policy) == expected


def test_load_policy_reads_custom_permissions(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        "group_permissions: {}\ncustom_permissions:\n  exec_jobs: state_change\n",
    )
    assert load_policy(path).custom_permissions == {"exec_jobs": "state_change"}


def test_load_policy_custom_permissions_default_empty(tmp_path: Path) -> None:
    path = _write_policy(tmp_path, "group_permissions: {}\n")
    assert load_policy(path).custom_permissions == {}


@pytest.mark.parametrize(
    ("body", "needle"),
    [
        ("exec_jobs: write", "action_type"),
        ("read_data: state_change", "built-in"),
    ],
)
def test_load_policy_rejects_bad_custom_permissions(
    tmp_path: Path, body: str, needle: str
) -> None:
    path = _write_policy(tmp_path, f"custom_permissions:\n  {body}\n")
    with pytest.raises(ValueError, match=needle):
        load_policy(path)


# ---------------------------------------------------------------------------
# DISABLED_PERMISSION ("__disabled__"): the per-tool required_permission
# resolver's sentinel for "dict form declared, this tool isn't in it, and
# there's no __default__ to fall back to" -- opt-in-only per-tool gating
# (registry.py's ServiceRegistry.required_permission_for). Deny unconditionally,
# the same way "__none__" is unconditionally allowed.
# ---------------------------------------------------------------------------


def test_disabled_permission_denies_every_principal(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    principal = make_principal(groups=["af-admins"])
    allow, reason = check_entitlement(
        principal, DISABLED_PERMISSION, "condor_service", policy
    )
    assert not allow
    assert "condor_service" in reason


def test_disabled_permission_action_type_defaults_to_read(
    policy: EntitlementPolicy,
) -> None:
    """Never actually reachable (the call is denied first), but must not
    crash the action-type resolver used for audit/span labeling."""
    assert (
        get_action_type("condor_service", "submit_job", DISABLED_PERMISSION, policy)
        == "read"
    )


@pytest.mark.parametrize(
    ("admin_group", "groups", "expected"),
    [
        pytest.param(
            "af-admins",
            ["atlas", "af-admins"],
            True,
            id="true_when_member_of_configured_admin_group",
        ),
        pytest.param("af-admins", ["atlas"], False, id="false_when_not_a_member"),
        pytest.param(
            "", ["af-admins"], False, id="false_when_admin_group_unconfigured"
        ),
        pytest.param("af-admins", [], False, id="false_when_principal_has_no_groups"),
    ],
)
def test_is_admin(
    make_principal: Callable[..., object],
    admin_group: str,
    groups: list[str],
    expected: bool,
) -> None:
    settings = Settings(admin_group=admin_group)
    principal = make_principal(groups=groups)
    assert is_admin(principal, settings) is expected


@pytest.mark.parametrize(
    ("access_groups", "groups", "expected"),
    [
        pytest.param([], [], True, id="unset_admits_everyone"),
        pytest.param([], ["atlas"], True, id="unset_admits_any_group"),
        pytest.param(["/example/af"], ["/example/af"], True, id="member"),
        pytest.param(["/example/af"], [], False, id="no_groups"),
        pytest.param(["/example/af"], ["/example/other"], False, id="other_group"),
        pytest.param(
            ["/example/af", "/example/ops"], ["/example/ops"], True, id="any_of"
        ),
        pytest.param(["/Example/AF"], ["/example/af"], True, id="case_insensitive"),
        pytest.param(
            ["/example/af"], ["/example/af/sub"], False, id="subgroup_not_a_prefix"
        ),
        pytest.param(
            ["/example/af"], ["/example/afx"], False, id="exact_not_substring"
        ),
    ],
)
def test_is_platform_member(
    make_principal: Callable[..., object],
    access_groups: list[str],
    groups: list[str],
    expected: bool,
) -> None:
    settings = Settings(access_groups=access_groups)
    principal = make_principal(groups=groups)
    assert is_platform_member(principal, settings) is expected


# --- groups_granting_any (issue #395) ---------------------------------------


def test_groups_granting_any_names_every_group_granting_a_permission() -> None:
    policy = EntitlementPolicy(
        group_permissions={
            "/connect/atlas-af": ["read_data", "manage_jobs"],
            "/connect/escape": ["read_data"],
            "/connect/ops": ["manage_jobs"],
            "__authenticated__": ["read_metadata"],
        }
    )
    assert groups_granting_any(policy, {"read_data"}) == [
        "/connect/atlas-af",
        "/connect/escape",
    ]
    # A union across several permissions, sorted, each group once.
    assert groups_granting_any(policy, {"read_data", "manage_jobs"}) == [
        "/connect/atlas-af",
        "/connect/escape",
        "/connect/ops",
    ]


def test_groups_granting_any_excludes_the_authenticated_pseudo_group() -> None:
    """__authenticated__ is not a group anyone can join, so naming it would
    send a user looking for a membership that doesn't exist."""
    policy = EntitlementPolicy(
        group_permissions={"__authenticated__": ["read_data"], "atlas": ["read_data"]}
    )
    assert groups_granting_any(policy, {"read_data"}) == ["atlas"]


def test_groups_granting_any_is_empty_for_an_ungranted_permission() -> None:
    policy = EntitlementPolicy(group_permissions={"atlas": ["read_data"]})
    assert groups_granting_any(policy, {"manage_jobs"}) == []
    assert groups_granting_any(policy, set()) == []

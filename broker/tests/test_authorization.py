from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from af_mcp_broker.authorization import (
    DISABLED_PERMISSION,
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
    get_principal_permissions,
    is_admin,
)
from af_mcp_broker.config import Settings

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import Any


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
    owner from the group that used to grant a permission kills that
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


def test_is_admin_true_when_member_of_configured_admin_group(
    make_principal: Callable[..., object],
) -> None:
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas", "af-admins"])
    assert is_admin(principal, settings) is True


def test_is_admin_false_when_not_a_member(
    make_principal: Callable[..., object],
) -> None:
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas"])
    assert is_admin(principal, settings) is False


def test_is_admin_false_when_admin_group_unconfigured(
    make_principal: Callable[..., object],
) -> None:
    settings = Settings(admin_group="")
    principal = make_principal(groups=["af-admins"])
    assert is_admin(principal, settings) is False


def test_is_admin_false_when_principal_has_no_groups(
    make_principal: Callable[..., object],
) -> None:
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=[])
    assert is_admin(principal, settings) is False


def _write_policy(tmp_path: Path, text: str) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    return str(path)


def _write_services(tmp_path: Path, text: str) -> str:
    path = tmp_path / "services.yaml"
    path.write_text(text)
    return str(path)


def test_startup_refuses_to_start_when_group_permissions_empty(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """An empty ``group_permissions`` means every principal falls back to
    ``__authenticated__``-only permissions, silently denying every backend
    that requires a permission ``__authenticated__`` doesn't grant (issue
    #59: the chart's configmap template rendered ``groups:`` instead of
    ``group_permissions:``, so ``/v1/catalog`` returned zero tools for
    every user). This is Kubernetes: a Deployment rollout with a failing new
    pod leaves the previous ReplicaSet serving, so refusing to start turns
    the misconfiguration into a visible rollout failure with zero outage,
    naming both the affected backend and the unreachable permission.
    """
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(tmp_path, "group_permissions: {}\ntarget_action_types: {}\n"),
    )

    with pytest.raises(RuntimeError) as exc_info:  # noqa: SIM117
        with app_client_factory():
            pass

    # SHIPPED_SERVICES' "rucio" entry requires "read_data" (!= "__none__"),
    # so both must be named in the failure.
    message = str(exc_info.value)
    assert "rucio" in message, message
    assert "read_data" in message, message


def test_startup_quiet_when_permissions_are_all_reachable(
    app_client_factory: Callable[..., Any],
) -> None:
    """The shipped policy.yaml grants every permission SHIPPED_SERVICES
    requires (to at least one group), so startup must succeed for the
    default local-dev configuration."""
    with app_client_factory() as (client, _):
        resp = client.get("/v1/healthz")

    assert resp.status_code == 200, resp.text


def test_startup_refuses_to_start_for_typoed_permission_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """group_permissions that cover some, but not all, required permissions
    (e.g. a typo'd permission name) must name exactly the unreachable one --
    reachable permissions must not be named."""
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(
            tmp_path,
            "group_permissions:\n"
            "  atlas: [read_data, read_metadta]\n"  # typo: read_metadta
            "target_action_types: {}\n",
        ),
    )

    with pytest.raises(RuntimeError) as exc_info:  # noqa: SIM117
        with app_client_factory():
            pass

    message = str(exc_info.value)
    # "ami" requires read_metadata, which the typo means nobody actually
    # grants -- it must be named.
    assert "ami" in message, message
    assert "read_metadata" in message, message
    # "rucio" requires read_data, correctly spelled and reachable -- it must
    # not be named.
    assert "rucio" not in message, message


def test_startup_refuses_to_start_for_unreachable_permission_in_dict_form(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """A dict-form required_permission's values are checked individually --
    a typo'd (or simply ungranted) per-tool value must be named, exactly like
    the flat-string case."""
    # This services.yaml has no auth_type: x509 backend at all -- drop
    # conftest's default x509 entry (targets ["ami"], absent here), same as
    # test_app.py's test_omitted_permission_without_credential_provider_
    # refuses_to_start.
    monkeypatch.setenv("IDENTITY_PROVIDERS", "[]")
    monkeypatch.setenv(
        "SERVICES_FILE",
        _write_services(
            tmp_path,
            "services:\n"
            "  - name: condor_service\n"
            "    prefix: condor\n"
            "    url: http://condor.invalid/mcp\n"
            "    auth_type: none\n"
            "    required_permission:\n"
            "      __default__: manage_jobs\n"
            "      query_jobs: read_monitroing\n",  # typo: read_monitroing
        ),
    )
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(
            tmp_path,
            "group_permissions:\n  atlas: [manage_jobs]\ntarget_action_types: {}\n",
        ),
    )

    with pytest.raises(RuntimeError) as exc_info:  # noqa: SIM117
        with app_client_factory():
            pass

    message = str(exc_info.value)
    assert "condor_service" in message, message
    assert "read_monitroing" in message, message
    # manage_jobs is correctly spelled and reachable -- must not be named.
    assert "manage_jobs" not in message, message


def test_startup_stays_quiet_with_empty_group_permissions_and_no_gated_backends(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """Backends that omit required_permission (with a credential-layer gate)
    or set it to __none__ need no group_permissions entry at all -- an
    empty group_permissions must not be flagged as unreachable for them,
    and the broker must still start cleanly."""
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(tmp_path, "group_permissions: {}\ntarget_action_types: {}\n"),
    )
    monkeypatch.setenv(
        "SERVICES_FILE",
        _write_services(
            tmp_path,
            "services:\n"
            "  - name: docs\n"
            "    prefix: docs\n"
            "    url: http://docs.invalid/mcp\n"
            "    auth_type: none\n"
            "    required_permission: __none__\n"
            "  - name: ami\n"
            "    prefix: ami\n"
            "    url: http://ami.invalid/mcp\n"
            "    auth_type: x509\n",
        ),
    )

    with app_client_factory() as (client, _):
        resp = client.get("/v1/healthz")

    assert resp.status_code == 200, resp.text

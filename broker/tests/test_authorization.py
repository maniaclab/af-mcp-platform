from __future__ import annotations

from typing import TYPE_CHECKING

from af_mcp_broker.authorization import (
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
    get_principal_capabilities,
)

if TYPE_CHECKING:
    from collections.abc import Callable


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
    caps = get_principal_capabilities(principal, policy)
    # __authenticated__ grants read_metadata + read_monitoring, nothing more.
    assert caps == {"read_metadata", "read_monitoring"}

    # ami requires read_metadata -> allowed for any authenticated user.
    allow, reason = check_entitlement(principal, "read_metadata", "ami", policy)
    assert allow, reason


def test_no_groups_denied_panda(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    principal = make_principal(groups=[])
    # panda requires submit_jobs, which __authenticated__ does not grant.
    allow, reason = check_entitlement(principal, "submit_jobs", "panda", policy)
    assert not allow
    assert "submit_jobs" in reason


def test_unknown_target_denied(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    principal = make_principal(groups=["atlas"])
    allow, reason = check_entitlement(principal, "read_data", "no-such-target", policy)
    assert not allow
    assert "not registered" in reason


def test_action_type_resolution(policy: EntitlementPolicy) -> None:
    # panda submit_* is a state_change override.
    assert get_action_type("panda", "submit_job", policy) == "state_change"
    # A non-override tool falls back to the capability's action type
    # (panda -> submit_jobs -> state_change).
    assert get_action_type("panda", "list_jobs", policy) == "state_change"
    # rucio -> read_data -> read.
    assert get_action_type("rucio", "list_dids", policy) == "read"

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from af_mcp_broker.authorization import (
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
    get_principal_capabilities,
)

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


def test_open_sentinel_requires_no_capability(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    """ "__none__" is a deliberate open-access opt-in: no capability, not even
    __authenticated__'s, is required."""
    principal = make_principal(groups=[])
    allow, reason = check_entitlement(principal, "__none__", "docs", policy)
    assert allow, reason


def test_omitted_capability_is_allowed(
    policy: EntitlementPolicy, make_principal: Callable[..., object]
) -> None:
    """Omitted required_capability (None) means the credential layer is the
    gate instead of a capability check (issue #60) -- enforced at startup
    (see test_app.py's fail-closed test), not here. check_entitlement itself
    must allow any authenticated principal straight through."""
    principal = make_principal(groups=[])
    allow, reason = check_entitlement(principal, None, "some-target", policy)
    assert allow, reason


def test_action_type_resolution(policy: EntitlementPolicy) -> None:
    # panda submit_* is a state_change override.
    assert (
        get_action_type("panda", "submit_job", "submit_jobs", policy) == "state_change"
    )
    # A non-override tool falls back to the capability's action type
    # (panda's declared capability is submit_jobs -> state_change).
    assert (
        get_action_type("panda", "list_jobs", "submit_jobs", policy) == "state_change"
    )
    # rucio -> read_data -> read.
    assert get_action_type("rucio", "list_dids", "read_data", policy) == "read"


def test_action_type_resolution_omitted_capability_defaults_to_read(
    policy: EntitlementPolicy,
) -> None:
    """A target with no glob override and no declared capability (None) has
    no action-type signal to derive from, so it defaults to "read"."""
    assert get_action_type("mystery", "list_things", None, policy) == "read"


def _write_policy(tmp_path: Path, text: str) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    return str(path)


def _write_backends(tmp_path: Path, text: str) -> str:
    path = tmp_path / "backends.yaml"
    path.write_text(text)
    return str(path)


def test_startup_refuses_to_start_when_group_capabilities_empty(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """An empty ``group_capabilities`` means every principal falls back to
    ``__authenticated__``-only capabilities, silently denying every backend
    that requires a capability ``__authenticated__`` doesn't grant (issue
    #59: the chart's configmap template rendered ``groups:`` instead of
    ``group_capabilities:``, so ``/v1/catalog`` returned zero tools for
    every user). This is Kubernetes: a Deployment rollout with a failing new
    pod leaves the previous ReplicaSet serving, so refusing to start turns
    the misconfiguration into a visible rollout failure with zero outage,
    naming both the affected backend and the unreachable capability.
    """
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(tmp_path, "group_capabilities: {}\ntarget_action_types: {}\n"),
    )

    with pytest.raises(RuntimeError) as exc_info:  # noqa: SIM117
        with app_client_factory():
            pass

    # SHIPPED_BACKENDS' "rucio" entry requires "read_data" (!= "__none__"),
    # so both must be named in the failure.
    message = str(exc_info.value)
    assert "rucio" in message, message
    assert "read_data" in message, message


def test_startup_quiet_when_capabilities_are_all_reachable(
    app_client_factory: Callable[..., Any],
) -> None:
    """The shipped policy.yaml grants every capability SHIPPED_BACKENDS
    requires (to at least one group), so startup must succeed for the
    default local-dev configuration."""
    with app_client_factory() as (client, _):
        resp = client.get("/v1/healthz")

    assert resp.status_code == 200, resp.text


def test_startup_refuses_to_start_for_typoed_capability_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """group_capabilities that cover some, but not all, required capabilities
    (e.g. a typo'd capability name) must name exactly the unreachable one --
    reachable capabilities must not be named."""
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(
            tmp_path,
            "group_capabilities:\n"
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


def test_startup_stays_quiet_with_empty_group_capabilities_and_no_gated_backends(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """Backends that omit required_capability (with a credential-layer gate)
    or set it to __none__ need no group_capabilities entry at all -- an
    empty group_capabilities must not be flagged as unreachable for them,
    and the broker must still start cleanly."""
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(tmp_path, "group_capabilities: {}\ntarget_action_types: {}\n"),
    )
    monkeypatch.setenv(
        "BACKENDS_FILE",
        _write_backends(
            tmp_path,
            "backends:\n"
            "  - name: docs\n"
            "    prefix: docs\n"
            "    url: http://docs.invalid/mcp\n"
            "    auth_type: none\n"
            "    required_capability: __none__\n"
            "  - name: ami\n"
            "    prefix: ami\n"
            "    url: http://ami.invalid/mcp\n"
            "    auth_type: x509\n",
        ),
    )

    with app_client_factory() as (client, _):
        resp = client.get("/v1/healthz")

    assert resp.status_code == 200, resp.text

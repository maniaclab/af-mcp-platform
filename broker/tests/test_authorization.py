from __future__ import annotations

from typing import TYPE_CHECKING, Any

from af_mcp_broker.authorization import (
    EntitlementPolicy,
    check_entitlement,
    get_action_type,
    get_principal_capabilities,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest


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


def _write_empty_group_capabilities_policy(tmp_path: Path) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text("group_capabilities: {}\ntarget_action_types: {}\n")
    return str(path)


def test_startup_errors_on_empty_group_capabilities_with_gated_backends(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """An empty ``group_capabilities`` means every principal falls back to
    ``__authenticated__``-only capabilities, silently denying every backend
    that requires one (issue #59: the chart's configmap template rendered
    ``groups:`` instead of ``group_capabilities:``, so ``/v1/catalog``
    returned zero tools for every user). Not a startup failure -- operators
    may deliberately deploy with an all-open policy -- but it must be a
    loud, visible ERROR-level structlog line naming the affected backends.

    configure_logging() rewrites the root logger's handlers during the app
    lifespan, which would otherwise swallow pytest's caplog handler, so this
    asserts directly against the app module's logger call instead, mirroring
    test_health.py::test_startup_warns_on_no_backends.
    """
    monkeypatch.setenv("POLICY_FILE", _write_empty_group_capabilities_policy(tmp_path))

    from af_mcp_broker import app as app_module

    events: list[tuple[str, dict[str, Any]]] = []
    original_error = app_module.logger.error

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append((event, kwargs))
        return original_error(event, **kwargs)

    monkeypatch.setattr(app_module.logger, "error", _capture)

    with app_client_factory():
        pass

    matches = [
        kwargs
        for event, kwargs in events
        if event == "policy.group_capabilities_empty_but_required"
    ]
    assert matches, events
    # SHIPPED_BACKENDS' "rucio" entry requires "read_data" (!= "__none__"),
    # so it must be named among the affected backends.
    assert "rucio" in matches[0]["backends"]

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from authorization_support import (
    _write_policy,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import Any


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
    naming the policy file and the setting that points at it.
    """
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(tmp_path, "group_permissions: {}\ntarget_action_types: {}\n"),
    )

    with pytest.raises(RuntimeError) as exc_info:  # noqa: SIM117
        with app_client_factory():
            pass

    message = str(exc_info.value)
    assert "POLICY_FILE" in message, message
    assert "grants no permissions" in message, message


def test_startup_quiet_when_permissions_are_all_reachable(
    app_client_factory: Callable[..., Any],
) -> None:
    """The shipped policy.yaml grants every permission TEST_SERVICES
    requires (to at least one group), so startup must succeed for the
    default local-dev configuration."""
    with app_client_factory() as (client, _):
        resp = client.get("/v1/healthz")

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "ok"}


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


def test_startup_refuses_empty_group_permissions_even_with_no_gated_backends(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """Backends that omit required_permission (with a credential-layer gate)
    or set it to __none__ need no group_permissions entry, but an empty
    policy is still a boot error: it is never a deliberate configuration."""
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

    with pytest.raises(RuntimeError, match="grants no permissions"):  # noqa: SIM117
        with app_client_factory():
            pass


def test_startup_refuses_to_start_for_unknown_permission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """A required_permission that is neither built-in nor declared in
    custom_permissions has no action_type to resolve, so it would silently
    be labelled "read" -- refuse to start, naming the service and the
    permission."""
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
            "      __default__: __none__\n"
            "      exec_in_job: exec_jobs\n",
        ),
    )
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(
            tmp_path,
            "group_permissions:\n  atlas: [exec_jobs]\ntarget_action_types: {}\n",
        ),
    )

    with pytest.raises(RuntimeError) as exc_info:  # noqa: SIM117
        with app_client_factory():
            pass

    message = str(exc_info.value)
    assert "condor_service" in message, message
    assert "exec_jobs" in message, message
    assert "custom_permissions" in message, message


def test_startup_accepts_declared_custom_permission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
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
            "      __default__: __none__\n"
            "      exec_in_job: exec_jobs\n",
        ),
    )
    monkeypatch.setenv(
        "POLICY_FILE",
        _write_policy(
            tmp_path,
            "group_permissions:\n  atlas: [exec_jobs]\n"
            "custom_permissions:\n  exec_jobs: state_change\n",
        ),
    )

    with app_client_factory() as (client, _):
        resp = client.get("/v1/healthz")

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "ok"}

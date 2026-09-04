"""Tests for app.py's lifespan helpers that don't require booting the full
FastAPI app (see test_dev_bypass.py / test_api.py for full-boot coverage).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
import structlog

import af_mcp_broker.app as app_module
from af_mcp_broker.app import _build_target_to_alias
from af_mcp_broker.config import (
    KeycloakBrokeredProviderConfig,
    OAuth21DirectProviderConfig,
    X509ProviderConfig,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def test_build_target_to_alias_covers_all_auth_shapes() -> None:
    """target_to_alias (issue #90) joins backend targets to whichever
    credential provider services them, uniformly from the configured
    `identity_providers` list: x509 targets get their entry's alias
    (previously a hardcoded synthetic "x509" string — every auth_type: x509
    backend now needs an explicit entry, so this helper no longer
    special-cases x509 at all), keycloak-brokered/oauth21-direct targets get
    their configured alias, and auth_type "none" targets (e.g. "docs") are
    simply absent — no user credential is needed for them.
    """
    identity_providers_cfgs = [
        KeycloakBrokeredProviderConfig(alias="atlas-oidc", targets=["rucio"]),
        OAuth21DirectProviderConfig(
            alias="rucio-mcp-atlas",
            targets=["rucio-mcp-atlas"],
            authorization_endpoint="https://backend-as.example/authorize",
            token_endpoint="https://backend-as.example/token",
            issuer="https://backend-as.example",
        ),
        X509ProviderConfig(alias="x509", targets=["ami"]),
    ]

    mapping = _build_target_to_alias(identity_providers_cfgs)

    assert mapping == {
        "rucio": "atlas-oidc",
        "rucio-mcp-atlas": "rucio-mcp-atlas",
        "ami": "x509",
    }
    assert "docs" not in mapping


def test_build_target_to_alias_uses_the_real_x509_entry_alias() -> None:
    """An operator-chosen x509 alias flows through to /v1/catalog's
    credential_provider — nothing hardcodes the "x509" string anymore."""
    mapping = _build_target_to_alias(
        [X509ProviderConfig(alias="grid-cert-atlas", targets=["ami", "panda"])]
    )

    assert mapping == {"ami": "grid-cert-atlas", "panda": "grid-cert-atlas"}


# ---------------------------------------------------------------------------
# Fail-closed startup validation (issue #60): a backend that omits
# `required_permission` relies on the credential layer as its sole
# authorization gate. If no credential provider resolves for its target
# either, there is no gate at all -- the broker must refuse to start.
# ---------------------------------------------------------------------------


def _write_services(tmp_path: Path, text: str) -> str:
    path = tmp_path / "services.yaml"
    path.write_text(text)
    return str(path)


def test_omitted_permission_with_credential_provider_starts_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """Omitting required_permission is allowed as long as the credential
    layer actually gates the backend. Here that's via ``auth_type: x509``,
    gated by conftest's default `identity_providers` entry (alias "x509",
    targets ["ami"]) -- so this backend has a real gate (a mintable
    credential) even without a declared permission.
    """
    monkeypatch.setenv(
        "SERVICES_FILE",
        _write_services(
            tmp_path,
            "services:\n"
            "  - name: ami\n"
            "    prefix: ami\n"
            "    url: http://ami.invalid/mcp\n"
            "    auth_type: x509\n",
        ),
    )

    with app_client_factory() as (client, _):
        resp = client.get("/v1/healthz")

    assert resp.status_code == 200, resp.text


def test_omitted_permission_without_credential_provider_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """A backend that omits required_permission AND has no credential
    provider resolving for its target (here: `auth_type: bearer`, the
    default, with no `identity_providers` entry naming it) has no
    authorization gate at all -- neither a declared permission nor a
    mintable credential. The broker must refuse to start naming the
    offending backend rather than silently exposing it to any authenticated
    caller.
    """
    monkeypatch.setenv(
        "SERVICES_FILE",
        _write_services(
            tmp_path,
            "services:\n"
            "  - name: mystery\n"
            "    prefix: mystery\n"
            "    url: http://mystery.invalid/mcp\n"
            "    auth_type: bearer\n",
        ),
    )
    # This services.yaml has no auth_type: x509 backend at all, so drop
    # conftest's default x509 entry (targets ["ami"], absent here) -- an
    # x509 entry targeting a nonexistent backend would trip the OTHER
    # direction of the coverage check before we ever reach the assertion
    # this test cares about.
    monkeypatch.setenv("IDENTITY_PROVIDERS", "[]")

    with pytest.raises(RuntimeError, match="mystery"):  # noqa: SIM117
        with app_client_factory():
            pass


# ---------------------------------------------------------------------------
# /mcp transport mode startup check (issue #128): mcp_stateless_http=False
# only pins a session safely with more than one replica if something in
# front of the broker (e.g. client-IP-hash ingress affinity) provides it,
# which the broker itself cannot see -- so this can only warn, never refuse
# to start (unlike the fail-closed permission check above).
# ---------------------------------------------------------------------------


def test_stateful_multi_replica_warns_at_startup(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setenv("MCP_STATELESS_HTTP", "false")
    monkeypatch.setenv("MCP_REPLICA_COUNT", "2")

    events: list[tuple[str, dict[str, Any]]] = []
    original_warning = app_module.logger.warning

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append((event, kwargs))
        return original_warning(event, **kwargs)

    monkeypatch.setattr(app_module.logger, "warning", _capture)

    with app_client_factory():
        pass

    matches = [
        kwargs for event, kwargs in events if event == "mcp_stateful_multi_replica"
    ]
    assert matches, events
    assert matches[0]["replica_count"] == 2


# ---------------------------------------------------------------------------
# Maintenance-mode backend startup check: the in_memory backend is
# process-local, so it can't propagate a toggle across replicas -- warn
# (never fail), the same shape as the mcp_stateful_multi_replica check above.
# ---------------------------------------------------------------------------


def test_warns_when_in_memory_maintenance_backend_with_multiple_replicas(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setenv("MCP_REPLICA_COUNT", "3")
    monkeypatch.setenv("MAINTENANCE_MODE_BACKEND", "in_memory")

    events: list[tuple[str, dict[str, Any]]] = []
    original_warning = app_module.logger.warning

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append((event, kwargs))
        return original_warning(event, **kwargs)

    monkeypatch.setattr(app_module.logger, "warning", _capture)

    with app_client_factory():
        pass

    matches = [
        kwargs
        for event, kwargs in events
        if event == "maintenance_mode_in_memory_multi_replica"
    ]
    assert matches, events
    assert matches[0]["replica_count"] == 3


@pytest.mark.parametrize(
    "replica_count",
    [
        "1",  # single replica is the in_memory default's home turf
        None,  # replica count unknown -- nothing to warn about
    ],
)
def test_maintenance_mode_warning_does_not_fire_at_safe_replica_counts(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    replica_count: str | None,
) -> None:
    if replica_count is not None:
        monkeypatch.setenv("MCP_REPLICA_COUNT", replica_count)

    events: list[tuple[str, dict[str, Any]]] = []
    original_warning = app_module.logger.warning

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append((event, kwargs))
        return original_warning(event, **kwargs)

    monkeypatch.setattr(app_module.logger, "warning", _capture)

    with app_client_factory():
        pass

    assert not any(
        event == "maintenance_mode_in_memory_multi_replica" for event, _ in events
    )


def test_maintenance_mode_warning_does_not_fire_for_replica_visible_backend(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    postgres_dsn: str,
) -> None:
    """The postgres backend is visible to every replica, so it needs no warning even at replica_count > 1 -- unlike the in_memory default above."""
    monkeypatch.setenv("MAINTENANCE_MODE_BACKEND", "postgres")
    monkeypatch.setenv("MAINTENANCE_MODE_POSTGRES_DSN", postgres_dsn)
    monkeypatch.setenv("MCP_REPLICA_COUNT", "3")

    events: list[tuple[str, dict[str, Any]]] = []
    original_warning = app_module.logger.warning

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append((event, kwargs))
        return original_warning(event, **kwargs)

    monkeypatch.setattr(app_module.logger, "warning", _capture)

    with app_client_factory():
        pass

    assert not any(
        event == "maintenance_mode_in_memory_multi_replica" for event, _ in events
    )


# ---------------------------------------------------------------------------
# Tracing wiring (observability roadmap PR D): off by default -- with
# OTEL_EXPORTER_OTLP_ENDPOINT unset at import time, module-scope
# instrument_fastapi() must have been a no-op; and the lifespan teardown must
# flush whatever provider init_tracing() installed (a no-op when none was).
# ---------------------------------------------------------------------------


async def test_bind_request_logging_context_binds_a_fresh_correlation_id() -> None:
    """Issue #281: the only /v1 middleware that runs before keycloak_dependency
    resolves identity, so this is where every request -- even one whose
    credentials never validate -- gets a correlation_id to log by."""
    structlog.contextvars.clear_contextvars()

    async def call_next(request: Any) -> str:
        return "response"

    result = await app_module._bind_request_logging_context(None, call_next)

    assert result == "response"
    assert structlog.contextvars.get_contextvars()["correlation_id"]


def test_app_not_instrumented_by_default() -> None:
    assert not getattr(app_module.app, "_is_instrumented_by_opentelemetry", False)


def test_lifespan_teardown_flushes_tracing(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    calls: list[bool] = []
    monkeypatch.setattr(app_module, "shutdown_tracing", lambda: calls.append(True))

    with app_client_factory():
        pass

    assert calls == [True]


@pytest.mark.parametrize(
    ("stateless_http", "replica_count"),
    [
        ("true", "2"),  # safe default, even at replicaCount > 1
        ("false", "1"),  # stateful is fine at a single replica
        ("false", None),  # replica count unknown -- nothing to warn about
    ],
)
def test_stateful_multi_replica_warning_does_not_fire_when_safe(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    stateless_http: str,
    replica_count: str | None,
) -> None:
    monkeypatch.setenv("MCP_STATELESS_HTTP", stateless_http)
    if replica_count is not None:
        monkeypatch.setenv("MCP_REPLICA_COUNT", replica_count)

    events: list[tuple[str, dict[str, Any]]] = []
    original_warning = app_module.logger.warning

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append((event, kwargs))
        return original_warning(event, **kwargs)

    monkeypatch.setattr(app_module.logger, "warning", _capture)

    with app_client_factory():
        pass

    assert not any(event == "mcp_stateful_multi_replica" for event, _ in events)

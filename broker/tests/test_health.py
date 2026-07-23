"""Readiness semantics: an empty backends list is a valid degraded state
(issue #29) — /v1/readyz must gate only on JWKS reachability, surfacing
backends config as informational fields instead of failing the probe.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest


async def _ok_jwks(settings: Any) -> list[dict[str, Any]]:
    del settings
    return [{"kid": "test-key"}]


async def _unreachable_jwks(settings: Any) -> list[dict[str, Any]]:
    del settings
    raise RuntimeError("jwks endpoint unreachable")


def _write_empty_backends(tmp_path: Path) -> str:
    path = tmp_path / "backends.yaml"
    path.write_text("backends: []\n")
    return str(path)


def test_readyz_ok_with_empty_backends(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setenv("BACKENDS_FILE", _write_empty_backends(tmp_path))
    monkeypatch.setattr("af_mcp_broker.api.health.get_jwks", _ok_jwks)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/v1/readyz")

    assert resp.status_code == 200, resp.text


def test_readyz_503_when_jwks_unreachable(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setattr("af_mcp_broker.api.health.get_jwks", _unreachable_jwks)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/v1/readyz")

    assert resp.status_code == 503, resp.text
    assert resp.json()["status"] == "not_ready"


def test_readyz_body_reports_backends_count(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setattr("af_mcp_broker.api.health.get_jwks", _ok_jwks)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/v1/readyz")
        backends_count_on_app = len(client.app.state.backends)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["backends_count"] == backends_count_on_app
    # The shipped backends.yaml used by app_client_factory is non-empty —
    # this asserts we're actually exercising the "backends present" case.
    assert body["backends_count"] > 0


def test_readyz_body_reports_backends_count_zero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setenv("BACKENDS_FILE", _write_empty_backends(tmp_path))
    monkeypatch.setattr("af_mcp_broker.api.health.get_jwks", _ok_jwks)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/v1/readyz")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["backends_count"] == 0
    assert body["backends_loaded"] is True


def test_startup_warns_on_no_backends(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """Emptying the backends file must not gate readiness, but must still be
    a loud, visible signal — a WARNING structlog line at startup.

    configure_logging() rewrites the root logger's handlers during the app
    lifespan, which would otherwise swallow pytest's caplog handler, so this
    asserts directly against the app module's logger call instead.
    """
    monkeypatch.setenv("BACKENDS_FILE", _write_empty_backends(tmp_path))

    from af_mcp_broker import app as app_module

    events: list[str] = []
    original_warning = app_module.logger.warning

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append(event)
        return original_warning(event, **kwargs)

    monkeypatch.setattr(app_module.logger, "warning", _capture)

    with app_client_factory():
        pass

    assert "no_backends_configured" in events

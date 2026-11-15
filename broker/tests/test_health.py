"""Readiness semantics: /v1/readyz gates only on JWKS reachability; the
services count is an informational field. An empty or missing services file
never reaches readiness because it refuses to boot.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


async def _ok_jwks(settings: Any, http_client: Any) -> list[dict[str, Any]]:
    del settings, http_client
    return [{"kid": "test-key"}]


async def _unreachable_jwks(settings: Any, http_client: Any) -> list[dict[str, Any]]:
    del settings, http_client
    raise RuntimeError("jwks endpoint unreachable")


def test_readyz_503_when_jwks_unreachable(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setattr("af_mcp_broker.api.health.get_jwks", _unreachable_jwks)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/v1/readyz")

    assert resp.status_code == 503, resp.text
    assert resp.json()["status"] == "not_ready"


def test_readyz_body_reports_services_count(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setattr("af_mcp_broker.api.health.get_jwks", _ok_jwks)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/v1/readyz")
        services_count_on_app = len(client.app.state.broker.services)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["services_count"] == services_count_on_app
    # The shipped services.yaml used by app_client_factory is non-empty —
    # this asserts we're actually exercising the "backends present" case.
    assert body["services_count"] > 0


def test_readyz_body_has_no_services_loaded_field(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setattr("af_mcp_broker.api.health.get_jwks", _ok_jwks)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/v1/readyz")

    assert "services_loaded" not in resp.json()


def test_startup_refuses_an_empty_services_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text("services: []\n")
    monkeypatch.setenv("SERVICES_FILE", str(services_file))
    monkeypatch.setenv("IDENTITY_PROVIDERS", "[]")

    with pytest.raises(RuntimeError, match="SERVICES_FILE"):  # noqa: SIM117
        with app_client_factory():
            pass

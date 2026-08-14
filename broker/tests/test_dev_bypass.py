"""Tests for the BROKER_DEV_INSECURE_PRINCIPAL local-dev auth bypass.

The bypass short-circuits ``keycloak_dependency`` when the env var is set AND
the configured issuer looks local. Every code path here is a security-adjacent
regression net — do not weaken these tests without security review.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# The shipped policy/backends need to be findable regardless of the caller's CWD.
_SRC = Path(__file__).resolve().parents[1] / "src" / "af_mcp_broker"
SHIPPED_POLICY = _SRC / "authorization" / "policy.yaml"
SHIPPED_BACKENDS = _SRC / "mcp" / "backends.yaml"

# Copy-paste value from docs/local-development.md so the tests exercise the
# exact string a developer will use.
DEV_PRINCIPAL_JSON = json.dumps(
    {
        "uid": 1000,
        "gid": 1000,
        "unixname": "devuser",
        "email": "dev@localhost",
        "groups": ["af-users"],
    }
)


def _bootstrap_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the app at the shipped YAML and an ephemeral metrics port."""
    monkeypatch.setenv("POLICY_FILE", str(SHIPPED_POLICY))
    monkeypatch.setenv("BACKENDS_FILE", str(SHIPPED_BACKENDS))
    monkeypatch.setenv("METRICS_PORT", "0")


def _clear_settings_cache() -> None:
    """``get_settings`` is ``lru_cache``d — force a re-read after env changes."""
    from af_mcp_broker.config import get_settings

    get_settings.cache_clear()


def _fresh_app():
    """Reimport the app so per-test env changes are picked up cleanly."""
    _clear_settings_cache()
    from af_mcp_broker.app import app

    # Belt-and-braces: any override installed by another test's fixture must not
    # leak into these tests, which exercise the real keycloak_dependency.
    app.dependency_overrides.clear()
    return app


def test_bypass_activates_with_local_issuer(monkeypatch: pytest.MonkeyPatch) -> None:
    _bootstrap_env(monkeypatch)
    monkeypatch.setenv("BROKER_DEV_INSECURE_PRINCIPAL", DEV_PRINCIPAL_JSON)
    monkeypatch.setenv("OIDC_ISSUER", "http://localhost:8081/realms/x")

    app = _fresh_app()
    with TestClient(app) as client:
        resp = client.get("/v1/identities")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["uid"] == 1000
    assert body["gid"] == 1000
    assert body["unixname"] == "devuser"
    assert body["email"] == "dev@localhost"
    assert body["groups"] == ["af-users"]


def test_bypass_refuses_to_start_with_real_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bootstrap_env(monkeypatch)
    monkeypatch.setenv("BROKER_DEV_INSECURE_PRINCIPAL", DEV_PRINCIPAL_JSON)
    monkeypatch.setenv(
        "OIDC_ISSUER",
        "https://auth.af.uchicago.edu/realms/connect",
    )

    app = _fresh_app()
    with pytest.raises(RuntimeError, match=r"auth\.af\.uchicago\.edu"):  # noqa: SIM117
        with TestClient(app):
            pass


def test_bypass_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _bootstrap_env(monkeypatch)
    monkeypatch.delenv("BROKER_DEV_INSECURE_PRINCIPAL", raising=False)
    # Unreachable issuer keeps startup JWKS priming a no-op (non-fatal).
    monkeypatch.setenv("OIDC_ISSUER", "https://keycloak.invalid/realms/connect")
    # Issue #144 step 3: with the bypass disabled, the broker now refuses to
    # start at all unless a Keycloak admin service account is configured
    # (see test_no_bypass_and_no_directory_refuses_to_start below for that
    # check itself) -- configure one here so this test can exercise its own
    # point (a missing bearer is a real 401) rather than a startup failure.
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_ID", "test-admin-client")
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_SECRET", "test-admin-secret")

    app = _fresh_app()
    with TestClient(app) as client:
        resp = client.get("/v1/identities")

    assert resp.status_code == 401, resp.text


def test_no_bypass_and_no_directory_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #144 step 3: neither the dev bypass nor a Keycloak admin
    service account configured means the broker can never authenticate
    anyone (JWT groups resolution now depends on the directory too, not
    just PATs) -- refuse to start rather than boot into a broker that
    accepts every request and can satisfy none of them. Same fail-fast
    reasoning as the other startup checks in app.py's lifespan (issue #125):
    a Kubernetes rollout with a failing new pod leaves the previous
    ReplicaSet serving, so this surfaces as a visible rollout failure with
    zero outage risk."""
    _bootstrap_env(monkeypatch)
    monkeypatch.delenv("BROKER_DEV_INSECURE_PRINCIPAL", raising=False)
    monkeypatch.delenv("KEYCLOAK_ADMIN_CLIENT_ID", raising=False)
    monkeypatch.delenv("KEYCLOAK_ADMIN_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("OIDC_ISSUER", "https://keycloak.invalid/realms/connect")

    app = _fresh_app()
    with pytest.raises(RuntimeError, match="KEYCLOAK_ADMIN_CLIENT_ID"):  # noqa: SIM117
        with TestClient(app):
            pass


def test_bypass_ignores_real_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _bootstrap_env(monkeypatch)
    monkeypatch.setenv("BROKER_DEV_INSECURE_PRINCIPAL", DEV_PRINCIPAL_JSON)
    monkeypatch.setenv("OIDC_ISSUER", "http://localhost:8081/realms/x")

    app = _fresh_app()
    with TestClient(app) as client:
        resp = client.get(
            "/v1/identities",
            headers={"Authorization": "Bearer this-token-is-not-checked"},
        )

    assert resp.status_code == 200, resp.text
    # Real token is ignored; dev principal is what came back.
    assert resp.json()["unixname"] == "devuser"


def test_bypass_bad_json_fails_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    _bootstrap_env(monkeypatch)
    monkeypatch.setenv("BROKER_DEV_INSECURE_PRINCIPAL", "{not json")
    monkeypatch.setenv("OIDC_ISSUER", "http://localhost:8081/realms/x")

    app = _fresh_app()
    with pytest.raises(RuntimeError, match="BROKER_DEV_INSECURE_PRINCIPAL"):  # noqa: SIM117
        with TestClient(app):
            pass


def test_bypass_response_header_present(monkeypatch: pytest.MonkeyPatch) -> None:
    _bootstrap_env(monkeypatch)
    monkeypatch.setenv("BROKER_DEV_INSECURE_PRINCIPAL", DEV_PRINCIPAL_JSON)
    monkeypatch.setenv("OIDC_ISSUER", "http://localhost:8081/realms/x")

    app = _fresh_app()
    with TestClient(app) as client:
        resp = client.get("/v1/identities")

    assert resp.status_code == 200, resp.text
    assert resp.headers.get("X-Dev-Bypass") == "true"


def test_bypass_missing_required_key_fails_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guardrail: a payload missing uid/gid/unixname must trip the startup check
    rather than crashing later at request time with a KeyError."""
    _bootstrap_env(monkeypatch)
    monkeypatch.setenv(
        "BROKER_DEV_INSECURE_PRINCIPAL", json.dumps({"unixname": "onlyname"})
    )
    monkeypatch.setenv("OIDC_ISSUER", "http://localhost:8081/realms/x")

    app = _fresh_app()
    with pytest.raises(RuntimeError, match="BROKER_DEV_INSECURE_PRINCIPAL"):  # noqa: SIM117
        with TestClient(app):
            pass

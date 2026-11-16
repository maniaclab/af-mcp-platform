"""The documented local-development modes boot the broker out of the box.

The environment is not rebuilt by hand: it is what ``pixi run -e <env>``
activates, read from ``pixi.toml``'s feature activation tables and expanded by
a real shell (the activation values use ``${VAR:-default}`` and
``${PIXI_PROJECT_ROOT}``), against the real dev registry and policy files.
docs/local-development.md names the extra settings the ``dev`` mode needs.
"""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from af_mcp_broker.app import app
from af_mcp_broker.config import get_settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Activation variables a local mode must not inherit from the test runner's own
# shell (the dev pixi environment already activates some of them).
_LOCAL_MODE_VARS = (
    "POLICY_FILE",
    "SERVICES_FILE",
    "OIDC_ISSUER",
    "BROKER_DEV_INSECURE_PRINCIPAL",
    "IDENTITY_PROVIDERS",
    "ADMIN_GROUP",
    "KEYCLOAK_ADMIN_CLIENT_ID",
    "KEYCLOAK_ADMIN_CLIENT_SECRET",
    "BROKER_SIGNING_KEY_FILE",
    "VAULT_ADDR",
)


def _activation_env(environment: str) -> dict[str, str]:
    """The variables ``pixi run -e <environment>`` exports, expanded as the shell does."""
    manifest = tomllib.loads((_PROJECT_ROOT / "pixi.toml").read_text())
    spec = manifest["environments"][environment]
    features = spec["features"] if isinstance(spec, dict) else spec
    raw: dict[str, str] = {}
    for feature in features:
        raw.update(
            manifest.get("feature", {})
            .get(feature, {})
            .get("activation", {})
            .get("env", {})
        )
    expanded: dict[str, str] = {}
    for name, value in raw.items():
        # pixi writes `export NAME="value"` (so ${...} expands in the shell),
        # and single-quotes a value that holds double quotes (JSON).
        quoted = f"'{value}'" if '"' in value else f'"{value}"'
        script = f'export PIXI_PROJECT_ROOT="$1"; export {name}={quoted}; printf %s "${name}"'
        expanded[name] = subprocess.run(
            ["bash", "-c", script, "bash", str(_PROJECT_ROOT)],
            check=True,
            capture_output=True,
            text=True,
            env={},
        ).stdout
    return expanded


@pytest.fixture
def local_mode_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in _LOCAL_MODE_VARS:
        monkeypatch.delenv(name, raising=False)
    # An ephemeral metrics port keeps the test off the real :9090.
    monkeypatch.setenv("METRICS_PORT", "0")
    get_settings.cache_clear()
    app.dependency_overrides.clear()
    return monkeypatch


def test_bypass_mode_boots(local_mode_env: pytest.MonkeyPatch) -> None:
    for name, value in _activation_env("bypass").items():
        local_mode_env.setenv(name, value)

    with TestClient(app) as client:
        resp = client.get("/v1/identities")

    assert resp.status_code == 200, resp.text
    assert resp.json()["unixname"] == "devuser"


def test_dev_mode_boots_with_the_documented_keycloak_settings(
    local_mode_env: pytest.MonkeyPatch,
) -> None:
    for name, value in _activation_env("dev").items():
        local_mode_env.setenv(name, value)
    # docs/local-development.md: `dev` is the no-bypass mode, so it needs a
    # realm URL and the Keycloak admin service account.
    local_mode_env.setenv("OIDC_ISSUER", "https://keycloak.invalid/realms/dev")
    local_mode_env.setenv("KEYCLOAK_ADMIN_CLIENT_ID", "dev-admin")
    local_mode_env.setenv("KEYCLOAK_ADMIN_CLIENT_SECRET", "dev-secret")

    with TestClient(app) as client:
        resp = client.get("/v1/identities")

    assert resp.status_code == 401, resp.text
    assert resp.json()["detail"] == "Not authenticated"

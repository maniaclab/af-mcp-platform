"""The flat environment-variable interface of ``Settings`` is stable.

``data/chart_env/<values>.json`` holds, for each ``charts/af-mcp-platform/ci``
values file, the broker container's env as the chart renders it (secret
references replaced by a ``<secret:name/key>`` placeholder) and either the
``Settings`` parsed from it or the validation error it is refused with.

The chart is rendered live with ``helm`` (a dev-environment dependency) on
every run, so a chart change that alters the broker env fails here until the
fixtures are regenerated on purpose. Regenerate them with
``UPDATE_CHART_ENV_FIXTURES=1 pixi run -e dev pytest
broker/tests/test_config_chart_env.py`` and review the diff.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from af_mcp_broker.config import Settings

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHART = _REPO_ROOT / "charts" / "af-mcp-platform"
_FIXTURE_DIR = Path(__file__).parent / "data" / "chart_env"
_VALUES_FILES = sorted((_CHART / "ci").glob("*-values.yaml"))
_UPDATE = os.environ.get("UPDATE_CHART_ENV_FIXTURES") == "1"


def _fixture_path(values: Path) -> Path:
    return _FIXTURE_DIR / f"{values.name.removesuffix('-values.yaml')}.json"


def _render_broker_env(values: Path) -> dict[str, str]:
    """Render *values* with helm and return the broker container's env."""
    rendered = subprocess.run(
        [
            "helm",
            "template",
            "af-mcp-platform",
            str(_CHART),
            "--set",
            "image.broker.tag=sha-test",
            "--set",
            "image.portal.tag=sha-test",
            "-f",
            str(values),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    env: dict[str, str] = {}
    for doc in yaml.safe_load_all(rendered):
        if not doc or doc.get("kind") != "Deployment":
            continue
        if not doc["metadata"]["name"].endswith("broker"):
            continue
        for container in doc["spec"]["template"]["spec"]["containers"]:
            if container["name"] != "broker":
                continue
            for var in container.get("env", []):
                if "value" in var:
                    env[var["name"]] = var["value"]
                else:
                    ref = var["valueFrom"]["secretKeyRef"]
                    env[var["name"]] = f"<secret:{ref['name']}/{ref['key']}>"
    assert env, f"no broker env rendered for {values.name}"
    return env


def _clear_settings_env(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> None:
    """Make *env* the only source of settings, whatever the host environment sets."""
    for name in list(os.environ):
        if name.lower() in Settings.model_fields:
            monkeypatch.delenv(name)
    for name, value in env.items():
        monkeypatch.setenv(name, value)


def _parse(env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Parse *env* as the only settings source: ``{"settings": ...}`` or ``{"error": ...}``."""
    _clear_settings_env(monkeypatch, env)
    try:
        return {"settings": Settings(_env_file=None).model_dump(mode="json")}
    except ValidationError as exc:
        return {"error": exc.errors()[0]["msg"]}


@pytest.mark.parametrize("values", _VALUES_FILES, ids=lambda p: p.name)
def test_chart_env_parses_to_pinned_settings(
    values: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _render_broker_env(values)
    fixture = _fixture_path(values)
    if _UPDATE:
        fixture.write_text(
            json.dumps(
                {"env": env, **_parse(env, monkeypatch)}, indent=2, sort_keys=True
            )
            + "\n"
        )
        return

    pinned: dict[str, Any] = json.loads(fixture.read_text())
    assert env == pinned["env"], (
        f"the chart's rendered broker env for {values.name} differs from "
        f"{fixture.name}; regenerate with UPDATE_CHART_ENV_FIXTURES=1 and review"
    )
    parsed = _parse(env, monkeypatch)
    assert parsed == {k: v for k, v in pinned.items() if k != "env"}


def test_every_fixture_has_a_values_file() -> None:
    expected = {_fixture_path(values).name for values in _VALUES_FILES}
    assert {path.name for path in _FIXTURE_DIR.glob("*.json")} == expected


_VAULT_MESSAGE = (
    "{field} ({env}) must be set when token_store_backend, "
    "token_registry_backend, principal_cache_backend, or "
    "maintenance_mode_backend is 'vault' or an x509, krb5-token, or "
    "servicex-token identity_providers entry is configured (their credential "
    "material persists in Vault, with no in-memory fallback)."
)
_CREDMON_MESSAGE = (
    "{field} ({env}) must be set when credmon_enabled is true -- the storer "
    "needs it to store top tokens in credd through htcondor-api."
)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        pytest.param(
            {"token_store_backend": "vault", "vault_auth_role": "r"},
            "Value error, "
            + _VAULT_MESSAGE.format(field="vault_addr", env="VAULT_ADDR"),
            id="vault-addr",
        ),
        pytest.param(
            {"maintenance_mode_backend": "vault", "vault_addr": "https://v"},
            "Value error, "
            + _VAULT_MESSAGE.format(field="vault_auth_role", env="VAULT_AUTH_ROLE"),
            id="vault-auth-role",
        ),
        pytest.param(
            {"usage_store_backend": "postgres"},
            "Value error, usage_postgres_dsn (USAGE_POSTGRES_DSN) must be set "
            "when usage_store_backend is 'postgres' -- typically the `uri` key "
            "of a Crunchy PGO `<cluster>-pguser-<user>` secret.",
            id="usage-dsn",
        ),
        pytest.param(
            {"maintenance_mode_backend": "postgres"},
            "Value error, maintenance_mode_postgres_dsn "
            "(MAINTENANCE_MODE_POSTGRES_DSN) or usage_postgres_dsn "
            "(USAGE_POSTGRES_DSN) must be set when maintenance_mode_backend is "
            "'postgres'.",
            id="maintenance-dsn",
        ),
        pytest.param(
            {"credmon_enabled": True},
            "Value error, "
            + _CREDMON_MESSAGE.format(
                field="credmon_htcondor_api_url", env="CREDMON_HTCONDOR_API_URL"
            ),
            id="credmon-url",
        ),
        pytest.param(
            {"credmon_enabled": True, "credmon_htcondor_api_url": "http://x"},
            "Value error, "
            + _CREDMON_MESSAGE.format(
                field="credmon_htcondor_api_token_file",
                env="CREDMON_HTCONDOR_API_TOKEN_FILE",
            ),
            id="credmon-token-file",
        ),
        pytest.param(
            {
                "credmon_enabled": True,
                "credmon_htcondor_api_url": "http://x",
                "credmon_htcondor_api_token_file": "/f",
            },
            "Value error, "
            + _CREDMON_MESSAGE.format(
                field="credmon_user_domain", env="CREDMON_USER_DOMAIN"
            ),
            id="credmon-user-domain",
        ),
    ],
)
def test_validation_error_messages_are_pinned(
    kwargs: dict[str, Any], message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_settings_env(monkeypatch, {})
    with pytest.raises(ValidationError) as excinfo:
        Settings(_env_file=None, **kwargs)
    assert excinfo.value.errors()[0]["msg"] == message

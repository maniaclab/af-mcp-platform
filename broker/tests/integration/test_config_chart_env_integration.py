"""Integration tests for the area ``test_config_chart_env.py`` covers; the unit tests live in ``unit/test_config_chart_env.py``."""

from __future__ import annotations

import json
import os
import subprocess
from typing import TYPE_CHECKING, Any

import pytest
import yaml
from config_chart_env_support import (
    _CHART,
    _VALUES_FILES,
    _clear_settings_env,
    _fixture_path,
)
from pydantic import ValidationError

from af_mcp_broker.config import Settings

if TYPE_CHECKING:
    from pathlib import Path

_UPDATE = os.environ.get("UPDATE_CHART_ENV_FIXTURES") == "1"


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

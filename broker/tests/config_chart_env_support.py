"""Fixtures and helpers shared by the unit and integration tests of ``test_config_chart_env``."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from af_mcp_broker.config import Settings

if TYPE_CHECKING:
    import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHART = _REPO_ROOT / "charts" / "af-mcp-platform"
_FIXTURE_DIR = Path(__file__).resolve().parent / "data" / "chart_env"
_VALUES_FILES = sorted((_CHART / "ci").glob("*-values.yaml"))


def _fixture_path(values: Path) -> Path:
    return _FIXTURE_DIR / f"{values.name.removesuffix('-values.yaml')}.json"


def _clear_settings_env(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> None:
    """Make *env* the only source of settings, whatever the host environment sets."""
    for name in list(os.environ):
        if name.lower() in Settings.model_fields:
            monkeypatch.delenv(name)
    for name, value in env.items():
        monkeypatch.setenv(name, value)

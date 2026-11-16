"""Integration tests for the area ``test_check_chart_version.py`` covers; the unit tests live in ``unit/test_check_chart_version.py``."""

from __future__ import annotations

import re
import subprocess
import tomllib
from typing import TYPE_CHECKING

import pytest
from check_chart_version_support import (
    _REPO_ROOT,
)

if TYPE_CHECKING:
    from pathlib import Path

_TBUMP_TOML = _REPO_ROOT / "tbump.toml"


def _tbump_version_pattern() -> re.Pattern[str]:
    regex = tomllib.loads(_TBUMP_TOML.read_text())["version"]["regex"]
    return re.compile(regex, re.VERBOSE)


def _helm_package(tmp_path: Path, version: str) -> subprocess.CompletedProcess[str]:
    chart_dir = tmp_path / "chart"
    chart_dir.mkdir()
    (chart_dir / "Chart.yaml").write_text(
        f"apiVersion: v2\nname: chart\nversion: {version}\n"
    )
    return subprocess.run(
        ["helm", "package", str(chart_dir), "--destination", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("version", ["1.2.3", "1.2.3-rc.1", "0.12.0-rc.10"])
def test_tbump_versions_are_accepted_by_helm_package(
    tmp_path: Path, version: str
) -> None:
    assert _tbump_version_pattern().fullmatch(version)

    result = _helm_package(tmp_path, version)

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("version", ["1.2.3rc1"])
def test_tbump_rejects_versions_that_helm_package_rejects(
    tmp_path: Path, version: str
) -> None:
    assert _tbump_version_pattern().fullmatch(version) is None

    assert _helm_package(tmp_path, version).returncode != 0

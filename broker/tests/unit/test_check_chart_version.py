"""``scripts/check-chart-version.py`` gates the chart's OCI publish on the release tag.

The chart is pushed to the registry under ``Chart.yaml``'s ``version``, so a
tag whose version differs would publish the chart under the wrong version.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "check-chart-version.py"
_CHART_YAML = _REPO_ROOT / "charts" / "af-mcp-platform" / "Chart.yaml"
_TBUMP_TOML = _REPO_ROOT / "tbump.toml"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_chart_version", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _chart(tmp_path: Path, version_line: str) -> Path:
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        f'apiVersion: v2\nname: af-mcp-platform\n{version_line}\nappVersion: "9.9.9"\n'
    )
    return chart


@pytest.mark.parametrize("tag", ["v1.2.3", "v10.20.30"])
def test_matching_tag_passes(tmp_path: Path, tag: str) -> None:
    script = _load_script()
    chart = _chart(tmp_path, f"version: {tag.removeprefix('v')}")

    assert script.main([tag, str(chart)]) == 0


def test_mismatched_tag_fails_and_names_both_versions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    script = _load_script()
    chart = _chart(tmp_path, "version: 1.2.3")

    assert script.main(["v1.2.4", str(chart)]) == 1
    err = capsys.readouterr().err
    assert "1.2.4" in err
    assert "1.2.3" in err


def test_tag_without_v_prefix_fails(tmp_path: Path) -> None:
    script = _load_script()
    chart = _chart(tmp_path, "version: 1.2.3")

    assert script.main(["1.2.3", str(chart)]) == 1


def test_appversion_is_not_mistaken_for_version(tmp_path: Path) -> None:
    script = _load_script()
    chart = _chart(tmp_path, "version: 1.2.3")

    assert script.main(["v9.9.9", str(chart)]) == 1


def test_chart_without_version_fails(tmp_path: Path) -> None:
    script = _load_script()
    chart = tmp_path / "Chart.yaml"
    chart.write_text("apiVersion: v2\nname: af-mcp-platform\n")

    assert script.main(["v1.2.3", str(chart)]) == 1


def test_committed_chart_version_matches_its_own_tag() -> None:
    script = _load_script()
    version = script.chart_version(_CHART_YAML)

    assert script.main([f"v{version}", str(_CHART_YAML)]) == 0


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


def test_release_candidate_tag_matches_its_chart_version(tmp_path: Path) -> None:
    script = _load_script()
    chart = _chart(tmp_path, "version: 1.2.3-rc.1")

    assert script.main(["v1.2.3-rc.1", str(chart)]) == 0

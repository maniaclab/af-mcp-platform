"""``scripts/check-chart-version.py`` gates the chart's OCI publish on the release tag.

The chart is pushed to the registry under ``Chart.yaml``'s ``version``, so a
tag whose version differs would publish the chart under the wrong version.
"""

from __future__ import annotations

import importlib.util
from typing import TYPE_CHECKING

import pytest
from check_chart_version_support import (
    _REPO_ROOT,
)

if TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType
_SCRIPT = _REPO_ROOT / "scripts" / "check-chart-version.py"
_CHART_YAML = _REPO_ROOT / "charts" / "af-mcp-platform" / "Chart.yaml"


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


def test_release_candidate_tag_matches_its_chart_version(tmp_path: Path) -> None:
    script = _load_script()
    chart = _chart(tmp_path, "version: 1.2.3-rc.1")

    assert script.main(["v1.2.3-rc.1", str(chart)]) == 0

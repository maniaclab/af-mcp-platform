"""``values.schema.json`` rejects bad chart values before any template renders.

Each file in ``data/chart_values_schema`` is a deliberately bad overlay on
``ci/test-values.yaml``. The chart is rendered live with ``helm`` (a
dev-environment dependency) and must refuse it, naming the offending keys.
Helm's wording for a schema violation differs between releases, so the
assertions match key names, not sentences.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHART = _REPO_ROOT / "charts" / "af-mcp-platform"
_BASE_VALUES = _CHART / "ci" / "test-values.yaml"
_BAD_VALUES = Path(__file__).parent / "data" / "chart_values_schema"


def _helm_template(*overlays: Path) -> subprocess.CompletedProcess[str]:
    """Render the chart over the CI base values plus *overlays*; never raises on failure."""
    command = [
        "helm",
        "template",
        "af-mcp-platform",
        str(_CHART),
        "--set",
        "image.broker.tag=sha-test",
        "--set",
        "image.portal.tag=sha-test",
        "-f",
        str(_BASE_VALUES),
    ]
    for overlay in overlays:
        command += ["-f", str(overlay)]
    return subprocess.run(command, check=False, capture_output=True, text=True)


@pytest.mark.parametrize(
    ("overlay", "fragments"),
    [
        ("typo-key", ["keycloakAdmn"]),
        ("wrong-type", ["replicaCount"]),
        ("bad-backend", ["tokenRegistry", "backend"]),
        ("empty-services", ["aggregator", "services"]),
        ("empty-policy", ["entitlements", "group_permissions"]),
        ("service-typo", ["requried_permission"]),
        ("x509-without-service-url", ["serviceUrl"]),
        ("missing-required", ["issuer", "clientId", "brokerOrigin"]),
        ("several-errors", ["keycloakAdmn", "replicaCount", "services"]),
    ],
)
def test_bad_values_are_rejected_by_the_schema(
    overlay: str, fragments: list[str]
) -> None:
    result = _helm_template(_BAD_VALUES / f"{overlay}.yaml")

    assert result.returncode != 0
    assert "values don't meet the specifications of the schema" in result.stderr
    for fragment in fragments:
        assert fragment in result.stderr


def test_base_values_pass_the_schema() -> None:
    result = _helm_template()

    assert result.returncode == 0, result.stderr

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
_EXAMPLES = _CHART / "examples"
_BAD_VALUES = Path(__file__).parent / "data" / "chart_values_schema"


def _helm_template(
    *overlays: Path, sets: tuple[str, ...] = ()
) -> subprocess.CompletedProcess[str]:
    """Render the chart over the CI base values plus *overlays* and ``--set`` *sets*; never raises on failure."""
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
    for assignment in sets:
        command += ["--set", assignment]
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
        ("x509-without-voms", ["voms"]),
        ("ingress-without-hosts", ["mcpHost", "portalHost"]),
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


def test_ingress_disabled_needs_no_hosts() -> None:
    result = _helm_template(
        sets=("ingress.enabled=false", "ingress.mcpHost=", "ingress.portalHost=")
    )

    assert result.returncode == 0, result.stderr


def test_default_render_carries_no_facility_content() -> None:
    # Template comments may cite an example; the rendered values must not.
    rendered = "\n".join(
        line
        for line in _helm_template().stdout.lower().splitlines()
        if not line.lstrip().startswith("#")
    )

    for facility_marker in ("uchicago", "letsencrypt", "mwt2"):
        assert facility_marker not in rendered


@pytest.mark.parametrize(
    "kind", ["kind: ServiceMonitor", "grafana_dashboard", "cert-manager.io"]
)
def test_optional_integrations_are_opt_in(kind: str) -> None:
    assert kind not in _helm_template().stdout


def test_tls_secret_names_derive_from_the_release() -> None:
    rendered = _helm_template().stdout

    assert 'secretName: "af-mcp-platform-mcp-tls"' in rendered
    assert 'secretName: "af-mcp-platform-portal-tls"' in rendered


def test_example_values_render_a_complete_deployment() -> None:
    result = _helm_template(_EXAMPLES / "example-values.yaml")

    assert result.returncode == 0, result.stderr
    for expected in (
        "kind: ServiceMonitor",
        "grafana_dashboard",
        "mcp.af.example.org",
        "cert-manager.io/cluster-issuer",
        "kind: NetworkPolicy",
        "192.0.2.0/24",
        "2001:db8::/32",
        "198.51.100.0/24",
    ):
        assert expected in result.stdout

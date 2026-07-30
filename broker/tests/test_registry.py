"""Tests for BackendSpec/BackendRegistry — the config-driven backend catalog
that both /v1/catalog and the /mcp aggregator's routing read from.
"""

from __future__ import annotations

from pathlib import Path

from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec

SHIPPED_BACKENDS = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "af_mcp_broker"
    / "mcp"
    / "backends.yaml"
)


def test_backend_spec_description_and_display_name_default_to_empty() -> None:
    spec = BackendSpec(
        name="rucio",
        prefix="rucio",
        url="http://rucio-mcp/mcp",
        transport="http",
        required_capability="read_data",
    )
    assert spec.description == ""
    assert spec.display_name == ""


def test_registry_load_reads_description_and_display_name_from_yaml(
    tmp_path: Path,
) -> None:
    backends_yaml = tmp_path / "backends.yaml"
    backends_yaml.write_text(
        "backends:\n"
        "  - name: rucio\n"
        "    prefix: rucio\n"
        "    url: http://rucio-mcp/mcp\n"
        "    required_capability: read_data\n"
        "    display_name: Rucio\n"
        "    description: ATLAS distributed data management\n"
    )
    registry = BackendRegistry()
    registry.load(str(backends_yaml))
    spec = registry.get("rucio")
    assert spec is not None
    assert spec.display_name == "Rucio"
    assert spec.description == "ATLAS distributed data management"


def test_shipped_backends_carry_display_name_and_description() -> None:
    """The shipped backends.yaml must not ship description-less entries
    forever — every entry gets a real display_name/description."""
    registry = BackendRegistry()
    registry.load(str(SHIPPED_BACKENDS))
    for spec in registry.all_backends():
        assert spec.display_name, f"{spec.name} is missing display_name"
        assert spec.description, f"{spec.name} is missing description"

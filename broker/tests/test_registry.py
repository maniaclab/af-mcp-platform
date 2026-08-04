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


def test_backend_spec_required_capability_defaults_to_none() -> None:
    """Omitted required_capability means "no capability gate; the credential
    layer is the gate instead" (issue #60) -- distinct from the "__none__"
    sentinel, which is an explicit open-access opt-in."""
    spec = BackendSpec(
        name="rucio",
        prefix="rucio",
        url="http://rucio-mcp/mcp",
        transport="http",
    )
    assert spec.required_capability is None


def test_registry_load_omitted_required_capability_is_none(tmp_path: Path) -> None:
    """backends.yaml entries that omit required_capability must load as None,
    not silently default to "__none__" (open access) -- that would collapse
    the "credential layer is the gate" case into the "no gate at all" case."""
    backends_yaml = tmp_path / "backends.yaml"
    backends_yaml.write_text(
        "backends:\n  - name: rucio\n    prefix: rucio\n    url: http://rucio-mcp/mcp\n"
    )
    registry = BackendRegistry()
    registry.load(str(backends_yaml))
    spec = registry.get("rucio")
    assert spec is not None
    assert spec.required_capability is None


def test_recent_list_failure_absent_by_default() -> None:
    """A backend with no recorded tools/list failure reports None -- the
    common case for a healthy backend (issue #123's /v1/catalog status)."""
    registry = BackendRegistry()
    assert registry.recent_list_failure("rucio") is None


def test_recent_list_failure_reflects_last_recorded_reason() -> None:
    """record_list_failure() is how the aggregator's _ObservableProxyProvider
    (see aggregator.py's _classify_list_failure) reports a classified
    tools/list failure so /v1/catalog can factor it into a backend's status
    without an extra live probe (issue #123). Last write wins -- no history
    is kept, only the most recent reason."""
    registry = BackendRegistry()
    registry.record_list_failure("rucio", "unauthorized")
    assert registry.recent_list_failure("rucio") == "unauthorized"
    registry.record_list_failure("rucio", "unavailable")
    assert registry.recent_list_failure("rucio") == "unavailable"

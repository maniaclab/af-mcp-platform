from __future__ import annotations

from pathlib import Path

import pytest

from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec

# The shipped backends.yaml is the authoritative source for the apply_namespace
# behavior this file tests (rucio is self-prefixed; everything else is not).
_SRC = Path(__file__).resolve().parents[1] / "src" / "af_mcp_broker"
SHIPPED_BACKENDS = _SRC / "mcp" / "backends.yaml"


def test_backend_spec_apply_namespace_defaults_true() -> None:
    spec = BackendSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_capability="__none__",
    )
    assert spec.apply_namespace is True


def test_load_defaults_apply_namespace_true_when_absent(tmp_path: Path) -> None:
    backends_file = tmp_path / "backends.yaml"
    backends_file.write_text(
        """
backends:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_capability: __none__
"""
    )
    registry = BackendRegistry()
    registry.load(str(backends_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.apply_namespace is True


def test_load_respects_apply_namespace_false(tmp_path: Path) -> None:
    backends_file = tmp_path / "backends.yaml"
    backends_file.write_text(
        """
backends:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_capability: __none__
    apply_namespace: false
"""
    )
    registry = BackendRegistry()
    registry.load(str(backends_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.apply_namespace is False


def test_shipped_backends_rucio_apply_namespace_false() -> None:
    """rucio-mcp's tools are already self-prefixed (rucio_list_dids, ...);
    namespacing again would produce rucio_rucio_*."""
    registry = BackendRegistry()
    registry.load(str(SHIPPED_BACKENDS))
    rucio = registry.get("rucio")
    assert rucio is not None
    assert rucio.apply_namespace is False


@pytest.mark.parametrize(
    "name", ["ami", "atlasopenmagic", "jupyter-control", "monitoring", "docs"]
)
def test_shipped_backends_others_apply_namespace_true(name: str) -> None:
    registry = BackendRegistry()
    registry.load(str(SHIPPED_BACKENDS))
    spec = registry.get(name)
    assert spec is not None
    assert spec.apply_namespace is True


def test_get_by_tool_prefix_unaffected_by_apply_namespace() -> None:
    """apply_namespace only controls FastMCP's namespace= wiring; the
    registry's own prefix matching used for entitlement filtering is
    unchanged regardless of its value."""
    registry = BackendRegistry()
    registry.register(
        BackendSpec(
            name="rucio",
            prefix="rucio",
            url="http://rucio.invalid/mcp",
            transport="http",
            required_capability="read_data",
            apply_namespace=False,
        )
    )
    assert registry.get_by_tool_prefix("rucio_list_dids") is not None
    assert registry.get_by_tool_prefix("rucio_list_dids").name == "rucio"

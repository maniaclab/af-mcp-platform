from __future__ import annotations

from pathlib import Path

import pytest

from af_mcp_broker.config import Settings
from af_mcp_broker.mcp.registry import (
    DIAGNOSTIC_TOOL_NAMES,
    LINK_IDENTITY_TOOL_NAME,
    BackendRegistry,
    BackendSpec,
    identity_provider_url,
)

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


def test_backend_spec_timeout_seconds_defaults_to_30() -> None:
    spec = BackendSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_capability="__none__",
    )
    assert spec.timeout_seconds == 30.0


def test_load_defaults_timeout_seconds_when_absent(tmp_path: Path) -> None:
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
    assert spec.timeout_seconds == 30.0


def test_load_respects_custom_timeout_seconds(tmp_path: Path) -> None:
    backends_file = tmp_path / "backends.yaml"
    backends_file.write_text(
        """
backends:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_capability: __none__
    timeout_seconds: 5
"""
    )
    registry = BackendRegistry()
    registry.load(str(backends_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.timeout_seconds == 5.0


def test_register_rejects_reserved_diagnostic_prefix() -> None:
    """issue #153: no backend may be configured under the "af" prefix -- it's
    reserved for the broker-native af_whoami/af_list_identities/
    af_list_mcp_servers diagnostic tools (mcp/diagnostics.py), which must
    stay impossible to shadow."""
    registry = BackendRegistry()
    with pytest.raises(ValueError, match="af"):
        registry.register(
            BackendSpec(
                name="shadow",
                prefix="af",
                url="http://shadow.invalid/mcp",
                transport="http",
                required_capability="__none__",
            )
        )


def test_load_rejects_reserved_diagnostic_prefix_in_backends_yaml(
    tmp_path: Path,
) -> None:
    backends_file = tmp_path / "backends.yaml"
    backends_file.write_text(
        """
backends:
  - name: shadow
    prefix: af
    url: "http://shadow.invalid/mcp"
    required_capability: __none__
"""
    )
    registry = BackendRegistry()
    with pytest.raises(ValueError, match="af"):
        registry.load(str(backends_file))


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


def test_link_identity_tool_name_is_reserved_diagnostic_tool() -> None:
    """af_link_identity (stage 1 of the elicitation/link-identity design) is
    a broker-native diagnostic tool like the other three -- it must be in
    DIAGNOSTIC_TOOL_NAMES so middleware special-cases it as always-callable,
    no credential, no ProxyProvider, the same as af_whoami/af_list_identities/
    af_list_mcp_servers."""
    assert LINK_IDENTITY_TOOL_NAME == "af_link_identity"
    assert LINK_IDENTITY_TOOL_NAME in DIAGNOSTIC_TOOL_NAMES


def test_identity_provider_url_builds_portal_deep_link() -> None:
    settings = Settings(
        oidc_issuer="https://issuer.example", oidc_audience="test-audience"
    )
    url = identity_provider_url(settings, "atlas-iam")
    assert url == f"{settings.portal_url}/identities#identity-card-atlas-iam"


def test_identity_provider_url_strips_trailing_slash_from_portal_url() -> None:
    settings = Settings(
        oidc_issuer="https://issuer.example",
        oidc_audience="test-audience",
        portal_url="https://mcp-portal.af.uchicago.edu/",
    )
    url = identity_provider_url(settings, "x509")
    assert url == "https://mcp-portal.af.uchicago.edu/identities#identity-card-x509"

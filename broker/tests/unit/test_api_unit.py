from __future__ import annotations

from af_mcp_broker.api.credentials import ProxyRequest


def test_proxy_request_schema_has_no_voms_field() -> None:
    """The VO is the x509 provider's configured ``voms``, never client-supplied."""
    assert "voms" not in ProxyRequest.model_json_schema()["properties"]


def test_proxy_request_schema_has_no_valid_field() -> None:
    """The proxy lifetime is the x509 provider's configured ``valid``, never client-supplied."""
    assert "valid" not in ProxyRequest.model_json_schema()["properties"]

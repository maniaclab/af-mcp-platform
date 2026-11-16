"""The e2e flow's settings parsing: no secret in output, either URL form accepted."""

from __future__ import annotations

import pytest
from e2e_flow_support import BearerToken, broker_origin


class TestBearerToken:
    def test_repr_and_str_hide_the_token(self) -> None:
        token = BearerToken("mcp_pat_abc_secretvalue")

        assert "secretvalue" not in repr(token)
        assert "secretvalue" not in str(token)
        assert repr(token) == "BearerToken('<redacted>')"

    def test_authorization_header_carries_the_token(self) -> None:
        token = BearerToken("mcp_pat_abc_secretvalue")

        assert token.authorization_header() == {
            "Authorization": "Bearer mcp_pat_abc_secretvalue"
        }


class TestBrokerOrigin:
    @pytest.mark.parametrize(
        "configured",
        [
            "https://mcp.example.org",
            "https://mcp.example.org/",
            "https://mcp.example.org/mcp",
            "https://mcp.example.org/mcp/",
        ],
    )
    def test_accepts_the_origin_or_the_mcp_endpoint(self, configured: str) -> None:
        assert broker_origin(configured) == "https://mcp.example.org"

    def test_keeps_a_path_prefix_before_mcp(self) -> None:
        assert broker_origin("https://example.org/af/mcp/") == "https://example.org/af"

"""Unit tests for the area ``test_mcp_oauth_discovery.py`` covers; the integration tests live in ``integration/test_mcp_oauth_discovery.py``."""

from __future__ import annotations

from mcp_oauth_discovery_support import (
    ISSUER,
)

from af_mcp_broker.api.mcp_oauth import (
    _keycloak_authorization_endpoint,
    _keycloak_token_endpoint,
)
from af_mcp_broker.config import Settings


def test_keycloak_endpoints_split_front_and_back_channel() -> None:
    """With oidc_internal_url set, the code-for-token exchange (a server-side
    POST from the broker) must go to the internal URL, while the
    authorization endpoint (a browser redirect) must stay on the
    externally-advertised issuer."""
    internal = "http://keycloak.svc.test:8080/realms/connect"
    settings = Settings(oidc_issuer=ISSUER, oidc_internal_url=internal)

    assert (
        _keycloak_token_endpoint(settings)
        == f"{internal}/protocol/openid-connect/token"
    )
    assert (
        _keycloak_authorization_endpoint(settings)
        == f"{ISSUER}/protocol/openid-connect/auth"
    )

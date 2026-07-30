"""Tests for app.py's lifespan helpers that don't require booting the full
FastAPI app (see test_dev_bypass.py / test_api.py for full-boot coverage).
"""

from __future__ import annotations

from af_mcp_broker.app import _build_target_to_alias
from af_mcp_broker.config import (
    KeycloakBrokeredProviderConfig,
    OAuth21DirectProviderConfig,
)


def test_build_target_to_alias_covers_all_auth_shapes() -> None:
    """target_to_alias (issue #90) joins backend targets to whichever
    credential provider services them: x509 targets get the synthetic
    "x509" alias, keycloak-brokered/oauth21-direct targets get their
    configured alias, and auth_type "none" targets (e.g. "docs") are simply
    absent — no user credential is needed for them.
    """
    identity_providers_cfgs = [
        KeycloakBrokeredProviderConfig(alias="atlas-oidc", targets=["rucio"]),
        OAuth21DirectProviderConfig(
            alias="rucio-mcp-atlas",
            targets=["rucio-mcp-atlas"],
            authorization_endpoint="https://backend-as.example/authorize",
            token_endpoint="https://backend-as.example/token",
            issuer="https://backend-as.example",
        ),
    ]

    mapping = _build_target_to_alias(
        x509_targets=["ami"],
        identity_providers_cfgs=identity_providers_cfgs,
    )

    assert mapping == {
        "rucio": "atlas-oidc",
        "rucio-mcp-atlas": "rucio-mcp-atlas",
        "ami": "x509",
    }
    assert "docs" not in mapping

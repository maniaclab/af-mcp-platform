"""The environment setup shared by the tests of ``test_identities`` and the app-level cache-invalidation tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet
from oauth21_support import (
    ALIAS,
    AUTHORIZATION_ENDPOINT,
    PROVIDER_ISSUER,
    TOKEN_ENDPOINT,
)

if TYPE_CHECKING:
    import pytest


def _configure_oauth21_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROKER_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OAUTH21_CLIENT_ID", "https://mcp.example.com/.well-known/cimd")
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp-portal.example.com")
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "oauth21-direct",
                    "alias": ALIAS,
                    "targets": [ALIAS],
                    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "issuer": PROVIDER_ISSUER,
                    "display_name": "Rucio (ATLAS)",
                    "enables": "ATLAS Rucio operations via rucio-mcp",
                },
                # This override replaces conftest's default entirely, but
                # the shipped services.yaml's "ami" (auth_type: x509) still
                # needs an explicit entry or the broker refuses to start.
                {
                    "type": "x509",
                    "voms": "atlas",
                    "service_url": "http://voms-token-service.invalid:8000",
                    "alias": "x509",
                    "targets": ["ami"],
                },
            ]
        ),
    )

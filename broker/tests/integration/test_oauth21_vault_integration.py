"""Integration tests for the area ``test_oauth21_vault.py`` covers; the unit tests live in ``unit/test_oauth21_vault.py``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx2
import pytest
from conftest import TEST_SERVICES
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from oauth21_vault_support import (  # noqa: F401
    ALIAS,
    KV_PATH_PREFIX,
    broker_signing_key_fixture,
)
from vault_fakes import ADDR, AUTH_ROLE, FakeVault

from af_mcp_broker.app import app as broker_app
from af_mcp_broker.config import get_settings
from af_mcp_broker.credentials.vault import VaultTokenStore

# ---------------------------------------------------------------------------
# App startup wiring: trial authentication fails fast on Vault misconfig.
# ---------------------------------------------------------------------------

_SRC = Path(__file__).resolve().parents[2] / "src" / "af_mcp_broker"
SHIPPED_POLICY = _SRC / "authorization" / "policy.yaml"
STATE_ISSUER = "https://keycloak.invalid/realms/connect"
CIMD_CLIENT_ID = "https://mcp.example.org/.well-known/cimd"


def _bootstrap_oauth21_vault_env(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    monkeypatch.setenv("POLICY_FILE", str(SHIPPED_POLICY))
    monkeypatch.setenv("SERVICES_FILE", str(TEST_SERVICES))
    monkeypatch.setenv("METRICS_PORT", "0")
    monkeypatch.setenv("OIDC_ISSUER", STATE_ISSUER)
    monkeypatch.setenv("BROKER_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OAUTH21_CLIENT_ID", CIMD_CLIENT_ID)
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp-portal.example.com")
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "oauth21-direct",
                    "alias": ALIAS,
                    "targets": [ALIAS],
                    "authorization_endpoint": "https://backend-as.example/authorize",
                    "token_endpoint": "https://backend-as.example/token",
                    "issuer": "https://backend-as.example",
                },
                # The shipped services.yaml's "ami" (auth_type: x509) needs
                # an explicit entry covering it or the broker refuses to
                # start (there is no synthesized fallback).
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
    monkeypatch.setenv("TOKEN_STORE_BACKEND", "vault")
    monkeypatch.setenv("VAULT_ADDR", ADDR)
    monkeypatch.setenv("VAULT_KV_ROOT", "mcp")
    monkeypatch.setenv("VAULT_AUTH_ROLE", AUTH_ROLE)
    monkeypatch.setenv("VAULT_SA_TOKEN_PATH", str(sa_token_path))
    # Issue #144 step 3: the broker refuses to start without a configured
    # Keycloak admin service account (dev bypass aside).
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_ID", "test-admin-client")
    monkeypatch.setenv("KEYCLOAK_ADMIN_CLIENT_SECRET", "test-admin-secret")


def _fresh_app() -> Any:

    get_settings.cache_clear()
    broker_app.dependency_overrides.clear()
    return broker_app


def test_lifespan_boots_with_vault_backend_on_successful_trial_auth(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    _bootstrap_oauth21_vault_env(monkeypatch, sa_token_path)
    fake = FakeVault(key_prefix=KV_PATH_PREFIX)
    monkeypatch.setattr(
        "af_mcp_broker.app.build_http_client",
        lambda _stack: httpx2.AsyncClient(transport=httpx2.MockTransport(fake.handle)),
    )

    app = _fresh_app()
    with TestClient(app):
        assert isinstance(app.state.broker.oauth21_token_store, VaultTokenStore)
    assert len(fake.login_calls) == 1


def test_lifespan_fails_fast_when_vault_login_rejected(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    _bootstrap_oauth21_vault_env(monkeypatch, sa_token_path)

    def _reject_login(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            403, json={"errors": ["permission denied"]}, request=request
        )

    monkeypatch.setattr(
        "af_mcp_broker.app.build_http_client",
        lambda _stack: httpx2.AsyncClient(
            transport=httpx2.MockTransport(_reject_login)
        ),
    )

    app = _fresh_app()
    with pytest.raises(RuntimeError, match="Vault"), TestClient(app):
        pass

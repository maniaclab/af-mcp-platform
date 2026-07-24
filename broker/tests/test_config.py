from __future__ import annotations

import pytest

from af_mcp_broker.config import Settings, get_settings


def test_get_settings_is_cached():
    assert get_settings() is get_settings()


def test_oidc_issuer_env_var_still_works(monkeypatch):
    """Bug 6 — dropping the explicit Field aliases must not break env names."""
    get_settings.cache_clear()
    monkeypatch.setenv("OIDC_ISSUER", "https://kc.example/realms/foo")
    monkeypatch.setenv("OIDC_AUDIENCE", "custom-aud")

    settings = get_settings()
    assert settings.oidc_issuer == "https://kc.example/realms/foo"
    assert settings.oidc_audience == "custom-aud"
    # jwks_uri is derived from the issuer when not set explicitly.
    assert settings.oidc_jwks_uri.startswith("https://kc.example/realms/foo/")
    get_settings.cache_clear()


def test_env_var_is_case_insensitive(monkeypatch):
    """pydantic-settings matches field names case-insensitively by default."""
    monkeypatch.setenv("oidc_audience", "lowercase-aud")
    assert Settings().oidc_audience == "lowercase-aud"


# ---------------------------------------------------------------------------
# identity_providers (issue #66 PR4) — discriminated-union parsing +
# oauth21-direct dependent-settings validation
# ---------------------------------------------------------------------------

_KEYCLOAK_ENTRY = {
    "type": "keycloak-brokered",
    "alias": "atlas-oidc",
    "targets": ["rucio"],
}

_OAUTH21_ENTRY = {
    "type": "oauth21-direct",
    "alias": "a",
    "targets": ["a"],
    "authorization_endpoint": "https://backend-as.example/authorize",
    "token_endpoint": "https://backend-as.example/token",
    "issuer": "https://backend-as.example",
}


def test_identity_providers_empty_list_is_valid():
    Settings()  # must not raise -- a degraded but valid config


def test_identity_providers_keycloak_brokered_only_is_valid():
    Settings(identity_providers=[_KEYCLOAK_ENTRY])  # must not raise -- no
    # broker_state_key/oauth21_client_id needed for this provider type


def test_identity_providers_discriminates_entries_by_type():
    settings = Settings(
        broker_state_key="fake-key",
        oauth21_client_id="https://mcp.example/.well-known/cimd",
        identity_providers=[_KEYCLOAK_ENTRY, _OAUTH21_ENTRY],
    )
    assert [p.type for p in settings.identity_providers] == [
        "keycloak-brokered",
        "oauth21-direct",
    ]
    assert [p.alias for p in settings.identity_providers] == ["atlas-oidc", "a"]


def test_identity_providers_oauth21_direct_ok_when_state_key_and_client_id_set():
    Settings(
        broker_state_key="fake-key",
        oauth21_client_id="https://mcp.example/.well-known/cimd",
        identity_providers=[_OAUTH21_ENTRY],
    )  # must not raise


def test_identity_providers_oauth21_direct_raises_when_state_key_missing():
    with pytest.raises(ValueError, match="broker_state_key"):
        Settings(
            oauth21_client_id="https://mcp.example/.well-known/cimd",
            identity_providers=[_OAUTH21_ENTRY],
        )


def test_identity_providers_oauth21_direct_raises_when_client_id_missing():
    with pytest.raises(ValueError, match="oauth21_client_id"):
        Settings(
            broker_state_key="fake-key",
            identity_providers=[_OAUTH21_ENTRY],
        )


# ---------------------------------------------------------------------------
# Vault TokenStore backend config
# ---------------------------------------------------------------------------


def test_vault_config_ok_when_backend_is_in_memory():
    Settings(token_store_backend="in_memory")  # must not raise


def test_vault_config_ok_when_addr_and_role_set():
    Settings(
        token_store_backend="vault",
        vault_addr="https://vault.example",
        vault_auth_role="af-mcp-broker",
    )  # must not raise


def test_vault_config_raises_when_addr_missing():
    with pytest.raises(ValueError, match="vault_addr"):
        Settings(token_store_backend="vault", vault_auth_role="af-mcp-broker")


def test_vault_config_raises_when_auth_role_missing():
    with pytest.raises(ValueError, match="vault_auth_role"):
        Settings(token_store_backend="vault", vault_addr="https://vault.example")

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
# oauth21_providers <-> cimd_idp_aliases alias parity
# ---------------------------------------------------------------------------

_A_PROVIDER = {
    "alias": "a",
    "targets": ["a"],
    "authorization_endpoint": "https://backend-as.example/authorize",
    "token_endpoint": "https://backend-as.example/token",
    "issuer": "https://backend-as.example",
}


def test_oauth21_cimd_alias_parity_ok_when_both_empty():
    Settings()  # must not raise


def test_oauth21_cimd_alias_parity_ok_when_alias_sets_match():
    Settings(
        broker_state_key="fake-key",
        oauth21_client_id="https://mcp.example/.well-known/cimd",
        cimd_idp_aliases=["a"],
        oauth21_providers=[_A_PROVIDER],
    )  # must not raise


def test_oauth21_cimd_alias_parity_raises_when_oauth21_alias_missing_from_cimd():
    with pytest.raises(ValueError, match="cimd_idp_aliases"):
        Settings(
            broker_state_key="fake-key",
            oauth21_client_id="https://mcp.example/.well-known/cimd",
            cimd_idp_aliases=[],
            oauth21_providers=[_A_PROVIDER],
        )


def test_oauth21_cimd_alias_parity_raises_when_cimd_alias_is_dangling():
    """A cimd_idp_aliases entry with no matching oauth21_providers alias
    advertises a redirect URI nothing will ever complete."""
    with pytest.raises(ValueError, match="oauth21_providers"):
        Settings(cimd_idp_aliases=["dangling-alias"])


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

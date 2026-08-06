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

_PUBLIC_ORIGIN = "https://mcp-portal.example"


def test_identity_providers_empty_list_is_valid():
    Settings()  # must not raise -- a degraded but valid config


def test_identity_providers_keycloak_brokered_only_is_valid():
    Settings(identity_providers=[_KEYCLOAK_ENTRY])  # must not raise -- no
    # broker_state_key/oauth21_client_id needed for this provider type


def test_identity_providers_discriminates_entries_by_type():
    settings = Settings(
        broker_state_key="fake-key",
        oauth21_client_id="https://mcp.example/.well-known/cimd",
        broker_public_origin=_PUBLIC_ORIGIN,
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
        broker_public_origin=_PUBLIC_ORIGIN,
        identity_providers=[_OAUTH21_ENTRY],
    )  # must not raise


def test_identity_providers_oauth21_direct_raises_when_state_key_missing():
    with pytest.raises(ValueError, match="broker_state_key"):
        Settings(
            oauth21_client_id="https://mcp.example/.well-known/cimd",
            broker_public_origin=_PUBLIC_ORIGIN,
            identity_providers=[_OAUTH21_ENTRY],
        )


def test_identity_providers_oauth21_direct_raises_when_client_id_missing():
    with pytest.raises(ValueError, match="oauth21_client_id"):
        Settings(
            broker_state_key="fake-key",
            broker_public_origin=_PUBLIC_ORIGIN,
            identity_providers=[_OAUTH21_ENTRY],
        )


def test_identity_providers_oauth21_direct_raises_when_public_origin_missing():
    with pytest.raises(ValueError, match="broker_public_origin"):
        Settings(
            broker_state_key="fake-key",
            oauth21_client_id="https://mcp.example/.well-known/cimd",
            identity_providers=[_OAUTH21_ENTRY],
        )


def test_identity_providers_oauth21_direct_raises_when_public_origin_has_trailing_slash():
    with pytest.raises(ValueError, match="trailing slash"):
        Settings(
            broker_state_key="fake-key",
            oauth21_client_id="https://mcp.example/.well-known/cimd",
            broker_public_origin=f"{_PUBLIC_ORIGIN}/",
            identity_providers=[_OAUTH21_ENTRY],
        )


def test_identity_providers_oauth21_direct_raises_when_public_origin_not_http():
    with pytest.raises(ValueError, match="broker_public_origin"):
        Settings(
            broker_state_key="fake-key",
            oauth21_client_id="https://mcp.example/.well-known/cimd",
            broker_public_origin="ftp://mcp-portal.example",
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


# ---------------------------------------------------------------------------
# Vault TokenRegistryBackend config (issue #115) — shares the same
# vault_addr/vault_auth_role validation as the TokenStore backend above.
# ---------------------------------------------------------------------------


def test_vault_config_ok_when_registry_backend_is_in_memory():
    Settings(token_registry_backend="in_memory")  # must not raise


def test_vault_config_ok_when_registry_backend_vault_and_addr_and_role_set():
    Settings(
        token_registry_backend="vault",
        vault_addr="https://vault.example",
        vault_auth_role="af-mcp-broker",
    )  # must not raise


def test_vault_config_raises_when_registry_backend_vault_and_addr_missing():
    with pytest.raises(ValueError, match="vault_addr"):
        Settings(token_registry_backend="vault", vault_auth_role="af-mcp-broker")


def test_vault_config_raises_when_registry_backend_vault_and_auth_role_missing():
    with pytest.raises(ValueError, match="vault_auth_role"):
        Settings(token_registry_backend="vault", vault_addr="https://vault.example")


def test_token_sweep_grace_seconds_defaults_to_seven_days():
    assert Settings().token_sweep_grace_seconds == 7 * 24 * 60 * 60


# ---------------------------------------------------------------------------
# Vault PrincipalCacheBackend config (issue #144 step 2b) — shares the same
# vault_addr/vault_auth_role validation as the TokenStore/TokenRegistry
# backends above.
# ---------------------------------------------------------------------------


def test_vault_config_ok_when_principal_cache_backend_is_in_memory():
    Settings(principal_cache_backend="in_memory")  # must not raise


def test_vault_config_ok_when_principal_cache_backend_vault_and_addr_and_role_set():
    Settings(
        principal_cache_backend="vault",
        vault_addr="https://vault.example",
        vault_auth_role="af-mcp-broker",
    )  # must not raise


def test_vault_config_raises_when_principal_cache_backend_vault_and_addr_missing():
    with pytest.raises(ValueError, match="vault_addr"):
        Settings(principal_cache_backend="vault", vault_auth_role="af-mcp-broker")


def test_vault_config_raises_when_principal_cache_backend_vault_and_auth_role_missing():
    with pytest.raises(ValueError, match="vault_auth_role"):
        Settings(principal_cache_backend="vault", vault_addr="https://vault.example")


# ---------------------------------------------------------------------------
# /mcp aggregator transport mode (issue #128)
# ---------------------------------------------------------------------------


def test_mcp_stateless_http_defaults_to_true():
    # Safe-by-default at any replica count -- see app.py's startup check.
    assert Settings().mcp_stateless_http is True


def test_mcp_stateless_http_env_var_still_works(monkeypatch):
    monkeypatch.setenv("MCP_STATELESS_HTTP", "false")
    assert Settings().mcp_stateless_http is False


def test_mcp_replica_count_defaults_to_none():
    assert Settings().mcp_replica_count is None


def test_mcp_replica_count_env_var_still_works(monkeypatch):
    monkeypatch.setenv("MCP_REPLICA_COUNT", "3")
    assert Settings().mcp_replica_count == 3


# ---------------------------------------------------------------------------
# broker-issued identity providers (issue #162) — the AF Broker Identity
# Token's config surface: discriminated-union parsing, per-target options,
# and the signing-key / issuer / TTL settings the issuer core reads.
# ---------------------------------------------------------------------------

_BROKER_ISSUED_ENTRY = {
    "type": "broker-issued",
    "alias": "af-native",
    "targets": ["condor-token-service", "jupyter-mcp"],
    "target_options": {
        "condor-token-service": {"include_posix": True},
        "jupyter-mcp": {"audience": "jupyter"},
    },
}


def test_identity_providers_broker_issued_parses():
    settings = Settings(identity_providers=[_BROKER_ISSUED_ENTRY])

    (cfg,) = settings.identity_providers
    assert cfg.type == "broker-issued"
    assert cfg.alias == "af-native"
    assert cfg.targets == ["condor-token-service", "jupyter-mcp"]
    assert cfg.target_options["condor-token-service"].include_posix is True
    assert cfg.target_options["condor-token-service"].audience == ""
    assert cfg.target_options["jupyter-mcp"].audience == "jupyter"
    assert cfg.target_options["jupyter-mcp"].include_posix is False


def test_identity_providers_broker_issued_target_options_default_empty():
    settings = Settings(
        identity_providers=[
            {"type": "broker-issued", "alias": "af-native", "targets": ["condor-mcp"]}
        ]
    )

    (cfg,) = settings.identity_providers
    assert cfg.target_options == {}


def test_identity_providers_broker_issued_rejects_options_for_unknown_target():
    """A target_options key naming a target absent from `targets` is a typo
    that would otherwise silently apply to nothing -- fail construction
    loudly instead."""
    with pytest.raises(ValueError, match="target_options"):
        Settings(
            identity_providers=[
                {
                    "type": "broker-issued",
                    "alias": "af-native",
                    "targets": ["condor-mcp"],
                    "target_options": {"condor-mpc": {"include_posix": True}},
                }
            ]
        )


def test_identity_providers_broker_issued_needs_no_oauth21_settings():
    # Unlike oauth21-direct, a broker-issued entry has no dependent
    # broker_state_key/oauth21_client_id/broker_public_origin requirement at
    # Settings level -- the signing-key check lives in app.py's lifespan,
    # where the key file is actually loaded.
    Settings(identity_providers=[_BROKER_ISSUED_ENTRY])  # must not raise


def test_broker_token_ttl_defaults_to_600():
    # 600 = 2x the credential layer's default min-remaining floor (300s) --
    # see the Settings field comment for why a TTL at or below that floor
    # would defeat the CredentialCache entirely.
    assert Settings().broker_token_ttl_seconds == 600


def test_broker_token_ttl_rejects_nonpositive():
    with pytest.raises(ValueError, match="broker_token_ttl_seconds"):
        Settings(broker_token_ttl_seconds=0)


def test_broker_token_effective_issuer_falls_back_to_public_origin():
    settings = Settings(broker_public_origin="https://mcp.example.com")
    assert settings.broker_token_effective_issuer == "https://mcp.example.com"


def test_broker_token_effective_issuer_prefers_explicit_setting():
    settings = Settings(
        broker_public_origin="https://mcp.example.com",
        broker_token_issuer="https://issuer.example.com",
    )
    assert settings.broker_token_effective_issuer == "https://issuer.example.com"


def test_broker_signing_key_file_defaults_to_unset():
    settings = Settings()
    assert settings.broker_signing_key_file == ""
    assert settings.broker_additional_public_keys_dir == ""


# ---------------------------------------------------------------------------
# condor-token identity providers (issue #169) — CondorTokenProvider's config
# surface: discriminated-union parsing, the required service URL, and the
# audience default.
# ---------------------------------------------------------------------------

_CONDOR_TOKEN_ENTRY = {
    "type": "condor-token",
    "alias": "condor",
    "targets": ["condor-mcp"],
    "service_url": "http://condor-token-service.af-mcp.svc:8080",
}


def test_identity_providers_condor_token_parses():
    settings = Settings(identity_providers=[_CONDOR_TOKEN_ENTRY])

    (cfg,) = settings.identity_providers
    assert cfg.type == "condor-token"
    assert cfg.alias == "condor"
    assert cfg.targets == ["condor-mcp"]
    assert str(cfg.service_url).rstrip("/") == (
        "http://condor-token-service.af-mcp.svc:8080"
    )
    assert cfg.audience == "condor-token-service"


def test_identity_providers_condor_token_requires_service_url():
    """A condor-token entry without a service URL is unusable -- fail
    construction loudly instead of failing at first request."""
    entry = {k: v for k, v in _CONDOR_TOKEN_ENTRY.items() if k != "service_url"}
    with pytest.raises(ValueError, match="service_url"):
        Settings(identity_providers=[entry])


def test_identity_providers_condor_token_audience_is_overridable():
    settings = Settings(
        identity_providers=[
            {**_CONDOR_TOKEN_ENTRY, "audience": "condor-token-service-dev"}
        ]
    )

    (cfg,) = settings.identity_providers
    assert cfg.audience == "condor-token-service-dev"

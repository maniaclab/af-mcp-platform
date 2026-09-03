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


def test_oidc_backchannel_url_falls_back_to_issuer():
    """Without oidc_internal_url, back-channel calls go to the issuer."""
    settings = Settings(oidc_issuer="https://kc.example/realms/foo")
    assert settings.oidc_backchannel_url == "https://kc.example/realms/foo"


def test_oidc_backchannel_url_prefers_internal_url(monkeypatch):
    """OIDC_INTERNAL_URL redirects every server-to-server Keycloak call.

    Lets a deployment validate `iss` against the externally-advertised
    issuer while reaching Keycloak (JWKS, token endpoint, Admin REST API,
    brokered-token fetch) via an internal URL (e.g. same-cluster Keycloak
    reached over cluster-local DNS instead of hairpinning back through the
    public ingress).
    """
    get_settings.cache_clear()
    monkeypatch.setenv("OIDC_ISSUER", "https://kc.example/realms/foo")
    monkeypatch.setenv(
        "OIDC_INTERNAL_URL",
        "http://keycloak.internal.svc.cluster.local:8080/realms/foo",
    )

    settings = get_settings()
    assert (
        settings.oidc_backchannel_url
        == "http://keycloak.internal.svc.cluster.local:8080/realms/foo"
    )
    # iss validation must keep using the external issuer.
    assert settings.oidc_issuer == "https://kc.example/realms/foo"
    get_settings.cache_clear()


def test_oidc_jwks_uri_derived_from_internal_url():
    """JWKS derivation follows the back-channel URL, not the issuer."""
    settings = Settings(
        oidc_issuer="https://kc.example/realms/foo",
        oidc_internal_url="http://keycloak.internal.svc.cluster.local:8080/realms/foo",
    )
    assert settings.oidc_jwks_uri == (
        "http://keycloak.internal.svc.cluster.local:8080/realms/foo"
        "/protocol/openid-connect/certs"
    )


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
# Vault MaintenanceModeStore backend config — shares the same
# vault_addr/vault_auth_role validation as the TokenStore/TokenRegistry/
# PrincipalCache backends above.
# ---------------------------------------------------------------------------


def test_vault_config_ok_when_maintenance_mode_backend_is_in_memory():
    Settings(maintenance_mode_backend="in_memory")  # must not raise


def test_vault_config_ok_when_maintenance_mode_backend_vault_and_addr_and_role_set():
    Settings(
        maintenance_mode_backend="vault",
        vault_addr="https://vault.example",
        vault_auth_role="af-mcp-broker",
    )  # must not raise


def test_vault_config_raises_when_maintenance_mode_backend_vault_and_addr_missing():
    with pytest.raises(ValueError, match="vault_addr"):
        Settings(maintenance_mode_backend="vault", vault_auth_role="af-mcp-broker")


def test_vault_config_raises_when_maintenance_mode_backend_vault_and_auth_role_missing():
    with pytest.raises(ValueError, match="vault_auth_role"):
        Settings(maintenance_mode_backend="vault", vault_addr="https://vault.example")


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


def test_builtin_service_name_defaults_and_env_override(monkeypatch):
    """The builtin gateway service name (issue #240) defaults to
    registry.BUILTIN_SERVICE_NAME and is overridable via BUILTIN_SERVICE_NAME."""
    from af_mcp_broker.mcp.registry import BUILTIN_SERVICE_NAME

    assert Settings().builtin_service_name == BUILTIN_SERVICE_NAME
    monkeypatch.setenv("BUILTIN_SERVICE_NAME", "facility_service")
    assert Settings().builtin_service_name == "facility_service"


# ---------------------------------------------------------------------------
# broker-issued identity providers (issue #162) — the AF Broker Identity
# Token's config surface: discriminated-union parsing and the signing-key /
# issuer / TTL settings the issuer core reads. Per-target token options
# (audience, requires_posix) no longer live here: they moved to the service
# entry (ServiceSpec, issue #257), so the provider config is just alias +
# targets + portal metadata.
# ---------------------------------------------------------------------------

_BROKER_ISSUED_ENTRY = {
    "type": "broker-issued",
    "alias": "af-native",
    "targets": ["condor-token-service", "jupyter-mcp"],
}


def test_identity_providers_broker_issued_parses():
    settings = Settings(identity_providers=[_BROKER_ISSUED_ENTRY])

    (cfg,) = settings.identity_providers
    assert cfg.type == "broker-issued"
    assert cfg.alias == "af-native"
    assert cfg.targets == ["condor-token-service", "jupyter-mcp"]


def test_identity_providers_broker_issued_ignores_stray_target_options():
    """target_options moved to the service entry (issue #257); a leftover key
    on the provider entry is harmlessly ignored, not a parse error, so a
    mid-migration config still boots."""
    settings = Settings(
        identity_providers=[
            {
                **_BROKER_ISSUED_ENTRY,
                "target_options": {"jupyter-mcp": {"audience": "jupyter"}},
            }
        ]
    )

    (cfg,) = settings.identity_providers
    assert not hasattr(cfg, "target_options")


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


# krb5-token identity providers (issue #274) -- KrbTokenProvider's config.
def test_krb5_token_provider_config_parses():
    settings = Settings(
        identity_providers=[
            {
                "type": "krb5-token",
                "alias": "krb5",
                "display_name": "CERN Kerberos ticket",
                "enables": "Kerberos-authenticated access",
                "targets": ["some-service"],
                "service_url": "http://krb5-token-service.invalid",
            }
        ],
        **_VAULT_ENV,
    )
    (cfg,) = settings.identity_providers
    assert cfg.type == "krb5-token"
    assert cfg.alias == "krb5"
    assert cfg.targets == ["some-service"]
    assert str(cfg.service_url) == "http://krb5-token-service.invalid/"
    assert cfg.audience == "krb5-token-service"  # default


def test_krb5_token_provider_config_requires_service_url():
    valid_entry = {
        "type": "krb5-token",
        "alias": "krb5",
        "display_name": "CERN Kerberos ticket",
        "enables": "Kerberos-authenticated access",
        "targets": ["some-service"],
        "service_url": "http://krb5-token-service.invalid",
    }
    entry = {k: v for k, v in valid_entry.items() if k != "service_url"}
    with pytest.raises(ValueError, match="service_url"):
        Settings(identity_providers=[entry], **_VAULT_ENV)


def test_vault_config_required_by_krb5_token_entry():
    """Unlike x509 there is no legacy/service-mode split for krb5-token --
    service_url is mandatory on every entry, and a given entry can't declare
    ahead of time whether any caller will ever request its optional
    "remember" persistence -- so Vault is required unconditionally."""
    entry = {
        "type": "krb5-token",
        "alias": "krb5",
        "targets": ["some-service"],
        "service_url": "http://krb5-token-service.invalid",
    }
    with pytest.raises(ValueError, match="vault_addr"):
        Settings(identity_providers=[entry])
    with pytest.raises(ValueError, match="vault_auth_role"):
        Settings(identity_providers=[entry], vault_addr="https://vault.example")


def test_krb5_kv_path_prefix_default():
    assert Settings().krb5_kv_path_prefix == "mcp/krb5"


# ---------------------------------------------------------------------------
# x509 identity providers — X509Provider's config surface, replacing the
# global VOMS_TOKEN_SERVICE_URL special case (which crash-looped a broker
# whose operator intuitively wrote an identityProviders entry for the voms
# service: `union_tag_invalid`, no such type existed). Discriminated-union
# parsing, the voms/valid defaults, and the Vault-connection coupling.
# ---------------------------------------------------------------------------

_X509_ENTRY = {
    "type": "x509",
    "alias": "x509",
    "targets": ["ami"],
    "service_url": "http://voms-token-service.af-mcp.svc:8080",
}

_VAULT_ENV = {"vault_addr": "https://vault.example", "vault_auth_role": "broker"}


def test_identity_providers_x509_parses():
    settings = Settings(identity_providers=[_X509_ENTRY], **_VAULT_ENV)

    (cfg,) = settings.identity_providers
    assert cfg.type == "x509"
    assert cfg.alias == "x509"
    assert cfg.targets == ["ami"]
    assert str(cfg.service_url).rstrip("/") == (
        "http://voms-token-service.af-mcp.svc:8080"
    )
    # Defaults match the voms-token-service contract (its own
    # DEFAULT_VOMS/DEFAULT_VALID/EXPECTED_AUDIENCE).
    assert cfg.voms == "atlas"
    assert cfg.valid == "192:00"
    assert cfg.audience == "voms-token-service"


def test_identity_providers_x509_voms_and_valid_are_overridable():
    settings = Settings(
        identity_providers=[{**_X509_ENTRY, "voms": "dune", "valid": "24:00"}],
        **_VAULT_ENV,
    )

    (cfg,) = settings.identity_providers
    assert cfg.voms == "dune"
    assert cfg.valid == "24:00"


def test_identity_providers_multiple_x509_entries_are_expressible():
    """Two entries with different service URLs/VOs — a functional gain over
    the single global env var, which could only ever describe one service."""
    settings = Settings(
        identity_providers=[
            _X509_ENTRY,
            {
                "type": "x509",
                "alias": "x509-dune",
                "targets": ["dune-mcp"],
                "service_url": "http://voms-token-service-dune.af-mcp.svc:8080",
                "voms": "dune",
            },
        ],
        **_VAULT_ENV,
    )

    atlas, dune = settings.identity_providers
    assert atlas.voms == "atlas"
    assert dune.voms == "dune"
    assert str(atlas.service_url) != str(dune.service_url)


def test_identity_providers_x509_service_url_defaults_to_none():
    """No service_url selects the legacy k8s-Job/local-dev mint path."""
    entry = {k: v for k, v in _X509_ENTRY.items() if k != "service_url"}
    settings = Settings(identity_providers=[entry])

    (cfg,) = settings.identity_providers
    assert cfg.service_url is None


def test_vault_config_required_by_x509_entry_with_service_url():
    """voms-token-service mode persists proxies and passphrases in Vault
    (there is no in-memory fallback), so an x509 entry with a service_url
    implies the x509 store."""
    with pytest.raises(ValueError, match="vault_addr"):
        Settings(identity_providers=[_X509_ENTRY])
    with pytest.raises(ValueError, match="vault_auth_role"):
        Settings(identity_providers=[_X509_ENTRY], vault_addr="https://vault.example")


def test_vault_config_not_required_by_legacy_x509_entry():
    """A legacy-mode entry (no service_url) mints via the k8s-Job/local path
    and touches no Vault store — the connection settings stay optional."""
    entry = {k: v for k, v in _X509_ENTRY.items() if k != "service_url"}
    Settings(identity_providers=[entry])  # must not raise


# ---------------------------------------------------------------------------
# Metering backend selection (audit/pipeline.py's MeteringBackend seam)
# ---------------------------------------------------------------------------


def test_metering_backend_defaults_to_in_process():
    assert Settings().metering_backend == "in_process"


def test_metering_backend_rejects_unknown_value():
    """The Literal is single-valued on purpose: a value must never be
    accepted before its backend implementation exists (fail-closed)."""
    with pytest.raises(ValueError, match="metering_backend"):
        Settings(metering_backend="taskiq")


# ---------------------------------------------------------------------------
# Usage store selection (usage/ -- per-user usage accounting, PR C)
# ---------------------------------------------------------------------------


def test_usage_store_backend_defaults_to_in_memory():
    settings = Settings()
    assert settings.usage_store_backend == "in_memory"
    assert settings.usage_postgres_dsn is None


def test_usage_store_postgres_ok_when_dsn_set():
    Settings(
        usage_store_backend="postgres",
        usage_postgres_dsn="postgresql://broker:pw@pg.example/usage",
    )  # must not raise


def test_usage_store_postgres_raises_when_dsn_missing():
    with pytest.raises(ValueError, match="usage_postgres_dsn"):
        Settings(usage_store_backend="postgres")


def test_usage_store_rejects_unknown_backend():
    with pytest.raises(ValueError, match="usage_store_backend"):
        Settings(usage_store_backend="mysql")


# ---------------------------------------------------------------------------
# Admin group (admin gating)
# ---------------------------------------------------------------------------


def test_admin_group_defaults_to_empty():
    settings = Settings()
    assert settings.admin_group == ""


# ---------------------------------------------------------------------------
# Maintenance mode backend
# ---------------------------------------------------------------------------


def test_maintenance_mode_backend_defaults_to_in_memory():
    settings = Settings()
    assert settings.maintenance_mode_backend == "in_memory"
    assert settings.maintenance_mode_postgres_dsn is None


def test_maintenance_mode_postgres_ok_when_own_dsn_set():
    Settings(
        maintenance_mode_backend="postgres",
        maintenance_mode_postgres_dsn="postgresql://broker:pw@pg.example/maint",
    )  # must not raise


def test_maintenance_mode_postgres_falls_back_to_usage_dsn():
    settings = Settings(
        maintenance_mode_backend="postgres",
        usage_postgres_dsn="postgresql://broker:pw@pg.example/usage",
    )  # must not raise -- reuses usage_postgres_dsn
    assert (
        settings.maintenance_mode_effective_postgres_dsn.get_secret_value()
        == "postgresql://broker:pw@pg.example/usage"
    )


def test_maintenance_mode_postgres_raises_when_no_dsn_available():
    with pytest.raises(ValueError, match="maintenance_mode_postgres_dsn"):
        Settings(maintenance_mode_backend="postgres")


def test_maintenance_mode_rejects_unknown_backend():
    with pytest.raises(ValueError, match="maintenance_mode_backend"):
        Settings(maintenance_mode_backend="mysql")

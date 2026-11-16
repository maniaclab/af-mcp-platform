from __future__ import annotations

import pytest

from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.constants import BUILTIN_SERVICE_NAME


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
    assert Settings().identity_providers == []


def test_identity_providers_keycloak_brokered_only_is_valid():
    settings = Settings(identity_providers=[_KEYCLOAK_ENTRY])

    assert [p.alias for p in settings.identity_providers] == ["atlas-oidc"]
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
    settings = Settings(
        broker_state_key="fake-key",
        oauth21_client_id="https://mcp.example/.well-known/cimd",
        broker_public_origin=_PUBLIC_ORIGIN,
        identity_providers=[_OAUTH21_ENTRY],
    )

    assert [p.alias for p in settings.identity_providers] == ["a"]


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
# oauth21-direct per-provider client registration (client_id + confidential)
# ---------------------------------------------------------------------------

_OWN_CLIENT_ENTRY = {**_OAUTH21_ENTRY, "alias": "own", "client_id": "own-client"}

_CONFIDENTIAL_ENTRY = {
    **_OAUTH21_ENTRY,
    "alias": "jupyter-hub.af",
    "targets": ["jupyterhub_service"],
    "client_id": "service-af-mcp-platform",
    "confidential": True,
}


def test_oauth21_direct_client_id_defaults_to_none():
    settings = Settings(
        broker_state_key="fake-key",
        oauth21_client_id="https://mcp.example/.well-known/cimd",
        broker_public_origin=_PUBLIC_ORIGIN,
        identity_providers=[_OAUTH21_ENTRY],
    )
    provider = settings.identity_providers[0]
    assert provider.type == "oauth21-direct"
    assert provider.client_id is None
    assert provider.confidential is False
    assert provider.client_secret is None


def test_oauth21_direct_own_client_id_needs_no_cimd_client_id():
    # Every oauth21-direct entry brings its own client_id, so the shared CIMD
    # client_id (OAUTH21_CLIENT_ID) is never used and must not be required.
    settings = Settings(
        broker_state_key="fake-key",
        broker_public_origin=_PUBLIC_ORIGIN,
        identity_providers=[_OWN_CLIENT_ENTRY],
    )
    provider = settings.identity_providers[0]
    assert provider.type == "oauth21-direct"
    assert provider.client_id == "own-client"
    assert provider.client_secret is None


def test_oauth21_direct_cimd_client_id_required_when_any_entry_lacks_client_id():
    with pytest.raises(ValueError, match="oauth21_client_id"):
        Settings(
            broker_state_key="fake-key",
            broker_public_origin=_PUBLIC_ORIGIN,
            identity_providers=[_OWN_CLIENT_ENTRY, _OAUTH21_ENTRY],
        )


def test_oauth21_direct_confidential_reads_secret_from_alias_env_var(monkeypatch):
    # alias "jupyter-hub.af": uppercased, every non-alphanumeric -> "_".
    monkeypatch.setenv("OAUTH21_CLIENT_SECRET_JUPYTER_HUB_AF", "s3cret")
    settings = Settings(
        broker_state_key="fake-key",
        broker_public_origin=_PUBLIC_ORIGIN,
        identity_providers=[_CONFIDENTIAL_ENTRY],
    )
    provider = settings.identity_providers[0]
    assert provider.type == "oauth21-direct"
    assert provider.client_secret_env_var == "OAUTH21_CLIENT_SECRET_JUPYTER_HUB_AF"
    assert provider.client_secret is not None
    assert provider.client_secret.get_secret_value() == "s3cret"


@pytest.mark.parametrize("secret", [None, ""])
def test_oauth21_direct_confidential_raises_when_secret_env_missing(
    monkeypatch, secret
):
    if secret is None:
        monkeypatch.delenv("OAUTH21_CLIENT_SECRET_JUPYTER_HUB_AF", raising=False)
    else:
        monkeypatch.setenv("OAUTH21_CLIENT_SECRET_JUPYTER_HUB_AF", secret)
    with pytest.raises(ValueError, match="OAUTH21_CLIENT_SECRET_JUPYTER_HUB_AF"):
        Settings(
            broker_state_key="fake-key",
            broker_public_origin=_PUBLIC_ORIGIN,
            identity_providers=[_CONFIDENTIAL_ENTRY],
        )


def test_oauth21_direct_confidential_raises_without_own_client_id(monkeypatch):
    monkeypatch.setenv("OAUTH21_CLIENT_SECRET_A", "s3cret")
    with pytest.raises(ValueError, match="client_id"):
        Settings(
            broker_state_key="fake-key",
            oauth21_client_id="https://mcp.example/.well-known/cimd",
            broker_public_origin=_PUBLIC_ORIGIN,
            identity_providers=[{**_OAUTH21_ENTRY, "confidential": True}],
        )


def test_oauth21_direct_public_ignores_secret_env(monkeypatch):
    # Only `confidential: true` opts a provider into client authentication --
    # a stray env var never silently turns a public client confidential.
    monkeypatch.setenv("OAUTH21_CLIENT_SECRET_OWN", "s3cret")
    settings = Settings(
        broker_state_key="fake-key",
        broker_public_origin=_PUBLIC_ORIGIN,
        identity_providers=[_OWN_CLIENT_ENTRY],
    )
    provider = settings.identity_providers[0]
    assert provider.type == "oauth21-direct"
    assert provider.client_secret is None


def test_oauth21_direct_client_secret_is_not_accepted_from_json():
    # The secret only ever comes from the environment, never from the
    # IDENTITY_PROVIDERS JSON, which the chart renders as a plain env value.
    settings = Settings(
        broker_state_key="fake-key",
        broker_public_origin=_PUBLIC_ORIGIN,
        identity_providers=[{**_OWN_CLIENT_ENTRY, "client_secret": "leaked"}],
    )
    provider = settings.identity_providers[0]
    assert provider.type == "oauth21-direct"
    assert provider.client_secret is None


def test_oauth21_direct_raises_when_two_confidential_aliases_share_env_var(
    monkeypatch,
):
    # "jupyter-hub.af" and "jupyter_hub-af" both map to the same env var;
    # silently sharing one secret between two providers is never intended.
    monkeypatch.setenv("OAUTH21_CLIENT_SECRET_JUPYTER_HUB_AF", "s3cret")
    with pytest.raises(ValueError, match="OAUTH21_CLIENT_SECRET_JUPYTER_HUB_AF"):
        Settings(
            broker_state_key="fake-key",
            broker_public_origin=_PUBLIC_ORIGIN,
            identity_providers=[
                _CONFIDENTIAL_ENTRY,
                {**_CONFIDENTIAL_ENTRY, "alias": "jupyter_hub-af"},
            ],
        )


# ---------------------------------------------------------------------------
# Vault backend config. Every Vault-backed store (TokenStore, TokenRegistry
# (issue #115), PrincipalCache (issue #144 step 2b), MaintenanceMode) shares
# the same vault_addr/vault_auth_role validation.
# ---------------------------------------------------------------------------

_VAULT_BACKEND_SETTINGS = [
    "token_store_backend",
    "token_registry_backend",
    "principal_cache_backend",
    "maintenance_mode_backend",
]


@pytest.mark.parametrize("backend_setting", _VAULT_BACKEND_SETTINGS)
def test_vault_config_ok_when_backend_is_in_memory(backend_setting):
    settings = Settings(**{backend_setting: "in_memory"})

    assert getattr(settings, backend_setting) == "in_memory"


@pytest.mark.parametrize("backend_setting", _VAULT_BACKEND_SETTINGS)
def test_vault_config_ok_when_backend_vault_and_addr_and_role_set(backend_setting):
    settings = Settings(
        **{backend_setting: "vault"},
        vault_addr="https://vault.example",
        vault_kv_root="mcp",
        vault_auth_role="af-mcp-broker",
    )

    assert getattr(settings, backend_setting) == "vault"
    assert settings.vault_addr == "https://vault.example"


@pytest.mark.parametrize("backend_setting", _VAULT_BACKEND_SETTINGS)
def test_vault_config_raises_when_backend_vault_and_addr_missing(backend_setting):
    with pytest.raises(ValueError, match="vault_addr"):
        Settings(**{backend_setting: "vault"}, vault_auth_role="af-mcp-broker")


@pytest.mark.parametrize("backend_setting", _VAULT_BACKEND_SETTINGS)
def test_vault_config_raises_when_backend_vault_and_auth_role_missing(
    backend_setting,
):
    with pytest.raises(ValueError, match="vault_auth_role"):
        Settings(**{backend_setting: "vault"}, vault_addr="https://vault.example")


def test_token_sweep_grace_seconds_defaults_to_seven_days():
    assert Settings().token_sweep_grace_seconds == 7 * 24 * 60 * 60


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
    monkeypatch.setenv("ALLOW_PER_REPLICA_STATE", "true")
    assert Settings().mcp_replica_count == 3


def test_builtin_service_name_defaults_and_env_override(monkeypatch):
    """The builtin gateway service name (issue #240) defaults to
    registry.BUILTIN_SERVICE_NAME and is overridable via BUILTIN_SERVICE_NAME."""

    assert Settings().builtin_service_name == BUILTIN_SERVICE_NAME
    monkeypatch.setenv("BUILTIN_SERVICE_NAME", "facility_service")
    assert Settings().builtin_service_name == "facility_service"


# ---------------------------------------------------------------------------
# broker-issued identity providers (issue #162) — the AF Broker Identity
# Token's config surface: discriminated-union parsing and the signing-key /
# issuer / TTL settings the issuer core reads. Per-target token options
# (audience, requires_posix) do not live here: they are on the service
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
    """target_options belong on the service entry (issue #257); a leftover key
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
    settings = Settings(identity_providers=[_BROKER_ISSUED_ENTRY])

    assert [p.alias for p in settings.identity_providers] == ["af-native"]


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


# krb5-token identity providers (issue #274) -- KrbTokenProvider's config --
# and servicex-token identity providers (issue #295) -- ServiceXProvider's
# config. Both are token-service entries with the same required fields.
_TOKEN_SERVICE_ENTRIES = pytest.mark.parametrize(
    ("provider_type", "alias", "display_name", "enables"),
    [
        pytest.param(
            "krb5-token",
            "krb5",
            "CERN Kerberos ticket",
            "Kerberos-authenticated access",
            id="krb5-token",
        ),
        pytest.param(
            "servicex-token",
            "servicex",
            "ServiceX access token",
            "ServiceX on-demand data delivery",
            id="servicex-token",
        ),
    ],
)


@_TOKEN_SERVICE_ENTRIES
def test_token_service_provider_config_parses(
    provider_type, alias, display_name, enables
):
    settings = Settings(
        identity_providers=[
            {
                "type": provider_type,
                "alias": alias,
                "display_name": display_name,
                "enables": enables,
                "targets": ["some-service"],
                "service_url": f"http://{provider_type}-service.invalid",
            }
        ],
        **_VAULT_ENV,
    )
    (cfg,) = settings.identity_providers
    assert cfg.type == provider_type
    assert cfg.alias == alias
    assert cfg.targets == ["some-service"]
    assert str(cfg.service_url) == f"http://{provider_type}-service.invalid/"
    assert cfg.audience == f"{provider_type}-service"  # default


@_TOKEN_SERVICE_ENTRIES
def test_token_service_provider_config_requires_service_url(
    provider_type, alias, display_name, enables
):
    valid_entry = {
        "type": provider_type,
        "alias": alias,
        "display_name": display_name,
        "enables": enables,
        "targets": ["some-service"],
        "service_url": f"http://{provider_type}-service.invalid",
    }
    entry = {k: v for k, v in valid_entry.items() if k != "service_url"}
    with pytest.raises(ValueError, match="service_url"):
        Settings(identity_providers=[entry], **_VAULT_ENV)


@_TOKEN_SERVICE_ENTRIES
def test_vault_config_required_by_token_service_entry(
    provider_type, alias, display_name, enables
):
    """service_url is mandatory on every token-service entry, and a given
    entry can't declare ahead of time whether any caller will ever request
    its optional "remember" persistence (krb5-token) or the refresh token it
    vaults has no in-memory fallback (servicex-token) -- so Vault is
    required unconditionally."""
    entry = {
        "type": provider_type,
        "alias": alias,
        "targets": ["some-service"],
        "service_url": f"http://{provider_type}-service.invalid",
    }
    with pytest.raises(ValueError, match="vault_addr"):
        Settings(identity_providers=[entry])
    with pytest.raises(ValueError, match="vault_auth_role"):
        Settings(identity_providers=[entry], vault_addr="https://vault.example")


# ---------------------------------------------------------------------------
# x509 identity providers — X509Provider's config surface, replacing the
# global VOMS_TOKEN_SERVICE_URL special case (which crash-looped a broker
# whose operator intuitively wrote an identityProviders entry for the voms
# service: `union_tag_invalid`, no such type existed). Discriminated-union
# parsing, the voms/valid defaults, and the Vault-connection coupling.
# ---------------------------------------------------------------------------

_X509_ENTRY = {
    "type": "x509",
    "voms": "atlas",
    "alias": "x509",
    "targets": ["ami"],
    "service_url": "http://voms-token-service.af-mcp.svc:8080",
}

_VAULT_ENV = {
    "vault_addr": "https://vault.example",
    "vault_auth_role": "broker",
    "vault_kv_root": "mcp",
}


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


def test_identity_providers_x509_requires_service_url():
    """voms-token-service is the only x509 mint path, so every entry names it."""
    entry = {k: v for k, v in _X509_ENTRY.items() if k != "service_url"}
    with pytest.raises(ValueError, match="service_url"):
        Settings(identity_providers=[entry], **_VAULT_ENV)


def test_vault_config_required_by_x509_entry():
    """x509 persists proxies and passphrases in Vault (there is no in-memory
    fallback), so an x509 entry implies the x509 store."""
    with pytest.raises(ValueError, match="vault_addr"):
        Settings(identity_providers=[_X509_ENTRY])
    with pytest.raises(ValueError, match="vault_auth_role"):
        Settings(identity_providers=[_X509_ENTRY], vault_addr="https://vault.example")


# ---------------------------------------------------------------------------
# Metering backend selection (metering.py's MeteringBackend seam)
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
    settings = Settings(
        usage_store_backend="postgres",
        usage_postgres_dsn="postgresql://broker:pw@pg.example/usage",
    )

    assert settings.usage_store_backend == "postgres"
    assert settings.usage_postgres_dsn is not None
    assert (
        settings.usage_postgres_dsn.get_secret_value()
        == "postgresql://broker:pw@pg.example/usage"
    )


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
    settings = Settings(
        maintenance_mode_backend="postgres",
        maintenance_mode_postgres_dsn="postgresql://broker:pw@pg.example/maint",
    )

    assert settings.maintenance_mode_backend == "postgres"
    assert settings.maintenance_mode_postgres_dsn is not None
    assert (
        settings.maintenance_mode_postgres_dsn.get_secret_value()
        == "postgresql://broker:pw@pg.example/maint"
    )


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


# ---------------------------------------------------------------------------
# HTCondor credmon integration (docs/credmon.md)
# ---------------------------------------------------------------------------


def test_credmon_disabled_needs_no_htcondor_api_settings():
    assert Settings(credmon_enabled=False).credmon_api is None


def test_credmon_enabled_with_htcondor_api_settings_is_ok():
    settings = Settings(
        credmon_enabled=True,
        credmon_htcondor_api_url="https://htcondor-api.example",
        credmon_htcondor_api_token_file="/var/run/secrets/credmon/token",
        credmon_user_domain="af.example.org",
        token_store_backend="vault",
        **_VAULT_ENV,
    )

    credmon_api = settings.credmon_api
    assert credmon_api is not None
    assert credmon_api.user_domain == "af.example.org"


def test_credmon_enabled_raises_without_user_domain():
    """credd rejects a bare unixname with "not in user@domain format"."""
    with pytest.raises(ValueError, match="credmon_user_domain"):
        Settings(
            credmon_enabled=True,
            credmon_htcondor_api_url="https://htcondor-api.example",
            credmon_htcondor_api_token_file="/var/run/secrets/credmon/token",
        )


def test_credmon_enabled_raises_without_htcondor_api_url():
    with pytest.raises(ValueError, match="credmon_htcondor_api_url"):
        Settings(
            credmon_enabled=True,
            credmon_htcondor_api_token_file="/var/run/secrets/credmon/token",
            credmon_user_domain="af.example.org",
        )


def test_credmon_enabled_raises_without_htcondor_api_token_file():
    with pytest.raises(ValueError, match="credmon_htcondor_api_token_file"):
        Settings(
            credmon_enabled=True,
            credmon_htcondor_api_url="https://htcondor-api.example",
            credmon_user_domain="af.example.org",
        )


def test_credmon_top_token_ttl_must_exceed_sync_interval():
    """A top token that expires before the next cycle replaces it would leave
    every job without credentials for the gap."""
    with pytest.raises(ValueError, match="credmon_top_token_ttl_seconds"):
        Settings(
            credmon_top_token_ttl_seconds=3600, credmon_sync_interval_seconds=14400
        )


def test_mcp_list_timeout_defaults_to_ten_seconds_and_reads_env(monkeypatch):
    assert Settings().mcp_list_timeout_seconds == pytest.approx(10.0)
    monkeypatch.setenv("MCP_LIST_TIMEOUT_SECONDS", "4.5")
    assert Settings().mcp_list_timeout_seconds == pytest.approx(4.5)


@pytest.mark.parametrize("value", ["0", "-1"])
def test_mcp_list_timeout_must_be_positive(monkeypatch, value):
    monkeypatch.setenv("MCP_LIST_TIMEOUT_SECONDS", value)
    with pytest.raises(ValueError, match="mcp_list_timeout_seconds"):
        Settings()


def test_shared_state_key_prefix_defaults_to_the_historical_namespace():
    assert Settings().shared_state_key_prefix == "af-mcp:"


def test_shared_state_key_prefix_env_var(monkeypatch):
    monkeypatch.setenv("SHARED_STATE_KEY_PREFIX", "release-a:")
    assert Settings().shared_state_key_prefix == "release-a:"


def test_multiple_replicas_without_shared_state_refuse_to_start(monkeypatch):
    monkeypatch.setenv("MCP_REPLICA_COUNT", "2")
    with pytest.raises(ValueError, match="SHARED_STATE_URL"):
        Settings()


@pytest.mark.parametrize(
    "env",
    [
        {"MCP_REPLICA_COUNT": "2", "SHARED_STATE_URL": "redis://cache:6379/0"},
        {"MCP_REPLICA_COUNT": "2", "ALLOW_PER_REPLICA_STATE": "true"},
        {"MCP_REPLICA_COUNT": "1"},
        {},  # replica count unknown (local dev): nothing to refuse
    ],
)
def test_replica_state_guard_passes(monkeypatch, env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    settings = Settings()

    assert settings.mcp_replica_count == (
        int(env["MCP_REPLICA_COUNT"]) if "MCP_REPLICA_COUNT" in env else None
    )


def test_usage_batch_settings_default_and_read_env(monkeypatch):
    assert Settings().usage_batch_max == 100
    assert Settings().usage_batch_interval_ms == 1000
    monkeypatch.setenv("USAGE_BATCH_MAX", "7")
    monkeypatch.setenv("USAGE_BATCH_INTERVAL_MS", "250")
    assert Settings().usage_batch_max == 7
    assert Settings().usage_batch_interval_ms == 250


def test_usage_retention_settings_default_and_read_env(monkeypatch):
    assert Settings().usage_retention_days == 365
    assert Settings().usage_rollup_interval_seconds == 3600
    monkeypatch.setenv("USAGE_RETENTION_DAYS", "0")
    monkeypatch.setenv("USAGE_ROLLUP_INTERVAL_SECONDS", "60")
    assert Settings().usage_retention_days == 0
    assert Settings().usage_rollup_interval_seconds == 60


def test_usage_retention_days_rejects_negative():
    with pytest.raises(ValueError, match="usage_retention_days"):
        Settings(usage_retention_days=-1)


@pytest.mark.parametrize("value", [0, -1])
def test_usage_rollup_interval_must_be_positive(value):
    with pytest.raises(ValueError, match="usage_rollup_interval_seconds"):
        Settings(usage_rollup_interval_seconds=value)


@pytest.mark.parametrize("name", ["usage_batch_max", "usage_batch_interval_ms"])
@pytest.mark.parametrize("value", [0, -1])
def test_usage_batch_settings_must_be_positive(name, value):
    with pytest.raises(ValueError, match=name):
        Settings(**{name: value})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("/example/af", ["/example/af"], id="single"),
        pytest.param(
            "/example/af, /example/ops", ["/example/af", "/example/ops"], id="trimmed"
        ),
        pytest.param("a,,b, ,", ["a", "b"], id="empty-entries-dropped"),
        pytest.param("", [], id="empty-string"),
        pytest.param("  ,  ", [], id="only-separators"),
    ],
)
def test_access_groups_parses_a_comma_list_from_the_environment(
    monkeypatch, raw, expected
):
    monkeypatch.setenv("ACCESS_GROUPS", raw)
    assert Settings().access_groups == expected


def test_access_groups_defaults_to_empty():
    assert Settings().access_groups == []


def test_access_groups_accepts_a_list_and_normalises_entries():
    assert Settings(access_groups=[" a ", "", "b"]).access_groups == ["a", "b"]

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal

import structlog
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# OAuth 2.1 provider config (issue #66 PR1) — one entry per backend
# authorization server the broker acts as a direct OAuth 2.1 client to.
# ---------------------------------------------------------------------------


class OAuth21ProviderConfig(BaseModel):
    alias: str
    targets: list[str]
    authorization_endpoint: AnyHttpUrl
    token_endpoint: AnyHttpUrl
    issuer: str
    scope: str = "openid profile email"

    # Portal-facing metadata for GET /v1/identities. Optional so a minimal
    # provider config still parses; an operator who leaves these blank just
    # gets an empty label/description on the Identities page until they fill
    # them in.
    display_name: str = ""
    enables: str = ""


# pydantic-settings matches env vars to field names case-insensitively, so the
# uppercase env var names (OIDC_ISSUER, ...) map to these fields without
# explicit aliases.


class Settings(BaseSettings):
    # ``keycloak_dependency`` injects Settings via ``Depends(Settings)``. FastAPI
    # builds a request model from the callable's signature, and the pydantic-
    # settings ``BaseSettings.__init__`` exposes private (``_cli_parse_args`` …)
    # parameters that FastAPI cannot turn into fields. Overriding ``__init__``
    # with a plain ``**data`` signature keeps env loading intact while giving
    # FastAPI a clean signature to introspect.
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

    # OIDC configuration
    oidc_issuer: str = "https://keycloak-prod.tempest.uchicago.edu/realms/connect"
    oidc_audience: str = "mcp-gateway"
    # Derived from oidc_issuer when not set explicitly.
    oidc_jwks_uri: str = ""

    # Linked external IdP alias — must match the IdP alias in the OIDC
    # issuer's connect realm. Verified alias is "atlas-oidc" (Settings →
    # Identity Providers → ATLAS IAM).
    oidc_idp_alias: str = "atlas-oidc"

    # The portal's own Keycloak client id (a public client — see
    # portal/src/lib/auth.ts). GET /v1/identities uses this to build the
    # `kc_action=LINK_IDP` URL for keycloak-brokered providers, so the portal
    # doesn't need Keycloak details itself. Empty means the broker can't
    # build these URLs — keycloak-brokered `link_url`s come back null and the
    # portal renders no Link button for them.
    identities_link_client_id: str = ""

    # Filesystem
    home_root: str = "/data/homes"

    # Broker-owned per-uid proxy files live here (tmpfs in the chart, which
    # passes PROXY_DIR when broker.tmpfsProxy is enabled).
    proxy_dir: str = "/run/broker/proxies"

    # Policy and backend config files read at startup
    policy_file: str = "/etc/af-mcp/policy.yaml"
    backends_file: str = "/etc/af-mcp/backends.yaml"

    # Audit log destination; "-" means stdout
    audit_log_file: str = "-"

    # Prometheus /metrics is served on its own port so a NetworkPolicy can
    # firewall scraping separately from API traffic. 0 picks an ephemeral
    # port (tests); a negative value disables the metrics server.
    metrics_port: int = 9090

    # User-facing portal, used in unlock hints and identity-linking redirects.
    portal_url: str = "https://mcp-portal.af.uchicago.edu"

    # Loopback base URL the aggregator middleware uses to reach the broker's
    # own /v1 API. The broker contract is HTTP even when co-located.
    broker_internal_url: str = Field(
        default="http://localhost:8080",
        alias="BROKER_INTERNAL_URL",
    )

    log_level: str = Field(
        default="INFO",
        alias="LOG_LEVEL",
    )

    # Local-development auth bypass. When set to a JSON blob describing a
    # principal, the broker's keycloak_dependency short-circuits and returns
    # that principal *without validating any bearer token*. This exists so
    # `astro dev` can hit `/v1/*` on a locally-running broker without
    # oauth2-proxy in front. The lifespan refuses to start unless
    # ``oidc_issuer`` points at a local host — defence-in-depth against
    # accidental production deployment. Never set this in any chart values,
    # container default, or CI env.
    dev_insecure_principal: str | None = Field(
        default=None,
        alias="BROKER_DEV_INSECURE_PRINCIPAL",
    )

    # CredentialCache.check_unlock_rate_limit()/get()/put() count failed cache
    # lookups and bad passphrase attempts per uid; this many are allowed
    # inside the window below before RateLimitError trips. 5 is generous
    # enough to tolerate a mistyped passphrase but tight enough to slow a
    # brute-force guesser who has read access to a user's ~/.globus.
    credential_unlock_max_failures: int = 5

    # Sliding window, in seconds, over which the failures above are counted.
    # 15 minutes roughly matches how often a browser session's token refresh
    # forces re-authentication anyway, so it rarely inconveniences real users.
    credential_unlock_window_seconds: int = 15 * 60

    # Client ID Metadata Document (CIMD, draft-ietf-oauth-client-id-metadata-
    # document) served at /.well-known/cimd — lets the broker identify itself
    # to backend OAuth 2.1 authorization servers without per-backend Dynamic
    # Client Registration.
    cimd_client_name: str = "AF MCP Broker"

    # Keycloak IdP aliases the broker proxies for; each becomes a
    # redirect_uris entry in the CIMD document. Parsed from CIMD_IDP_ALIASES
    # as a JSON array, e.g. '["rucio-atlas","rucio-escape"]'.
    cimd_idp_aliases: list[str] = Field(default_factory=list)

    # Fernet key (urlsafe-base64-encoded 32 bytes) that encrypts the OAuth 2.1
    # flow's `state` token — see oauth_state.py. Required (non-empty) whenever
    # `oauth21_providers` is non-empty; enforced by `_validate_oauth21_config`.
    broker_state_key: SecretStr = SecretStr("")

    # `iss`/`aud` self-reference embedded in the OAuth 2.1 state token, so a
    # token minted by one deployment is rejected by another. Empty means "use
    # oidc_issuer" — resolved at read time via `oauth21_effective_state_issuer`
    # rather than baked in here, so it always tracks the current oidc_issuer.
    oauth21_state_issuer: str = ""

    # The broker's own CIMD URL (e.g. https://mcp.af.uchicago.edu/.well-known/cimd),
    # used as `client_id` when the broker acts as an OAuth 2.1 client.
    oauth21_client_id: str = ""

    # One entry per OAuth 2.1 backend authorization server. Parsed from
    # OAUTH21_PROVIDERS as a JSON array, same style as CIMD_IDP_ALIASES.
    oauth21_providers: list[OAuth21ProviderConfig] = Field(default_factory=list)

    # Which TokenStore implementation backs the OAuth 2.1 providers above.
    # "in_memory" is single-replica and lost on restart (fine for dev/testing);
    # "vault" persists to Vault/OpenBao KV-v2 via the broker's K8s auth
    # identity — see credentials/vault.py.
    token_store_backend: Literal["in_memory", "vault"] = "in_memory"

    # Vault/OpenBao HTTP API base URL, no trailing slash (e.g.
    # https://vault.example.com). Required when token_store_backend="vault".
    vault_addr: str = ""

    # Vault auth mount point for the K8s auth backend (auth/<mount>/login).
    vault_auth_mount: str = "kubernetes"

    # Vault role the broker's ServiceAccount JWT is exchanged against.
    # Required when token_store_backend="vault".
    vault_auth_role: str = ""

    # Vault KV-v2 secrets engine mount point.
    vault_kv_mount: str = "secret"

    # Path prefix under the KV mount where per-subject/alias credentials are
    # stored: {vault_kv_mount}/data/{vault_kv_path_prefix}/{subject}/{alias}.
    vault_kv_path_prefix: str = "mcp/tokens"

    # Filesystem path to the broker's own ServiceAccount JWT, projected by
    # Kubernetes automatically whenever a ServiceAccount is set on the pod —
    # no extra volume mount needed at the chart's default.
    vault_sa_token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"

    @property
    def oauth21_effective_state_issuer(self) -> str:
        """``oauth21_state_issuer`` if set, else ``oidc_issuer``.

        Computed at read time (unlike ``oidc_jwks_uri``, which is derived once
        in ``_derive_jwks_uri``) so it always reflects the current value of
        either field rather than a value frozen at construction time.
        """
        return self.oauth21_state_issuer or self.oidc_issuer

    @field_validator(
        "credential_unlock_max_failures", "credential_unlock_window_seconds"
    )
    @classmethod
    def _validate_positive_rate_limit(cls, value: int, info: ValidationInfo) -> int:
        if value < 1:
            raise ValueError(
                f"{info.field_name} must be >= 1; a zero or negative value "
                "disables the rate limit instead of tuning it, defeating "
                "its purpose as a brute-force defence."
            )
        return value

    @model_validator(mode="after")
    def _derive_jwks_uri(self) -> Settings:
        if not self.oidc_jwks_uri:
            # Standard OIDC discovery path
            self.oidc_jwks_uri = (
                f"{self.oidc_issuer.rstrip('/')}/protocol/openid-connect/certs"
            )
        return self

    @model_validator(mode="after")
    def _validate_oauth21_config(self) -> Settings:
        """Fail startup loudly when OAuth 2.1 providers are configured but the
        settings they depend on are not — a half-configured OAuth21Provider
        would otherwise fail at first request instead of at boot.
        """
        if not self.oauth21_providers:
            return self
        if not self.broker_state_key.get_secret_value():
            log.error(
                "oauth21_config_invalid",
                reason="broker_state_key is empty but oauth21_providers is configured",
            )
            raise ValueError(
                "broker_state_key (BROKER_STATE_KEY) must be set when "
                "oauth21_providers is non-empty — it protects in-flight "
                "OAuth 2.1 linking flows."
            )
        if not self.oauth21_client_id:
            log.error(
                "oauth21_config_invalid",
                reason="oauth21_client_id is empty but oauth21_providers is configured",
            )
            raise ValueError(
                "oauth21_client_id (OAUTH21_CLIENT_ID) must be set when "
                "oauth21_providers is non-empty — it identifies the broker "
                "as an OAuth 2.1 client via its CIMD document."
            )
        return self

    @model_validator(mode="after")
    def _validate_oauth21_cimd_alias_parity(self) -> Settings:
        """Every ``oauth21_providers`` alias must have a matching
        ``cimd_idp_aliases`` entry, and vice versa.

        The CIMD document advertises ``redirect_uris`` per alias — an
        ``OAuth21Provider`` whose alias is missing from ``cimd_idp_aliases``
        would silently be unable to complete its callback with backends that
        actually check the advertised redirect URIs, and a ``cimd_idp_aliases``
        entry with no matching provider is dangling config that advertises a
        redirect URI nothing will ever complete. This is a stopgap until both
        settings collapse into one unified identity-provider config.
        """
        oauth21_aliases = {cfg.alias for cfg in self.oauth21_providers}
        cimd_aliases = set(self.cimd_idp_aliases)
        if oauth21_aliases != cimd_aliases:
            missing_from_cimd = sorted(oauth21_aliases - cimd_aliases)
            missing_from_oauth21 = sorted(cimd_aliases - oauth21_aliases)
            log.error(
                "oauth21_cimd_alias_mismatch",
                missing_from_cimd_idp_aliases=missing_from_cimd,
                missing_from_oauth21_providers=missing_from_oauth21,
            )
            raise ValueError(
                "oauth21_providers aliases and cimd_idp_aliases must match "
                f"exactly; missing from cimd_idp_aliases: {missing_from_cimd}; "
                f"missing from oauth21_providers: {missing_from_oauth21}"
            )
        return self

    @model_validator(mode="after")
    def _validate_vault_config(self) -> Settings:
        """Fail startup loudly when the vault TokenStore backend is selected
        but the settings it depends on are not — a half-configured
        VaultTokenStore would otherwise fail at first request instead of at
        boot (see also app.py's lifespan trial authentication).
        """
        if self.token_store_backend != "vault":
            return self
        if not self.vault_addr:
            log.error(
                "vault_config_invalid",
                reason="vault_addr is empty but token_store_backend is 'vault'",
            )
            raise ValueError(
                "vault_addr (VAULT_ADDR) must be set when token_store_backend "
                "is 'vault'."
            )
        if not self.vault_auth_role:
            log.error(
                "vault_config_invalid",
                reason="vault_auth_role is empty but token_store_backend is 'vault'",
            )
            raise ValueError(
                "vault_auth_role (VAULT_AUTH_ROLE) must be set when "
                "token_store_backend is 'vault'."
            )
        return self

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance.

    Use as a FastAPI dependency (``Depends(get_settings)``) so ``.env`` is read
    once at first access rather than re-instantiated on every request.
    """
    return Settings()

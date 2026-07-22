from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings

# pydantic-settings matches env vars to field names case-insensitively, so the
# uppercase env var names (KEYCLOAK_ISSUER, ...) map to these fields without
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

    # Keycloak OIDC configuration
    keycloak_issuer: str = "https://keycloak-prod.tempest.uchicago.edu/realms/connect"
    keycloak_audience: str = "mcp-gateway"
    # Derived from keycloak_issuer when not set explicitly.
    keycloak_jwks_uri: str = ""

    # ATLAS IAM broker alias — must match the IdP alias in Keycloak connect realm.
    # Verified alias is "atlas-oidc" (Settings → Identity Providers → ATLAS IAM).
    atlas_iam_broker_alias: str = "atlas-oidc"

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
    # ``keycloak_issuer`` points at a local host — defence-in-depth against
    # accidental production deployment. Never set this in any chart values,
    # container default, or CI env.
    dev_insecure_principal: str | None = Field(
        default=None,
        alias="BROKER_DEV_INSECURE_PRINCIPAL",
    )

    @model_validator(mode="after")
    def _derive_jwks_uri(self) -> Settings:
        if not self.keycloak_jwks_uri:
            # Standard OIDC discovery path
            self.keycloak_jwks_uri = (
                f"{self.keycloak_issuer.rstrip('/')}/protocol/openid-connect/certs"
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

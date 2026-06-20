from __future__ import annotations

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Keycloak OIDC configuration
    keycloak_issuer: str = Field(
        default="https://keycloak-prod.tempest.uchicago.edu/realms/connect",
        alias="KEYCLOAK_ISSUER",
    )
    keycloak_audience: str = Field(
        default="mcp-gateway",
        alias="KEYCLOAK_AUDIENCE",
    )
    # Derived from keycloak_issuer when not set explicitly.
    keycloak_jwks_uri: str = Field(
        default="",
        alias="KEYCLOAK_JWKS_URI",
    )

    # ATLAS IAM broker alias used in Keycloak identity provider config
    atlas_iam_broker_alias: str = Field(
        default="atlas-iam",
        alias="ATLAS_IAM_BROKER_ALIAS",
    )

    # Filesystem
    home_root: str = Field(
        default="/data/homes",
        alias="HOME_ROOT",
    )

    # Policy and backend config files read at startup
    policy_file: str = Field(
        default="/etc/af-mcp/policy.yaml",
        alias="POLICY_FILE",
    )
    backends_file: str = Field(
        default="/etc/af-mcp/backends.yaml",
        alias="BACKENDS_FILE",
    )

    # Audit log destination; "-" means stdout
    audit_log_file: str = Field(
        default="-",
        alias="AUDIT_LOG_FILE",
    )

    log_level: str = Field(
        default="INFO",
        alias="LOG_LEVEL",
    )

    @model_validator(mode="after")
    def _derive_jwks_uri(self) -> Settings:
        if not self.keycloak_jwks_uri:
            # Standard OIDC discovery path
            self.keycloak_jwks_uri = (
                f"{self.keycloak_issuer.rstrip('/')}/protocol/openid-connect/certs"
            )
        return self

    model_config = {"populate_by_name": True, "env_file": ".env", "extra": "ignore"}

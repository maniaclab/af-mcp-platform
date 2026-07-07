from __future__ import annotations

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings

# pydantic-settings matches env vars to field names case-insensitively, so the
# uppercase env var names (KEYCLOAK_ISSUER, ...) map to these fields without
# explicit aliases.


class Settings(BaseSettings):
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

    # Policy and backend config files read at startup
    policy_file: str = "/etc/af-mcp/policy.yaml"
    backends_file: str = "/etc/af-mcp/backends.yaml"

    # Audit log destination; "-" means stdout
    audit_log_file: str = "-"

    log_level: str = "INFO"

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

"""No facility-specific defaults in ``Settings`` or the x509 provider config."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from af_mcp_broker.config import Settings, X509ProviderConfig
from af_mcp_broker.wiring.identity import require_oidc_issuer


def test_settings_defaults_name_no_facility() -> None:
    settings = Settings(_env_file=None)

    assert settings.oidc_issuer == ""
    assert settings.portal_url == ""


def test_boot_without_an_oidc_issuer_is_refused() -> None:
    with pytest.raises(RuntimeError, match="OIDC_ISSUER"):
        require_oidc_issuer(Settings(_env_file=None))


def test_boot_with_an_oidc_issuer_is_accepted() -> None:
    settings = Settings(_env_file=None, oidc_issuer="https://keycloak.example.com/r")

    require_oidc_issuer(settings)


def test_x509_provider_config_requires_voms() -> None:
    with pytest.raises(ValidationError, match="voms"):
        X509ProviderConfig.model_validate(
            {
                "alias": "x509",
                "service_url": "http://voms-token-service.invalid",
            }
        )

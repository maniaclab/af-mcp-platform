"""Unit tests for the area ``test_x509_identity_provider.py`` covers; the integration tests live in ``integration/test_x509_identity_provider.py``."""

from __future__ import annotations

import pytest

from af_mcp_broker.config import (
    KeycloakBrokeredProviderConfig,
    X509ProviderConfig,
)
from af_mcp_broker.wiring.checks import validate_x509_provider_targets

# ---------------------------------------------------------------------------
# validate_x509_provider_targets — fail-closed drift protection between
# `auth_type: x509` backends and explicit entry targets. Universal: there is
# no synthesized-entry escape hatch, so the zero-entries case is one more
# quadrant of the same check, not a separate "validates trivially" path.
# ---------------------------------------------------------------------------


class TestValidateTargets:
    def test_exact_coverage_passes(self) -> None:
        cfgs = [
            X509ProviderConfig(
                voms="atlas",
                alias="x509",
                targets=["ami", "panda"],
                service_url="http://voms-token-service.invalid",
            )
        ]

        assert validate_x509_provider_targets(cfgs, {"ami", "panda"}) is None

    def test_uncovered_x509_backend_refuses_to_start(self) -> None:
        """An auth_type: x509 backend no explicit entry targets would have no
        provider (and no catalog alias) at all — refuse to boot naming it."""
        cfgs = [
            X509ProviderConfig(
                voms="atlas",
                alias="x509",
                targets=["ami"],
                service_url="http://voms-token-service.invalid",
            )
        ]

        with pytest.raises(RuntimeError, match="panda"):
            validate_x509_provider_targets(cfgs, {"ami", "panda"})

    def test_entry_targeting_a_non_x509_backend_refuses_to_start(self) -> None:
        """An x509 entry targeting a backend that isn't auth_type: x509 is a
        typo or a stale services.yaml — the aggregator would never inject an
        identity JWT for it and the redeem endpoint would reject its
        audience, so the entry silently does nothing. Refuse to boot."""
        cfgs = [
            X509ProviderConfig(
                voms="atlas",
                alias="x509",
                targets=["ami", "rucio"],
                service_url="http://voms-token-service.invalid",
            )
        ]

        with pytest.raises(RuntimeError, match="rucio"):
            validate_x509_provider_targets(cfgs, {"ami"})

    def test_no_explicit_entries_and_x509_backends_refuses_to_start(self) -> None:
        """There is no synthesized fallback: an entry-less deployment with an
        auth_type: x509 backend refuses to boot naming it, exactly like a
        backend covered by the wrong entry."""
        with pytest.raises(RuntimeError, match="ami"):
            validate_x509_provider_targets([], {"ami"})

    def test_no_explicit_entries_and_no_x509_backends_validates_nothing(self) -> None:
        assert validate_x509_provider_targets([], set()) is None

    def test_error_is_not_raised_for_non_x509_config_types(self) -> None:
        """Only x509 entries participate — a keycloak-brokered entry naming
        a bearer backend is the pre-existing, valid shape."""
        cfgs = [
            KeycloakBrokeredProviderConfig(alias="atlas-oidc", targets=["rucio"]),
            X509ProviderConfig(
                voms="atlas",
                alias="x509",
                targets=["ami"],
                service_url="http://voms-token-service.invalid",
            ),
        ]

        assert validate_x509_provider_targets(cfgs, {"ami"}) is None

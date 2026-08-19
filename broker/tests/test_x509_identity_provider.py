"""Tests for the first-class x509 `identity_providers` entry.

x509 used to be the one credential source with no `identity_providers`
config of its own: the voms-token-service URL was a global env var
(`VOMS_TOKEN_SERVICE_URL`), the catalog alias a hardcoded "x509" string, and
the Identities row a synthetic entry. Normalizing it into an
`X509ProviderConfig` entry (type "x509") removes those special cases while
keeping the wire behavior — backend-side proxy redemption — unchanged.

Covered here:

* `_effective_identity_provider_configs` — the synthesis rules: explicit
  entries pass through (and win over the deprecated env var, with a
  warning); the env var alone synthesizes an equivalent service-mode entry
  (deprecation warning); x509 backends with neither synthesize a legacy-mode
  entry so the registry/catalog/identities surfaces stay populated.
* `_validate_x509_provider_targets` — the fail-closed boot check for
  drift between `auth_type: x509` backends and explicit entry targets
  (both directions), same reasoning as issue #60's required_capability
  consolidation.
* Full-boot wiring — per-entry service_url/voms/valid/audience reaching
  VomsTokenServiceClient, multiple entries resolving to distinct providers,
  and the explicit-entry signing-key requirement (fail-closed, mirroring
  the broker-issued/condor-token check).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from test_broker_issued import _make_rsa_key, _private_pem

import af_mcp_broker.app as app_module
from af_mcp_broker.app import (
    _effective_identity_provider_configs,
    _validate_x509_provider_targets,
)
from af_mcp_broker.config import (
    KeycloakBrokeredProviderConfig,
    Settings,
    X509ProviderConfig,
)
from af_mcp_broker.credentials import X509Provider

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_SERVICE_URL = "http://voms-token-service.af-mcp.svc:8080"

_X509_BACKENDS_YAML = (
    "backends:\n"
    "  - name: ami\n"
    "    prefix: ami\n"
    "    url: http://ami-mcp.invalid/mcp\n"
    "    auth_type: x509\n"
    "    required_capability: read_data\n"
)


def _x509_entry(**overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "x509",
        "alias": "x509",
        "display_name": "Grid certificate (x509)",
        "enables": "VOMS proxy minting",
        "targets": ["ami"],
        "service_url": _SERVICE_URL,
    }
    entry.update(overrides)
    return entry


def _settings(**overrides: Any) -> Settings:
    # Vault connection settings satisfy _validate_vault_config whenever a
    # service-mode entry (or the deprecated env var) is present.
    defaults: dict[str, Any] = {
        "vault_addr": "https://vault.example",
        "vault_auth_role": "af-mcp-broker",
    }
    defaults.update(overrides)
    return Settings(**defaults)


@pytest.fixture
def warning_events(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict]]:
    """Capture app_module.logger.warning events (configure_logging rewrites
    root handlers during the lifespan, swallowing caplog — same pattern as
    test_health.py's startup-warning test)."""
    events: list[tuple[str, dict]] = []
    original_warning = app_module.logger.warning

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append((event, kwargs))
        return original_warning(event, **kwargs)

    monkeypatch.setattr(app_module.logger, "warning", _capture)
    return events


# ---------------------------------------------------------------------------
# _effective_identity_provider_configs — synthesis rules
# ---------------------------------------------------------------------------


class TestEffectiveConfigs:
    def test_explicit_entries_pass_through_unchanged(
        self, warning_events: list[tuple[str, dict]]
    ) -> None:
        settings = _settings(identity_providers=[_x509_entry()])

        configs = _effective_identity_provider_configs(settings, ["ami"])

        assert configs == settings.identity_providers
        assert not warning_events

    def test_explicit_entries_win_over_the_deprecated_env_var(
        self, warning_events: list[tuple[str, dict]]
    ) -> None:
        """When both are set the explicit entries are authoritative and the
        env var is ignored, loudly."""
        settings = _settings(
            identity_providers=[_x509_entry()],
            voms_token_service_url="http://somewhere-else.invalid:8000",
        )

        configs = _effective_identity_provider_configs(settings, ["ami"])

        assert configs == settings.identity_providers
        assert any(
            event == "voms_token_service_url_ignored" for event, _ in warning_events
        )

    def test_env_var_synthesizes_an_equivalent_service_mode_entry(
        self, warning_events: list[tuple[str, dict]]
    ) -> None:
        """Deprecation path: VOMS_TOKEN_SERVICE_URL with no x509 entry keeps
        existing deployments working unchanged through one release — a
        synthesized entry (alias "x509", targets = every auth_type-x509
        backend) carrying the global service settings, plus a loud warning
        pointing at the new config."""
        settings = _settings(
            voms_token_service_url=_SERVICE_URL,
            voms_token_service_voms="dune",
            voms_token_service_valid="24:00",
            voms_token_service_audience="voms-token-service-dev",
        )

        configs = _effective_identity_provider_configs(settings, ["ami", "panda"])

        (cfg,) = configs
        assert isinstance(cfg, X509ProviderConfig)
        assert cfg.alias == "x509"
        assert cfg.targets == ["ami", "panda"]
        assert str(cfg.service_url).rstrip("/") == _SERVICE_URL
        assert cfg.voms == "dune"
        assert cfg.valid == "24:00"
        assert cfg.audience == "voms-token-service-dev"
        # Portal-facing metadata is filled so the Identities row keeps its
        # pre-existing label/description.
        assert cfg.display_name
        assert cfg.enables
        assert any(
            event == "voms_token_service_url_deprecated" for event, _ in warning_events
        )

    def test_x509_backends_with_no_config_synthesize_a_legacy_entry(
        self, warning_events: list[tuple[str, dict]]
    ) -> None:
        """Legacy k8s-Job/local-dev mode (no entry, no env var) stays a
        working, entry-less default: the lifespan synthesizes a legacy-mode
        entry (service_url None) so the registry/catalog/identities surfaces
        stay populated without any synthetic-alias special case downstream."""
        settings = Settings()

        configs = _effective_identity_provider_configs(settings, ["ami"])

        (cfg,) = configs
        assert isinstance(cfg, X509ProviderConfig)
        assert cfg.alias == "x509"
        assert cfg.targets == ["ami"]
        assert cfg.service_url is None
        assert cfg.display_name
        assert cfg.enables
        # Legacy mode is supported, not deprecated -- no warning.
        assert not warning_events

    def test_no_x509_backends_and_no_env_var_synthesizes_nothing(self) -> None:
        settings = Settings(
            identity_providers=[
                {
                    "type": "keycloak-brokered",
                    "alias": "atlas-oidc",
                    "targets": ["rucio"],
                }
            ]
        )

        configs = _effective_identity_provider_configs(settings, [])

        assert configs == settings.identity_providers

    def test_synthesized_entry_is_appended_after_configured_entries(self) -> None:
        """The synthesized entry has no config-order slot of its own — it
        always trails the operator-configured entries, preserving the
        pre-existing /v1/identities ordering."""
        settings = Settings(
            identity_providers=[
                {
                    "type": "keycloak-brokered",
                    "alias": "atlas-oidc",
                    "targets": ["rucio"],
                }
            ]
        )

        configs = _effective_identity_provider_configs(settings, ["ami"])

        assert [cfg.alias for cfg in configs] == ["atlas-oidc", "x509"]


# ---------------------------------------------------------------------------
# _validate_x509_provider_targets — fail-closed drift protection between
# `auth_type: x509` backends and explicit entry targets (all four quadrants;
# same reasoning as issue #60's required_capability consolidation).
# ---------------------------------------------------------------------------


class TestValidateTargets:
    def test_exact_coverage_passes(self) -> None:
        cfgs = [X509ProviderConfig(alias="x509", targets=["ami", "panda"])]

        _validate_x509_provider_targets(cfgs, {"ami", "panda"})  # must not raise

    def test_uncovered_x509_backend_refuses_to_start(self) -> None:
        """An auth_type: x509 backend no explicit entry targets would have no
        provider (and no catalog alias) at all — refuse to boot naming it."""
        cfgs = [X509ProviderConfig(alias="x509", targets=["ami"])]

        with pytest.raises(RuntimeError, match="panda"):
            _validate_x509_provider_targets(cfgs, {"ami", "panda"})

    def test_entry_targeting_a_non_x509_backend_refuses_to_start(self) -> None:
        """An x509 entry targeting a backend that isn't auth_type: x509 is a
        typo or a stale backends.yaml — the aggregator would never inject an
        identity JWT for it and the redeem endpoint would reject its
        audience, so the entry silently does nothing. Refuse to boot."""
        cfgs = [X509ProviderConfig(alias="x509", targets=["ami", "rucio"])]

        with pytest.raises(RuntimeError, match="rucio"):
            _validate_x509_provider_targets(cfgs, {"ami"})

    def test_no_explicit_entries_validates_nothing(self) -> None:
        """Entry-less deployments (legacy/env-var synthesis covers every
        x509 backend by construction) must keep booting."""
        _validate_x509_provider_targets([], {"ami"})  # must not raise

    def test_error_is_not_raised_for_non_x509_config_types(self) -> None:
        """Only x509 entries participate — a keycloak-brokered entry naming
        a bearer backend is the pre-existing, valid shape."""
        cfgs = [
            KeycloakBrokeredProviderConfig(alias="atlas-oidc", targets=["rucio"]),
            X509ProviderConfig(alias="x509", targets=["ami"]),
        ]

        _validate_x509_provider_targets(cfgs, {"ami"})  # must not raise


# ---------------------------------------------------------------------------
# Full-boot wiring
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_key_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(_private_pem(_make_rsa_key()))
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")


@pytest.fixture
def vault_stub_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Vault connection settings + a stubbed startup trial auth, so a
    service-mode entry can boot without a Vault deployment (same stub as
    test_x509_service_mode's TestAppWiring)."""
    from af_mcp_broker.vault_kv import VaultKV

    async def _fake_authenticate(self: VaultKV) -> str:
        return "vault-test-token"

    monkeypatch.setattr(VaultKV, "_authenticate", _fake_authenticate)
    monkeypatch.setenv("VAULT_ADDR", "https://vault.invalid")
    monkeypatch.setenv("VAULT_AUTH_ROLE", "af-mcp-broker")


def _set_backends(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str = _X509_BACKENDS_YAML
) -> None:
    backends_file = tmp_path / "backends.yaml"
    backends_file.write_text(text)
    monkeypatch.setenv("BACKENDS_FILE", str(backends_file))


def _set_identity_providers(
    monkeypatch: pytest.MonkeyPatch, entries: list[dict[str, Any]]
) -> None:
    import json

    monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(entries))


class TestBootWiring:
    def test_explicit_service_entry_wires_per_entry_settings(
        self,
        signing_key_env: None,
        vault_stub_env: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """The entry's service_url/voms/valid/audience — not the deprecated
        global settings — reach VomsTokenServiceClient."""
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(
            monkeypatch,
            [_x509_entry(voms="dune", valid="24:00", audience="voms-dev")],
        )

        with app_client_factory() as (client, _):
            provider = client.app.state.x509_provider
            assert isinstance(provider, X509Provider)
            assert provider.uses_voms_service is True
            voms_client = provider._voms_client
            assert voms_client._mint_endpoint == f"{_SERVICE_URL}/v1/mint"
            assert voms_client._voms == "dune"
            assert voms_client._valid == "24:00"
            assert voms_client._audience == "voms-dev"
            # The catalog join uses the real entry alias.
            assert client.app.state.target_to_alias["ami"] == "x509"

    def test_explicit_legacy_entry_boots_and_registers_targets(
        self,
        signing_key_env: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """An entry without service_url selects the legacy mint path — same
        semantics as an empty VOMS_TOKEN_SERVICE_URL — under an operator-
        chosen alias."""
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(
            monkeypatch, [_x509_entry(alias="grid-cert", service_url=None)]
        )

        with app_client_factory() as (client, _):
            provider = client.app.state.x509_provider
            assert isinstance(provider, X509Provider)
            assert provider.uses_voms_service is False
            assert client.app.state.target_to_alias["ami"] == "grid-cert"
            assert "grid-cert" in client.app.state.identity_providers

    def test_multiple_entries_resolve_to_distinct_providers(
        self,
        signing_key_env: None,
        vault_stub_env: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """Two entries with different service URLs/VOs service their own
        targets — the functional gain over the single global env var."""
        _set_backends(
            monkeypatch,
            tmp_path,
            _X509_BACKENDS_YAML
            + (
                "  - name: dune-mcp\n"
                "    prefix: dune\n"
                "    url: http://dune-mcp.invalid/mcp\n"
                "    auth_type: x509\n"
                "    required_capability: read_data\n"
            ),
        )
        _set_identity_providers(
            monkeypatch,
            [
                _x509_entry(),
                _x509_entry(
                    alias="x509-dune",
                    targets=["dune-mcp"],
                    service_url="http://voms-token-service-dune.af-mcp.svc:8080",
                    voms="dune",
                ),
            ],
        )

        with app_client_factory() as (client, _):
            registry = client.app.state.credential_registry
            import asyncio

            ami_provider = asyncio.run(registry.resolve("ami"))
            dune_provider = asyncio.run(registry.resolve("dune-mcp"))
            assert ami_provider is not dune_provider
            assert ami_provider._voms_client._voms == "atlas"
            assert dune_provider._voms_client._voms == "dune"
            # IDENTITY_PROVIDERS was overridden with just the two x509
            # entries, so the join contains exactly their targets.
            assert client.app.state.target_to_alias == {
                "ami": "x509",
                "dune-mcp": "x509-dune",
            }

    def test_deprecated_env_var_still_boots_with_a_warning(
        self,
        signing_key_env: None,
        vault_stub_env: None,
        warning_events: list[tuple[str, dict]],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        _set_backends(monkeypatch, tmp_path)
        monkeypatch.setenv("VOMS_TOKEN_SERVICE_URL", _SERVICE_URL)

        with app_client_factory() as (client, _):
            provider = client.app.state.x509_provider
            assert provider.uses_voms_service is True
            assert client.app.state.target_to_alias["ami"] == "x509"

        assert any(
            event == "voms_token_service_url_deprecated" for event, _ in warning_events
        )


class TestBootValidation:
    def test_uncovered_x509_backend_refuses_to_start(
        self,
        signing_key_env: None,
        vault_stub_env: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        _set_backends(
            monkeypatch,
            tmp_path,
            _X509_BACKENDS_YAML
            + (
                "  - name: panda\n"
                "    prefix: panda\n"
                "    url: http://panda-mcp.invalid/mcp\n"
                "    auth_type: x509\n"
                "    required_capability: read_data\n"
            ),
        )
        _set_identity_providers(monkeypatch, [_x509_entry(targets=["ami"])])

        with pytest.raises(RuntimeError, match="panda"), app_client_factory():
            pass  # pragma: no cover - boot must fail before yielding

    def test_entry_targeting_non_x509_backend_refuses_to_start(
        self,
        signing_key_env: None,
        vault_stub_env: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(
            monkeypatch, [_x509_entry(targets=["ami", "not-a-backend"])]
        )

        with pytest.raises(RuntimeError, match="not-a-backend"), app_client_factory():
            pass  # pragma: no cover - boot must fail before yielding

    def test_explicit_entry_without_signing_key_refuses_to_start(
        self,
        vault_stub_env: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """The aggregator injects broker-signed identity JWTs for x509
        targets and the redeem endpoint verifies them, so an explicit entry
        requires the signing key — fail-closed, mirroring the broker-issued/
        condor-token check. (Entry-less legacy deployments keep the
        pre-existing loud warning instead: the shipped backends.yaml has
        always declared an x509 backend, so refusing to boot would break
        existing keyless deployments that never call it.)"""
        monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(monkeypatch, [_x509_entry()])

        with (
            pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"),
            app_client_factory(),
        ):
            pass  # pragma: no cover - boot must fail before yielding

    def test_entry_less_legacy_mode_still_warns_instead_of_failing(
        self,
        warning_events: list[tuple[str, dict]],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)
        _set_backends(monkeypatch, tmp_path)

        with app_client_factory():
            pass

        assert any(
            event == "x509_backends_without_signing_key" for event, _ in warning_events
        )

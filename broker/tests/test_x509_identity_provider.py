"""Tests for the first-class x509 `identity_providers` entry.

x509 used to be the one credential source with no `identity_providers`
config of its own: the voms-token-service URL was a global env var
(`VOMS_TOKEN_SERVICE_URL`), the catalog alias a hardcoded "x509" string, and
the Identities row a synthetic entry. Normalizing it into an
`X509ProviderConfig` entry (type "x509") removes those special cases while
keeping the wire behavior — backend-side proxy redemption — unchanged.

**Breaking change**: `VOMS_TOKEN_SERVICE_URL` (and its `_AUDIENCE`/`_VOMS`/
`_VALID` companions) have been removed entirely, along with the synthesis
that once covered an entry-less `auth_type: x509` backend. Every such
backend now needs an explicit `identity_providers` entry, full stop — there
is no fallback.

Covered here:

* `_validate_x509_provider_targets` — the fail-closed boot check for drift
  between `auth_type: x509` backends and explicit entry targets, now
  UNIVERSAL (both directions, including the zero-entries case): a
  `auth_type: x509` backend with no covering entry refuses to boot the same
  as one covered by the wrong entry — same reasoning as issue #60's
  required_capability consolidation.
* Full-boot wiring — per-entry service_url/voms/valid/audience reaching
  VomsTokenServiceClient, multiple entries resolving to distinct providers,
  the service-mode signing-key requirement (fail-closed, mirroring the
  broker-issued/condor-token check), and the keyless-legacy-entry carve-out
  (warning, not error).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from test_broker_issued import _make_rsa_key, _private_pem

import af_mcp_broker.app as app_module
from af_mcp_broker.app import _validate_x509_provider_targets
from af_mcp_broker.config import (
    KeycloakBrokeredProviderConfig,
    X509ProviderConfig,
)
from af_mcp_broker.credentials import X509Provider

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_SERVICE_URL = "http://voms-token-service.af-mcp.svc:8080"

_X509_BACKENDS_YAML = (
    "services:\n"
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
# _validate_x509_provider_targets — fail-closed drift protection between
# `auth_type: x509` backends and explicit entry targets. Universal: there is
# no synthesized-entry escape hatch, so the zero-entries case is one more
# quadrant of the same check, not a separate "validates trivially" path.
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
        typo or a stale services.yaml — the aggregator would never inject an
        identity JWT for it and the redeem endpoint would reject its
        audience, so the entry silently does nothing. Refuse to boot."""
        cfgs = [X509ProviderConfig(alias="x509", targets=["ami", "rucio"])]

        with pytest.raises(RuntimeError, match="rucio"):
            _validate_x509_provider_targets(cfgs, {"ami"})

    def test_no_explicit_entries_and_x509_backends_refuses_to_start(self) -> None:
        """There is no synthesized fallback: an entry-less deployment with an
        auth_type: x509 backend refuses to boot naming it, exactly like a
        backend covered by the wrong entry."""
        with pytest.raises(RuntimeError, match="ami"):
            _validate_x509_provider_targets([], {"ami"})

    def test_no_explicit_entries_and_no_x509_backends_validates_nothing(self) -> None:
        _validate_x509_provider_targets([], set())  # must not raise

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
    services_file = tmp_path / "services.yaml"
    services_file.write_text(text)
    monkeypatch.setenv("SERVICES_FILE", str(services_file))


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
        """An entry without service_url selects the legacy mint path — under
        an operator-chosen alias."""
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

    def test_explicit_service_entry_without_signing_key_refuses_to_start(
        self,
        vault_stub_env: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """The aggregator injects broker-signed identity JWTs for x509
        targets and the redeem endpoint verifies them, and in service mode
        voms-token-service mint calls are authenticated the same way -- so a
        service-mode entry (``service_url`` set) requires the signing key —
        fail-closed, mirroring the broker-issued/condor-token check. (A
        keyless LEGACY entry — ``service_url`` None — keeps the pre-existing
        loud warning instead of failing; see the test below.)"""
        monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(monkeypatch, [_x509_entry()])

        with (
            pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"),
            app_client_factory(),
        ):
            pass  # pragma: no cover - boot must fail before yielding

    def test_no_explicit_entries_with_x509_backends_refuses_to_start(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """There is no synthesized fallback: an entry-less deployment with an
        ``auth_type: x509`` backend refuses to boot naming it -- an operator
        must declare an explicit entry, even a bare legacy one, for every
        such backend."""
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(monkeypatch, [])

        with pytest.raises(RuntimeError, match="ami"), app_client_factory():
            pass  # pragma: no cover - boot must fail before yielding

    def test_explicit_legacy_entry_without_signing_key_warns_instead_of_failing(
        self,
        warning_events: list[tuple[str, dict]],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """A keyless legacy entry (``service_url`` None) still boots -- it
        mints via the k8s-Job/local-dev path, which needs no broker-signed
        token -- with a loud warning that x509 backends can't be called over
        /mcp until the signing key is mounted."""
        monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(monkeypatch, [_x509_entry(service_url=None)])

        with app_client_factory():
            pass

        assert any(
            event == "x509_services_without_signing_key" for event, _ in warning_events
        )


# ---------------------------------------------------------------------------
# Per-target provider resolution on the /v1 x509 surfaces: with multiple
# entries, the unlock and redeem endpoints must use the provider registered
# for the *requested* target, not a single app-wide default.
# ---------------------------------------------------------------------------


_TWO_ENTRY_BACKENDS_YAML = _X509_BACKENDS_YAML + (
    "  - name: dune-mcp\n"
    "    prefix: dune\n"
    "    url: http://dune-mcp.invalid/mcp\n"
    "    auth_type: x509\n"
    "    required_capability: read_data\n"
)


class TestPerTargetResolution:
    @pytest.fixture
    def two_entry_app(
        self,
        signing_key_env: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ):
        """Boot with two legacy-mode x509 entries (no Vault needed at boot),
        then flip the SECOND entry's provider into service mode with fakes —
        the first stays legacy, so any endpoint that wrongly falls back to
        the default provider takes the wrong mint/redeem path."""
        import asyncio

        from test_x509_service_mode import FakeVomsClient, FakeX509Store

        _set_backends(monkeypatch, tmp_path, _TWO_ENTRY_BACKENDS_YAML)
        _set_identity_providers(
            monkeypatch,
            [
                _x509_entry(service_url=None),
                _x509_entry(alias="x509-dune", targets=["dune-mcp"], service_url=None),
            ],
        )
        with app_client_factory() as (client, state):
            registry = client.app.state.credential_registry
            dune_provider = asyncio.run(registry.resolve("dune-mcp"))
            store = FakeX509Store()
            dune_provider._vault_store = store
            dune_provider._voms_client = FakeVomsClient()
            assert dune_provider.uses_voms_service is True
            # The default provider (first x509 target, "ami") stays legacy.
            assert client.app.state.x509_provider.uses_voms_service is False
            yield client, store, state

    def test_redeem_resolves_the_target_entry_provider(self, two_entry_app) -> None:
        """Redeeming aud=dune-mcp must consult the dune entry's Vault store,
        not the default (legacy) provider's tmpfs path."""
        import asyncio
        import time as _time

        from pydantic import SecretStr
        from test_x509_service_mode import _PEM

        client, store, _state = two_entry_app
        subject = "sub-abc"
        asyncio.run(
            store.store_link(
                subject,
                passphrase=SecretStr("stored"),
                unixname="tuser",
                uid=1000,
                gid=1000,
            )
        )
        asyncio.run(
            store.store_proxy(
                subject,
                pem=_PEM,
                dn="/DC=ch/DC=cern/CN=Test User",
                voms_attributes=["/dune"],
                not_after=_time.time() + 3600.0,
            )
        )
        token, _ = client.app.state.broker_token_issuer.mint(subject, "dune-mcp")

        resp = client.post(
            "/v1/credentials/x509/redeem",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["pem"] == _PEM

    def test_unlock_resolves_the_target_entry_provider(self, two_entry_app) -> None:
        """POST /v1/x509/proxy with an explicit target mints via that
        target's entry (the dune fakes), storing the link in its store."""
        client, store, state = two_entry_app

        resp = client.post(
            "/v1/x509/proxy",
            json={"passphrase": "hunter2", "target": "dune-mcp"},
        )

        assert resp.status_code == 201, resp.text
        subject = state["principal"].subject
        assert subject in store.records

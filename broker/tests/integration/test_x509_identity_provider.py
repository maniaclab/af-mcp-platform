"""Tests for the first-class x509 `identity_providers` entry.

x509 is an `identity_providers` entry (an `X509ProviderConfig`, type
"x509") like every other credential source: the voms-token-service URL, the
catalog alias and the Identities row all come from that entry, not from a
global env var (`VOMS_TOKEN_SERVICE_URL`), a hardcoded "x509" string or a
synthetic row. The wire behavior — backend-side proxy redemption — is
independent of that.

Every `auth_type: x509` backend needs an explicit `identity_providers`
entry carrying the voms-token-service `service_url`, full stop — there is no
fallback.

Covered here:

* `validate_x509_provider_targets` — the fail-closed boot check for drift
  between `auth_type: x509` backends and explicit entry targets, now
  UNIVERSAL (both directions, including the zero-entries case): a
  `auth_type: x509` backend with no covering entry refuses to boot the same
  as one covered by the wrong entry — same reasoning as issue #60's
  required_permission consolidation.
* Full-boot wiring — per-entry service_url/voms/valid/audience reaching
  VomsTokenServiceClient, multiple entries resolving to distinct providers,
  and the signing-key requirement (fail-closed, mirroring the
  broker-issued/condor-token check).
"""

from __future__ import annotations

import asyncio
import json
import time as _time
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr
from x509_fakes import PEM as _PEM
from x509_fakes import FakeVomsClient, FakeX509Store

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
    "    required_permission: read_data\n"
)


def _x509_entry(**overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "x509",
        "voms": "atlas",
        "alias": "x509",
        "display_name": "Grid certificate (x509)",
        "enables": "VOMS proxy minting",
        "targets": ["ami"],
        "service_url": _SERVICE_URL,
    }
    entry.update(overrides)
    return entry


# ---------------------------------------------------------------------------
# Full-boot wiring
# ---------------------------------------------------------------------------


def _set_backends(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str = _X509_BACKENDS_YAML
) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(text)
    monkeypatch.setenv("SERVICES_FILE", str(services_file))


def _set_identity_providers(
    monkeypatch: pytest.MonkeyPatch, entries: list[dict[str, Any]]
) -> None:

    monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(entries))


class TestBootWiring:
    def test_explicit_service_entry_wires_per_entry_settings(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """The entry's service_url/voms/valid/audience — not any global
        settings — reach VomsTokenServiceClient."""
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(
            monkeypatch,
            [_x509_entry(voms="dune", valid="24:00", audience="voms-dev")],
        )

        with app_client_factory() as (client, _):
            provider = client.app.state.broker.x509_provider
            assert isinstance(provider, X509Provider)
            voms_client = provider._voms_client
            assert voms_client._mint_endpoint == f"{_SERVICE_URL}/v1/mint"
            assert voms_client._voms == "dune"
            assert voms_client._valid == "24:00"
            assert voms_client._audience == "voms-dev"
            # The catalog join uses the real entry alias.
            assert client.app.state.broker.target_to_alias["ami"] == "x509"

    def test_explicit_entry_registers_targets_under_its_alias(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """An entry registers its targets under an operator-chosen alias."""
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(monkeypatch, [_x509_entry(alias="grid-cert")])

        with app_client_factory() as (client, _):
            provider = client.app.state.broker.x509_provider
            assert isinstance(provider, X509Provider)
            assert client.app.state.broker.target_to_alias["ami"] == "grid-cert"
            assert "grid-cert" in client.app.state.broker.identity_providers

    def test_multiple_entries_resolve_to_distinct_providers(
        self,
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
                "    required_permission: read_data\n"
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
            registry = client.app.state.broker.credential_registry

            ami_provider = asyncio.run(registry.resolve("ami"))
            dune_provider = asyncio.run(registry.resolve("dune-mcp"))
            assert ami_provider is not dune_provider
            assert ami_provider._voms_client._voms == "atlas"
            assert dune_provider._voms_client._voms == "dune"
            # IDENTITY_PROVIDERS was overridden with just the two x509
            # entries, so the join contains exactly their targets.
            assert client.app.state.broker.target_to_alias == {
                "ami": "x509",
                "dune-mcp": "x509-dune",
            }


class TestBootValidation:
    def test_uncovered_x509_backend_refuses_to_start(
        self,
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
                "    required_permission: read_data\n"
            ),
        )
        _set_identity_providers(monkeypatch, [_x509_entry(targets=["ami"])])

        with pytest.raises(RuntimeError, match="panda"), app_client_factory():
            pass  # pragma: no cover - boot must fail before yielding

    def test_entry_targeting_non_x509_backend_refuses_to_start(
        self,
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
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """The aggregator injects broker-signed identity JWTs for x509
        targets and the redeem endpoint verifies them, and in service mode
        voms-token-service mint calls are authenticated the same way -- so an
        x509 entry requires the signing key — fail-closed, mirroring the
        broker-issued/condor-token check."""
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
        must declare an explicit entry for every such backend."""
        _set_backends(monkeypatch, tmp_path)
        _set_identity_providers(monkeypatch, [])

        with pytest.raises(RuntimeError, match="ami"), app_client_factory():
            pass  # pragma: no cover - boot must fail before yielding


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
    "    required_permission: read_data\n"
)


class TestPerTargetResolution:
    @pytest.fixture
    def two_entry_app(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ):
        """Boot with two x509 entries, then give the SECOND entry's provider
        its own fakes — the first keeps the default ones, so any endpoint that
        wrongly falls back to the default provider consults the wrong store
        and voms client."""

        _set_backends(monkeypatch, tmp_path, _TWO_ENTRY_BACKENDS_YAML)
        _set_identity_providers(
            monkeypatch,
            [
                _x509_entry(),
                _x509_entry(alias="x509-dune", targets=["dune-mcp"]),
            ],
        )
        with app_client_factory() as (client, state):
            registry = client.app.state.broker.credential_registry
            dune_provider = asyncio.run(registry.resolve("dune-mcp"))
            store = FakeX509Store()
            dune_provider._vault_store = store
            dune_provider._voms_client = FakeVomsClient()
            # The default provider (first x509 target, "ami") keeps its own.
            assert client.app.state.broker.x509_provider is not dune_provider
            yield client, store, state

    def test_redeem_resolves_the_target_entry_provider(self, two_entry_app) -> None:
        """Redeeming aud=dune-mcp must consult the dune entry's Vault store,
        not the default provider's."""

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
        token, _ = client.app.state.broker.broker_token_issuer.mint(subject, "dune-mcp")

        resp = client.post(
            "/v1/credentials/x509/redeem",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["pem"] == _PEM

    def test_proxy_mint_notifies_listing_caches_for_that_entry_only(
        self, two_entry_app
    ) -> None:
        client, _store, state = two_entry_app
        linked: list[tuple[str, str]] = []
        client.app.state.broker.credential_cache._on_link = lambda subject, target: (
            linked.append((subject, target))
        )

        resp = client.post(
            "/v1/x509/proxy",
            json={"passphrase": "hunter2", "target": "dune-mcp"},
        )

        assert resp.status_code == 201, resp.text
        assert linked == [(state["principal"].subject, "dune-mcp")]

    def test_proxy_delete_invalidates_listing_caches_via_revoke(
        self, two_entry_app
    ) -> None:
        client, _store, state = two_entry_app
        revoked: list[tuple[str, str]] = []
        client.app.state.broker.credential_cache._on_revoke = lambda subject, target: (
            revoked.append((subject, target))
        )

        resp = client.delete("/v1/x509/proxy", params={"target": "dune-mcp"})

        assert resp.status_code == 204, resp.text
        assert revoked == [(state["principal"].subject, "dune-mcp")]

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

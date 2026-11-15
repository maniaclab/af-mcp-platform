"""Tests for the backend-facing x509 proxy redeem endpoint (issue #112).

POST /v1/credentials/x509/redeem is authenticated by an AF Broker Identity
Token (NOT a Keycloak token): the broker verifies its own signature, requires
``aud`` to be a configured x509 target, and returns the caller's Vault-stored
proxy PEM. This is the "backend calls back" wire format — the one deliberate
exception to the portal-facing "the PEM never leaves the broker" rule, for
authenticated backend targets only.

This module covers the audience/authentication gates and the credmon top
token; the Vault-backed serve/renew behavior is in test_x509_redeem_vault.py.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING

import pytest
from pydantic import SecretStr
from x509_fakes import FakeVomsClient, FakeX509Store

from af_mcp_broker.identity import keycloak_dependency

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fastapi.testclient import TestClient

_REDEEM = "/v1/credentials/x509/redeem"

# ami is an x509 backend (auth_type: x509): that single flag drives portal
# minting (X509Provider registration), aggregator identity-JWT injection, and
# this endpoint's audience gate. An explicit identity_providers entry
# covering it is required too (conftest's app_client_factory default
# supplies one; the broker refuses to start otherwise).
_BACKENDS_YAML = (
    "services:\n"
    "  - name: ami\n"
    "    prefix: ami\n"
    "    url: http://ami-mcp.invalid/mcp\n"
    "    auth_type: x509\n"
    "    required_permission: read_data\n"
)

# An x509 service whose registry name and token audience diverge (issue #257):
# the broker mints aud=ami-mcp (effective_audience) for the target ami_service.
_DIVERGENT_YAML = (
    "services:\n"
    "  - name: ami_service\n"
    "    prefix: ami\n"
    "    url: http://ami-mcp.invalid/mcp\n"
    "    auth_type: x509\n"
    "    audience: ami-mcp\n"
    "    required_permission: read_data\n"
)

_PEM = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"


@pytest.fixture
def x509_redeem_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Point the app at an x509 service for the redeem tests."""

    def _apply(
        services_yaml: str = _BACKENDS_YAML,
        x509_targets: list[str] | None = None,
    ) -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(services_yaml)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        # When a test uses a service whose name differs from conftest's default
        # x509 target ("ami"), it must also point the x509 identity_providers
        # entry at the new name, or the broker refuses to boot
        # (validate_x509_provider_targets).
        if x509_targets is not None:
            monkeypatch.setenv(
                "IDENTITY_PROVIDERS",
                json.dumps(
                    [
                        {
                            "type": "x509",
                            "alias": "x509",
                            "display_name": "Grid certificate (x509)",
                            "targets": x509_targets,
                            "service_url": "http://voms-token-service.invalid:8000",
                        }
                    ]
                ),
            )

    return _apply


def _seed_vault_proxy(client: TestClient, *, subject: str) -> None:
    """Swap the app's X509Provider onto in-memory fakes and store a valid proxy for *subject*."""
    store = FakeX509Store()
    provider = client.app.state.broker.x509_provider
    provider._vault_store = store
    provider._voms_client = FakeVomsClient()
    asyncio.run(
        store.store_link(
            subject, passphrase=SecretStr("stored"), unixname="tuser", uid=1, gid=1
        )
    )
    asyncio.run(
        store.store_proxy(
            subject,
            pem=_PEM,
            dn="/DC=ch/DC=cern/CN=Test User",
            voms_attributes=["/atlas/Role=NULL", "/atlas"],
            not_after=time.time() + 3600.0,
        )
    )


def _mint(
    client: TestClient, *, subject: str = "sub-abc", audience: str = "ami"
) -> str:
    token, _ = client.app.state.broker.broker_token_issuer.mint(
        subject, audience, uid=1000, gid=1000, unixname="tuser"
    )
    return str(token)


class TestRedeemAuth:
    def test_missing_authorization_is_401(
        self, x509_redeem_env, app_client_factory
    ) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            resp = client.post(_REDEEM, json={})
        assert resp.status_code == 401

    def test_garbage_token_is_401(self, x509_redeem_env, app_client_factory) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": "Bearer nonsense"}
            )
        assert resp.status_code == 401

    def test_non_x509_audience_is_403(
        self, x509_redeem_env, app_client_factory
    ) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            token = _mint(client, audience="condor-token-service")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 403

    def test_redeem_never_calls_keycloak(
        self, x509_redeem_env, app_client_factory
    ) -> None:
        """Regression: /credentials/x509/redeem must authenticate purely via
        BrokerTokenIssuer.verify() (its own RS256 signature check), never via
        keycloak_dependency.

        Every other test in this module (like every route test in this
        codebase) runs through app_client_factory's blanket
        ``app.dependency_overrides[keycloak_dependency] = ...``, which would
        silently mask this endpoint being wired behind keycloak_dependency
        the way the rest of credentials.router's routes correctly are (see
        api/router.py: redeem lives on credentials.backend_router precisely
        so it never gets pulled in there). This test removes that override
        for this one call so a regression -- redeem ending up back on a
        router gated by require_not_in_maintenance, whose admin-bypass check
        depends on keycloak_dependency -- fails loudly: OIDC_ISSUER here
        points at an unreachable host, so an actual Keycloak round trip
        can only ever error, never return 200.
        """

        x509_redeem_env()
        with app_client_factory() as (client, _):
            client.app.dependency_overrides.pop(keycloak_dependency, None)
            _seed_vault_proxy(client, subject="sub-abc")
            token = _mint(client, audience="ami")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200
        assert "FAKE" in resp.json()["pem"]

    def test_redeem_maps_audience_to_target_when_name_differs(
        self, x509_redeem_env, app_client_factory
    ) -> None:
        """issue #257 regression: for an x509 service whose name and audience
        diverge (name=ami_service, audience=ami-mcp), the broker mints tokens
        with aud=ami-mcp. The redeem endpoint must map that audience back to
        the x509 target ('ami_service') and serve the proxy stored for it --
        NOT 403 because 'ami-mcp' isn't a target name. This is the redeem-side
        of the name/audience split; before the fix it 401'd every proxy-needing
        x509 call in prod on 2026-08-27."""
        x509_redeem_env(services_yaml=_DIVERGENT_YAML, x509_targets=["ami_service"])
        with app_client_factory() as (client, _):
            _seed_vault_proxy(client, subject="sub-abc")
            token = _mint(client, audience="ami-mcp")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200
        assert "FAKE" in resp.json()["pem"]


def _enable_credmon(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Turn on the credmon integration with a valid htcondor-api config. The sync loop sleeps one poll interval (60s) before its first tick, so booting the app in a test starts no background sync against the network.

    The credmon storer requires a Vault client at boot (it enumerates linked
    users from the Vault-backed stores); app_client_factory already supplies
    the stubbed Vault connection that forces one into existence.
    """

    token_file = tmp_path / "credmon-htcondor-api-token"
    token_file.write_text("storer-idtoken\n")
    monkeypatch.setenv("CREDMON_ENABLED", "true")
    monkeypatch.setenv("CREDMON_HTCONDOR_API_URL", "https://htcondor-api.invalid")
    monkeypatch.setenv("CREDMON_HTCONDOR_API_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("CREDMON_USER_DOMAIN", "af.example.org")


class TestCredmonTopToken:
    """A credmon top token (aud ``af-credmon/x509``) redeems the caller's x509
    identity from the first configured x509 target -- see
    test_krb5_redeem.py's TestCredmonTopToken for the krb5 counterpart."""

    def test_credmon_audience_redeems_default_x509_target_when_enabled(
        self,
        x509_redeem_env,
        app_client_factory,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        x509_redeem_env()
        _enable_credmon(monkeypatch, tmp_path)
        with app_client_factory() as (client, _):
            _seed_vault_proxy(client, subject="sub-abc")
            token = _mint(client, audience="af-credmon/x509")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        assert "FAKE" in resp.json()["pem"]

    def test_credmon_audience_is_403_when_disabled(
        self, x509_redeem_env, app_client_factory
    ) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            _seed_vault_proxy(client, subject="sub-abc")
            token = _mint(client, audience="af-credmon/x509")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 403

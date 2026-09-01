"""Tests for the backend-facing x509 proxy redeem endpoint (issue #112).

POST /v1/credentials/x509/redeem is authenticated by an AF Broker Identity
Token (NOT a Keycloak token): the broker verifies its own signature, requires
``aud`` to be a configured x509 target, and returns the caller's cached
proxy PEM. This is the "backend calls back" wire format — the one deliberate
exception to the portal-facing "the PEM never leaves the broker" rule, for
authenticated backend targets only.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING

import pytest
from test_broker_issued import _make_rsa_key, _private_pem

from af_mcp_broker.credentials.cache import ProxyMeta

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fastapi.testclient import TestClient

_REDEEM = "/v1/credentials/x509/redeem"
_STATUS = "/v1/x509/proxy/status"

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


@pytest.fixture
def x509_redeem_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Configure a broker-issued provider for the x509 target 'ami' with a real signing key."""

    def _apply(
        services_yaml: str = _BACKENDS_YAML,
        x509_targets: list[str] | None = None,
    ) -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(services_yaml)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
        # When a test uses a service whose name differs from conftest's default
        # x509 target ("ami"), it must also point the x509 identity_providers
        # entry at the new name, or the broker refuses to boot
        # (_validate_x509_provider_targets).
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
                        }
                    ]
                ),
            )
        key_file = tmp_path / "signing-key.pem"
        key_file.write_bytes(_private_pem(_make_rsa_key()))
        monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))

    return _apply


def _seed_proxy(
    client: TestClient,
    tmp_path: Path,
    *,
    subject: str,
    remaining: float = 3600.0,
    target: str = "ami",
) -> Path:
    """Store a fake proxy for *subject* against x509 *target* in the cache."""
    proxy_file = tmp_path / f"proxy-{subject}.pem"
    proxy_file.write_text("FAKE PROXY PEM\n")
    not_after = time.time() + remaining
    meta = ProxyMeta(
        dn="/DC=ch/DC=cern/CN=Test User",
        voms_attributes=["/atlas/Role=NULL", "/atlas"],
        not_after=not_after,
        proxy_path=str(proxy_file),
    )
    asyncio.run(
        client.app.state.credential_cache.put(
            subject,
            target,
            {"proxy_handle": subject, "proxy_path": str(proxy_file)},
            expires_at=not_after,
            proxy_meta=meta,
        )
    )
    return proxy_file


def _mint(
    client: TestClient, *, subject: str = "sub-abc", audience: str = "ami"
) -> str:
    token, _ = client.app.state.broker_token_issuer.mint(
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
        self, x509_redeem_env, app_client_factory, tmp_path: Path
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
        from af_mcp_broker.identity import keycloak_dependency

        x509_redeem_env()
        with app_client_factory() as (client, _):
            client.app.dependency_overrides.pop(keycloak_dependency, None)
            _seed_proxy(client, tmp_path, subject="sub-abc", target="ami")
            token = _mint(client, audience="ami")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200
        assert "FAKE PROXY PEM" in resp.json()["pem"]

    def test_redeem_maps_audience_to_target_when_name_differs(
        self, x509_redeem_env, app_client_factory, tmp_path: Path
    ) -> None:
        """issue #257 regression: for an x509 service whose name and audience
        diverge (name=ami_service, audience=ami-mcp), the broker mints tokens
        with aud=ami-mcp. The redeem endpoint must map that audience back to
        the x509 target ('ami_service') and serve the proxy cached under it --
        NOT 403 because 'ami-mcp' isn't a target name. This is the redeem-side
        of the name/audience split; before the fix it 401'd every proxy-needing
        x509 call in prod on 2026-08-27."""
        x509_redeem_env(services_yaml=_DIVERGENT_YAML, x509_targets=["ami_service"])
        with app_client_factory() as (client, _):
            _seed_proxy(client, tmp_path, subject="sub-abc", target="ami_service")
            token = _mint(client, audience="ami-mcp")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200
        assert "FAKE PROXY PEM" in resp.json()["pem"]


class TestRedeem:
    def test_no_cached_proxy_is_404_with_actionable_detail(
        self, x509_redeem_env, app_client_factory
    ) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 404
        assert "portal" in resp.json()["detail"]

    def test_expired_proxy_is_404(
        self, x509_redeem_env, app_client_factory, tmp_path: Path
    ) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            _seed_proxy(client, tmp_path, subject="sub-abc", remaining=-10.0)
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 404

    def test_missing_proxy_file_is_404(
        self, x509_redeem_env, app_client_factory, tmp_path: Path
    ) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            proxy_file = _seed_proxy(client, tmp_path, subject="sub-abc")
            proxy_file.unlink()
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 404

    def test_happy_path_returns_pem_and_metadata(
        self, x509_redeem_env, app_client_factory, tmp_path: Path
    ) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            _seed_proxy(client, tmp_path, subject="sub-abc")
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["pem"] == "FAKE PROXY PEM\n"
        assert body["dn"] == "/DC=ch/DC=cern/CN=Test User"
        assert body["voms_attributes"] == ["/atlas/Role=NULL", "/atlas"]
        assert 3500 < body["remaining_seconds"] <= 3600
        assert body["expires_at"]

    def test_proxy_is_per_subject(
        self, x509_redeem_env, app_client_factory, tmp_path: Path
    ) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            _seed_proxy(client, tmp_path, subject="someone-else")
            token = _mint(client, subject="sub-abc")
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 404

    def test_redeem_writes_audit_record(
        self, x509_redeem_env, app_client_factory, tmp_path: Path, capsys
    ) -> None:
        x509_redeem_env()
        with app_client_factory() as (client, _):
            _seed_proxy(client, tmp_path, subject="sub-abc")
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200
        audit_lines = [
            json.loads(line)
            for line in capsys.readouterr().out.splitlines()
            if '"event": "audit"' in line
        ]
        releases = [
            rec for rec in audit_lines if rec.get("action") == "x509_proxy_release"
        ]
        assert len(releases) == 1
        assert releases[0]["principal_sub"] == "sub-abc"
        assert releases[0]["target"] == "ami"
        assert releases[0]["outcome"] == "success"
        # Legacy ProxyMeta carries no nickname (see test_legacy_path_has_no_nickname),
        # so the release audit record's nickname (issue #199) stays null here.
        assert releases[0]["nickname"] is None

    def test_legacy_path_has_no_nickname(
        self, x509_redeem_env, app_client_factory, tmp_path: Path
    ) -> None:
        """Known gap (issue #191): the legacy k8s-Job/local-dev mint path
        stores proxy metadata in ``ProxyMeta`` (cache.py), which carries no
        nickname field — plumbing one through would mean broadening that
        cache schema, which is out of scope here. Vault-backed
        (voms-token-service) mode does carry it; see test_x509_redeem_vault.py."""
        x509_redeem_env()
        with app_client_factory() as (client, _):
            _seed_proxy(client, tmp_path, subject="sub-abc")
            token = _mint(client)
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["nickname"] is None

    def test_status_legacy_path_has_no_nickname(
        self, x509_redeem_env, app_client_factory, tmp_path: Path
    ) -> None:
        """Same known gap as above, for GET /v1/x509/proxy/status (the
        endpoint the portal polls): the legacy ProxyMeta cache carries no
        nickname field."""
        x509_redeem_env()
        with app_client_factory() as (client, _):
            _seed_proxy(client, tmp_path, subject="sub-abc")
            resp = client.get(_STATUS)
        assert resp.status_code == 200, resp.text
        assert resp.json()["nickname"] is None


class TestKeylessBoot:
    def test_x509_backend_without_signing_key_boots_and_503s_redeem(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path, app_client_factory
    ) -> None:
        """Keyless boot stays possible with an explicit LEGACY entry
        (service_url omitted -- an entry is still required, there is no
        synthesized fallback), but the redeem endpoint answers 503 until the
        signing key is mounted -- enforcement at point of use, with a loud
        startup warning (see app.py's x509_services_without_signing_key)."""
        services_file = tmp_path / "services.yaml"
        services_file.write_text(_BACKENDS_YAML)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv(
            "IDENTITY_PROVIDERS",
            json.dumps([{"type": "x509", "alias": "x509", "targets": ["ami"]}]),
        )
        monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)

        with app_client_factory() as (client, _):
            resp = client.post(
                _REDEEM, json={}, headers={"Authorization": "Bearer whatever"}
            )
        assert resp.status_code == 503

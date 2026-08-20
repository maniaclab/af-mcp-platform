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

# ami is an x509 backend (auth_type: x509): that single flag drives portal
# minting (X509Provider registration), aggregator identity-JWT injection, and
# this endpoint's audience gate. An explicit identity_providers entry
# covering it is required too (conftest's app_client_factory default
# supplies one; the broker refuses to start otherwise).
_BACKENDS_YAML = (
    "backends:\n"
    "  - name: ami\n"
    "    prefix: ami\n"
    "    url: http://ami-mcp.invalid/mcp\n"
    "    auth_type: x509\n"
    "    required_capability: read_data\n"
)


@pytest.fixture
def x509_redeem_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Configure a broker-issued provider for the x509 target 'ami' with a real signing key."""

    def _apply() -> None:
        backends_file = tmp_path / "backends.yaml"
        backends_file.write_text(_BACKENDS_YAML)
        monkeypatch.setenv("BACKENDS_FILE", str(backends_file))
        monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
        key_file = tmp_path / "signing-key.pem"
        key_file.write_bytes(_private_pem(_make_rsa_key()))
        monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))

    return _apply


def _seed_proxy(
    client: TestClient, tmp_path: Path, *, subject: str, remaining: float = 3600.0
) -> Path:
    """Store a fake proxy for *subject* against target 'ami' in the cache."""
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
            "ami",
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


class TestKeylessBoot:
    def test_x509_backend_without_signing_key_boots_and_503s_redeem(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path, app_client_factory
    ) -> None:
        """Keyless boot stays possible with an explicit LEGACY entry
        (service_url omitted -- an entry is still required, there is no
        synthesized fallback), but the redeem endpoint answers 503 until the
        signing key is mounted -- enforcement at point of use, with a loud
        startup warning (see app.py's x509_backends_without_signing_key)."""
        backends_file = tmp_path / "backends.yaml"
        backends_file.write_text(_BACKENDS_YAML)
        monkeypatch.setenv("BACKENDS_FILE", str(backends_file))
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

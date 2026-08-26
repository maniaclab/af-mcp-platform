"""Tests for the redeem endpoint's Vault-backed path (issue #112 follow-up).

When X509Provider runs in voms-token-service mode, POST
/v1/credentials/x509/redeem consults the Vault store instead of the
in-memory CredentialCache: a valid stored proxy is served; an expired one
with a stored passphrase is re-minted hands-free, stored, and served; a
bad-passphrase failure on that re-mint unlinks the identity and answers 404
telling the user to re-link at the portal; an infra failure answers 502 and
keeps the link. Feature off falls back to the existing CredentialCache
behavior (covered by test_x509_redeem.py, which keeps passing untouched).

Also covers the unlock endpoint's (POST /v1/x509/proxy) error mapping in
service mode: 400 for a bad passphrase, 502 for a service infra failure.

Service mode is activated by injecting the same fakes test_x509_service_mode
uses into the app's already-booted X509Provider — the endpoint keys off
``provider.uses_voms_service``, so no Vault or voms-token-service deployment
is needed.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import TYPE_CHECKING

import pytest
from pydantic import SecretStr
from test_broker_issued import _make_rsa_key, _private_pem
from test_x509_redeem import _BACKENDS_YAML
from test_x509_service_mode import FakeVomsClient, FakeX509Store

from af_mcp_broker.credentials.voms_service import (
    VomsServiceBadPassphraseError,
    VomsServiceMintError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from fastapi.testclient import TestClient

_REDEEM = "/v1/credentials/x509/redeem"
_UNLOCK = "/v1/x509/proxy"

_PEM = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
_DN = "/DC=ch/DC=cern/CN=Test User"
_VOMS_ATTRS = ["/atlas/Role=NULL", "/atlas"]


@pytest.fixture
def service_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, app_client_factory
) -> Iterator[tuple[TestClient, FakeX509Store, FakeVomsClient, dict]]:
    """Boot the real app with an x509 backend + signing key, then flip its X509Provider into service mode with fakes."""
    services_file = tmp_path / "services.yaml"
    services_file.write_text(_BACKENDS_YAML)
    monkeypatch.setenv("SERVICES_FILE", str(services_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(_private_pem(_make_rsa_key()))
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
    # Audit to a file (not stdout): the app boots inside this fixture, and a
    # stdout handle grabbed then does not reliably land in a test's capsys.
    monkeypatch.setenv("AUDIT_LOG_FILE", str(tmp_path / "audit.log"))

    with app_client_factory() as (client, state):
        store = FakeX509Store()
        voms_client = FakeVomsClient()
        provider = client.app.state.x509_provider
        provider._vault_store = store
        provider._voms_client = voms_client
        assert provider.uses_voms_service is True
        yield client, store, voms_client, {**state, "audit_log": tmp_path / "audit.log"}


def _mint_token(
    client: TestClient, *, subject: str = "sub-abc", audience: str = "ami"
) -> str:
    token, _ = client.app.state.broker_token_issuer.mint(
        subject, audience, uid=1000, gid=1000, unixname="tuser"
    )
    return str(token)


def _redeem(client: TestClient, token: str):
    return client.post(_REDEEM, json={}, headers={"Authorization": f"Bearer {token}"})


async def _seed_link(store: FakeX509Store, subject: str = "sub-abc") -> None:
    await store.store_link(
        subject,
        passphrase=SecretStr("stored-passphrase"),
        unixname="tuser",
        uid=1000,
        gid=1000,
    )


async def _seed_proxy(
    store: FakeX509Store,
    subject: str = "sub-abc",
    *,
    remaining: float = 3600.0,
    nickname: str | None = None,
) -> float:
    not_after = time.time() + remaining
    await store.store_proxy(
        subject,
        pem=_PEM,
        dn=_DN,
        voms_attributes=_VOMS_ATTRS,
        not_after=not_after,
        nickname=nickname,
    )
    return not_after


def _release_audit_records(state: dict) -> list[dict]:
    audit_log: Path = state["audit_log"]
    if not audit_log.exists():
        return []
    return [
        rec
        for rec in (
            json.loads(line)
            for line in audit_log.read_text().splitlines()
            if '"event": "audit"' in line
        )
        if rec.get("action") == "x509_proxy_release"
    ]


class TestRedeemVaultServe:
    async def test_valid_vault_proxy_is_served(self, service_app) -> None:
        client, store, voms_client, state = service_app
        await _seed_link(store)
        await _seed_proxy(store)

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["pem"] == _PEM
        assert body["dn"] == _DN
        assert body["voms_attributes"] == _VOMS_ATTRS
        assert 3500 < body["remaining_seconds"] <= 3600
        assert voms_client.calls == []  # no renewal needed

        releases = _release_audit_records(state)
        assert len(releases) == 1
        assert releases[0]["outcome"] == "success"
        assert releases[0]["principal_sub"] == "sub-abc"
        assert releases[0]["target"] == "ami"

    async def test_stored_nickname_is_included_in_the_response(
        self, service_app
    ) -> None:
        """issue #191: the VOMS nickname (the redeeming backend's source of
        the CERN/Rucio account, which AF unixnames don't match) rides
        alongside the proxy PEM."""
        client, store, _, _ = service_app
        await _seed_link(store)
        await _seed_proxy(store, nickname="jdoe")

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 200, resp.text
        assert resp.json()["nickname"] == "jdoe"

    async def test_stored_nickname_is_recorded_in_the_release_audit(
        self, service_app
    ) -> None:
        """issue #199: the resolved nickname is the grid identity the released
        proxy authenticates as -- an operator grepping the audit trail during
        an incident must be able to see which CERN/Rucio account a credential
        was actually usable as, not just the AF principal."""
        client, store, _, state = service_app
        await _seed_link(store)
        await _seed_proxy(store, nickname="jdoe")

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 200, resp.text
        releases = _release_audit_records(state)
        assert len(releases) == 1
        assert releases[0]["outcome"] == "success"
        assert releases[0]["nickname"] == "jdoe"

    async def test_missing_nickname_records_none_in_the_release_audit(
        self, service_app
    ) -> None:
        """A record stored before voms-token-service shipped nicknames still
        releases successfully, with the audit nickname simply absent."""
        client, store, _, state = service_app
        await _seed_link(store)
        await _seed_proxy(store)

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 200, resp.text
        releases = _release_audit_records(state)
        assert len(releases) == 1
        assert releases[0]["nickname"] is None

    async def test_missing_nickname_serves_as_none(self, service_app) -> None:
        """A record stored before voms-token-service shipped nicknames must
        still redeem successfully, with nickname simply absent."""
        client, store, _, _ = service_app
        await _seed_link(store)
        await _seed_proxy(store)

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 200, resp.text
        assert resp.json()["nickname"] is None

    def test_vault_mode_ignores_the_in_memory_cache(
        self, service_app, tmp_path: Path
    ) -> None:
        """A leftover tmpfs-cached proxy from before the feature flip must
        not be served once Vault is authoritative."""
        from test_x509_redeem import _seed_proxy as seed_legacy_cache_proxy

        client, _, _, _ = service_app
        seed_legacy_cache_proxy(client, tmp_path, subject="sub-abc")

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 404

    async def test_no_link_is_the_existing_404(self, service_app) -> None:
        client, _, _, _ = service_app

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 404
        assert "portal" in resp.json()["detail"]


class TestRedeemHandsFreeRenewal:
    async def test_expired_proxy_with_link_renews_and_serves(self, service_app) -> None:
        client, store, voms_client, state = service_app
        await _seed_link(store)
        await _seed_proxy(store, remaining=-10.0)

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 200, resp.text
        assert resp.json()["pem"] == voms_client.outcome.pem
        assert len(voms_client.calls) == 1
        call = voms_client.calls[0]
        assert call["subject"] == "sub-abc"
        assert call["unixname"] == "tuser"
        assert call["passphrase"].get_secret_value() == "stored-passphrase"
        # The renewed proxy persisted for the next redeem.
        record = await store.get_proxy("sub-abc")
        assert record is not None

        releases = _release_audit_records(state)
        assert [rec["outcome"] for rec in releases] == ["success"]

    async def test_renewal_bad_passphrase_unlinks_and_404s_with_relink_hint(
        self, service_app
    ) -> None:
        client, store, _, state = service_app
        store_client = FakeVomsClient(VomsServiceBadPassphraseError())
        client.app.state.x509_provider._voms_client = store_client
        await _seed_link(store)

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 404
        assert "re-link" in resp.json()["detail"].lower()
        assert store.deleted == ["sub-abc"]

        releases = _release_audit_records(state)
        assert [rec["outcome"] for rec in releases] == ["error"]
        assert releases[0]["error"]

    async def test_renewal_infra_failure_is_502_and_keeps_the_link(
        self, service_app
    ) -> None:
        client, store, _, state = service_app
        client.app.state.x509_provider._voms_client = FakeVomsClient(
            VomsServiceMintError("service down")
        )
        await _seed_link(store)

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 502
        assert store.deleted == []
        assert await store.get_link("sub-abc") is not None

        releases = _release_audit_records(state)
        assert [rec["outcome"] for rec in releases] == ["error"]


class TestUnlockEndpointServiceMode:
    def test_bad_passphrase_is_400(self, service_app) -> None:
        client, _, _, _ = service_app
        client.app.state.x509_provider._voms_client = FakeVomsClient(
            VomsServiceBadPassphraseError()
        )

        resp = client.post(_UNLOCK, json={"passphrase": "wrong"})

        assert resp.status_code == 400

    def test_infra_failure_is_502(self, service_app) -> None:
        client, _, _, _ = service_app
        client.app.state.x509_provider._voms_client = FakeVomsClient(
            VomsServiceMintError("service down")
        )

        resp = client.post(_UNLOCK, json={"passphrase": "hunter2"})

        assert resp.status_code == 502

    def test_successful_unlock_links_and_returns_metadata(self, service_app) -> None:
        client, store, voms_client, _ = service_app

        resp = client.post(_UNLOCK, json={"passphrase": "hunter2"})

        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["dn"] == voms_client.outcome.dn
        assert body["remaining_seconds"] > 0
        # The link persisted: sub-abc is the app_client principal's subject.
        assert store.records["sub-abc"].passphrase is not None


# ---------------------------------------------------------------------------
# remember=false custody (issue: custody consent toggle)
# ---------------------------------------------------------------------------


async def _seed_unremembered_link(
    store: FakeX509Store, subject: str = "sub-abc"
) -> None:
    await store.store_link(
        subject,
        passphrase=None,
        unixname="tuser",
        uid=1000,
        gid=1000,
    )


class TestRedeemUntilExpiry:
    async def test_valid_proxy_without_passphrase_is_served(self, service_app) -> None:
        """remember=false custody: redemption works exactly like the
        remembered mode for as long as the proxy is valid."""
        client, store, voms_client, _ = service_app
        await _seed_unremembered_link(store)
        await _seed_proxy(store)

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 200, resp.text
        assert resp.json()["pem"] == _PEM
        assert voms_client.calls == []

    async def test_expired_proxy_without_passphrase_is_404_without_unlinking(
        self, service_app
    ) -> None:
        """The expiry transition: no stored passphrase means no hands-free
        renewal — the existing re-link-at-the-portal 404 surfaces, and the
        record is NOT deleted eagerly (unlinking stays a deliberate act)."""
        client, store, voms_client, _ = service_app
        await _seed_unremembered_link(store)
        await _seed_proxy(store, remaining=-10.0)

        resp = _redeem(client, _mint_token(client))

        assert resp.status_code == 404
        assert "portal" in resp.json()["detail"]
        assert voms_client.calls == []  # renewal never attempted
        assert store.deleted == []
        assert "sub-abc" in store.records


class TestUnlockEndpointCustodyConsent:
    def test_remember_false_stores_proxy_but_not_passphrase(self, service_app) -> None:
        client, store, _, _ = service_app

        resp = client.post(_UNLOCK, json={"passphrase": "hunter2", "remember": False})

        assert resp.status_code == 201, resp.text
        record = store.records["sub-abc"]
        assert record.passphrase is None
        assert record.proxy_pem is not None

    def test_remember_defaults_to_true_on_the_wire(self, service_app) -> None:
        """Omitting the field preserves the pre-toggle behavior exactly."""
        client, store, _, _ = service_app

        resp = client.post(_UNLOCK, json={"passphrase": "hunter2"})

        assert resp.status_code == 201, resp.text
        assert store.records["sub-abc"].passphrase is not None


# ---------------------------------------------------------------------------
# GET /v1/x509/proxy/status in service mode: Vault-authoritative
# ---------------------------------------------------------------------------

_STATUS = "/v1/x509/proxy/status"


class TestProxyStatusServiceMode:
    async def test_answers_from_vault_when_in_memory_cache_is_empty(
        self, service_app
    ) -> None:
        """The round-robin production symptom: only the replica that minted
        holds an in-memory ProxyMeta, so a replica with an empty cache used
        to answer cached=false while the proxy was alive and well in Vault.
        Service mode must answer from the store, same rule as
        /v1/identities' proxy_expires_at (#183) and the redeem path."""
        client, store, _, _ = service_app
        await _seed_link(store)
        not_after = await _seed_proxy(store)

        resp = client.get(_STATUS)

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["cached"] is True
        assert body["dn"] == _DN
        assert body["voms_attributes"] == _VOMS_ATTRS
        parsed = datetime.fromisoformat(body["expires_at"])
        assert parsed.timestamp() == pytest.approx(not_after, abs=1.0)
        assert 3500 < body["remaining_seconds"] <= 3600

    async def test_stored_nickname_is_included_in_the_response(
        self, service_app
    ) -> None:
        """issue #191: the portal surfaces the same VOMS nickname the
        redeem path already carries, so a user can visually confirm it was
        parsed correctly."""
        client, store, _, _ = service_app
        await _seed_link(store)
        await _seed_proxy(store, nickname="jdoe")

        resp = client.get(_STATUS)

        assert resp.status_code == 200, resp.text
        assert resp.json()["nickname"] == "jdoe"

    async def test_missing_nickname_serves_as_none(self, service_app) -> None:
        """A record stored before voms-token-service shipped nicknames must
        still report status successfully, with nickname simply absent."""
        client, store, _, _ = service_app
        await _seed_link(store)
        await _seed_proxy(store)

        resp = client.get(_STATUS)

        assert resp.status_code == 200, resp.text
        assert resp.json()["nickname"] is None

    def test_no_proxy_when_vault_holds_no_record(self, service_app) -> None:
        client, _, _, _ = service_app

        resp = client.get(_STATUS)

        assert resp.status_code == 200, resp.text
        assert resp.json()["cached"] is False

    async def test_expired_vault_proxy_reads_as_no_proxy(self, service_app) -> None:
        client, store, _, _ = service_app
        await _seed_link(store)
        await _seed_proxy(store, remaining=-10.0)

        resp = client.get(_STATUS)

        assert resp.status_code == 200, resp.text
        assert resp.json()["cached"] is False

    def test_vault_mode_ignores_a_stale_in_memory_meta(
        self, service_app, tmp_path: Path
    ) -> None:
        """The mirror-image divergence: a leftover in-memory ProxyMeta on
        THIS replica must not report a proxy Vault no longer holds."""
        from test_x509_redeem import _seed_proxy as seed_legacy_cache_proxy

        client, _, _, _ = service_app
        seed_legacy_cache_proxy(client, tmp_path, subject="sub-abc")

        resp = client.get(_STATUS)

        assert resp.status_code == 200, resp.text
        assert resp.json()["cached"] is False

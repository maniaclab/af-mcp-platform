"""Tests for X509Provider's voms-token-service mode (issue #112 follow-up).

When constructed with a ``VomsTokenServiceClient`` and a ``VaultX509Store``,
the provider mints via the service and persists everything in Vault:
unlock/link stores the passphrase + proxy, ``is_linked()`` asks Vault,
issue() serves the Vault proxy and — when it's expired or near expiry —
RE-MINTS with the stored passphrase (hands-free renewal). A bad-passphrase
failure on re-mint unlinks and surfaces ``NeedsUnlock`` so the portal
prompts a re-link; infra failures do neither. The legacy k8s-Job path stays
untouched when the service is not wired (feature-flagged coexistence —
covered by the pre-existing tests in test_x509.py).

The Vault store here is a lightweight in-memory fake implementing the
``VaultX509Store`` API (its Vault wire behavior is covered by
test_x509_vault.py); the voms client is a recording fake with a scriptable
outcome.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretBytes, SecretStr
from test_x509 import _principal

from af_mcp_broker.credentials.base import CredentialKind, NeedsUnlock
from af_mcp_broker.credentials.cache import CredentialCache, RateLimitError
from af_mcp_broker.credentials.voms_service import (
    MintedProxy,
    VomsServiceBadPassphraseError,
    VomsServiceMintError,
)
from af_mcp_broker.credentials.x509 import PosixIdentityRequiredError, X509Provider
from af_mcp_broker.credentials.x509_vault import StoredX509Credential

_PEM = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
_DN = "/DC=ch/DC=cern/CN=Test User"
_VOMS_ATTRS = ["/atlas/Role=NULL", "/atlas"]


class FakeX509Store:
    """In-memory stand-in for ``VaultX509Store`` (same public API)."""

    def __init__(self) -> None:
        self.records: dict[str, StoredX509Credential] = {}
        self.deleted: list[str] = []

    async def store_link(
        self,
        subject: str,
        *,
        passphrase: SecretStr,
        unixname: str,
        uid: int,
        gid: int,
    ) -> None:
        self.records[subject] = StoredX509Credential(
            passphrase=passphrase, unixname=unixname, uid=uid, gid=gid
        )

    async def get_link(self, subject: str) -> StoredX509Credential | None:
        record = self.records.get(subject)
        if record is None or not record.has_link:
            return None
        return record

    async def store_proxy(
        self,
        subject: str,
        *,
        pem: str,
        dn: str,
        voms_attributes: list[str],
        not_after: float,
    ) -> None:
        base = self.records.get(subject, StoredX509Credential())
        self.records[subject] = base.model_copy(
            update={
                "proxy_pem": SecretStr(pem),
                "dn": dn,
                "voms_attributes": list(voms_attributes),
                "not_after": not_after,
            }
        )

    async def get_proxy(
        self, subject: str, min_remaining: float = 0.0
    ) -> StoredX509Credential | None:
        record = self.records.get(subject)
        if record is None or record.proxy_pem is None or record.not_after is None:
            return None
        if record.not_after - time.time() < min_remaining:
            return None
        return record

    async def clear_proxy(self, subject: str) -> None:
        record = self.records.get(subject)
        if record is None:
            return
        self.records[subject] = record.model_copy(
            update={
                "proxy_pem": None,
                "dn": None,
                "voms_attributes": [],
                "not_after": None,
            }
        )

    async def delete(self, subject: str) -> None:
        self.records.pop(subject, None)
        self.deleted.append(subject)


class FakeVomsClient:
    """Recording fake for ``VomsTokenServiceClient.mint``.

    ``outcome`` is a ``MintedProxy`` to return or an exception to raise;
    every call's kwargs are recorded in ``calls``.
    """

    def __init__(
        self, outcome: MintedProxy | Exception | None = None, delay: float = 0.0
    ) -> None:
        self.outcome = outcome or _minted()
        self.delay = delay
        self.calls: list[dict[str, Any]] = []

    async def mint(self, **kwargs: Any) -> MintedProxy:
        self.calls.append(kwargs)
        if self.delay:
            await asyncio.sleep(self.delay)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _minted(remaining: float = 3600.0) -> MintedProxy:
    return MintedProxy(
        pem=_PEM,
        dn=_DN,
        voms_attributes=list(_VOMS_ATTRS),
        not_after=time.time() + remaining,
    )


def _make_provider(
    voms_client: FakeVomsClient | None = None,
    store: FakeX509Store | None = None,
    cache: CredentialCache | None = None,
) -> tuple[X509Provider, FakeVomsClient, FakeX509Store, CredentialCache]:
    voms_client = voms_client if voms_client is not None else FakeVomsClient()
    store = store if store is not None else FakeX509Store()
    cache = cache if cache is not None else CredentialCache()
    # Only the posix_*_attribute names (PosixIdentityRequiredError's message)
    # are ever read from settings in service mode — no filesystem paths.
    settings = SimpleNamespace(
        posix_uid_attribute="uid",
        posix_gid_attribute="gid",
        posix_unixname_attribute="unixname",
    )
    provider = X509Provider(
        settings=settings,  # type: ignore[arg-type]
        cache=cache,
        backends=[],
        voms_client=voms_client,  # type: ignore[arg-type]
        vault_store=store,  # type: ignore[arg-type]
    )
    return provider, voms_client, store, cache


async def _seed_link(store: FakeX509Store, subject: str = "user-123") -> None:
    await store.store_link(
        subject,
        passphrase=SecretStr("stored-passphrase"),
        unixname="auser",
        uid=50123,
        gid=5000,
    )


# ---------------------------------------------------------------------------
# is_linked
# ---------------------------------------------------------------------------


class TestIsLinked:
    async def test_true_when_vault_holds_a_link(self) -> None:
        provider, _, store, _ = _make_provider()
        await _seed_link(store)
        assert await provider.is_linked(_principal("auser")) is True

    async def test_false_when_vault_has_no_link(self) -> None:
        provider, _, _, _ = _make_provider()
        assert await provider.is_linked(_principal("auser")) is False

    async def test_ignores_the_filesystem_entirely(self) -> None:
        """settings=None would crash any ~/.globus path construction — the
        Vault answer must be authoritative in service mode."""
        provider, _, store, _ = _make_provider()
        await _seed_link(store)
        principal = _principal(None, uid=None, gid=None)  # no POSIX identity
        assert await provider.is_linked(principal) is True


# ---------------------------------------------------------------------------
# issue() with a passphrase: the link/unlock flow
# ---------------------------------------------------------------------------


class TestLinkFlow:
    async def test_mints_via_service_and_stores_link_and_proxy(self) -> None:
        provider, voms_client, store, _ = _make_provider()
        principal = _principal("auser")

        cred = await provider.issue(
            principal, "ami", passphrase=SecretBytes(b"hunter2")
        )

        assert len(voms_client.calls) == 1
        call = voms_client.calls[0]
        assert call["subject"] == "user-123"
        assert call["unixname"] == "auser"
        assert call["uid"] == 50123
        assert call["gid"] == 5000
        assert call["passphrase"].get_secret_value() == "hunter2"

        link = await store.get_link("user-123")
        assert link is not None
        assert link.passphrase is not None
        assert link.passphrase.get_secret_value() == "hunter2"
        record = await store.get_proxy("user-123")
        assert record is not None
        assert record.proxy_pem is not None
        assert record.proxy_pem.get_secret_value() == _PEM

        assert cred.kind == CredentialKind.X509_PROXY_REDEEM
        assert cred.payload["delivery"] == "redeem"
        assert "proxy_path" not in cred.payload
        assert cred.source == "voms_token_service"

    async def test_bad_passphrase_counts_against_rate_limiter_and_stores_nothing(
        self,
    ) -> None:
        provider, _, store, cache = _make_provider(
            voms_client=FakeVomsClient(VomsServiceBadPassphraseError())
        )
        principal = _principal("auser")

        with pytest.raises(VomsServiceBadPassphraseError):
            await provider.issue(principal, "ami", passphrase=SecretBytes(b"wrong"))

        assert store.records == {}
        assert cache._failed_unlocks[50123].attempts == 1

    async def test_infra_failure_does_not_count_against_rate_limiter(self) -> None:
        provider, _, store, cache = _make_provider(
            voms_client=FakeVomsClient(VomsServiceMintError("service down"))
        )
        principal = _principal("auser")

        with pytest.raises(VomsServiceMintError):
            await provider.issue(principal, "ami", passphrase=SecretBytes(b"hunter2"))

        assert store.records == {}
        assert 50123 not in cache._failed_unlocks

    async def test_rate_limit_is_checked_before_the_service_is_called(self) -> None:
        cache = CredentialCache(max_failed_unlocks=1)
        provider, voms_client, _, _ = _make_provider(
            voms_client=FakeVomsClient(VomsServiceBadPassphraseError()), cache=cache
        )
        principal = _principal("auser")

        for _ in range(2):
            with pytest.raises((VomsServiceBadPassphraseError, RateLimitError)):
                await provider.issue(principal, "ami", passphrase=SecretBytes(b"wrong"))
        calls_after_lockout = len(voms_client.calls)
        with pytest.raises(RateLimitError):
            await provider.issue(principal, "ami", passphrase=SecretBytes(b"wrong"))
        assert len(voms_client.calls) == calls_after_lockout

    async def test_successful_link_resets_the_rate_limiter(self) -> None:
        provider, _, _, cache = _make_provider()
        principal = _principal("auser")
        cache.record_failed_unlock(50123)

        await provider.issue(principal, "ami", passphrase=SecretBytes(b"hunter2"))

        assert 50123 not in cache._failed_unlocks

    async def test_posix_identity_required_to_link(self) -> None:
        provider, voms_client, store, _ = _make_provider()
        principal = _principal(None, uid=None, gid=None)

        with pytest.raises(PosixIdentityRequiredError):
            await provider.issue(principal, "ami", passphrase=SecretBytes(b"hunter2"))

        assert voms_client.calls == []
        assert store.records == {}

    async def test_explicit_passphrase_relinks_even_with_valid_stored_proxy(
        self,
    ) -> None:
        """POSTing a passphrase is a linking act: it must update the stored
        passphrase even while a valid proxy exists (the user may have just
        changed their Globus password), rather than short-circuiting on the
        cache the way a passphrase-less issue() does."""
        provider, voms_client, store, _ = _make_provider()
        principal = _principal("auser")
        await provider.issue(principal, "ami", passphrase=SecretBytes(b"old-pass"))

        await provider.issue(principal, "ami", passphrase=SecretBytes(b"new-pass"))

        assert len(voms_client.calls) == 2
        link = await store.get_link("user-123")
        assert link is not None
        assert link.passphrase is not None
        assert link.passphrase.get_secret_value() == "new-pass"

    async def test_mint_counter_is_incremented(self) -> None:
        from prometheus_client import REGISTRY

        provider, _, _, _ = _make_provider()
        before = REGISTRY.get_sample_value("af_mcp_x509_proxy_mints_total") or 0.0
        await provider.issue(
            _principal("auser"), "ami", passphrase=SecretBytes(b"hunter2")
        )
        after = REGISTRY.get_sample_value("af_mcp_x509_proxy_mints_total")
        assert after == before + 1

    async def test_concurrent_renewals_single_flight_one_service_mint(self) -> None:
        """N concurrent passphrase-less issue() calls hitting an expired
        stored proxy must produce exactly one service mint (issue #94's
        pattern — this is where thundering herds actually happen, unlike
        explicit link POSTs, which are deliberate one-off user acts and are
        NOT deduped so a re-link always reaches the service)."""
        voms_client = FakeVomsClient(delay=0.01)
        provider, _, store, _ = _make_provider(voms_client=voms_client)
        await _seed_link(store)
        await store.store_proxy(
            "user-123",
            pem="OLD PEM",
            dn=_DN,
            voms_attributes=_VOMS_ATTRS,
            not_after=time.time() - 10,
        )
        principal = _principal("auser")

        results = await asyncio.gather(
            *[provider.issue(principal, "ami") for _ in range(5)]
        )

        assert len(voms_client.calls) == 1
        assert all(r.payload["proxy_handle"] for r in results)


# ---------------------------------------------------------------------------
# issue() without a passphrase: stored proxy / hands-free renewal
# ---------------------------------------------------------------------------


class TestStoredProxyAndRenewal:
    async def test_valid_vault_proxy_is_served_without_calling_the_service(
        self,
    ) -> None:
        provider, voms_client, store, _ = _make_provider()
        await _seed_link(store)
        await store.store_proxy(
            "user-123",
            pem=_PEM,
            dn=_DN,
            voms_attributes=_VOMS_ATTRS,
            not_after=time.time() + 3600,
        )

        cred = await provider.issue(_principal("auser"), "ami")

        assert voms_client.calls == []
        assert cred.kind == CredentialKind.X509_PROXY_REDEEM

    async def test_vault_proxy_serves_a_principal_without_posix_identity(self) -> None:
        """POSIX identity isn't needed just to serve an already-minted
        credential — same rule as the legacy path's cache hit."""
        provider, _, store, _ = _make_provider()
        await _seed_link(store)
        await store.store_proxy(
            "user-123",
            pem=_PEM,
            dn=_DN,
            voms_attributes=_VOMS_ATTRS,
            not_after=time.time() + 3600,
        )

        cred = await provider.issue(_principal(None, uid=None, gid=None), "ami")
        assert cred.kind == CredentialKind.X509_PROXY_REDEEM

    async def test_expired_proxy_with_stored_link_renews_hands_free(self) -> None:
        provider, voms_client, store, _ = _make_provider()
        await _seed_link(store)
        await store.store_proxy(
            "user-123",
            pem="OLD PEM",
            dn=_DN,
            voms_attributes=_VOMS_ATTRS,
            not_after=time.time() - 10,
        )

        cred = await provider.issue(_principal("auser"), "ami")

        assert len(voms_client.calls) == 1
        call = voms_client.calls[0]
        # Renewal identity comes from the stored link, not the live principal.
        assert call["unixname"] == "auser"
        assert call["uid"] == 50123
        assert call["passphrase"].get_secret_value() == "stored-passphrase"
        record = await store.get_proxy("user-123")
        assert record is not None
        assert record.proxy_pem is not None
        assert record.proxy_pem.get_secret_value() == _PEM
        assert cred.kind == CredentialKind.X509_PROXY_REDEEM

    async def test_renewal_bad_passphrase_unlinks_and_raises_needs_unlock(
        self,
    ) -> None:
        """The user changed their Globus password: the stored passphrase is
        dead weight. Unlink so the portal prompts a re-link."""
        provider, _, store, cache = _make_provider(
            voms_client=FakeVomsClient(VomsServiceBadPassphraseError())
        )
        await _seed_link(store)

        with pytest.raises(NeedsUnlock):
            await provider.issue(_principal("auser"), "ami")

        assert store.deleted == ["user-123"]
        assert await store.get_link("user-123") is None
        # A stored-passphrase failure is not a user brute-force attempt.
        assert 50123 not in cache._failed_unlocks

    async def test_renewal_infra_failure_neither_unlinks_nor_needs_unlock(
        self,
    ) -> None:
        provider, _, store, cache = _make_provider(
            voms_client=FakeVomsClient(VomsServiceMintError("service down"))
        )
        await _seed_link(store)

        with pytest.raises(VomsServiceMintError):
            await provider.issue(_principal("auser"), "ami")

        assert store.deleted == []
        assert await store.get_link("user-123") is not None
        assert 50123 not in cache._failed_unlocks

    async def test_no_link_and_no_passphrase_raises_needs_unlock(self) -> None:
        provider, voms_client, _, _ = _make_provider()

        with pytest.raises(NeedsUnlock) as excinfo:
            await provider.issue(_principal("auser"), "ami")

        assert excinfo.value.unlock_endpoint == "/v1/x509/proxy"
        assert voms_client.calls == []

    async def test_no_link_and_no_posix_identity_raises_posix_error(self) -> None:
        """An unlinked principal with no POSIX identity can never complete a
        link, so say that instead of asking for a passphrase (same ordering
        as the legacy path)."""
        provider, _, _, _ = _make_provider()

        with pytest.raises(PosixIdentityRequiredError):
            await provider.issue(_principal(None, uid=None, gid=None), "ami")

    async def test_second_issue_hits_the_in_memory_cache(self) -> None:
        provider, voms_client, store, _ = _make_provider()
        principal = _principal("auser")
        await provider.issue(principal, "ami", passphrase=SecretBytes(b"hunter2"))

        store.records.clear()  # a cache hit must not consult Vault at all
        cred = await provider.issue(principal, "ami")

        assert len(voms_client.calls) == 1
        assert cred.kind == CredentialKind.X509_PROXY_REDEEM


# ---------------------------------------------------------------------------
# revoke() in service mode
# ---------------------------------------------------------------------------


class TestRevoke:
    async def test_revoke_clears_stored_proxy_but_keeps_the_link(self) -> None:
        """Burning the proxy must not unlink the identity: the passphrase
        stays so the next issue() renews hands-free."""
        provider, _, store, _ = _make_provider()
        principal = _principal("auser")
        await provider.issue(principal, "ami", passphrase=SecretBytes(b"hunter2"))

        await provider.revoke(principal, "ami")

        assert await store.get_proxy("user-123") is None
        assert await store.get_link("user-123") is not None

    async def test_revoke_without_anything_stored_is_a_noop(self) -> None:
        provider, _, _, _ = _make_provider()
        await provider.revoke(_principal("auser"), "ami")  # must not raise


# ---------------------------------------------------------------------------
# Settings validation and app wiring
# ---------------------------------------------------------------------------


class TestSettingsValidation:
    def test_voms_service_requires_vault(self) -> None:
        """Proxies and passphrases persist in Vault in service mode, so a
        service URL without Vault connection settings must fail at boot."""
        from af_mcp_broker.config import Settings

        with pytest.raises(ValueError, match="vault_addr"):
            Settings(voms_token_service_url="http://voms-token-service:8000")

    def test_voms_service_requires_vault_role(self) -> None:
        from af_mcp_broker.config import Settings

        with pytest.raises(ValueError, match="vault_auth_role"):
            Settings(
                voms_token_service_url="http://voms-token-service:8000",
                vault_addr="https://vault.example",
            )

    def test_voms_service_with_vault_configured_is_valid(self) -> None:
        from af_mcp_broker.config import Settings

        settings = Settings(
            voms_token_service_url="http://voms-token-service:8000",
            vault_addr="https://vault.example",
            vault_auth_role="af-mcp-broker",
        )
        assert settings.voms_token_service_url == "http://voms-token-service:8000"


class TestAppWiring:
    @pytest.fixture
    def voms_service_env(self, monkeypatch: pytest.MonkeyPatch):
        """Point the app at a voms-token-service + Vault without either existing: Vault's startup trial auth is stubbed out."""
        from af_mcp_broker.vault_kv import VaultKV

        async def _fake_authenticate(self) -> str:
            return "vault-test-token"

        monkeypatch.setattr(VaultKV, "_authenticate", _fake_authenticate)
        monkeypatch.setenv(
            "VOMS_TOKEN_SERVICE_URL", "http://voms-token-service.invalid:8000"
        )
        monkeypatch.setenv("VAULT_ADDR", "https://vault.invalid")
        monkeypatch.setenv("VAULT_AUTH_ROLE", "af-mcp-broker")

    def test_boot_fails_without_signing_key(
        self,
        voms_service_env,
        monkeypatch: pytest.MonkeyPatch,
        app_client_factory,
    ) -> None:
        """Minting at the service needs broker-signed identity tokens: a
        service URL with no signing key is fail-closed at boot (same
        reasoning as the broker-issued provider check)."""
        monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)
        with (
            pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"),
            app_client_factory(),
        ):
            pass  # pragma: no cover - boot must fail before yielding

    def test_boot_wires_service_mode(
        self,
        voms_service_env,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
        app_client_factory,
    ) -> None:
        from test_broker_issued import _make_rsa_key, _private_pem

        key_file = tmp_path / "signing-key.pem"
        key_file.write_bytes(_private_pem(_make_rsa_key()))
        monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
        monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")

        with app_client_factory() as (client, _):
            provider = client.app.state.x509_provider
            assert provider.uses_voms_service is True
            assert provider.vault_store is not None

    def test_boot_without_service_url_stays_in_legacy_mode(
        self, app_client_factory
    ) -> None:
        with app_client_factory() as (client, _):
            provider = client.app.state.x509_provider
            assert provider.uses_voms_service is False
            assert provider.vault_store is None


# ---------------------------------------------------------------------------
# API response rendering for the new credential kind
# ---------------------------------------------------------------------------


class TestToResponse:
    async def test_redeem_kind_renders_proxy_handle_without_a_path(self) -> None:
        from af_mcp_broker.api.credentials import _to_response

        provider, _, _, _ = _make_provider()
        cred = await provider.issue(
            _principal("auser"), "ami", passphrase=SecretBytes(b"hunter2")
        )

        response = _to_response(cred)

        assert response.kind == "x509_proxy_redeem"
        assert response.proxy_handle == cred.payload["proxy_handle"]
        assert response.proxy_path is None
        assert response.token is None

"""Unit tests for KrbTokenProvider (issue #274, #274 remember/keytab follow-up).

Covers the five-tier fallback (cache -> vault repopulation -> renew-from-Vault ->
remint-from-stored-keytab -> interactive password), is_linked() reflecting
ANY of cache/link/renewable-ticket state, and revoke()'s ticket-only clear.
The krb5-token-service HTTP exchange itself is covered by
test_krb5_service_client.py, and the Vault record shape/CAS behavior by
test_krb5_vault.py -- here both the service client and the Vault store are
fake doubles.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace

import pytest
from prometheus_client import REGISTRY
from pydantic import SecretBytes, SecretStr

from af_mcp_broker.credentials.base import CredentialKind, NeedsUnlock
from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.credentials.krb5 import KrbTokenProvider
from af_mcp_broker.credentials.krb5_service import (
    Krb5TokenBadCredentialError,
    Krb5TokenMintError,
    Krb5TokenRenewalWindowClosedError,
    MintedTicket,
)
from af_mcp_broker.credentials.krb5_vault import StoredKrb5Credential
from af_mcp_broker.identity import Principal


def make_principal(subject: str = "user1") -> Principal:
    return Principal(
        subject=subject,
        email="user1@example.org",
        groups=[],
        unixname=None,
        uid=None,
        gid=None,
        raw_token=SecretStr(""),
    )


class _FakeClient:
    """Recording fake for ``Krb5TokenServiceClient``'s mint/renew/mint_keytab.

    Each method's outcome is scripted independently via the constructor
    (a success value, or an exception to raise) and every call's kwargs are
    recorded in that method's own ``*_calls`` list -- ``mint``'s list keeps
    the pre-existing name ``calls`` so the original tests need no changes.
    """

    def __init__(
        self,
        ticket: MintedTicket | None = None,
        error: Exception | None = None,
        renew_ticket: MintedTicket | None = None,
        renew_error: Exception | None = None,
        keytab_result: tuple[str, str] | None = None,
        keytab_error: Exception | None = None,
    ):
        self._ticket = ticket
        self._error = error
        self._renew_ticket = renew_ticket
        self._renew_error = renew_error
        self._keytab_result = keytab_result
        self._keytab_error = keytab_error
        self.calls: list[dict] = []
        self.renew_calls: list[dict] = []
        self.keytab_calls: list[dict] = []

    async def mint(
        self,
        *,
        subject,
        username,
        password=None,
        keytab_b64=None,
        lifetime=None,
        renewable_lifetime=None,
    ):
        self.calls.append(
            {
                "subject": subject,
                "username": username,
                "password": password.get_secret_value()
                if password is not None
                else None,
                "keytab_b64": (
                    keytab_b64.get_secret_value() if keytab_b64 is not None else None
                ),
                "lifetime": lifetime,
                "renewable_lifetime": renewable_lifetime,
            }
        )
        if self._error is not None:
            raise self._error
        assert self._ticket is not None
        return self._ticket

    async def renew(self, *, subject, ccache_b64):
        self.renew_calls.append({"subject": subject, "ccache_b64": ccache_b64})
        if self._renew_error is not None:
            raise self._renew_error
        assert self._renew_ticket is not None
        return self._renew_ticket

    async def mint_keytab(self, *, subject, username, password):
        self.keytab_calls.append(
            {
                "subject": subject,
                "username": username,
                "password": password.get_secret_value(),
            }
        )
        if self._keytab_error is not None:
            raise self._keytab_error
        assert self._keytab_result is not None
        return self._keytab_result


class FakeKrb5VaultStore:
    """In-memory stand-in for ``Krb5VaultStore`` (same public API).

    Mirrors test_x509_service_mode.py's ``FakeX509Store`` convention: a
    plain dict keyed by subject, holding the same frozen record dataclass
    the real store round-trips.
    """

    def __init__(self) -> None:
        self.records: dict[str, StoredKrb5Credential] = {}
        self.deleted: list[str] = []

    async def store_link(
        self, subject: str, *, username: str, keytab_b64: SecretStr
    ) -> None:
        base = self.records.get(subject, StoredKrb5Credential())
        self.records[subject] = replace(base, username=username, keytab_b64=keytab_b64)

    async def get_link(self, subject: str) -> StoredKrb5Credential | None:
        record = self.records.get(subject)
        if record is None or not record.has_link:
            return None
        return record

    async def store_ticket(
        self,
        subject: str,
        *,
        ccache_b64: SecretStr,
        principal: str,
        realm: str,
        not_after: float,
        renew_until: float | None,
    ) -> None:
        base = self.records.get(subject, StoredKrb5Credential())
        self.records[subject] = replace(
            base,
            ccache_b64=ccache_b64,
            principal=principal,
            realm=realm,
            not_after=not_after,
            renew_until=renew_until,
        )

    async def get_ticket(
        self, subject: str, min_remaining: float = 0.0
    ) -> StoredKrb5Credential | None:
        record = self.records.get(subject)
        if record is None or not record.has_ticket:
            return None
        assert record.not_after is not None  # has_ticket guarantees this
        if record.not_after - time.time() < min_remaining:
            return None
        return record

    async def get_renewable_ticket(self, subject: str) -> StoredKrb5Credential | None:
        record = self.records.get(subject)
        if record is None or not record.has_ticket:
            return None
        if record.renew_until is None or record.renew_until <= time.time():
            return None
        return record

    async def clear_ticket(self, subject: str) -> None:
        record = self.records.get(subject)
        if record is None:
            return
        self.records[subject] = replace(
            record,
            ccache_b64=None,
            principal=None,
            realm=None,
            not_after=None,
            renew_until=None,
        )

    async def delete(self, subject: str) -> None:
        self.records.pop(subject, None)
        self.deleted.append(subject)


def provider_factory(client, targets=("krb5-target",), vault_store=None):
    cache = CredentialCache()
    if vault_store is None:
        vault_store = FakeKrb5VaultStore()
    provider = KrbTokenProvider(
        client=client,
        cache=cache,
        vault_store=vault_store,
        alias="krb5",
        targets=frozenset(targets),
    )
    return provider, cache, vault_store


def _ticket(not_after=None, renew_until=None, ccache_b64="ZmFrZQ==") -> MintedTicket:
    return MintedTicket(
        ccache_b64=ccache_b64,
        principal="alice@CERN.CH",
        realm="CERN.CH",
        not_after=not_after if not_after is not None else time.time() + 3600,
        renew_until=renew_until,
    )


async def test_issue_without_credentials_raises_needs_unlock():
    provider, _, _ = provider_factory(_FakeClient())
    with pytest.raises(NeedsUnlock) as exc_info:
        await provider.issue(make_principal(), "krb5-target")
    assert exc_info.value.unlock_endpoint == "/v1/krb5/ticket"


async def test_issue_with_credentials_mints_and_caches():
    client = _FakeClient(ticket=_ticket())
    provider, cache, _ = provider_factory(client)
    principal = make_principal()
    cred = await provider.issue(
        principal,
        "krb5-target",
        passphrase=SecretBytes(b"hunter2"),
        username="alice",
    )
    assert cred.cred_class == "krb5_ticket"
    assert cred.kind == CredentialKind.KRB5_CCACHE
    assert cred.payload["ccache_b64"] == "ZmFrZQ=="
    assert cred.payload["principal"] == "alice@CERN.CH"
    assert client.calls[0]["username"] == "alice"
    assert client.calls[0]["password"] == "hunter2"

    cached = await cache.get(principal.subject, "krb5-target", min_remaining=0)
    assert cached is not None


async def test_issue_returns_cached_credential_without_recontacting_service():
    client = _FakeClient(ticket=_ticket())
    provider, _, _ = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )
    # Second call within validity, no credentials supplied -- must hit cache.
    cred = await provider.issue(principal, "krb5-target")
    assert cred.payload["ccache_b64"] == "ZmFrZQ=="
    assert len(client.calls) == 1


async def test_is_linked_false_with_no_cached_ticket():
    """None of the three is_linked() routes (cache / stored link / renewable
    ticket) has anything -- must report unlinked."""
    provider, _, _ = provider_factory(_FakeClient())
    assert await provider.is_linked(make_principal()) is False


async def test_is_linked_true_after_mint():
    """Cache route: a live in-process cache entry alone is enough."""
    client = _FakeClient(ticket=_ticket())
    provider, _, _ = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )
    assert await provider.is_linked(principal) is True


async def test_is_linked_true_from_stored_link_alone():
    """Vault-link route: a stored keytab with an empty cache and no stored
    ticket is enough."""
    vault_store = FakeKrb5VaultStore()
    principal = make_principal()
    await vault_store.store_link(
        principal.subject, username="alice", keytab_b64=SecretStr("a2V5dGFi")
    )
    provider, _, _ = provider_factory(_FakeClient(), vault_store=vault_store)
    assert await provider.is_linked(principal) is True


async def test_is_linked_true_from_renewable_ticket_alone():
    """Vault-renewable-ticket route: a ticket half past not_after but still
    within its renew_until, with an empty cache and no stored link."""
    vault_store = FakeKrb5VaultStore()
    principal = make_principal()
    await vault_store.store_ticket(
        principal.subject,
        ccache_b64=SecretStr("b2xkY2NhY2hl"),
        principal="alice@CERN.CH",
        realm="CERN.CH",
        not_after=time.time() - 60,
        renew_until=time.time() + 3600,
    )
    provider, _, _ = provider_factory(_FakeClient(), vault_store=vault_store)
    assert await provider.is_linked(principal) is True


async def test_revoke_drops_cached_ticket():
    client = _FakeClient(ticket=_ticket())
    provider, cache, _ = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )
    await provider.revoke(principal, "krb5-target")
    assert await cache.get(principal.subject, "krb5-target", min_remaining=0) is None


async def test_revoke_clears_vault_ticket_but_preserves_link():
    """revoke() drops the Vault ticket half too, but a stored keytab link
    survives -- burning a ticket must not unlink the identity (mirrors
    X509Provider.revoke()'s revoke/unlink distinction)."""
    client = _FakeClient(ticket=_ticket(), keytab_result=("a2V5dGFi", "alice@CERN.CH"))
    provider, cache, vault_store = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal,
        "krb5-target",
        passphrase=SecretBytes(b"hunter2"),
        username="alice",
        remember=True,
    )
    assert await vault_store.get_link(principal.subject) is not None
    assert await vault_store.get_ticket(principal.subject, min_remaining=0) is not None

    await provider.revoke(principal, "krb5-target")

    assert await cache.get(principal.subject, "krb5-target", min_remaining=0) is None
    assert await vault_store.get_ticket(principal.subject, min_remaining=0) is None
    assert await vault_store.get_link(principal.subject) is not None


async def test_is_linked_true_when_only_one_of_multiple_targets_has_a_ticket():
    """``is_linked()`` loops over all of this entry's configured targets with
    ``any()``, not ``all()`` -- a ticket cached for just one of them must
    still report linked."""
    client = _FakeClient(ticket=_ticket())
    provider, _, _ = provider_factory(
        client, targets=("krb5-target-a", "krb5-target-b")
    )
    principal = make_principal()
    await provider.issue(
        principal,
        "krb5-target-a",
        passphrase=SecretBytes(b"hunter2"),
        username="alice",
    )

    assert await provider.is_linked(principal) is True


async def test_is_linked_does_not_affect_cache_metrics():
    """``is_linked()`` is a live cache-state probe, not a credential-serving
    lookup -- it must not move ``af_mcp_credential_cache_hits_total``/
    ``..._misses_total`` (see ``CredentialCache.peek()``)."""
    client = _FakeClient(ticket=_ticket())
    provider, _, _ = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )

    def _sample(name: str) -> float:
        return REGISTRY.get_sample_value(name, {"target": "krb5-target"}) or 0.0

    before_hits = _sample("af_mcp_credential_cache_hits_total")
    before_misses = _sample("af_mcp_credential_cache_misses_total")

    for _ in range(3):
        assert await provider.is_linked(principal) is True

    assert _sample("af_mcp_credential_cache_hits_total") == before_hits
    assert _sample("af_mcp_credential_cache_misses_total") == before_misses


async def test_issue_mint_failure_propagates_and_does_not_cache():
    """A failed mint must propagate uncaught, and must not poison the cache
    -- mirrors test_condor_token.py's equivalent service-failure coverage."""
    client = _FakeClient(error=Krb5TokenBadCredentialError())
    provider, cache, vault_store = provider_factory(client)
    principal = make_principal()

    with pytest.raises(Krb5TokenBadCredentialError):
        await provider.issue(
            principal,
            "krb5-target",
            passphrase=SecretBytes(b"hunter2"),
            username="alice",
        )

    assert await cache.get(principal.subject, "krb5-target", min_remaining=0) is None
    # A bad FRESH password must not be mistaken for a bad stored keytab --
    # there is no link to delete here (none was ever stored), and none must
    # be created either.
    assert await vault_store.get_link(principal.subject) is None


async def test_issue_concurrent_password_mints_each_mint_independently():
    """N concurrent tier-5 issue() calls for the same (subject, target) each
    reach client.mint() independently -- an explicit password mint is NOT
    single-flighted through the cache the way tiers 1-4's cache/Vault reads
    are. Mirrors X509Provider's own accepted trade-off for its equivalent
    explicit-passphrase/consent path (see x509.py's ``_link_and_mint`` and
    the comment on ``_issue_via_service``'s link/unlock branch): deduping an
    explicit user action with a consent flag (``remember``) against a
    concurrent, possibly-different request would silently let one caller's
    consent decision win over another's."""

    class _SlowClient(_FakeClient):
        async def mint(self, **kwargs):
            # Force a real suspension so concurrent callers actually overlap.
            await asyncio.sleep(0.01)
            return await super().mint(**kwargs)

    client = _SlowClient(ticket=_ticket())
    provider, _, _ = provider_factory(client)
    principal = make_principal()

    results = await asyncio.gather(
        *[
            provider.issue(
                principal,
                "krb5-target",
                passphrase=SecretBytes(b"hunter2"),
                username="alice",
            )
            for _ in range(5)
        ]
    )

    assert len(client.calls) == 5
    assert all(r.payload["ccache_b64"] == "ZmFrZQ==" for r in results)


# ------------------------------------------------------------------
# Tier 3: renew from a Vault-stored renewable ticket
# ------------------------------------------------------------------


async def test_issue_tier3_renew_success():
    """A ticket half past its not_after but within renew_until, with no
    fresh username/passphrase supplied, is renewed rather than freshly
    minted -- and the renewed ticket is re-persisted to both Vault and the
    in-process cache."""
    vault_store = FakeKrb5VaultStore()
    principal = make_principal()
    await vault_store.store_ticket(
        principal.subject,
        ccache_b64=SecretStr("b2xkY2NhY2hl"),
        principal="alice@CERN.CH",
        realm="CERN.CH",
        not_after=time.time() - 60,
        renew_until=time.time() + 3600,
    )
    fresh_ticket = _ticket(ccache_b64="bmV3Y2NhY2hl")
    client = _FakeClient(renew_ticket=fresh_ticket)
    provider, cache, vault_store = provider_factory(client, vault_store=vault_store)

    cred = await provider.issue(principal, "krb5-target")

    assert cred.payload["ccache_b64"] == "bmV3Y2NhY2hl"
    assert client.renew_calls == [
        {"subject": principal.subject, "ccache_b64": "b2xkY2NhY2hl"}
    ]
    assert client.calls == []  # mint() must not be called on this path

    cached = await cache.get(principal.subject, "krb5-target", min_remaining=0)
    assert cached is not None
    assert cached.payload["ccache_b64"] == "bmV3Y2NhY2hl"

    stored = await vault_store.get_ticket(principal.subject, min_remaining=0)
    assert stored is not None
    assert stored.ccache_b64 is not None
    assert stored.ccache_b64.get_secret_value() == "bmV3Y2NhY2hl"


async def test_issue_tier3_renewal_window_closed_falls_through_to_needs_unlock():
    """A renewal-window-closed signal is expected and recoverable: with no
    stored keytab and no fresh credentials, it must fall through to
    NeedsUnlock rather than propagate."""
    vault_store = FakeKrb5VaultStore()
    principal = make_principal()
    await vault_store.store_ticket(
        principal.subject,
        ccache_b64=SecretStr("b2xkY2NhY2hl"),
        principal="alice@CERN.CH",
        realm="CERN.CH",
        not_after=time.time() - 60,
        renew_until=time.time() + 3600,
    )
    client = _FakeClient(renew_error=Krb5TokenRenewalWindowClosedError())
    provider, _, _ = provider_factory(client, vault_store=vault_store)

    with pytest.raises(NeedsUnlock) as exc_info:
        await provider.issue(principal, "krb5-target")

    assert exc_info.value.unlock_endpoint == "/v1/krb5/ticket"
    assert len(client.renew_calls) == 1
    assert client.calls == []  # no keytab was stored, so mint() is never reached


async def test_issue_tier3_renewal_window_closed_falls_through_to_tier4():
    """Same window-closed signal, but this time a keytab IS stored -- the
    fallthrough must actually reach and succeed at tier 4."""
    vault_store = FakeKrb5VaultStore()
    principal = make_principal()
    await vault_store.store_ticket(
        principal.subject,
        ccache_b64=SecretStr("b2xkY2NhY2hl"),
        principal="alice@CERN.CH",
        realm="CERN.CH",
        not_after=time.time() - 60,
        renew_until=time.time() + 3600,
    )
    await vault_store.store_link(
        principal.subject, username="alice", keytab_b64=SecretStr("a2V5dGFi")
    )
    remint_ticket = _ticket(ccache_b64="cmVtaW50ZWQ=")
    client = _FakeClient(
        renew_error=Krb5TokenRenewalWindowClosedError(), ticket=remint_ticket
    )
    provider, cache, _ = provider_factory(client, vault_store=vault_store)

    cred = await provider.issue(principal, "krb5-target")

    assert len(client.renew_calls) == 1
    assert cred.payload["ccache_b64"] == "cmVtaW50ZWQ="
    assert client.calls[0]["keytab_b64"] == "a2V5dGFi"
    cached = await cache.get(principal.subject, "krb5-target", min_remaining=0)
    assert cached is not None


async def test_issue_tier3_hard_failure_propagates():
    """A genuine infra failure from renew() must propagate uncaught -- never
    silently downgraded to demanding a password."""
    vault_store = FakeKrb5VaultStore()
    principal = make_principal()
    await vault_store.store_ticket(
        principal.subject,
        ccache_b64=SecretStr("b2xkY2NhY2hl"),
        principal="alice@CERN.CH",
        realm="CERN.CH",
        not_after=time.time() - 60,
        renew_until=time.time() + 3600,
    )
    # A stored keytab is also present, to prove the hard failure does NOT
    # fall through to tier 4 either.
    await vault_store.store_link(
        principal.subject, username="alice", keytab_b64=SecretStr("a2V5dGFi")
    )
    client = _FakeClient(
        renew_error=Krb5TokenMintError("krb5-token-service unreachable")
    )
    provider, _, _ = provider_factory(client, vault_store=vault_store)

    with pytest.raises(Krb5TokenMintError):
        await provider.issue(principal, "krb5-target")

    assert client.calls == []  # mint() must never be reached


# ------------------------------------------------------------------
# Tier 4: remint from a Vault-stored keytab
# ------------------------------------------------------------------


async def test_issue_tier4_keytab_remint_success():
    """No usable cache/ticket, but a keytab is stored and no fresh
    username/password was supplied -- mints via the stored keytab rather
    than raising NeedsUnlock."""
    vault_store = FakeKrb5VaultStore()
    principal = make_principal()
    await vault_store.store_link(
        principal.subject, username="alice", keytab_b64=SecretStr("a2V5dGFi")
    )
    client = _FakeClient(ticket=_ticket())
    provider, _cache, vault_store = provider_factory(client, vault_store=vault_store)

    cred = await provider.issue(principal, "krb5-target")

    assert cred.payload["ccache_b64"] == "ZmFrZQ=="
    assert client.calls[0]["username"] == "alice"
    assert client.calls[0]["keytab_b64"] == "a2V5dGFi"
    assert client.calls[0]["password"] is None

    stored = await vault_store.get_ticket(principal.subject, min_remaining=0)
    assert stored is not None


async def test_issue_tier4_bad_keytab_unlinks_and_raises_needs_unlock():
    """A rejected stored keytab (e.g. a rotated password) proactively
    unlinks the identity -- mirroring X509Provider.renew_from_stored_link's
    auto-unlink-on-bad-stored-passphrase behavior -- then raises
    NeedsUnlock, since there is nothing left to fall back to."""
    vault_store = FakeKrb5VaultStore()
    principal = make_principal()
    await vault_store.store_link(
        principal.subject, username="alice", keytab_b64=SecretStr("a2V5dGFi")
    )
    client = _FakeClient(error=Krb5TokenBadCredentialError())
    provider, _, vault_store = provider_factory(client, vault_store=vault_store)

    with pytest.raises(NeedsUnlock) as exc_info:
        await provider.issue(principal, "krb5-target")

    assert exc_info.value.unlock_endpoint == "/v1/krb5/ticket"
    assert vault_store.deleted == [principal.subject]
    assert await vault_store.get_link(principal.subject) is None


# ------------------------------------------------------------------
# Tier 5: fresh password mint, with optional keytab bootstrap ("remember")
# ------------------------------------------------------------------


async def test_issue_tier5_remember_true_also_mints_and_stores_keytab():
    """With remember=True, a successful password mint ALSO bootstraps and
    stores a keytab, reusing the SAME already-captured password (no second
    prompt)."""
    client = _FakeClient(ticket=_ticket(), keytab_result=("a2V5dGFi", "alice@CERN.CH"))
    provider, _, vault_store = provider_factory(client)
    principal = make_principal()

    await provider.issue(
        principal,
        "krb5-target",
        passphrase=SecretBytes(b"hunter2"),
        username="alice",
        remember=True,
    )

    assert client.keytab_calls == [
        {"subject": principal.subject, "username": "alice", "password": "hunter2"}
    ]
    link = await vault_store.get_link(principal.subject)
    assert link is not None
    assert link.username == "alice"
    assert link.keytab_b64 is not None
    assert link.keytab_b64.get_secret_value() == "a2V5dGFi"


async def test_issue_tier5_remember_true_keytab_bootstrap_failure_still_returns_ticket():
    """A failed keytab bootstrap (any krb5-token-service error -- e.g. the
    shared rate limiter tripping right after the password mint it follows)
    must NOT discard an already-successful ticket mint: remembering is
    best-effort, not a reason to fail a call that already succeeded at its
    primary job. No partial/corrupt link record is left behind either."""
    client = _FakeClient(ticket=_ticket(), keytab_error=Krb5TokenMintError("boom"))
    provider, _, vault_store = provider_factory(client)
    principal = make_principal()

    cred = await provider.issue(
        principal,
        "krb5-target",
        passphrase=SecretBytes(b"hunter2"),
        username="alice",
        remember=True,
    )

    assert cred.payload["ccache_b64"] == "ZmFrZQ=="
    assert await vault_store.get_link(principal.subject) is None


async def test_issue_tier5_remember_false_default_does_not_store_keytab():
    """Without remember=True (the default), no keytab is bootstrapped and
    no link half is stored -- but the ticket half IS always stored,
    regardless of remember, since tier-3 renewal must work for every user."""
    client = _FakeClient(ticket=_ticket())
    provider, _, vault_store = provider_factory(client)
    principal = make_principal()

    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )

    assert client.keytab_calls == []
    assert await vault_store.get_link(principal.subject) is None
    stored_ticket = await vault_store.get_ticket(principal.subject, min_remaining=0)
    assert stored_ticket is not None
    assert stored_ticket.ccache_b64 is not None
    assert stored_ticket.ccache_b64.get_secret_value() == "ZmFrZQ=="

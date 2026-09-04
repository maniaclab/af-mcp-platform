"""Tests for the Vault/OpenBao-backed krb5 credential store (issue #274 follow-up).

``Krb5VaultStore`` persists, per subject, a link half (keytab + username,
durable, opt-in via "remember") and a ticket half (last-minted ccache
metadata, written on every mint regardless of remember) — one KV-v2 record
at ``{prefix}/{subject}/krb5`` over the shared ``VaultKV`` transport,
mirroring ``credentials/x509_vault.py``'s ``VaultX509Store`` layout and CAS
conventions. A fake Vault HTTP API is built with ``httpx.MockTransport``
(same harness shape as ``test_x509_vault.py``).
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from pydantic import SecretStr

from af_mcp_broker.credentials.krb5_vault import Krb5VaultStore
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from pathlib import Path

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"
KV_PATH_PREFIX = "mcp/krb5"

SUBJECT = "kc-subject-123"

_CCACHE = "ZmFrZS1jY2FjaGU="
_KEYTAB = "ZmFrZS1rZXl0YWI="
_PRINCIPAL = "auser@CERN.CH"
_REALM = "CERN.CH"


class _FakeVault:
    """In-memory fake of the subset of Vault's HTTP API this store uses.

    ``entries`` maps the KV path under the prefix (i.e. ``{subject}/krb5``)
    to ``{"data": dict, "version": int}``. Absent keys behave as Vault does
    for never-written or metadata-destroyed paths: GET 404s, and a CAS write
    with ``cas=0`` succeeds.
    """

    def __init__(self) -> None:
        self.entries: dict[str, dict[str, Any]] = {}

    def _kv_key_from_path(self, path: str) -> str | None:
        for verb in ("data", "metadata"):
            prefix = f"{KV_MOUNT}/{verb}/{KV_PATH_PREFIX}/"
            if path.startswith(prefix):
                return path[len(prefix) :]
        return None

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "auth": {
                        "client_token": "vault-test-token",
                        "lease_duration": 3600,
                        "renewable": True,
                    }
                },
                request=request,
            )

        key = self._kv_key_from_path(path)
        if key is None:
            return httpx.Response(
                404, json={"errors": ["unknown path"]}, request=request
            )

        is_metadata = path.startswith(f"{KV_MOUNT}/metadata/")

        if request.method == "GET":
            entry = self.entries.get(key)
            if entry is None:
                return httpx.Response(404, json={"errors": []}, request=request)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "data": entry["data"],
                        "metadata": {"version": entry["version"]},
                    }
                },
                request=request,
            )

        if request.method == "POST" and not is_metadata:
            body = json.loads(request.content.decode())
            cas = body["options"]["cas"]
            current_version = self.entries.get(key, {}).get("version", 0)
            if cas != current_version:
                return httpx.Response(
                    400,
                    json={
                        "errors": [
                            "check-and-set parameter did not match the current version"
                        ]
                    },
                    request=request,
                )
            new_version = current_version + 1
            self.entries[key] = {"data": body["data"], "version": new_version}
            return httpx.Response(
                200, json={"data": {"version": new_version}}, request=request
            )

        if request.method == "DELETE" and is_metadata:
            self.entries.pop(key, None)
            return httpx.Response(204, request=request)

        return httpx.Response(
            404, json={"errors": ["unhandled"]}, request=request
        )  # pragma: no cover


@pytest.fixture
def sa_token_path(tmp_path: Path) -> Path:
    path = tmp_path / "sa-token"
    path.write_text("fake-sa-jwt\n")
    return path


@pytest.fixture
def fake_vault() -> _FakeVault:
    return _FakeVault()


@pytest.fixture
def store(fake_vault: _FakeVault, sa_token_path: Path) -> Krb5VaultStore:
    vault_kv = VaultKV(
        addr=ADDR,
        auth_mount=AUTH_MOUNT,
        auth_role=AUTH_ROLE,
        kv_mount=KV_MOUNT,
        sa_token_path=str(sa_token_path),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake_vault.handle)),
    )
    return Krb5VaultStore(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)


async def _link(store: Krb5VaultStore, subject: str = SUBJECT) -> None:
    await store.store_link(
        subject,
        username="auser",
        keytab_b64=SecretStr(_KEYTAB),
    )


async def _store_ticket(
    store: Krb5VaultStore,
    subject: str = SUBJECT,
    *,
    remaining: float = 3600.0,
    renew_remaining: float | None = 7 * 24 * 3600.0,
) -> tuple[float, float | None]:
    not_after = time.time() + remaining
    renew_until = time.time() + renew_remaining if renew_remaining is not None else None
    await store.store_ticket(
        subject,
        ccache_b64=SecretStr(_CCACHE),
        principal=_PRINCIPAL,
        realm=_REALM,
        not_after=not_after,
        renew_until=renew_until,
    )
    return not_after, renew_until


# ---------------------------------------------------------------------------
# Link half: store_link / get_link / path layout
# ---------------------------------------------------------------------------


class TestLink:
    async def test_get_link_returns_none_when_never_linked(self, store) -> None:
        assert await store.get_link(SUBJECT) is None

    async def test_store_link_roundtrips_username_and_keytab(self, store) -> None:
        await _link(store)
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.username == "auser"
        assert link.keytab_b64 is not None
        assert link.keytab_b64.get_secret_value() == _KEYTAB

    async def test_record_lives_at_prefix_subject_krb5(self, store, fake_vault) -> None:
        await _link(store)
        assert list(fake_vault.entries) == [f"{SUBJECT}/krb5"]

    async def test_keytab_is_stored_revealed_not_masked(
        self, store, fake_vault
    ) -> None:
        """pydantic masks SecretStr as ********** on model_dump-equivalent
        serialization; persistence must store the real value (same reveal
        discipline as VaultX509Store)."""
        await _link(store)
        stored = fake_vault.entries[f"{SUBJECT}/krb5"]["data"]
        assert stored["keytab_b64"] == _KEYTAB

    async def test_relink_replaces_keytab_and_preserves_ticket(self, store) -> None:
        """Unlike x509's passphrase (which the proxy was minted with), a
        krb5 ticket's validity has nothing to do with which keytab is
        currently on file — a re-link must not wipe a still-good ticket."""
        await _link(store)
        not_after, _renew_until = await _store_ticket(store)
        await store.store_link(
            SUBJECT, username="auser", keytab_b64=SecretStr("new-keytab")
        )
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.keytab_b64 is not None
        assert link.keytab_b64.get_secret_value() == "new-keytab"
        ticket = await store.get_ticket(SUBJECT)
        assert ticket is not None
        assert ticket.not_after == pytest.approx(not_after)


# ---------------------------------------------------------------------------
# Ticket half: store_ticket / get_ticket expiry awareness
# ---------------------------------------------------------------------------


class TestTicket:
    async def test_get_ticket_returns_none_when_nothing_stored(self, store) -> None:
        assert await store.get_ticket(SUBJECT) is None

    async def test_store_ticket_roundtrips_ccache_and_metadata(self, store) -> None:
        await _link(store)
        not_after, renew_until = await _store_ticket(store)
        record = await store.get_ticket(SUBJECT)
        assert record is not None
        assert record.ccache_b64 is not None
        assert record.ccache_b64.get_secret_value() == _CCACHE
        assert record.principal == _PRINCIPAL
        assert record.realm == _REALM
        assert record.not_after == pytest.approx(not_after)
        assert record.renew_until == pytest.approx(renew_until)

    async def test_store_ticket_preserves_the_link(self, store) -> None:
        await _link(store)
        await _store_ticket(store)
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.keytab_b64 is not None
        assert link.keytab_b64.get_secret_value() == _KEYTAB

    async def test_get_ticket_is_expiry_aware(self, store) -> None:
        await _link(store)
        await _store_ticket(store, remaining=-10.0)
        assert await store.get_ticket(SUBJECT) is None

    async def test_get_ticket_honors_min_remaining(self, store) -> None:
        await _link(store)
        await _store_ticket(store, remaining=100.0)
        assert await store.get_ticket(SUBJECT, min_remaining=300) is None
        assert await store.get_ticket(SUBJECT, min_remaining=50) is not None

    async def test_expired_ticket_does_not_hide_the_link(self, store) -> None:
        await _link(store)
        await _store_ticket(store, remaining=-10.0)
        assert await store.get_ticket(SUBJECT) is None
        assert await store.get_link(SUBJECT) is not None

    async def test_records_are_per_subject(self, store) -> None:
        await _link(store, subject="someone-else")
        await _store_ticket(store, subject="someone-else")
        assert await store.get_ticket(SUBJECT) is None
        assert await store.get_link(SUBJECT) is None

    async def test_ticket_without_a_link_round_trips(self, store) -> None:
        """A ticket half can exist with no stored keytab at all — the
        common case (remember=False writes only the ticket half)."""
        await _store_ticket(store)
        record = await store.get_ticket(SUBJECT)
        assert record is not None
        assert record.ccache_b64 is not None
        assert await store.get_link(SUBJECT) is None


# ---------------------------------------------------------------------------
# get_renewable_ticket: the second, later deadline (renew_until)
# ---------------------------------------------------------------------------


class TestRenewableTicket:
    async def test_returns_none_when_nothing_stored(self, store) -> None:
        assert await store.get_renewable_ticket(SUBJECT) is None

    async def test_returns_record_past_not_after_but_within_renew_until(
        self, store
    ) -> None:
        """This is exactly the tier-2 renewal window: not_after has passed
        but renew_until has not — get_ticket says no, get_renewable_ticket
        says yes."""
        await _store_ticket(store, remaining=-10.0, renew_remaining=3600.0)
        assert await store.get_ticket(SUBJECT) is None
        renewable = await store.get_renewable_ticket(SUBJECT)
        assert renewable is not None
        assert renewable.ccache_b64 is not None
        assert renewable.ccache_b64.get_secret_value() == _CCACHE

    async def test_returns_none_once_past_renew_until(self, store) -> None:
        await _store_ticket(store, remaining=-10.0, renew_remaining=-10.0)
        assert await store.get_renewable_ticket(SUBJECT) is None

    async def test_returns_none_when_renew_until_absent(self, store) -> None:
        """A ticket minted before renew_until was ever recorded (or one
        whose service response carried no renewable_lifetime) must not be
        treated as renewable."""
        await _store_ticket(store, remaining=-10.0, renew_remaining=None)
        assert await store.get_renewable_ticket(SUBJECT) is None

    async def test_returns_record_even_when_ticket_is_still_fresh(self, store) -> None:
        """get_renewable_ticket answers purely off renew_until, independent
        of not_after — a fresh ticket with a valid renew_until is still a
        legitimate answer (callers only reach for this accessor once
        get_ticket has already said no, but the method itself makes no such
        assumption)."""
        await _store_ticket(store, remaining=3600.0, renew_remaining=7200.0)
        assert await store.get_renewable_ticket(SUBJECT) is not None


# ---------------------------------------------------------------------------
# clear_ticket
# ---------------------------------------------------------------------------


class TestClearTicket:
    async def test_clear_ticket_removes_ticket_but_keeps_the_link(self, store) -> None:
        await _link(store)
        await _store_ticket(store)
        await store.clear_ticket(SUBJECT)
        assert await store.get_ticket(SUBJECT) is None
        link = await store.get_link(SUBJECT)
        assert link is not None
        assert link.keytab_b64 is not None
        assert link.keytab_b64.get_secret_value() == _KEYTAB

    async def test_clear_ticket_also_clears_renewability(self, store) -> None:
        await _store_ticket(store)
        await store.clear_ticket(SUBJECT)
        assert await store.get_renewable_ticket(SUBJECT) is None

    async def test_clear_ticket_when_nothing_stored_is_a_noop(self, store) -> None:
        await store.clear_ticket(SUBJECT)  # must not raise
        assert await store.get_link(SUBJECT) is None


# ---------------------------------------------------------------------------
# delete (unlink)
# ---------------------------------------------------------------------------


class TestDelete:
    async def test_delete_removes_link_and_ticket(self, store, fake_vault) -> None:
        await _link(store)
        await _store_ticket(store)
        await store.delete(SUBJECT)
        assert await store.get_link(SUBJECT) is None
        assert await store.get_ticket(SUBJECT) is None
        assert fake_vault.entries == {}

    async def test_delete_is_idempotent(self, store) -> None:
        await store.delete(SUBJECT)  # never linked — must not raise

    async def test_relink_after_delete_succeeds(self, store) -> None:
        """delete() must destroy metadata (not soft-delete data) so the next
        store_link's cas=0 create succeeds — same reasoning as
        VaultKV.delete_metadata's docstring."""
        await _link(store)
        await store.delete(SUBJECT)
        await _link(store)
        assert await store.get_link(SUBJECT) is not None


# ---------------------------------------------------------------------------
# CAS behavior
# ---------------------------------------------------------------------------


class TestCas:
    async def test_store_ticket_retries_on_cas_conflict(
        self, store, fake_vault, monkeypatch
    ) -> None:
        """A concurrent writer bumping the version between this store's read
        and write (cross-replica renewal race) must be absorbed by
        re-reading and retrying, not surfaced to the caller."""
        await _link(store)

        original_write_cas = store._vault_kv.write_cas
        raced = {"done": False}

        async def racing_write_cas(path, data, expected_version):
            if not raced["done"]:
                raced["done"] = True
                # Simulate another replica writing first: bump the stored
                # version so this call's expected_version is stale.
                entry = fake_vault.entries[f"{SUBJECT}/krb5"]
                entry["version"] += 1
            return await original_write_cas(path, data, expected_version)

        monkeypatch.setattr(store._vault_kv, "write_cas", racing_write_cas)
        await _store_ticket(store)
        record = await store.get_ticket(SUBJECT)
        assert record is not None

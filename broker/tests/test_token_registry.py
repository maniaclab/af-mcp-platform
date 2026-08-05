"""Tests for the token-registry backends, adapted for identity PATs (issue #144 step 2a; originally issue #115).

Covers the shared ``TokenRegistryBackend`` contract parametrized across both
implementations (``InMemoryTokenRegistryBackend``, ``VaultTokenRegistryBackend``
— the latter against a fake Vault HTTP API via ``httpx.MockTransport``, same
technique as ``test_oauth21_vault.py``), plus ``RevokedJtiCache``'s
refresh/staleness behavior.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest

if TYPE_CHECKING:
    from pathlib import Path

from af_mcp_broker.token_registry import (
    DuplicateNameError,
    InMemoryTokenRegistryBackend,
    RevokedJtiCache,
    SweepStats,
    TokenRecord,
    TokenRegistryBackend,
    VaultTokenRegistryBackend,
)
from af_mcp_broker.vault_kv import VaultKV

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"
KV_PATH_PREFIX = "mcp/token-registry"


def _make_record(**overrides: Any) -> TokenRecord:
    now = time.time()
    defaults: dict[str, Any] = {
        "lookup_id": "lookup-1",
        "principal_id": "kc-subject-1",
        "secret_hash": "deadbeef",
        "name": "claude-desktop",
        "created_at": now,
        "expires_at": now + 3600.0,
        "revoked_at": None,
        "last_used_at": None,
    }
    defaults.update(overrides)
    return TokenRecord(**defaults)


# ---------------------------------------------------------------------------
# Fake Vault KV-v2 HTTP API. Originally get/write_cas only -- the registry
# didn't remove entries, only set revoked_at. sweep_expired() (the expired-
# token janitor) needs LIST (to enumerate by-principal) and DELETE (metadata)
# too, so this fake now mirrors test_vault_kv.py's _FakeVault for those two
# verbs.
# ---------------------------------------------------------------------------


class _FakeRegistryVault:
    def __init__(self, *, login_lease_duration: int = 3600) -> None:
        self.entries: dict[str, dict[str, Any]] = {}
        self.login_calls: list[dict[str, Any]] = []
        self.login_lease_duration = login_lease_duration

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
            body = json.loads(request.content.decode())
            self.login_calls.append(body)
            return httpx.Response(
                200,
                json={
                    "auth": {
                        "client_token": "vault-test-token",
                        "lease_duration": self.login_lease_duration,
                        "renewable": True,
                    }
                },
                request=request,
            )

        data_prefix = f"{KV_MOUNT}/data/"
        meta_prefix = f"{KV_MOUNT}/metadata/"

        if path.startswith(data_prefix):
            key = path[len(data_prefix) :]
            is_metadata = False
        elif path.startswith(meta_prefix):
            key = path[len(meta_prefix) :]
            is_metadata = True
        else:
            return httpx.Response(
                404, json={"errors": ["unknown path"]}, request=request
            )

        if request.method == "GET" and not is_metadata:
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

        if request.method == "LIST" and is_metadata:
            keys = sorted(
                {
                    k[len(key) :].lstrip("/").split("/")[0]
                    for k in self.entries
                    if k.startswith(key)
                }
            )
            if not keys:
                return httpx.Response(404, json={"errors": []}, request=request)
            return httpx.Response(200, json={"data": {"keys": keys}}, request=request)

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


def _make_vault_backend(
    fake: _FakeRegistryVault, sa_token_path: Path
) -> VaultTokenRegistryBackend:
    vault_kv = VaultKV(
        addr=ADDR,
        auth_mount=AUTH_MOUNT,
        auth_role=AUTH_ROLE,
        kv_mount=KV_MOUNT,
        sa_token_path=str(sa_token_path),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)),
    )
    return VaultTokenRegistryBackend(vault_kv=vault_kv, kv_path_prefix=KV_PATH_PREFIX)


# ---------------------------------------------------------------------------
# Shared TokenRegistryBackend contract, parametrized across both backends.
# ---------------------------------------------------------------------------


@pytest.fixture(params=["in_memory", "vault"])
def backend(
    request: pytest.FixtureRequest, sa_token_path: Path
) -> TokenRegistryBackend:
    if request.param == "in_memory":
        return InMemoryTokenRegistryBackend()
    fake = _FakeRegistryVault()
    return _make_vault_backend(fake, sa_token_path)


async def test_list_for_principal_empty_when_nothing_minted(
    backend: TokenRegistryBackend,
) -> None:
    assert await backend.list_for_principal("kc-subject-1") == []


async def test_add_then_list_for_principal_returns_it(
    backend: TokenRegistryBackend,
) -> None:
    record = _make_record()
    await backend.add(record)

    rows = await backend.list_for_principal(record.principal_id)

    assert len(rows) == 1
    assert rows[0].lookup_id == record.lookup_id
    assert rows[0].name == record.name
    assert rows[0].revoked_at is None


async def test_list_for_principal_excludes_other_principals(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(_make_record(lookup_id="mine", principal_id="p1"))
    await backend.add(_make_record(lookup_id="theirs", principal_id="p2"))

    rows = await backend.list_for_principal("p1")

    assert [r.lookup_id for r in rows] == ["mine"]


async def test_get_unknown_lookup_id_returns_none(
    backend: TokenRegistryBackend,
) -> None:
    assert await backend.get("p1", "does-not-exist") is None


async def test_get_returns_record(backend: TokenRegistryBackend) -> None:
    await backend.add(_make_record())
    got = await backend.get("kc-subject-1", "lookup-1")
    assert got is not None
    assert got.lookup_id == "lookup-1"


async def test_owner_principal_id_unknown_lookup_id_returns_none(
    backend: TokenRegistryBackend,
) -> None:
    assert await backend.owner_principal_id("does-not-exist") is None


async def test_owner_principal_id_returns_owning_principal(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p42"))
    assert await backend.owner_principal_id("lookup-1") == "p42"


async def test_revoke_unknown_lookup_id_returns_none(
    backend: TokenRegistryBackend,
) -> None:
    assert await backend.revoke("p1", "does-not-exist", revoked_at=123.0) is None


async def test_revoke_wrong_principal_returns_none(
    backend: TokenRegistryBackend,
) -> None:
    """revoke() is principal-scoped: a lookup_id that exists under a
    *different* principal must not be revocable by passing the wrong
    principal_id -- API-layer ownership checks rely on this (see
    owner_principal_id(), used for the 403-vs-404 distinction)."""
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p1"))

    assert await backend.revoke("p-other", "lookup-1", revoked_at=123.0) is None
    # ... and the record is untouched.
    got = await backend.get("p1", "lookup-1")
    assert got is not None
    assert got.revoked_at is None


async def test_revoke_sets_revoked_at_and_appears_in_list_revoked_jtis(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p1"))

    updated = await backend.revoke("p1", "lookup-1", revoked_at=555.0)

    assert updated is not None
    assert updated.revoked_at == 555.0
    got = await backend.get("p1", "lookup-1")
    assert got is not None
    assert got.revoked_at == 555.0
    assert "lookup-1" in await backend.list_revoked_jtis()


async def test_list_revoked_jtis_excludes_active_tokens(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(
        _make_record(lookup_id="active-lookup", principal_id="p1", name="active-name")
    )
    await backend.add(
        _make_record(lookup_id="revoked-lookup", principal_id="p1", name="revoked-name")
    )
    await backend.revoke("p1", "revoked-lookup", revoked_at=1.0)

    revoked = await backend.list_revoked_jtis()

    assert revoked == frozenset({"revoked-lookup"})


async def test_add_stores_and_returns_note(backend: TokenRegistryBackend) -> None:
    await backend.add(
        _make_record(lookup_id="lookup-1", principal_id="p1", note="for the CI bot")
    )

    rows = await backend.list_for_principal("p1")

    assert len(rows) == 1
    assert rows[0].note == "for the CI bot"


async def test_add_note_absent_by_default(backend: TokenRegistryBackend) -> None:
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p1"))

    rows = await backend.list_for_principal("p1")

    assert rows[0].note is None


# ---------------------------------------------------------------------------
# touch_last_used()
# ---------------------------------------------------------------------------


async def test_touch_last_used_sets_the_field(backend: TokenRegistryBackend) -> None:
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p1"))

    await backend.touch_last_used("p1", "lookup-1", at=999.0)

    got = await backend.get("p1", "lookup-1")
    assert got is not None
    assert got.last_used_at == 999.0


async def test_touch_last_used_unknown_lookup_id_is_a_noop(
    backend: TokenRegistryBackend,
) -> None:
    # Must not raise.
    await backend.touch_last_used("p1", "does-not-exist", at=999.0)


async def test_touch_last_used_wrong_principal_is_a_noop(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p1"))

    await backend.touch_last_used("p-other", "lookup-1", at=999.0)

    got = await backend.get("p1", "lookup-1")
    assert got is not None
    assert got.last_used_at is None


# ---------------------------------------------------------------------------
# Never-expiring records (expires_at=None) -- explicit opt-in per #144.
# ---------------------------------------------------------------------------


async def test_never_expiring_record_round_trips(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(
        _make_record(lookup_id="lookup-1", principal_id="p1", expires_at=None)
    )

    got = await backend.get("p1", "lookup-1")
    assert got is not None
    assert got.expires_at is None


async def test_never_expiring_record_untouched_by_sweep(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(
        _make_record(lookup_id="lookup-1", principal_id="p1", expires_at=None)
    )

    stats = await backend.sweep_expired(grace_seconds=0)

    assert stats.records_removed == 0
    rows = await backend.list_for_principal("p1")
    assert [r.lookup_id for r in rows] == ["lookup-1"]


# ---------------------------------------------------------------------------
# Name uniqueness (per-principal, case-insensitive, dead tokens don't
# collide) -- name is a unique-per-principal identifier, not free text.
# ---------------------------------------------------------------------------


async def test_add_rejects_duplicate_name_for_same_principal(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(
        _make_record(lookup_id="lookup-1", principal_id="p1", name="claude-desktop")
    )

    with pytest.raises(DuplicateNameError):
        await backend.add(
            _make_record(lookup_id="lookup-2", principal_id="p1", name="claude-desktop")
        )

    # The rejected add() must not have been persisted.
    rows = await backend.list_for_principal("p1")
    assert [r.lookup_id for r in rows] == ["lookup-1"]


async def test_add_rejects_duplicate_name_case_insensitively(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(
        _make_record(lookup_id="lookup-1", principal_id="p1", name="Claude-Desktop")
    )

    with pytest.raises(DuplicateNameError):
        await backend.add(
            _make_record(lookup_id="lookup-2", principal_id="p1", name="claude-desktop")
        )


async def test_add_allows_same_name_for_different_principals(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(
        _make_record(lookup_id="lookup-1", principal_id="p1", name="claude-desktop")
    )

    # Must not raise -- uniqueness is per-principal, not global.
    await backend.add(
        _make_record(lookup_id="lookup-2", principal_id="p2", name="claude-desktop")
    )

    rows = await backend.list_for_principal("p2")
    assert [r.lookup_id for r in rows] == ["lookup-2"]


async def test_add_allows_name_that_collides_with_a_revoked_token(
    backend: TokenRegistryBackend,
) -> None:
    """Collisions with dead (revoked or expired) tokens would be confusing to
    reject -- the name is effectively free again once the old token can no
    longer be mistaken for the new one."""
    await backend.add(
        _make_record(lookup_id="lookup-1", principal_id="p1", name="claude-desktop")
    )
    await backend.revoke("p1", "lookup-1", revoked_at=time.time())

    # Must not raise.
    await backend.add(
        _make_record(lookup_id="lookup-2", principal_id="p1", name="claude-desktop")
    )

    rows = await backend.list_for_principal("p1")
    assert {r.lookup_id for r in rows} == {"lookup-1", "lookup-2"}


async def test_add_allows_name_that_collides_with_an_expired_token(
    backend: TokenRegistryBackend,
) -> None:
    now = time.time()
    await backend.add(
        _make_record(
            lookup_id="lookup-1",
            principal_id="p1",
            name="claude-desktop",
            created_at=now - 7200,
            expires_at=now - 3600,
        )
    )

    # Must not raise -- an expired token's name is free again.
    await backend.add(
        _make_record(lookup_id="lookup-2", principal_id="p1", name="claude-desktop")
    )

    rows = [
        r
        for r in await backend.list_for_principal("p1")
        if r.expires_at is None or r.expires_at > now
    ]
    assert [r.lookup_id for r in rows] == ["lookup-2"]


async def test_add_allows_name_that_collides_with_a_never_expiring_but_revoked_token(
    backend: TokenRegistryBackend,
) -> None:
    await backend.add(
        _make_record(
            lookup_id="lookup-1",
            principal_id="p1",
            name="claude-desktop",
            expires_at=None,
        )
    )
    await backend.revoke("p1", "lookup-1", revoked_at=time.time())

    # Must not raise -- revocation frees the name even for a never-expiring
    # record, since expiry alone would never have done so.
    await backend.add(
        _make_record(lookup_id="lookup-2", principal_id="p1", name="claude-desktop")
    )


# ---------------------------------------------------------------------------
# sweep_expired() -- the expired-token janitor (issue #28/#116/#117 chain's
# last layer, adapted for #144). Grace window keeps recently-expired tokens
# visible in the portal as "expired" for a while rather than yanking them the
# instant their expires_at passes.
# ---------------------------------------------------------------------------

_ONE_DAY = 24 * 3600.0


async def test_sweep_removes_record_expired_beyond_grace(
    backend: TokenRegistryBackend,
) -> None:
    now = time.time()
    await backend.add(
        _make_record(
            lookup_id="lookup-1",
            principal_id="p1",
            created_at=now - 10 * _ONE_DAY,
            expires_at=now - 2 * _ONE_DAY,
        )
    )

    stats = await backend.sweep_expired(grace_seconds=int(_ONE_DAY))

    assert stats.records_removed == 1
    assert stats.principals_emptied == 1
    assert await backend.list_for_principal("p1") == []


async def test_sweep_keeps_record_expired_within_grace(
    backend: TokenRegistryBackend,
) -> None:
    now = time.time()
    await backend.add(
        _make_record(
            lookup_id="lookup-1",
            principal_id="p1",
            created_at=now - 2 * _ONE_DAY,
            expires_at=now - 3600,
        )
    )

    stats = await backend.sweep_expired(grace_seconds=int(_ONE_DAY))

    assert stats.records_removed == 0
    assert stats.principals_emptied == 0
    rows = await backend.list_for_principal("p1")
    assert [r.lookup_id for r in rows] == ["lookup-1"]


async def test_sweep_keeps_live_record(backend: TokenRegistryBackend) -> None:
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p1"))

    stats = await backend.sweep_expired(grace_seconds=int(_ONE_DAY))

    assert stats.records_removed == 0
    rows = await backend.list_for_principal("p1")
    assert [r.lookup_id for r in rows] == ["lookup-1"]


async def test_sweep_leaves_revoked_but_live_record_in_denylist(
    backend: TokenRegistryBackend,
) -> None:
    """An expired-but-not-yet-past-grace record that was revoked must not be
    pruned from either the by-principal map or the revoked-lookup-ids
    denylist -- it's still within its display grace window."""
    now = time.time()
    await backend.add(
        _make_record(
            lookup_id="lookup-1",
            principal_id="p1",
            created_at=now - 3600,
            expires_at=now + 3600,
        )
    )
    await backend.revoke("p1", "lookup-1", revoked_at=now)

    stats = await backend.sweep_expired(grace_seconds=int(_ONE_DAY))

    assert stats.records_removed == 0
    assert stats.revoked_pruned == 0
    assert "lookup-1" in await backend.list_revoked_jtis()


async def test_sweep_prunes_revoked_and_expired_from_denylist(
    backend: TokenRegistryBackend,
) -> None:
    """A revoked lookup_id whose own expiry has also passed well past grace
    is dead regardless of revocation -- denylist hygiene so
    revoked-lookup-ids can't grow forever (see token_registry.py's module
    docstring)."""
    now = time.time()
    await backend.add(
        _make_record(
            lookup_id="lookup-1",
            principal_id="p1",
            created_at=now - 10 * _ONE_DAY,
            expires_at=now - 2 * _ONE_DAY,
        )
    )
    await backend.revoke("p1", "lookup-1", revoked_at=now - 2 * _ONE_DAY)

    stats = await backend.sweep_expired(grace_seconds=int(_ONE_DAY))

    assert stats.records_removed == 1
    assert stats.revoked_pruned == 1
    assert "lookup-1" not in await backend.list_revoked_jtis()


async def test_sweep_removes_only_expired_beyond_grace_leaves_others(
    backend: TokenRegistryBackend,
) -> None:
    """A dead record and a live one share a principal -- sweeping must not
    empty the whole principal entry, only the dead record.

    Doesn't assert on ``records_removed`` here: ``InMemoryTokenRegistryBackend``
    self-sweeps (grace=0) on every ``add()``, so its second ``add()`` call
    above already evicted "dead" before ``sweep_expired()`` ever runs --
    covered precisely instead by ``test_sweep_removes_record_expired_beyond_grace``.
    """
    now = time.time()
    await backend.add(
        _make_record(
            lookup_id="dead",
            principal_id="p1",
            created_at=now - 10 * _ONE_DAY,
            expires_at=now - 2 * _ONE_DAY,
        )
    )
    await backend.add(
        _make_record(lookup_id="alive", principal_id="p1", expires_at=now + 3600)
    )

    stats = await backend.sweep_expired(grace_seconds=int(_ONE_DAY))

    assert stats.principals_emptied == 0
    rows = await backend.list_for_principal("p1")
    assert [r.lookup_id for r in rows] == ["alive"]


async def test_sweep_stats_is_a_sweep_stats_instance(
    backend: TokenRegistryBackend,
) -> None:
    stats = await backend.sweep_expired(grace_seconds=int(_ONE_DAY))
    assert isinstance(stats, SweepStats)


async def test_sweep_owners_removed_for_vault_backend(sa_token_path: Path) -> None:
    """Vault-specific: sweeping a by-principal record must also delete its
    lookup-owner index entry -- owner_principal_id() must forget the
    lookup_id once its record is gone, not just leave a dangling ownership
    pointer."""
    fake = _FakeRegistryVault()
    backend = _make_vault_backend(fake, sa_token_path)
    now = time.time()
    await backend.add(
        _make_record(
            lookup_id="lookup-1",
            principal_id="p1",
            created_at=now - 10 * _ONE_DAY,
            expires_at=now - 2 * _ONE_DAY,
        )
    )

    stats = await backend.sweep_expired(grace_seconds=int(_ONE_DAY))

    assert stats.owners_removed == 1
    assert await backend.owner_principal_id("lookup-1") is None


async def test_sweep_emptied_principal_path_can_be_recreated(
    sa_token_path: Path,
) -> None:
    """Vault-specific: emptying a by-principal path must actually delete its
    metadata (not just write an empty dict) so a subsequent add() for that
    principal -- a plain CAS-create (expected_version=None) -- still works,
    exactly the cas=0 recreate semantics vault_kv.delete_metadata's docstring
    describes."""
    fake = _FakeRegistryVault()
    backend = _make_vault_backend(fake, sa_token_path)
    now = time.time()
    await backend.add(
        _make_record(
            lookup_id="lookup-1",
            principal_id="p1",
            created_at=now - 10 * _ONE_DAY,
            expires_at=now - 2 * _ONE_DAY,
        )
    )

    stats = await backend.sweep_expired(grace_seconds=int(_ONE_DAY))
    assert stats.principals_emptied == 1

    # Must not raise -- a stale cached version for the now-destroyed path
    # would surface as a CasConflict on this add()'s create-only write.
    await backend.add(_make_record(lookup_id="lookup-2", principal_id="p1"))
    rows = await backend.list_for_principal("p1")
    assert [r.lookup_id for r in rows] == ["lookup-2"]


# ---------------------------------------------------------------------------
# Vault-specific: HA consistency across two independent backend instances
# sharing the same fake KV (simulating two broker replicas), and "survives
# restart" (a fresh instance against the same fake sees prior writes).
# ---------------------------------------------------------------------------


async def test_mint_on_one_replica_visible_on_another(sa_token_path: Path) -> None:
    fake = _FakeRegistryVault()
    replica_a = _make_vault_backend(fake, sa_token_path)
    replica_b = _make_vault_backend(fake, sa_token_path)

    await replica_a.add(_make_record(lookup_id="lookup-1", principal_id="p1"))

    rows = await replica_b.list_for_principal("p1")
    assert [r.lookup_id for r in rows] == ["lookup-1"]


async def test_revoke_on_one_replica_visible_on_another(sa_token_path: Path) -> None:
    fake = _FakeRegistryVault()
    replica_a = _make_vault_backend(fake, sa_token_path)
    replica_b = _make_vault_backend(fake, sa_token_path)
    await replica_a.add(_make_record(lookup_id="lookup-1", principal_id="p1"))

    await replica_b.revoke("p1", "lookup-1", revoked_at=42.0)

    assert "lookup-1" in await replica_a.list_revoked_jtis()
    got = await replica_a.get("p1", "lookup-1")
    assert got is not None
    assert got.revoked_at == 42.0


async def test_records_survive_reconstructing_the_backend(sa_token_path: Path) -> None:
    """A fresh VaultTokenRegistryBackend pointed at the same fake KV models a
    broker pod restart -- the object is new, but persisted state is not."""
    fake = _FakeRegistryVault()
    backend_before = _make_vault_backend(fake, sa_token_path)
    await backend_before.add(_make_record(lookup_id="lookup-1", principal_id="p1"))

    backend_after = _make_vault_backend(fake, sa_token_path)
    rows = await backend_after.list_for_principal("p1")

    assert [r.lookup_id for r in rows] == ["lookup-1"]


async def test_add_retries_on_concurrent_cas_conflict(sa_token_path: Path) -> None:
    """Two concurrent add() calls for the same principal (different
    lookup_ids) must both succeed -- the read-modify-write CAS loop must
    retry on a version conflict rather than silently dropping one of the two
    writes."""
    fake = _FakeRegistryVault()
    replica_a = _make_vault_backend(fake, sa_token_path)
    replica_b = _make_vault_backend(fake, sa_token_path)

    await asyncio.gather(
        replica_a.add(
            _make_record(lookup_id="lookup-a", principal_id="p1", name="name-a")
        ),
        replica_b.add(
            _make_record(lookup_id="lookup-b", principal_id="p1", name="name-b")
        ),
    )

    rows = await replica_a.list_for_principal("p1")
    assert {r.lookup_id for r in rows} == {"lookup-a", "lookup-b"}


async def test_add_cas_retry_reevaluates_name_uniqueness_against_the_winner(
    sa_token_path: Path,
) -> None:
    """Two replicas racing to mint the *same name* for the same principal: a
    plain check-then-write (read list_for_principal, then add()) would let
    both pass the uniqueness check before either writes. The by-principal
    CAS write forces a loser to retry -- and that retry must re-read the
    winner's data and re-run the uniqueness check against it, not just retry
    the blind write."""
    fake = _FakeRegistryVault()
    replica_a = _make_vault_backend(fake, sa_token_path)
    replica_b = _make_vault_backend(fake, sa_token_path)

    results = await asyncio.gather(
        replica_a.add(
            _make_record(lookup_id="lookup-a", principal_id="p1", name="dup")
        ),
        replica_b.add(
            _make_record(lookup_id="lookup-b", principal_id="p1", name="dup")
        ),
        return_exceptions=True,
    )

    successes = [r for r in results if r is None]
    errors = [r for r in results if isinstance(r, DuplicateNameError)]
    assert len(successes) == 1, results
    assert len(errors) == 1, results

    # Only the winner's record was actually persisted.
    rows = await replica_a.list_for_principal("p1")
    assert len(rows) == 1


async def test_vault_authenticates_once_and_caches_token(sa_token_path: Path) -> None:
    fake = _FakeRegistryVault()
    backend = _make_vault_backend(fake, sa_token_path)

    await backend.add(_make_record())
    await backend.list_for_principal("kc-subject-1")

    assert len(fake.login_calls) == 1
    assert fake.login_calls[0] == {"role": AUTH_ROLE, "jwt": "fake-sa-jwt"}


# ---------------------------------------------------------------------------
# RevokedJtiCache
# ---------------------------------------------------------------------------


class _CountingBackend:
    """Wraps a real backend, counting list_revoked_jtis() calls and
    optionally raising on the next N calls -- for refresh-failure tests."""

    def __init__(self, inner: TokenRegistryBackend) -> None:
        self._inner = inner
        self.refresh_calls = 0
        self.fail_next = 0

    async def list_revoked_jtis(self) -> frozenset[str]:
        self.refresh_calls += 1
        if self.fail_next > 0:
            self.fail_next -= 1
            raise RuntimeError("vault unreachable")
        return await self._inner.list_revoked_jtis()


async def test_is_revoked_false_when_nothing_revoked() -> None:
    backend = InMemoryTokenRegistryBackend()
    cache = RevokedJtiCache(backend, refresh_interval_seconds=30.0)

    assert await cache.is_revoked("anything") is False


async def test_is_revoked_true_after_refresh_picks_up_revocation() -> None:
    backend = InMemoryTokenRegistryBackend()
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p1"))
    await backend.revoke("p1", "lookup-1", revoked_at=1.0)
    cache = RevokedJtiCache(backend, refresh_interval_seconds=30.0)

    assert await cache.is_revoked("lookup-1") is True


async def test_unknown_jti_never_revoked_even_with_no_registry_entry() -> None:
    """Ordinary Keycloak session tokens carry a jti that was never minted
    through the registry at all -- they must never be treated as revoked."""
    backend = InMemoryTokenRegistryBackend()
    await backend.add(_make_record(lookup_id="some-other-lookup", principal_id="p1"))
    cache = RevokedJtiCache(backend, refresh_interval_seconds=30.0)

    assert await cache.is_revoked("a-normal-keycloak-session-jti") is False


async def test_revocation_is_not_visible_until_next_refresh_interval() -> None:
    """Bounded staleness: a revocation that happens between refreshes is not
    picked up until the refresh interval has elapsed."""
    backend = InMemoryTokenRegistryBackend()
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p1"))
    cache = RevokedJtiCache(backend, refresh_interval_seconds=1000.0)

    # Prime the cache before the revocation happens.
    assert await cache.is_revoked("lookup-1") is False

    await backend.revoke("p1", "lookup-1", revoked_at=1.0)

    # Still within the refresh window -- must keep serving the stale (empty) set.
    assert await cache.is_revoked("lookup-1") is False


async def test_refresh_failure_serves_stale_set_instead_of_raising() -> None:
    backend = InMemoryTokenRegistryBackend()
    await backend.add(_make_record(lookup_id="lookup-1", principal_id="p1"))
    await backend.revoke("p1", "lookup-1", revoked_at=1.0)
    counting = _CountingBackend(backend)
    cache = RevokedJtiCache(counting, refresh_interval_seconds=0.0)

    assert await cache.is_revoked("lookup-1") is True  # primes the cache

    counting.fail_next = 1
    # Force a refresh attempt (interval is 0, so every call tries to refresh);
    # the failure must not raise and must not erase the previously-cached set.
    assert await cache.is_revoked("lookup-1") is True

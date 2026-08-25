"""Tests for scripts/migrate-pat-capability-grant.py (one-time OpenBao migration).

The script renames the legacy ``capability_grant`` key to
``permission_grant`` in every stored PAT record (see the fail-closed decode
guard in ``token_registry._record_from_fields`` for why unmigrated scoped
records are denied, never widened, until this runs). Tested against the same
fake Vault KV-v2 HTTP API as ``test_token_registry.py`` -- the script drives
the broker's own ``VaultKV`` transport, never raw HTTP.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from test_token_registry import (
    KV_PATH_PREFIX,
    _FakeRegistryVault,
    _make_vault_backend,
)


@pytest.fixture
def sa_token_path(tmp_path: Path) -> Path:
    path = tmp_path / "sa-token"
    path.write_text("fake-sa-jwt\n")
    return path

_SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "migrate-pat-capability-grant.py"
)


def _load_script() -> Any:
    spec = importlib.util.spec_from_file_location("migrate_pat_grant", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: @dataclass resolves the defining module through
    # sys.modules, which a bare module_from_spec object isn't in yet.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _fields(lookup_id: str, **extra: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "lookup_id": lookup_id,
        "principal_id": "p1",
        "secret_hash": "deadbeef",
        "name": f"pat-{lookup_id}",
        "created_at": 1000.0,
        "expires_at": None,
        "revoked_at": None,
        "last_used_at": None,
        "note": None,
    }
    fields.update(extra)
    return fields


def _seed(fake: _FakeRegistryVault, principal_id: str, *records: dict[str, Any]) -> None:
    fake.entries[f"{KV_PATH_PREFIX}/by-principal/{principal_id}"] = {
        "data": {fields["lookup_id"]: fields for fields in records},
        "version": 1,
    }


def _stored(fake: _FakeRegistryVault, principal_id: str) -> dict[str, Any]:
    return fake.entries[f"{KV_PATH_PREFIX}/by-principal/{principal_id}"]["data"]


async def test_apply_migrates_scoped_record(sa_token_path: Path) -> None:
    script = _load_script()
    fake = _FakeRegistryVault()
    _seed(fake, "p1", _fields("scoped", capability_grant=["read_data", "admin"]))
    backend = _make_vault_backend(fake, sa_token_path)

    stats = await script.migrate(
        backend._vault_kv, KV_PATH_PREFIX, apply=True  # noqa: SLF001
    )

    fields = _stored(fake, "p1")["scoped"]
    assert fields["permission_grant"] == ["read_data", "admin"]
    assert "capability_grant" not in fields
    assert stats.migrated == 1
    assert stats.skipped_unknown == 0


async def test_apply_migrates_null_record_preserving_null(
    sa_token_path: Path,
) -> None:
    script = _load_script()
    fake = _FakeRegistryVault()
    _seed(fake, "p1", _fields("unscoped", capability_grant=None))
    backend = _make_vault_backend(fake, sa_token_path)

    stats = await script.migrate(
        backend._vault_kv, KV_PATH_PREFIX, apply=True  # noqa: SLF001
    )

    fields = _stored(fake, "p1")["unscoped"]
    assert fields["permission_grant"] is None
    assert "capability_grant" not in fields
    assert stats.unscoped_null == 1
    assert stats.migrated == 0


async def test_already_migrated_record_is_counted_and_untouched(
    sa_token_path: Path,
) -> None:
    script = _load_script()
    fake = _FakeRegistryVault()
    _seed(fake, "p1", _fields("done", permission_grant=["read_data"]))
    backend = _make_vault_backend(fake, sa_token_path)

    stats = await script.migrate(
        backend._vault_kv, KV_PATH_PREFIX, apply=True  # noqa: SLF001
    )

    fields = _stored(fake, "p1")["done"]
    assert fields["permission_grant"] == ["read_data"]
    # Idempotent: no write happened, so the version is still the seeded one.
    assert (
        fake.entries[f"{KV_PATH_PREFIX}/by-principal/p1"]["version"] == 1
    )
    assert stats.already_migrated == 1
    assert stats.migrated == 0


async def test_record_with_both_keys_is_refused_untouched(
    sa_token_path: Path,
) -> None:
    script = _load_script()
    fake = _FakeRegistryVault()
    _seed(
        fake,
        "p1",
        _fields("weird", capability_grant=["a"], permission_grant=["b"]),
        _fields("scoped", capability_grant=["read_data"]),
    )
    backend = _make_vault_backend(fake, sa_token_path)

    stats = await script.migrate(
        backend._vault_kv, KV_PATH_PREFIX, apply=True  # noqa: SLF001
    )

    weird = _stored(fake, "p1")["weird"]
    assert weird["capability_grant"] == ["a"]
    assert weird["permission_grant"] == ["b"]
    # The healthy record in the same document still migrates.
    scoped = _stored(fake, "p1")["scoped"]
    assert scoped["permission_grant"] == ["read_data"]
    assert "capability_grant" not in scoped
    assert stats.skipped_unknown == 1
    assert stats.migrated == 1


async def test_dry_run_writes_nothing(sa_token_path: Path) -> None:
    script = _load_script()
    fake = _FakeRegistryVault()
    _seed(fake, "p1", _fields("scoped", capability_grant=["read_data"]))
    backend = _make_vault_backend(fake, sa_token_path)

    stats = await script.migrate(
        backend._vault_kv, KV_PATH_PREFIX, apply=False  # noqa: SLF001
    )

    fields = _stored(fake, "p1")["scoped"]
    assert fields["capability_grant"] == ["read_data"]
    assert "permission_grant" not in fields
    assert fake.entries[f"{KV_PATH_PREFIX}/by-principal/p1"]["version"] == 1
    # The dry run still reports what WOULD change.
    assert stats.migrated == 1

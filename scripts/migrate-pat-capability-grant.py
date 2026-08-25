"""One-time OpenBao migration: rename stored PAT ``capability_grant`` to ``permission_grant``.

The capability -> permission rename changed the key every PAT record stores
its grant under. Until a record is rewritten, the fail-closed guard in
``token_registry._record_from_fields`` decodes an unmigrated *scoped* record
as deny-all (never as unrestricted -- see that guard's docstring), so the
deploy -> migrate window denies scoped PATs rather than widening them. Run
this once per deployment, inside a broker pod (which already carries the
Vault env), e.g.:

    kubectl exec deploy/af-mcp-platform-broker -- \
        python /app/scripts/migrate-pat-capability-grant.py            # dry run
    kubectl exec deploy/af-mcp-platform-broker -- \
        python /app/scripts/migrate-pat-capability-grant.py --apply

Builds ``Settings`` from the environment and drives the broker's own
``VaultKV`` transport (same construction as ``token_sweep.py``) -- never raw
HTTP -- so it cannot drift from the registry's KV layout. Dry-run is the
default; ``--apply`` executes. Idempotent: already-migrated records are
counted and skipped, and a record with BOTH keys or an unrecognizable grant
shape is reported and left untouched.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass

import structlog

from af_mcp_broker.config import Settings
from af_mcp_broker.logging import configure_logging
from af_mcp_broker.vault_kv import CasConflict, VaultError, VaultKV

log = structlog.get_logger(__name__)

# Same bounded CAS retry budget as token_registry's read-modify-write loops.
_MAX_CAS_RETRIES = 5


@dataclass
class MigrationStats:
    """Counts for the final summary: what one migration pass did (or, on a dry run, would do)."""

    migrated: int = 0
    already_migrated: int = 0
    unscoped_null: int = 0
    skipped_unknown: int = 0


def _migrate_record(
    principal_id: str, lookup_id: str, fields: dict, stats: MigrationStats
) -> bool:
    """Rewrite one record's grant key in place; return True if *fields* changed.

    Counts the record into *stats* either way. Refuses (reports, doesn't
    touch) a record carrying BOTH keys or a ``capability_grant`` that is
    neither null nor a list -- those need a human, not a blind rewrite.
    """
    has_legacy = "capability_grant" in fields
    has_current = "permission_grant" in fields

    if has_legacy and has_current:
        log.warning(
            "migrate.refused_both_keys",
            principal_id=principal_id,
            lookup_id=lookup_id,
        )
        stats.skipped_unknown += 1
        return False

    if not has_legacy:
        # Already keyed permission_grant (or predates the grant field
        # entirely, which decodes identically before and after): nothing to
        # rename.
        stats.already_migrated += 1
        return False

    grant = fields["capability_grant"]
    if grant is not None and not isinstance(grant, list):
        log.warning(
            "migrate.refused_unknown_shape",
            principal_id=principal_id,
            lookup_id=lookup_id,
            grant_type=type(grant).__name__,
        )
        stats.skipped_unknown += 1
        return False

    log.info(
        "migrate.record",
        principal_id=principal_id,
        lookup_id=lookup_id,
        change=f"capability_grant -> permission_grant (value: {grant!r})",
    )
    fields["permission_grant"] = fields.pop("capability_grant")
    if grant is None:
        stats.unscoped_null += 1
    else:
        stats.migrated += 1
    return True


async def migrate(
    vault_kv: VaultKV, kv_path_prefix: str, *, apply: bool
) -> MigrationStats:
    """Run one migration pass over every by-principal document; return the counts."""
    stats = MigrationStats()
    prefix = kv_path_prefix.strip("/")
    by_principal = f"{prefix}/by-principal"

    for principal_id in await vault_kv.list(by_principal):
        path = f"{by_principal}/{principal_id}"
        for _attempt in range(_MAX_CAS_RETRIES):
            current = await vault_kv.get(path)
            if current is None:
                break
            data, version = current
            # Fresh stats per CAS attempt so a retried document isn't
            # double-counted; folded into the pass total only on success.
            doc_stats = MigrationStats()
            data = {
                lookup_id: dict(fields) for lookup_id, fields in data.items()
            }
            changed = False
            for lookup_id, fields in data.items():
                changed |= _migrate_record(principal_id, lookup_id, fields, doc_stats)
            if changed and apply:
                try:
                    await vault_kv.write_cas(path, data, version)
                except CasConflict:
                    log.info("migrate.cas_retry", principal_id=principal_id)
                    continue
            stats.migrated += doc_stats.migrated
            stats.already_migrated += doc_stats.already_migrated
            stats.unscoped_null += doc_stats.unscoped_null
            stats.skipped_unknown += doc_stats.skipped_unknown
            break
        else:
            raise VaultError(
                f"migrate(): exceeded retry budget for principal_id={principal_id!r}"
            )

    return stats


async def _run(settings: Settings, *, apply: bool) -> int:
    """Run one migration pass; return the process exit code."""
    if settings.token_registry_backend != "vault":
        log.error(
            "migrate.refused",
            reason=(
                f"TOKEN_REGISTRY_BACKEND is {settings.token_registry_backend!r}, "
                "not 'vault' -- InMemoryTokenRegistryBackend holds no persisted "
                "records to migrate."
            ),
        )
        return 2

    vault_kv = VaultKV(
        addr=settings.vault_addr,
        auth_mount=settings.vault_auth_mount,
        auth_role=settings.vault_auth_role,
        kv_mount=settings.vault_kv_mount,
        sa_token_path=settings.vault_sa_token_path,
    )
    try:
        stats = await migrate(
            vault_kv, settings.token_registry_kv_path_prefix, apply=apply
        )
    except VaultError:
        log.exception("migrate.failed")
        return 1

    log.info(
        "migrate.completed",
        mode="apply" if apply else "dry-run (nothing written; pass --apply)",
        migrated=stats.migrated,
        already_migrated=stats.already_migrated,
        unscoped_null=stats.unscoped_null,
        skipped_unknown=stats.skipped_unknown,
    )
    # Refused records deserve a nonzero exit so a scripted rollout notices.
    return 1 if stats.skipped_unknown else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write the renamed records back (default: dry run, print only)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="explicitly request the default print-only mode",
    )
    args = parser.parse_args()
    if args.apply and args.dry_run:
        parser.error("--apply and --dry-run are mutually exclusive")
    settings = Settings()
    configure_logging(settings.log_level)
    sys.exit(asyncio.run(_run(settings, apply=args.apply)))


if __name__ == "__main__":
    main()

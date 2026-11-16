"""CLI entrypoint for the expired-token sweep (issue #28 -> #116 -> #117's last layer).

Runnable as ``python -m af_mcp_broker.token_sweep``, meant to be invoked by
the ``CronJob`` in ``charts/af-mcp-platform/templates/cronjob-token-sweep.yaml``
on a schedule. Builds ``Settings`` from the environment exactly like
``app.py``'s lifespan does, constructs the same ``VaultKV`` transport +
``VaultTokenRegistryBackend`` the broker process itself uses, and runs one
``TokenRegistryBackend.sweep_expired()`` pass.

``InMemoryTokenRegistryBackend`` needs no cron: it already self-sweeps
expired records inline on every ``add()`` (see ``token_registry.py``), since
it's just an in-process dict with no external TTL of its own. Only the
Vault-backed registry accumulates state across broker restarts/replicas that
nothing else ever prunes -- see that module's docstring. This refuses to run
at all when ``TOKEN_REGISTRY_BACKEND`` isn't ``"vault"``, rather than
silently doing nothing.
"""

from __future__ import annotations

import asyncio
import sys
from contextlib import AsyncExitStack
from dataclasses import asdict
from typing import TYPE_CHECKING

import structlog

from af_mcp_broker.config import Settings
from af_mcp_broker.logging import configure_logging
from af_mcp_broker.token_registry import VaultTokenRegistryBackend
from af_mcp_broker.vault_kv import VaultError, VaultKV
from af_mcp_broker.wiring.http_client import build_http_client

if TYPE_CHECKING:
    import httpx2

log = structlog.get_logger(__name__)


def _build_vault_backend(
    settings: Settings, http_client: httpx2.AsyncClient
) -> VaultTokenRegistryBackend:
    vault_kv = VaultKV(
        addr=settings.vault_addr,
        auth_mount=settings.vault_auth_mount,
        auth_role=settings.vault_auth_role,
        kv_mount=settings.vault_kv_mount,
        sa_token_path=settings.vault_sa_token_path,
        http_client=http_client,
    )
    return VaultTokenRegistryBackend(
        vault_kv=vault_kv,
        kv_path_prefix=settings.vault_kv_paths.token_registry,
    )


async def _run(settings: Settings) -> int:
    """Run one sweep pass; return the process exit code."""
    if settings.token_registry_backend != "vault":  # noqa: S105 -- backend selector name, not a secret
        log.error(
            "token_sweep.refused",
            reason=(
                f"TOKEN_REGISTRY_BACKEND is {settings.token_registry_backend!r}, "
                "not 'vault' -- InMemoryTokenRegistryBackend self-sweeps inline "
                "on every add() and needs no cron (see token_registry.py)."
            ),
        )
        return 2

    async with AsyncExitStack() as stack:
        backend = _build_vault_backend(settings, build_http_client(stack))
        try:
            stats = await backend.sweep_expired(
                grace_seconds=settings.token_sweep_grace_seconds
            )
        except VaultError:
            log.exception("token_sweep.failed")
            return 1

    log.info(
        "token_sweep.completed",
        grace_seconds=settings.token_sweep_grace_seconds,
        **asdict(stats),
    )
    return 0


def main() -> None:
    settings = Settings()
    configure_logging(settings.log_level)
    sys.exit(asyncio.run(_run(settings)))


if __name__ == "__main__":
    main()

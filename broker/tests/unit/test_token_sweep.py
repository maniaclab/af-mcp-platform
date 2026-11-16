"""Tests for token_sweep.py, the expired-token sweep's CLI entrypoint (issue
#28 -> #116 -> #117's last layer).

``_run()`` is the testable core -- unlike ``main()`` it doesn't call
``configure_logging()`` (which rewrites the root logger's handlers and would
swallow pytest's caplog, see test_health.py's
``test_startup_warns_on_no_backends`` for the same issue), so these spy on
the module logger directly, same technique.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx2
from vault_fakes import ADDR, AUTH_MOUNT, AUTH_ROLE, KV_MOUNT, FakeVault

from af_mcp_broker import token_sweep
from af_mcp_broker.config import Settings
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

KV_PATH_PREFIX = "mcp/token-registry"


def _patch_vault_kv(monkeypatch: pytest.MonkeyPatch, fake: FakeVault) -> None:
    """Make token_sweep's VaultKV construction route through *fake* instead
    of a real HTTP connection, by injecting a MockTransport-backed client."""
    real_vault_kv = VaultKV

    def _factory(**kwargs: Any) -> VaultKV:
        kwargs["http_client"] = httpx2.AsyncClient(
            transport=httpx2.MockTransport(fake.handle)
        )
        return real_vault_kv(**kwargs)

    monkeypatch.setattr(token_sweep, "VaultKV", _factory)


def _vault_settings(sa_token_path: Path, **overrides: Any) -> Settings:
    defaults: dict[str, Any] = {
        "token_registry_backend": "vault",
        "vault_addr": ADDR,
        "vault_auth_mount": AUTH_MOUNT,
        "vault_auth_role": AUTH_ROLE,
        "vault_kv_mount": KV_MOUNT,
        "vault_kv_root": "mcp",
        "vault_sa_token_path": str(sa_token_path),
    }
    defaults.update(overrides)
    return Settings(**defaults)


# ---------------------------------------------------------------------------
# Wrong-backend refusal
# ---------------------------------------------------------------------------


async def test_run_refuses_when_backend_not_vault() -> None:
    settings = Settings(token_registry_backend="in_memory")

    exit_code = await token_sweep._run(settings)

    assert exit_code == 2


async def test_run_refusal_logs_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    original_error = token_sweep.log.error

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append(event)
        return original_error(event, **kwargs)

    monkeypatch.setattr(token_sweep.log, "error", _capture)
    settings = Settings(token_registry_backend="in_memory")

    await token_sweep._run(settings)

    assert "token_sweep.refused" in events


# ---------------------------------------------------------------------------
# Successful sweep: stats log line
# ---------------------------------------------------------------------------


async def test_run_returns_zero_on_success(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    fake = FakeVault()
    _patch_vault_kv(monkeypatch, fake)
    settings = _vault_settings(sa_token_path)

    exit_code = await token_sweep._run(settings)

    assert exit_code == 0


async def test_run_logs_sweep_stats_on_success(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    fake = FakeVault()
    _patch_vault_kv(monkeypatch, fake)
    settings = _vault_settings(sa_token_path)

    logged: list[dict[str, Any]] = []
    original_info = token_sweep.log.info

    def _capture(event: str, **kwargs: Any) -> Any:
        logged.append({"event": event, **kwargs})
        return original_info(event, **kwargs)

    monkeypatch.setattr(token_sweep.log, "info", _capture)

    await token_sweep._run(settings)

    completed = [row for row in logged if row["event"] == "token_sweep.completed"]
    assert len(completed) == 1
    assert completed[0]["records_removed"] == 0
    assert completed[0]["owners_removed"] == 0
    assert completed[0]["principals_emptied"] == 0
    assert completed[0]["grace_seconds"] == settings.token_sweep_grace_seconds


# ---------------------------------------------------------------------------
# VaultError -> nonzero exit
# ---------------------------------------------------------------------------


async def test_run_returns_nonzero_on_vault_error(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    fake = FakeVault(kv_status=500)
    _patch_vault_kv(monkeypatch, fake)
    settings = _vault_settings(sa_token_path)

    exit_code = await token_sweep._run(settings)

    assert exit_code != 0


async def test_run_logs_failure_on_vault_error(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    fake = FakeVault(kv_status=500)
    _patch_vault_kv(monkeypatch, fake)
    settings = _vault_settings(sa_token_path)

    events: list[str] = []
    original_exception = token_sweep.log.exception

    def _capture(event: str, **kwargs: Any) -> Any:
        events.append(event)
        return original_exception(event, **kwargs)

    monkeypatch.setattr(token_sweep.log, "exception", _capture)

    await token_sweep._run(settings)

    assert "token_sweep.failed" in events

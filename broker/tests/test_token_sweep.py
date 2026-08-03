"""Tests for token_sweep.py, the expired-token sweep's CLI entrypoint (issue
#28 -> #116 -> #117's last layer).

``_run()`` is the testable core -- unlike ``main()`` it doesn't call
``configure_logging()`` (which rewrites the root logger's handlers and would
swallow pytest's caplog, see test_health.py's
``test_startup_warns_on_no_backends`` for the same issue), so these spy on
the module logger directly, same technique.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from af_mcp_broker import token_sweep
from af_mcp_broker.config import Settings
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from pathlib import Path

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"
KV_PATH_PREFIX = "mcp/token-registry"


# ---------------------------------------------------------------------------
# Fake Vault KV-v2 HTTP API -- same shape as test_token_registry.py's
# _FakeRegistryVault (GET/POST/LIST/DELETE), plus an injectable status code
# to simulate a Vault-side failure for the VaultError exit-code test.
# ---------------------------------------------------------------------------


class _FakeVault:
    def __init__(
        self, *, login_lease_duration: int = 3600, kv_status: int | None = None
    ) -> None:
        self.entries: dict[str, dict[str, Any]] = {}
        self.login_lease_duration = login_lease_duration
        self.kv_status = kv_status

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
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

        if self.kv_status is not None:
            return httpx.Response(
                self.kv_status, json={"errors": ["internal error"]}, request=request
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


def _patch_vault_kv(monkeypatch: pytest.MonkeyPatch, fake: _FakeVault) -> None:
    """Make token_sweep's VaultKV construction route through *fake* instead
    of a real HTTP connection, by injecting a MockTransport-backed client."""
    real_vault_kv = VaultKV

    def _factory(**kwargs: Any) -> VaultKV:
        kwargs["http_client"] = httpx.AsyncClient(
            transport=httpx.MockTransport(fake.handle)
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
        "token_registry_kv_path_prefix": KV_PATH_PREFIX,
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
    fake = _FakeVault()
    _patch_vault_kv(monkeypatch, fake)
    settings = _vault_settings(sa_token_path)

    exit_code = await token_sweep._run(settings)

    assert exit_code == 0


async def test_run_logs_sweep_stats_on_success(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    fake = _FakeVault()
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
    assert completed[0]["revoked_pruned"] == 0
    assert completed[0]["uids_emptied"] == 0
    assert completed[0]["grace_seconds"] == settings.token_sweep_grace_seconds


# ---------------------------------------------------------------------------
# VaultError -> nonzero exit
# ---------------------------------------------------------------------------


async def test_run_returns_nonzero_on_vault_error(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    fake = _FakeVault(kv_status=500)
    _patch_vault_kv(monkeypatch, fake)
    settings = _vault_settings(sa_token_path)

    exit_code = await token_sweep._run(settings)

    assert exit_code != 0


async def test_run_logs_failure_on_vault_error(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    fake = _FakeVault(kv_status=500)
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

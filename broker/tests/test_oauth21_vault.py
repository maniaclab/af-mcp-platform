"""Tests for the Vault-backed ``TokenStore`` (issue #66 PR3).

A fake Vault HTTP API is built with ``httpx.MockTransport`` -- no real Vault
process, no ``hvac``. Covers the Kubernetes auth login/re-auth flow, KV-v2
CAS read/write/delete semantics, the ``SecretStr`` round trip through
storage, and error mapping.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from af_mcp_broker.config import get_settings
from af_mcp_broker.credentials.oauth21 import StoredOAuthCredential, VersionConflict
from af_mcp_broker.credentials.vault import VaultError, VaultTokenStore

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"
KV_PATH_PREFIX = "mcp/tokens"

SUBJECT = "kc-subject-123"
ALIAS = "rucio-mcp-atlas"


def _make_cred(**overrides: Any) -> StoredOAuthCredential:
    now = datetime.now(UTC)
    defaults: dict[str, Any] = {
        "alias": ALIAS,
        "subject": SUBJECT,
        "access_token": SecretStr("access-token-1"),
        "refresh_token": SecretStr("refresh-token-1"),
        "expires_at": now + timedelta(hours=1),
        "refresh_expires_at": now + timedelta(days=30),
        "scope": ["openid", "profile"],
        "issuer": "https://backend-as.example",
        "token_endpoint": "https://backend-as.example/token",
    }
    defaults.update(overrides)
    return StoredOAuthCredential(**defaults)


class _FakeVault:
    """In-memory fake of the subset of Vault's HTTP API this store uses.

    ``entries`` maps ``(subject, alias)`` -> ``{"data": dict, "version": int}``.
    A key absent from ``entries`` behaves as Vault does for a path that has
    never been written to *or* whose metadata has been destroyed: GET 404s,
    and a CAS write with ``cas=0`` succeeds (current version is 0). The
    broker only ever destroys via the metadata endpoint (never a bare
    soft-delete on ``data``), so collapsing "destroyed" and "never written"
    into one absent-key state matches exactly what production code exercises.
    """

    def __init__(
        self, *, login_lease_duration: int = 3600, kv_status: int | None = None
    ):
        self.entries: dict[tuple[str, str], dict[str, Any]] = {}
        self.login_calls: list[dict[str, Any]] = []
        self.login_lease_duration = login_lease_duration
        # When set, every KV data/metadata request responds with this status
        # instead of running the normal CAS logic -- for error-mapping tests.
        self.kv_status = kv_status

    def _kv_key_from_path(self, path: str) -> tuple[str, str] | None:
        # path looks like "secret/data/mcp/tokens/<subject>/<alias>" or
        # "secret/metadata/mcp/tokens/<subject>/<alias>".
        prefix = f"{KV_MOUNT}/data/{KV_PATH_PREFIX}/"
        meta_prefix = f"{KV_MOUNT}/metadata/{KV_PATH_PREFIX}/"
        if path.startswith(prefix):
            rest = path[len(prefix) :]
        elif path.startswith(meta_prefix):
            rest = path[len(meta_prefix) :]
        else:
            return None
        subject, _, alias = rest.partition("/")
        return subject, alias

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
            body = _json_body(request)
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

        key = self._kv_key_from_path(path)
        if key is None:
            return httpx.Response(
                404, json={"errors": ["unknown path"]}, request=request
            )

        if self.kv_status is not None:
            return httpx.Response(
                self.kv_status, json={"errors": ["internal error"]}, request=request
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
            body = _json_body(request)
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


def _json_body(request: httpx.Request) -> dict[str, Any]:
    import json

    return json.loads(request.content.decode())


def _make_store(
    fake: _FakeVault, sa_token_path: Path, **overrides: Any
) -> VaultTokenStore:
    kwargs: dict[str, Any] = {
        "addr": ADDR,
        "auth_mount": AUTH_MOUNT,
        "auth_role": AUTH_ROLE,
        "kv_mount": KV_MOUNT,
        "kv_path_prefix": KV_PATH_PREFIX,
        "sa_token_path": str(sa_token_path),
        "http_client": httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)),
    }
    kwargs.update(overrides)
    return VaultTokenStore(**kwargs)


@pytest.fixture
def sa_token_path(tmp_path: Path) -> Path:
    path = tmp_path / "sa-token"
    path.write_text("fake-sa-jwt\n")
    return path


# ---------------------------------------------------------------------------
# K8s auth: login, caching, re-authentication
# ---------------------------------------------------------------------------


async def test_authenticate_reads_sa_jwt_and_logs_in(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)

    token = await store._authenticate()

    assert token == "vault-test-token"
    assert len(fake.login_calls) == 1
    assert fake.login_calls[0] == {"role": AUTH_ROLE, "jwt": "fake-sa-jwt"}


async def test_authenticate_caches_token_across_calls(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)

    await store._authenticate()
    await store._authenticate()

    assert len(fake.login_calls) == 1


async def test_authenticate_reauthenticates_when_near_expiry(
    sa_token_path: Path,
) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)

    await store._authenticate()
    assert len(fake.login_calls) == 1

    # Force the cached token to look like it's within the safety margin of
    # expiry (or already past it) without needing to sleep in the test.
    store._expires_at = datetime.now(UTC) - timedelta(seconds=1)

    await store._authenticate()
    assert len(fake.login_calls) == 2


async def test_authenticate_concurrent_callers_login_once(sa_token_path: Path) -> None:
    """The asyncio.Lock around re-authentication must prevent a login storm
    when multiple coroutines race to authenticate with no cached token yet.
    """
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)

    await asyncio.gather(*(store._authenticate() for _ in range(5)))

    assert len(fake.login_calls) == 1


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------


async def test_get_returns_none_on_404(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)

    assert await store.get(SUBJECT, ALIAS) is None


async def test_get_round_trips_secret_str_values(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)
    cred = _make_cred()

    await store.write_cas(SUBJECT, ALIAS, cred, expected_version=None)
    got = await store.get(SUBJECT, ALIAS)

    assert got is not None
    got_cred, version = got
    assert version == 1
    assert got_cred.access_token.get_secret_value() == "access-token-1"
    assert got_cred.refresh_token is not None
    assert got_cred.refresh_token.get_secret_value() == "refresh-token-1"
    assert got_cred.alias == ALIAS
    assert got_cred.subject == SUBJECT

    # The wire payload must never carry pydantic's masked SecretStr rendering.
    stored_data = fake.entries[(SUBJECT, ALIAS)]["data"]
    assert stored_data["access_token"] == "access-token-1"
    assert stored_data["refresh_token"] == "refresh-token-1"


# ---------------------------------------------------------------------------
# write_cas() CAS semantics
# ---------------------------------------------------------------------------


async def test_write_cas_none_creates_when_missing(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)

    version = await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    assert version == 1


async def test_write_cas_none_conflicts_when_existing(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    with pytest.raises(VersionConflict):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)


async def test_write_cas_with_matching_version_succeeds(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)  # v1

    version = await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(access_token=SecretStr("access-token-2")),
        expected_version=1,
    )

    assert version == 2


async def test_write_cas_with_stale_version_conflicts(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)  # v1
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=1)  # v2

    with pytest.raises(VersionConflict):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=1)


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


async def test_delete_existing_then_get_returns_none(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    await store.delete(SUBJECT, ALIAS)

    assert await store.get(SUBJECT, ALIAS) is None


async def test_delete_then_write_cas_none_succeeds_again(sa_token_path: Path) -> None:
    """The metadata-endpoint delete must fully reset the version counter, or
    a subsequent create (``expected_version=None`` -> ``cas=0``) would fail
    forever against Vault's soft-delete semantics.
    """
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    await store.delete(SUBJECT, ALIAS)

    version = await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    assert version == 1


async def test_delete_nonexistent_is_idempotent(sa_token_path: Path) -> None:
    fake = _FakeVault()
    store = _make_store(fake, sa_token_path)

    await store.delete(SUBJECT, ALIAS)  # must not raise


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


async def test_get_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = _FakeVault(kv_status=500)
    store = _make_store(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await store.get(SUBJECT, ALIAS)


async def test_write_cas_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = _FakeVault(kv_status=500)
    store = _make_store(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)


async def test_delete_raises_vault_error_on_5xx(sa_token_path: Path) -> None:
    fake = _FakeVault(kv_status=500)
    store = _make_store(fake, sa_token_path)

    with pytest.raises(VaultError, match="vault"):
        await store.delete(SUBJECT, ALIAS)


# ---------------------------------------------------------------------------
# App startup wiring: trial authentication fails fast on Vault misconfig.
# ---------------------------------------------------------------------------

_SRC = Path(__file__).resolve().parents[1] / "src" / "af_mcp_broker"
SHIPPED_POLICY = _SRC / "authorization" / "policy.yaml"
SHIPPED_BACKENDS = _SRC / "mcp" / "backends.yaml"
STATE_ISSUER = "https://keycloak.invalid/realms/connect"
CIMD_CLIENT_ID = "https://mcp.af.uchicago.edu/.well-known/cimd"


def _bootstrap_oauth21_vault_env(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    monkeypatch.setenv("POLICY_FILE", str(SHIPPED_POLICY))
    monkeypatch.setenv("BACKENDS_FILE", str(SHIPPED_BACKENDS))
    monkeypatch.setenv("METRICS_PORT", "0")
    monkeypatch.setenv("OIDC_ISSUER", STATE_ISSUER)
    monkeypatch.setenv("BROKER_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OAUTH21_CLIENT_ID", CIMD_CLIENT_ID)
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp-portal.example.com")
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "oauth21-direct",
                    "alias": ALIAS,
                    "targets": [ALIAS],
                    "authorization_endpoint": "https://backend-as.example/authorize",
                    "token_endpoint": "https://backend-as.example/token",
                    "issuer": "https://backend-as.example",
                }
            ]
        ),
    )
    monkeypatch.setenv("TOKEN_STORE_BACKEND", "vault")
    monkeypatch.setenv("VAULT_ADDR", ADDR)
    monkeypatch.setenv("VAULT_AUTH_ROLE", AUTH_ROLE)
    monkeypatch.setenv("VAULT_SA_TOKEN_PATH", str(sa_token_path))


def _fresh_app() -> Any:
    from af_mcp_broker.app import app as broker_app

    get_settings.cache_clear()
    broker_app.dependency_overrides.clear()
    return broker_app


def test_lifespan_boots_with_vault_backend_on_successful_trial_auth(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    _bootstrap_oauth21_vault_env(monkeypatch, sa_token_path)
    fake = _FakeVault()
    monkeypatch.setattr(
        "af_mcp_broker.credentials.vault.get_http_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)),
    )

    app = _fresh_app()
    with TestClient(app):
        assert isinstance(app.state.oauth21_token_store, VaultTokenStore)
    assert len(fake.login_calls) == 1


def test_lifespan_fails_fast_when_vault_login_rejected(
    monkeypatch: pytest.MonkeyPatch, sa_token_path: Path
) -> None:
    _bootstrap_oauth21_vault_env(monkeypatch, sa_token_path)

    def _reject_login(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403, json={"errors": ["permission denied"]}, request=request
        )

    monkeypatch.setattr(
        "af_mcp_broker.credentials.vault.get_http_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(_reject_login)),
    )

    app = _fresh_app()
    with pytest.raises(RuntimeError, match="Vault"), TestClient(app):
        pass

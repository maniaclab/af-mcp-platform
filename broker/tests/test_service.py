"""Unit tests for ServiceProvider.

ServiceProvider uses the broker's own shared service credential, not any
per-user linkage, so is_linked() is always True regardless of the principal.
The service token itself comes from an env var, a mounted file, or a
client_credentials grant; the grant is exercised against an
``httpx2.MockTransport`` standing in for Keycloak's token endpoint.
"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

import httpx2
import jwt
import pytest
import structlog
from pydantic import SecretStr

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials.base import CredentialKind, ExecutionModel
from af_mcp_broker.credentials.service import ServiceProvider
from af_mcp_broker.principal import Principal

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import AuditBuffer


def _principal() -> Principal:
    return Principal(
        subject="user-123",
        email="user@example.org",
        uid=50123,
        gid=5000,
        unixname="auser",
        groups=["af-atlas-users"],
        raw_token=SecretStr("fake-token"),
    )


@pytest.mark.asyncio
async def test_is_linked_always_true():
    provider = ServiceProvider(
        settings=SimpleNamespace(), http_client=httpx2.AsyncClient()
    )

    assert await provider.is_linked(_principal()) is True


@pytest.mark.asyncio
async def test_client_credentials_grant_uses_internal_url_when_set(monkeypatch):
    """The service-account token grant is a server-side call and must follow
    oidc_internal_url, not the externally-advertised issuer."""
    captured_urls: list[str] = []

    class _FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, object]:
            return {"access_token": "svc-token", "expires_in": 3600}

    class _UrlCapturingClient:
        async def post(self, url: str, **kwargs: object) -> _FakeResponse:
            captured_urls.append(url)
            return _FakeResponse()

    monkeypatch.delenv("AF_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AF_SERVICE_TOKEN_FILE", raising=False)
    monkeypatch.setenv("AF_SERVICE_CLIENT_ID", "svc-client")
    monkeypatch.setenv("AF_SERVICE_CLIENT_SECRET", "svc-secret")

    internal = "http://keycloak.svc.test:8080/realms/connect"
    provider = ServiceProvider(
        settings=Settings(
            oidc_issuer="https://keycloak.test/realms/connect",
            oidc_internal_url=internal,
        ),
        http_client=_UrlCapturingClient(),
    )
    token, _expires_at = await provider._refresh_service_token()

    assert token == "svc-token"
    assert captured_urls == [f"{internal}/protocol/openid-connect/token"]


_ISSUER = "https://keycloak.test/realms/connect"
_TOKEN_URL = f"{_ISSUER}/protocol/openid-connect/token"
_NOW = 2_000_000.0


@pytest.fixture(autouse=True)
def _no_service_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test with no service credential source configured."""
    for var in (
        "AF_SERVICE_TOKEN",
        "AF_SERVICE_TOKEN_FILE",
        "AF_SERVICE_CLIENT_ID",
        "AF_SERVICE_CLIENT_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def now(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Controllable ``time.time``; mutate ``now[0]`` to move the clock."""
    clock = [_NOW]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    return clock


class _FakeKeycloak:
    """Token-endpoint test double: records requests, replies per ``reply``."""

    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []
        self.status = 200
        self.body: dict[str, object] = {"access_token": "svc-token", "expires_in": 3600}
        self.delay = 0.0

    async def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        await asyncio.sleep(self.delay)
        return httpx2.Response(self.status, json=self.body, request=request)


@pytest.fixture
def keycloak() -> _FakeKeycloak:
    return _FakeKeycloak()


def _provider(keycloak: _FakeKeycloak, *, issuer: str = _ISSUER) -> ServiceProvider:
    return ServiceProvider(
        settings=Settings(oidc_issuer=issuer),
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(keycloak.handle)),
    )


def _use_client_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AF_SERVICE_CLIENT_ID", "svc-client")
    monkeypatch.setenv("AF_SERVICE_CLIENT_SECRET", "svc-secret")


class TestTokenSourcePriority:
    async def test_env_token_is_used_without_calling_keycloak(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        monkeypatch.setenv("AF_SERVICE_TOKEN", "env-token")
        _use_client_credentials(monkeypatch)

        token, expires_at = await _provider(keycloak)._refresh_service_token()

        assert token == "env-token"
        assert expires_at is None
        assert keycloak.requests == []

    async def test_env_token_wins_over_the_token_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        tmp_path: Path,
    ) -> None:
        token_file = tmp_path / "token"
        token_file.write_text("file-token")
        monkeypatch.setenv("AF_SERVICE_TOKEN", "env-token")
        monkeypatch.setenv("AF_SERVICE_TOKEN_FILE", str(token_file))

        token, _ = await _provider(keycloak)._refresh_service_token()

        assert token == "env-token"

    async def test_empty_env_token_falls_through_to_the_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        tmp_path: Path,
    ) -> None:
        token_file = tmp_path / "token"
        token_file.write_text("file-token")
        monkeypatch.setenv("AF_SERVICE_TOKEN", "")
        monkeypatch.setenv("AF_SERVICE_TOKEN_FILE", str(token_file))

        token, _ = await _provider(keycloak)._refresh_service_token()

        assert token == "file-token"

    async def test_token_file_is_stripped_and_wins_over_client_credentials(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        tmp_path: Path,
        now: list[float],
    ) -> None:
        token_file = tmp_path / "token"
        token_file.write_text("  file-token\n")
        monkeypatch.setenv("AF_SERVICE_TOKEN_FILE", str(token_file))
        _use_client_credentials(monkeypatch)

        token, expires_at = await _provider(keycloak)._refresh_service_token()

        assert token == "file-token"
        assert expires_at is None
        assert keycloak.requests == []

    async def test_empty_env_token_file_variable_falls_through_to_client_credentials(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak
    ) -> None:
        monkeypatch.setenv("AF_SERVICE_TOKEN_FILE", "")
        _use_client_credentials(monkeypatch)

        token, _ = await _provider(keycloak)._refresh_service_token()

        assert token == "svc-token"
        assert len(keycloak.requests) == 1


class TestTokenSourceFailures:
    async def test_missing_token_file_raises(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("AF_SERVICE_TOKEN_FILE", str(tmp_path / "absent"))

        with pytest.raises(FileNotFoundError):
            await _provider(keycloak)._refresh_service_token()

    async def test_token_file_is_not_silently_replaced_by_client_credentials(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("AF_SERVICE_TOKEN_FILE", str(tmp_path / "absent"))
        _use_client_credentials(monkeypatch)

        with pytest.raises(FileNotFoundError):
            await _provider(keycloak)._refresh_service_token()

        assert keycloak.requests == []

    @pytest.mark.parametrize("contents", ["", "  \n"])
    async def test_blank_token_file_raises_instead_of_issuing_an_empty_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        tmp_path: Path,
        contents: str,
    ) -> None:
        token_file = tmp_path / "token"
        token_file.write_text(contents)
        monkeypatch.setenv("AF_SERVICE_TOKEN_FILE", str(token_file))

        with pytest.raises(RuntimeError, match="empty"):
            await _provider(keycloak)._refresh_service_token()

    async def test_no_source_configured_raises_naming_every_option(
        self, keycloak: _FakeKeycloak
    ) -> None:
        with pytest.raises(RuntimeError, match="No AF service credential") as excinfo:
            await _provider(keycloak)._refresh_service_token()

        for name in (
            "AF_SERVICE_TOKEN",
            "AF_SERVICE_TOKEN_FILE",
            "AF_SERVICE_CLIENT_ID",
            "AF_SERVICE_CLIENT_SECRET",
        ):
            assert name in str(excinfo.value)
        assert keycloak.requests == []

    @pytest.mark.parametrize(
        ("client_id", "client_secret"),
        [("svc-client", None), (None, "svc-secret"), ("", "svc-secret"), ("c", "")],
    )
    async def test_incomplete_client_credentials_raise_without_calling_keycloak(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        client_id: str | None,
        client_secret: str | None,
    ) -> None:
        if client_id is not None:
            monkeypatch.setenv("AF_SERVICE_CLIENT_ID", client_id)
        if client_secret is not None:
            monkeypatch.setenv("AF_SERVICE_CLIENT_SECRET", client_secret)

        with pytest.raises(RuntimeError, match="No AF service credential"):
            await _provider(keycloak)._refresh_service_token()

        assert keycloak.requests == []


class TestClientCredentialsGrant:
    async def test_posts_the_grant_as_a_form_to_the_token_endpoint(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak
    ) -> None:
        _use_client_credentials(monkeypatch)

        await _provider(keycloak)._refresh_service_token()

        (request,) = keycloak.requests
        assert request.method == "POST"
        assert str(request.url) == _TOKEN_URL
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        assert parse_qs(request.content.decode()) == {
            "grant_type": ["client_credentials"],
            "client_id": ["svc-client"],
            "client_secret": ["svc-secret"],
        }

    async def test_trailing_slash_on_the_realm_url_is_not_doubled(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak
    ) -> None:
        _use_client_credentials(monkeypatch)

        await _provider(keycloak, issuer=f"{_ISSUER}/")._refresh_service_token()

        assert str(keycloak.requests[0].url) == _TOKEN_URL

    async def test_expiry_comes_from_expires_in(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        keycloak.body = {"access_token": "t", "expires_in": 120}

        token, expires_at = await _provider(keycloak)._refresh_service_token()

        assert token == "t"
        assert expires_at == _NOW + 120

    async def test_missing_expires_in_defaults_to_five_minutes(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        keycloak.body = {"access_token": "t"}

        _, expires_at = await _provider(keycloak)._refresh_service_token()

        assert expires_at == _NOW + 300

    async def test_string_expires_in_is_coerced(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        keycloak.body = {"access_token": "t", "expires_in": "90"}

        _, expires_at = await _provider(keycloak)._refresh_service_token()

        assert expires_at == _NOW + 90

    @pytest.mark.parametrize("status", [400, 401, 500, 503])
    async def test_http_error_status_raises(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, status: int
    ) -> None:
        _use_client_credentials(monkeypatch)
        keycloak.status = status

        with pytest.raises(httpx2.HTTPStatusError):
            await _provider(keycloak)._refresh_service_token()

    async def test_response_without_access_token_raises(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak
    ) -> None:
        _use_client_credentials(monkeypatch)
        keycloak.body = {"expires_in": 60}

        with pytest.raises(KeyError, match="access_token"):
            await _provider(keycloak)._refresh_service_token()


class TestServiceTokenCaching:
    async def test_token_is_reused_while_comfortably_valid(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        provider = _provider(keycloak)

        first = await provider._get_service_token()
        now[0] += 3600 - 61
        second = await provider._get_service_token()

        assert first == second == "svc-token"
        assert len(keycloak.requests) == 1

    async def test_token_within_the_refresh_buffer_is_refreshed(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        provider = _provider(keycloak)
        await provider._get_service_token()

        keycloak.body = {"access_token": "rotated", "expires_in": 3600}
        now[0] += 3600 - 60  # exactly the buffer: no longer "remaining > buffer"
        token = await provider._get_service_token()

        assert token == "rotated"
        assert len(keycloak.requests) == 2

    async def test_expired_token_is_refreshed(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        provider = _provider(keycloak)
        await provider._get_service_token()

        keycloak.body = {"access_token": "rotated", "expires_in": 3600}
        now[0] += 7200
        token = await provider._get_service_token()

        assert token == "rotated"
        assert provider._service_token_expires_at == _NOW + 7200 + 3600

    async def test_concurrent_callers_share_one_refresh(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        keycloak.delay = 0.05
        provider = _provider(keycloak)

        tokens = await asyncio.gather(
            *(provider._get_service_token() for _ in range(5))
        )

        assert tokens == ["svc-token"] * 5
        assert len(keycloak.requests) == 1

    async def test_failed_refresh_is_retried_by_the_next_caller(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        provider = _provider(keycloak)
        keycloak.status = 503
        with pytest.raises(httpx2.HTTPStatusError):
            await provider._get_service_token()

        keycloak.status = 200
        token = await provider._get_service_token()

        assert token == "svc-token"
        assert len(keycloak.requests) == 2

    async def test_failed_refresh_does_not_discard_the_cached_token_bookkeeping(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        provider = _provider(keycloak)
        await provider._get_service_token()
        expires_at = provider._service_token_expires_at

        now[0] += 3600
        keycloak.status = 500
        with pytest.raises(httpx2.HTTPStatusError):
            await provider._get_service_token()

        assert provider._service_token == "svc-token"
        assert provider._service_token_expires_at == expires_at

    async def test_a_token_that_expires_inside_the_buffer_is_refreshed_every_time(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        keycloak.body = {"access_token": "short", "expires_in": 30}
        provider = _provider(keycloak)

        await provider._get_service_token()
        await provider._get_service_token()

        assert len(keycloak.requests) == 2


class TestIssue:
    async def test_issues_a_bearer_credential_backed_by_the_service_token(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        keycloak.body = {"access_token": "svc-token", "expires_in": 1800}

        cred = await _provider(keycloak).issue(_principal(), "docs")

        assert cred.cred_class == "service_account"
        assert cred.target == "docs"
        assert cred.kind is CredentialKind.BEARER
        assert cred.source == "af_service_account"
        assert cred.execution_model is ExecutionModel.ON_BEHALF
        assert cred.expires_at == _NOW + 1800
        assert cred.payload == {
            "access_token": "svc-token",
            "on_behalf_of": "user@example.org",
            "token_type": "Bearer",
        }

    async def test_issuance_writes_an_audit_line_naming_the_real_user(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        audit_buffer: AuditBuffer,
        now: list[float],
    ) -> None:
        _use_client_credentials(monkeypatch)

        cred = await _provider(keycloak).issue(_principal(), "monitoring")

        lines = [json.loads(line) for line in audit_buffer.getvalue().splitlines()]
        (audit,) = [line for line in lines if line["event"] == "audit"]
        assert audit["principal_sub"] == "user-123"
        assert audit["principal_uid"] == 50123
        assert audit["permission"] == "service_account"
        assert audit["target"] == "monitoring"
        assert audit["action"] == "credential.issued"
        assert audit["action_type"] == "state_change"
        assert audit["args_summary"] == "on_behalf_of=user@example.org username=auser"
        assert audit["audit_id"] == cred.audit_id
        assert audit["request_id"] == cred.audit_id
        assert audit["execution_model"] == "on_behalf"
        assert audit["outcome"] == "success"
        assert audit["recorded_at"].startswith("1970-01-24T")

    async def test_audit_names_a_principal_without_posix_identity(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        audit_buffer: AuditBuffer,
    ) -> None:
        _use_client_credentials(monkeypatch)
        principal = Principal(
            subject="user-9",
            email="n@example.org",
            uid=None,
            gid=None,
            unixname=None,
            groups=[],
            raw_token=SecretStr("t"),
        )

        await _provider(keycloak).issue(principal, "docs")

        lines = [json.loads(line) for line in audit_buffer.getvalue().splitlines()]
        (audit,) = [line for line in lines if line["event"] == "audit"]
        assert audit["principal_uid"] is None
        assert audit["args_summary"] == (
            "on_behalf_of=n@example.org username=<no-posix-identity>"
        )

    async def test_each_issuance_gets_its_own_audit_id_but_shares_the_token(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        provider = _provider(keycloak)

        first = await provider.issue(_principal(), "docs")
        second = await provider.issue(_principal(), "metadata")

        assert first.audit_id != second.audit_id
        assert first.payload["access_token"] == second.payload["access_token"]
        assert len(keycloak.requests) == 1

    async def test_no_credential_is_issued_when_no_service_token_is_configured(
        self, keycloak: _FakeKeycloak, audit_buffer: AuditBuffer
    ) -> None:
        with pytest.raises(RuntimeError, match="No AF service credential"):
            await _provider(keycloak).issue(_principal(), "docs")

        assert audit_buffer.getvalue() == ""


def _jwt(**claims: object) -> str:
    """An HS256 JWT; the broker never verifies a static token's signature."""
    return jwt.encode(claims, "irrelevant-signing-key-0123456789", algorithm="HS256")


class TestMinRemainingSeconds:
    async def test_cached_token_with_less_than_requested_is_refreshed(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        provider = _provider(keycloak)
        await provider.issue(_principal(), "docs")

        keycloak.body = {"access_token": "rotated", "expires_in": 3600}
        now[0] += 3600 - 61  # 61 s left: above the refresh buffer, below 300 s
        cred = await provider.issue(_principal(), "docs", min_remaining_seconds=300)

        assert cred.payload["access_token"] == "rotated"
        assert cred.expires_at == _NOW + 3600 - 61 + 3600
        assert len(keycloak.requests) == 2

    async def test_cached_token_with_enough_remaining_is_reused(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        provider = _provider(keycloak)
        await provider.issue(_principal(), "docs")

        now[0] += 3600 - 301
        await provider.issue(_principal(), "docs", min_remaining_seconds=300)

        assert len(keycloak.requests) == 1

    async def test_fresh_token_that_still_falls_short_is_returned_like_other_providers(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        _use_client_credentials(monkeypatch)
        keycloak.body = {"access_token": "short", "expires_in": 120}

        cred = await _provider(keycloak).issue(
            _principal(), "docs", min_remaining_seconds=300
        )

        assert cred.payload["access_token"] == "short"
        assert cred.expires_at == _NOW + 120


class TestStaticTokenExpiry:
    async def test_jwt_exp_claim_is_the_expiry(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        token = _jwt(exp=int(_NOW) + 7200)
        monkeypatch.setenv("AF_SERVICE_TOKEN", token)

        got, expires_at = await _provider(keycloak)._refresh_service_token()

        assert got == token
        assert expires_at == _NOW + 7200

    async def test_jwt_exp_claim_is_read_from_a_token_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        tmp_path: Path,
        now: list[float],
    ) -> None:
        token_file = tmp_path / "token"
        token_file.write_text(_jwt(exp=int(_NOW) + 900) + "\n")
        monkeypatch.setenv("AF_SERVICE_TOKEN_FILE", str(token_file))

        _, expires_at = await _provider(keycloak)._refresh_service_token()

        assert expires_at == _NOW + 900

    async def test_issued_credential_carries_the_jwt_expiry(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        monkeypatch.setenv("AF_SERVICE_TOKEN", _jwt(exp=int(_NOW) + 7200))

        cred = await _provider(keycloak).issue(_principal(), "docs")

        assert cred.expires_at == _NOW + 7200

    async def test_expired_jwt_fails_clearly_and_issues_nothing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        audit_buffer: AuditBuffer,
        now: list[float],
    ) -> None:
        monkeypatch.setenv("AF_SERVICE_TOKEN", _jwt(exp=int(_NOW) - 1))

        with pytest.raises(RuntimeError, match="expired"):
            await _provider(keycloak).issue(_principal(), "docs")

        assert audit_buffer.getvalue() == ""

    async def test_expired_jwt_in_a_token_file_fails_clearly(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keycloak: _FakeKeycloak,
        tmp_path: Path,
        now: list[float],
    ) -> None:
        token_file = tmp_path / "token"
        token_file.write_text(_jwt(exp=int(_NOW) - 1))
        monkeypatch.setenv("AF_SERVICE_TOKEN_FILE", str(token_file))

        with pytest.raises(RuntimeError, match="expired"):
            await _provider(keycloak).issue(_principal(), "docs")

    async def test_jwt_without_exp_is_non_expiring_and_warns_once(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        monkeypatch.setenv("AF_SERVICE_TOKEN", _jwt(sub="svc"))
        provider = _provider(keycloak)

        with structlog.testing.capture_logs() as logs:
            first = await provider.issue(_principal(), "docs")
            now[0] += 10 * 365 * 86400
            second = await provider.issue(_principal(), "docs")

        assert first.expires_at is None
        assert second.expires_at is None
        warnings = [e for e in logs if e["event"] == "service.token.static_no_expiry"]
        assert len(warnings) == 1
        assert warnings[0]["log_level"] == "warning"

    async def test_opaque_token_is_non_expiring_and_warns_once(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        monkeypatch.setenv("AF_SERVICE_TOKEN", "opaque-token")
        provider = _provider(keycloak)

        with structlog.testing.capture_logs() as logs:
            first = await provider.issue(_principal(), "docs")
            second = await provider.issue(_principal(), "docs")

        assert first.expires_at is None
        assert second.payload["access_token"] == "opaque-token"
        warnings = [e for e in logs if e["event"] == "service.token.static_no_expiry"]
        assert len(warnings) == 1
        assert "opaque-token" not in str(warnings)

    async def test_static_jwt_nearing_expiry_is_still_handed_out_until_it_expires(
        self, monkeypatch: pytest.MonkeyPatch, keycloak: _FakeKeycloak, now: list[float]
    ) -> None:
        monkeypatch.setenv("AF_SERVICE_TOKEN", _jwt(exp=int(_NOW) + 120))
        provider = _provider(keycloak)

        cred = await provider.issue(_principal(), "docs", min_remaining_seconds=300)

        assert cred.expires_at == _NOW + 120
        now[0] += 121
        with pytest.raises(RuntimeError, match="expired"):
            await provider.issue(_principal(), "docs")

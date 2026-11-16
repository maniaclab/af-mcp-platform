"""Unit tests for the area ``test_domain_error_edges.py`` covers; the integration tests live in ``integration/test_domain_error_edges.py``."""

from __future__ import annotations

import json

import httpx2
import pytest
from broker_state_helpers import asgi_auth_middleware
from conftest import make_claims
from domain_error_edges_support import (  # noqa: F401
    _CONDOR_RATE_LIMITED_DETAIL,
    _CREDENTIAL_FAILURES,
    _IDS,
    _OAUTH21_EXPIRED,
    _OAUTH21_NOT_STORED,
    _OAUTH21_REFRESH_FAILED,
    _OAUTH21_REJECTED,
    _OIDC_401,
    _OIDC_403,
    _OIDC_404,
    _POSIX_REQUIRED_BROKER_ISSUED,
    _POSIX_REQUIRED_CONDOR,
    _RATE_LIMITED_RESPONSES,
    _broker_issued_no_posix,
    _condor_exchange_producer,
    _condor_no_posix,
    _condor_provider,
    _KeycloakStatusClient,
    _oauth21_expired_without_refresh,
    _oauth21_not_stored,
    _oauth21_refresh_rejected,
    _oauth21_rejected,
    _oidc_producer,
    _raised,
    _UnreachableJwksClient,
    unreachable_jwks_fixture,
)
from fastmcp.exceptions import ToolError
from test_mcp_aggregator import _OPEN_POLICY, _FakeProvider, _patch_context, _spec
from test_mcp_middleware_identity import (
    _header,
    _http_scope,
    _InnerApp,
    _run,
    _status,
)
from test_request_logging import _capturing_info

from af_mcp_broker import retry_after as retry_after_module
from af_mcp_broker.credentials import (
    CredentialRegistry,
)
from af_mcp_broker.mcp.aggregator import _make_client_factory


@pytest.mark.parametrize(
    ("producer", "status_code", "detail", "headers"),
    [row[1:] for row in _CREDENTIAL_FAILURES],
    ids=_IDS,
)
async def test_mcp_edge_surfaces_the_credential_failure_detail_as_a_tool_error(
    producer, status_code, detail, headers, make_principal, settings, monkeypatch
) -> None:
    exc = await producer(make_principal)
    _patch_context(monkeypatch, make_principal())
    spec = _spec(auth_type="bearer")
    registry = CredentialRegistry()
    registry.register(spec.name, _FakeProvider(http_error=exc))  # type: ignore[arg-type]

    with pytest.raises(ToolError) as excinfo:
        await _make_client_factory(spec, registry, settings, _OPEN_POLICY)()

    assert str(excinfo.value) == detail


@pytest.mark.parametrize(("response", "retry_after"), _RATE_LIMITED_RESPONSES)
async def test_mcp_edge_puts_the_credential_429_wait_in_the_tool_error(
    response, retry_after, make_principal, settings, monkeypatch
) -> None:
    exc = await _condor_exchange_producer(response)(make_principal)
    _patch_context(monkeypatch, make_principal())
    spec = _spec(auth_type="bearer")
    registry = CredentialRegistry()
    registry.register(spec.name, _FakeProvider(http_error=exc))  # type: ignore[arg-type]

    with pytest.raises(ToolError) as excinfo:
        await _make_client_factory(spec, registry, settings, _OPEN_POLICY)()

    assert str(excinfo.value).startswith(
        f"{_CONDOR_RATE_LIMITED_DETAIL} Retry-After: {retry_after} seconds; retry_at: "
    )


async def test_mcp_edge_logs_the_dedicated_event_for_a_credential_429(
    make_principal, settings, monkeypatch
) -> None:
    principal = make_principal()
    exc = await _condor_exchange_producer(
        httpx2.Response(429, headers={"Retry-After": "17"})
    )(make_principal)
    _patch_context(monkeypatch, principal)
    spec = _spec(auth_type="bearer")
    registry = CredentialRegistry()
    registry.register(spec.name, _FakeProvider(http_error=exc))  # type: ignore[arg-type]
    events = _capturing_info(monkeypatch, retry_after_module.logger)

    with pytest.raises(ToolError):
        await _make_client_factory(spec, registry, settings, _OPEN_POLICY)()

    [event] = events
    assert event["event"] == "rate_limit.exceeded"
    assert event["subject"] == principal.subject
    assert event["limiter"] == "credential_service"
    assert event["retry_after_seconds"] == 17


async def test_mcp_edge_collapses_an_unreachable_jwks_into_the_vague_401(
    settings, sig_key, unreachable_jwks
) -> None:
    token = sig_key.sign(make_claims())
    inner = _InnerApp()
    middleware = asgi_auth_middleware(inner, settings, http_client=unreachable_jwks)

    messages = await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    assert not inner.called
    assert _status(messages) == 401
    assert _header(messages, "www-authenticate") == "Bearer"
    body = json.loads(
        b"".join(m["body"] for m in messages if m["type"] == "http.response.body")
    )
    assert body["detail"] == "Invalid bearer token"

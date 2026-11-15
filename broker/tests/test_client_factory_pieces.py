from __future__ import annotations

from typing import Any

import pytest
from fastapi import HTTPException
from fastmcp.exceptions import ToolError
from test_mcp_aggregator import (
    _FakeFastMCPContext,
    _FakeProvider,
    _make_issuer,
    _patch_context,
    _spec,
)

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.backend_errors import NotLinkedForListingError
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.credentials.errors import NeedsUnlockError
from af_mcp_broker.mcp.aggregator import (
    _bearer_call_client,
    _bearer_factory,
    _bearer_list_client,
    _identity_token_call_client,
    _identity_token_factory,
    _is_authorized_call,
    _issue_call_credential,
    _LinkGate,
    _make_client_factory,
)

_OPEN_POLICY = EntitlementPolicy()


def _gate(
    settings: Any, provider: _FakeProvider | None = None, **spec_overrides: Any
) -> _LinkGate:
    spec = _spec(**spec_overrides)
    registry = CredentialRegistry()
    if provider is not None:
        registry.register(spec.name, provider)
    return _LinkGate(spec, registry, settings, None, None)


class TestLinkGate:
    async def test_returns_provider_and_principal_for_a_linked_caller(
        self, settings: Any, make_principal
    ) -> None:
        principal = make_principal()
        provider = _FakeProvider()
        ctx = _FakeFastMCPContext(principal, "example")

        got_provider, got_principal = await _gate(settings, provider).authorize(ctx)

        assert got_provider is provider
        assert got_principal is principal

    async def test_fails_closed_without_a_principal(self, settings: Any) -> None:
        ctx = _FakeFastMCPContext(None, "example")

        with pytest.raises(ToolError, match="No authenticated principal"):
            await _gate(settings, _FakeProvider()).authorize(ctx)

    async def test_unregistered_service_is_a_tool_error(
        self, settings: Any, make_principal
    ) -> None:
        ctx = _FakeFastMCPContext(make_principal(), "example")

        with pytest.raises(ToolError):
            await _gate(settings).authorize(ctx)

    async def test_unlinked_caller_is_stopped_before_anything_is_minted(
        self, settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _FakeProvider(linked=False)
        ctx = _patch_context(monkeypatch, make_principal(), supports_elicitation=False)

        with pytest.raises(ToolError, match="not linked"):
            await _gate(settings, provider).authorize(ctx)

        assert provider.issue_calls == []


class TestIsAuthorizedCall:
    @pytest.mark.parametrize(
        ("active_backend", "expected"),
        [("example", True), ("other", False), (None, False)],
    )
    async def test_matches_only_the_target_service(
        self, active_backend: str | None, expected: bool
    ) -> None:
        ctx = _FakeFastMCPContext(None, active_backend)

        assert await _is_authorized_call(ctx, _spec()) is expected


class TestIssueCallCredential:
    async def test_returns_the_providers_credential(
        self, settings: Any, make_principal
    ) -> None:
        cred = await _issue_call_credential(
            _FakeProvider(token="t1"), make_principal(), _spec(), settings
        )

        assert cred.payload["access_token"] == "t1"

    async def test_needs_unlock_names_the_portal_endpoint(
        self, settings: Any, make_principal
    ) -> None:
        provider = _FakeProvider(
            needs_unlock=NeedsUnlockError(
                "example", "no cached proxy", unlock_endpoint="/v1/unlock/x"
            )
        )

        with pytest.raises(ToolError, match="/v1/unlock/x"):
            await _issue_call_credential(provider, make_principal(), _spec(), settings)

    async def test_http_exception_detail_is_surfaced(
        self, settings: Any, make_principal
    ) -> None:
        provider = _FakeProvider(
            http_error=HTTPException(status_code=401, detail="session expired")
        )

        with pytest.raises(ToolError, match="session expired"):
            await _issue_call_credential(provider, make_principal(), _spec(), settings)


class TestBearerCallClient:
    async def test_injects_the_minted_token(
        self, settings: Any, make_principal
    ) -> None:
        ctx = _FakeFastMCPContext(make_principal(), "example")
        gate = _gate(settings, _FakeProvider(token="minted-1"))

        client = await _bearer_call_client(ctx, gate)

        assert client.transport.headers["Authorization"] == "Bearer minted-1"


class TestBearerListClient:
    async def test_records_the_credential_status_per_service(
        self, settings: Any, make_principal
    ) -> None:
        ctx = _FakeFastMCPContext(make_principal(), None)
        spec = _spec()
        registry = CredentialRegistry()
        registry.register(spec.name, _FakeProvider(token="list-1"))

        client = await _bearer_list_client(ctx, spec, registry, _OPEN_POLICY)

        assert client.transport.headers["Authorization"] == "Bearer list-1"
        assert ctx.recorded_state["__list_credential_status__:example"] == (True, None)

    async def test_unlinked_caller_gets_no_listing(
        self, settings: Any, make_principal
    ) -> None:
        ctx = _FakeFastMCPContext(make_principal(), None)
        spec = _spec()
        registry = CredentialRegistry()
        registry.register(spec.name, _FakeProvider(linked=False))

        with pytest.raises(NotLinkedForListingError):
            await _bearer_list_client(ctx, spec, registry, _OPEN_POLICY)


class TestIdentityTokenCallClient:
    async def test_injects_a_broker_identity_token_for_the_service_audience(
        self, settings: Any, make_principal
    ) -> None:
        issuer = _make_issuer()
        ctx = _FakeFastMCPContext(make_principal(), "example")
        gate = _gate(settings, _FakeProvider(), auth_type="x509")

        client = await _identity_token_call_client(ctx, gate, issuer)

        header = client.transport.headers["Authorization"]
        assert header.startswith("Bearer ")
        assert header != "Bearer minted-token"

    async def test_unlinked_caller_never_gets_a_token(
        self, settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = _patch_context(monkeypatch, make_principal(), supports_elicitation=False)
        gate = _gate(settings, _FakeProvider(linked=False), auth_type="x509")

        with pytest.raises(ToolError, match="not linked"):
            await _identity_token_call_client(ctx, gate, _make_issuer())


class TestFactoryDispatch:
    async def test_identity_token_factory_lists_without_the_authorized_signal(
        self, settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = _patch_context(monkeypatch, make_principal(), active_backend=None)
        gate = _gate(settings, _FakeProvider(), auth_type="x509")

        client = await _identity_token_factory(gate, _OPEN_POLICY, _make_issuer())()

        assert client.transport.headers["Authorization"].startswith("Bearer ")
        assert ctx.recorded_state["__list_credential_status__:example"] == (True, None)

    async def test_bearer_factory_mints_on_an_authorized_call(
        self, settings: Any, make_principal, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_context(monkeypatch, make_principal())
        gate = _gate(settings, _FakeProvider(token="call-1"))

        client = await _bearer_factory(gate, _OPEN_POLICY)()

        assert client.transport.headers["Authorization"] == "Bearer call-1"

    @pytest.mark.parametrize("auth_type", ["x509", "krb5", "servicex"])
    def test_identity_token_auth_types_require_a_signing_issuer(
        self, settings: Any, auth_type: str
    ) -> None:
        with pytest.raises(Exception, match=auth_type):
            _make_client_factory(
                _spec(auth_type=auth_type),
                CredentialRegistry(),
                settings,
                _OPEN_POLICY,
            )

    def test_none_auth_type_builds_without_a_context(self, settings: Any) -> None:
        factory = _make_client_factory(
            _spec(auth_type="none"), CredentialRegistry(), settings, _OPEN_POLICY
        )

        assert factory().transport.headers == {}

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import mcp_types
import pytest
import structlog.testing
from conftest import (
    AUDIENCE,
    ISSUER,
    make_claims,
    run_aggregator_async,
    run_inprocess_server,
)
from cryptography.fernet import Fernet
from fastmcp import Client, FastMCP
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_headers
from fastmcp.tools.base import ToolResult
from mcp.shared.exceptions import MCPError
from pydantic import SecretStr

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import (
    CredentialKind,
    CredentialProvider,
    CredentialRegistry,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.credentials.errors import NeedsUnlockError
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.input_required import (
    InputRequiredState,
    InvalidInputRequiredStateError,
)
from af_mcp_broker.mcp.middleware import authorization_mw
from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from fastmcp.utilities.tests import ASGIServer

    from af_mcp_broker.audit import AuditRecord
    from af_mcp_broker.identity import Principal

# ---------------------------------------------------------------------------
# End-to-end coverage for delivering "go to the portal" prompts through MCP
# multi-round-trip results (SEP-2322): a real toy backend in-process, real
# signed JWTs, real fastmcp clients (modern and legacy protocol era), and a
# real build_aggregator() stack with only the credential provider faked.
# ---------------------------------------------------------------------------

# The wire text a client without SEP-2322 support has always received.
_NOT_LINKED_TEXT = "FakeProvider not linked. Visit "
_UNLOCK_TEXT = "Credential unlock required. Visit the portal: "
_UNLOCK_ENDPOINT = "/v1/x509/proxy"


class _FakeProvider(CredentialProvider):
    """Mints a deterministic token; link, rejection and unlock state are flags the tests flip, standing in for the shared token store."""

    cred_class = "fake"
    execution_model = ExecutionModel.DELEGATED

    def __init__(
        self,
        *,
        linked: bool = True,
        rejected: bool = False,
        needs_unlock: bool = False,
    ) -> None:
        self.linked = linked
        self.rejected = rejected
        self.needs_unlock = needs_unlock
        self.is_linked_calls = 0
        self.issue_calls = 0

    async def is_linked(self, principal: Principal) -> bool:
        self.is_linked_calls += 1
        return self.linked

    async def is_rejected(self, principal: Principal) -> bool:
        return self.rejected

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: Any = None,
    ) -> IssuedCredential:
        self.issue_calls += 1
        if self.needs_unlock:
            raise NeedsUnlockError(
                target, "no cached proxy", unlock_endpoint=_UNLOCK_ENDPOINT
            )
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.BEARER,
            expires_at=time.time() + 3600,
            payload={"access_token": f"minted-for-{principal.subject}"},
            audit_id="test-audit",
            source="test",
            execution_model=self.execution_model,
        )


def _toy_backend() -> FastMCP:
    mcp = FastMCP(name="toy-backend")

    @mcp.tool
    def seen_authorization() -> str | None:
        """Return the Authorization header this backend received."""
        return get_http_headers(include={"authorization"}).get("authorization")

    @mcp.tool
    def other() -> str:
        return "other"

    return mcp


@pytest.fixture
async def toy_backend_url() -> AsyncIterator[str]:
    async with run_inprocess_server(_toy_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
def mrtr_settings() -> Settings:
    """Settings carrying the shared Fernet key every replica is configured with."""
    return Settings(
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        broker_state_key=SecretStr(Fernet.generate_key().decode()),
    )


@pytest.fixture
def policy() -> EntitlementPolicy:
    return EntitlementPolicy(
        group_permissions={"atlas": ["read_data"], "__authenticated__": []},
    )


@pytest.fixture
def build_replica(toy_backend_url, policy, static_principal_cache):
    """Build one aggregator replica from config alone (settings + provider).

    Two calls with the same settings model two broker pods: nothing in-process
    is shared between the returned FastMCP instances.
    """
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = ["atlas"]
    directory.groups_by_subject["user-456"] = ["atlas"]

    def _build(settings: Settings, provider: CredentialProvider) -> FastMCP:
        registry = ServiceRegistry()
        registry.register(
            ServiceSpec(
                name="toy",
                prefix="toy",
                url=toy_backend_url,
                transport="http",
                required_permission="read_data",
                auth_type="bearer",
            )
        )
        credential_registry = CredentialRegistry()
        credential_registry.register("toy", provider)
        return build_aggregator(
            registry,
            settings,
            policy,
            credential_registry,
            principal_cache=principal_cache,
        )

    return _build


@pytest.fixture
def audits(monkeypatch: pytest.MonkeyPatch) -> list[AuditRecord]:
    """Capture every audit record the authorization middleware writes."""
    captured: list[AuditRecord] = []

    async def _capture(record: AuditRecord, *_: Any) -> None:
        captured.append(record)

    monkeypatch.setattr(authorization_mw, "write_audit", _capture)
    monkeypatch.setattr(authorization_mw, "submit_metered_audit", _capture)
    return captured


def _client(
    server: ASGIServer, token: str, *, mode: str = "2026-07-28", handler: Any = None
) -> Client:
    return server.client(
        headers={"Authorization": f"Bearer {token}"},
        mode=mode,
        elicitation_handler=handler,
    )


def _identities_url(settings: Settings) -> str:
    return f"{settings.portal_url.rstrip('/')}/identities"


class _Prompts:
    """An elicitation handler recording what the user was shown, then acting."""

    def __init__(self, act: Any = None, action: str = "accept") -> None:
        self.messages: list[str] = []
        self.schemas: list[Any] = []
        self._act = act
        self._action = action

    async def __call__(self, message, response_type, params, context):
        self.messages.append(message)
        self.schemas.append(params.requested_schema)
        if self._act is not None:
            self._act()
        return ElicitResult(action=self._action, content={})


# ---------------------------------------------------------------------------
# Link flow
# ---------------------------------------------------------------------------


async def test_not_linked_call_prompts_with_portal_link_then_retry_succeeds(
    mrtr_settings, build_replica, sig_key, prime_jwks, audits
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    prompts = _Prompts(act=lambda: setattr(provider, "linked", True))
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=prompts) as client,
    ):
        result = await client.call_tool("toy_seen_authorization", {})

    assert result.data == "Bearer minted-for-user-123"
    assert len(prompts.messages) == 1
    assert _identities_url(mrtr_settings) in prompts.messages[0]
    # One prompt only: the retry proceeded with the original call.
    assert provider.issue_calls == 1
    outcomes = [a.outcome for a in audits]
    assert outcomes == ["input_required", "success"]
    assert audits[0].mcp_service == "toy"
    assert audits[0].action == "toy_seen_authorization"


async def test_prompt_asks_for_confirmation_never_for_secrets(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    prompts = _Prompts(act=lambda: setattr(provider, "linked", True))
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=prompts) as client,
    ):
        await client.call_tool("toy_seen_authorization", {})

    assert prompts.schemas == [{"type": "object", "properties": {}}]


async def test_first_leg_is_an_input_required_result_naming_the_link(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=_Prompts()) as client,
    ):
        first = await client.session.call_tool(
            name="toy_seen_authorization",
            arguments={},
            allow_input_required=True,
        )

    assert isinstance(first, mcp_types.InputRequiredResult)
    assert first.request_state
    assert first.input_requests is not None
    ((_, request),) = first.input_requests.items()
    assert _identities_url(mrtr_settings) in request.params.message


async def test_declined_prompt_gets_the_plain_error_and_no_second_prompt(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    prompts = _Prompts(action="decline")
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=prompts) as client,
    ):
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("toy_seen_authorization", {})

    assert _NOT_LINKED_TEXT in str(excinfo.value)
    assert len(prompts.messages) == 1
    assert provider.issue_calls == 0


async def test_confirming_without_linking_gets_the_plain_error_not_a_loop(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    prompts = _Prompts()  # accepts but never links
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=prompts) as client,
    ):
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("toy_seen_authorization", {})

    assert _NOT_LINKED_TEXT in str(excinfo.value)
    assert len(prompts.messages) == 1


async def test_rejected_credential_prompt_says_relink(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False, rejected=True)
    prompts = _Prompts(act=lambda: setattr(provider, "linked", True))
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=prompts) as client,
    ):
        await client.call_tool("toy_seen_authorization", {})

    assert "re-link" in prompts.messages[0]
    assert _identities_url(mrtr_settings) in prompts.messages[0]


# ---------------------------------------------------------------------------
# Clients without SEP-2322 support keep today's error
# ---------------------------------------------------------------------------


async def test_legacy_protocol_client_without_elicitation_gets_the_unchanged_error(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, mode="legacy", handler=None) as client,
    ):
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("toy_seen_authorization", {})

    text = str(excinfo.value)
    assert _NOT_LINKED_TEXT in text
    assert f"{_identities_url(mrtr_settings)}" in text
    assert "af_link_identity" in text


class _LegacyPrompts:
    """A handshake-era elicitation handler: answers the select form with one option."""

    def __init__(self, choice: str | None, act: Any = None) -> None:
        self.messages: list[str] = []
        self._choice = choice
        self._act = act

    async def __call__(self, message, response_type, params, context):
        self.messages.append(message)
        if self._act is not None:
            self._act()
        if self._choice is None:
            return ElicitResult(action="decline")
        return ElicitResult(action="accept", content={"value": self._choice})


_TRY_AGAIN = "I've linked it \u2014 try again"


async def test_legacy_protocol_client_with_elicitation_gets_the_form_prompt_then_succeeds(
    mrtr_settings, build_replica, sig_key, prime_jwks, audits
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    prompts = _LegacyPrompts(_TRY_AGAIN, act=lambda: setattr(provider, "linked", True))
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, mode="legacy", handler=prompts) as client,
    ):
        result = await client.call_tool("toy_seen_authorization", {})

    assert result.data == "Bearer minted-for-user-123"
    assert len(prompts.messages) == 1
    assert _identities_url(mrtr_settings) in prompts.messages[0]
    assert [a.outcome for a in audits] == ["success"]


async def test_legacy_protocol_client_declining_the_form_gets_the_plain_error(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    prompts = _LegacyPrompts(None)
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, mode="legacy", handler=prompts) as client,
    ):
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("toy_seen_authorization", {})

    assert _NOT_LINKED_TEXT in str(excinfo.value)
    assert len(prompts.messages) == 1
    assert provider.issue_calls == 0


async def test_legacy_protocol_client_confirming_without_linking_is_prompted_once(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    prompts = _LegacyPrompts(_TRY_AGAIN)
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, mode="legacy", handler=prompts) as client,
    ):
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("toy_seen_authorization", {})

    assert _NOT_LINKED_TEXT in str(excinfo.value)
    assert len(prompts.messages) == 1


async def test_legacy_elicit_failure_is_logged_and_falls_back_to_the_plain_error(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)

    async def exploding(message, response_type, params, context):
        raise RuntimeError("client exploded")

    token = sig_key.sign(make_claims())

    with structlog.testing.capture_logs() as logs:
        async with (
            run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
            _client(server, token, mode="legacy", handler=exploding) as client,
        ):
            with pytest.raises(ToolError) as excinfo:
                await client.call_tool("toy_seen_authorization", {})

    assert _NOT_LINKED_TEXT in str(excinfo.value)
    warnings = [
        entry for entry in logs if entry["event"] == "mcp.portal_prompt_elicit_failed"
    ]
    assert len(warnings) == 1
    assert warnings[0]["log_level"] == "warning"
    assert warnings[0]["exc_type"]


async def test_legacy_needs_unlock_with_elicitation_gets_the_form_then_succeeds(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(needs_unlock=True)
    prompts = _LegacyPrompts(
        _TRY_AGAIN, act=lambda: setattr(provider, "needs_unlock", False)
    )
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, mode="legacy", handler=prompts) as client,
    ):
        result = await client.call_tool("toy_seen_authorization", {})

    assert result.data == "Bearer minted-for-user-123"
    portal = mrtr_settings.portal_url.rstrip("/")
    assert f"{portal}{_UNLOCK_ENDPOINT}" in prompts.messages[0]


async def test_modern_client_without_elicitation_gets_the_unchanged_error(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=None) as client,
    ):
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("toy_seen_authorization", {})

    assert _NOT_LINKED_TEXT in str(excinfo.value)


async def test_broker_without_state_key_gets_the_unchanged_error(
    settings, build_replica, sig_key, prime_jwks
) -> None:
    """With no broker_state_key there is nothing to seal request_state with, so a capable client still gets the plain error."""
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    prompts = _Prompts()
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(settings, provider)) as server,
        _client(server, token, handler=prompts) as client,
    ):
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("toy_seen_authorization", {})

    assert _NOT_LINKED_TEXT in str(excinfo.value)
    assert prompts.messages == []


# ---------------------------------------------------------------------------
# Unlock flow
# ---------------------------------------------------------------------------


async def test_needs_unlock_prompts_with_unlock_page_then_retry_succeeds(
    mrtr_settings, build_replica, sig_key, prime_jwks, audits
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(needs_unlock=True)
    prompts = _Prompts(act=lambda: setattr(provider, "needs_unlock", False))
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=prompts) as client,
    ):
        result = await client.call_tool("toy_seen_authorization", {})

    assert result.data == "Bearer minted-for-user-123"
    portal = mrtr_settings.portal_url.rstrip("/")
    assert f"{portal}{_UNLOCK_ENDPOINT}" in prompts.messages[0]
    assert "passphrase" in prompts.messages[0].lower()
    # The passphrase is entered in the portal, never through this prompt.
    assert prompts.schemas == [{"type": "object", "properties": {}}]
    assert [a.outcome for a in audits] == ["input_required", "success"]


async def test_needs_unlock_legacy_client_without_elicitation_gets_the_unchanged_error(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(needs_unlock=True)
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, mode="legacy", handler=None) as client,
    ):
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("toy_seen_authorization", {})

    portal = mrtr_settings.portal_url.rstrip("/")
    assert str(excinfo.value).endswith(f"{_UNLOCK_TEXT}{portal}{_UNLOCK_ENDPOINT}")


# ---------------------------------------------------------------------------
# request_state integrity and binding
# ---------------------------------------------------------------------------


async def _first_leg(client: Client, tool: str = "toy_seen_authorization"):
    first = await client.session.call_tool(
        name=tool, arguments={}, allow_input_required=True
    )
    assert isinstance(first, mcp_types.InputRequiredResult)
    assert first.input_requests is not None
    return first


def _accept(first: mcp_types.InputRequiredResult) -> dict[str, Any]:
    assert first.input_requests is not None
    return {
        key: mcp_types.ElicitResult(action="accept", content={})
        for key in first.input_requests
    }


async def test_tampered_request_state_is_refused(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=_Prompts()) as client,
    ):
        first = await _first_leg(client)
        provider.linked = True
        forged = first.request_state[:-2] + (
            "AA" if not first.request_state.endswith("AA") else "BB"
        )
        with pytest.raises((MCPError, ToolError)):
            await client.session.call_tool(
                name="toy_seen_authorization",
                arguments={},
                input_responses=_accept(first),
                request_state=forged,
            )

    assert provider.issue_calls == 0


async def test_request_state_for_another_tool_is_refused(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server,
        _client(server, token, handler=_Prompts()) as client,
    ):
        first = await _first_leg(client)
        provider.linked = True
        with pytest.raises((MCPError, ToolError)):
            await client.session.call_tool(
                name="toy_other",
                arguments={},
                input_responses=_accept(first),
                request_state=first.request_state,
            )

    assert provider.issue_calls == 0


async def test_request_state_for_another_principal_is_refused(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    alice = sig_key.sign(make_claims(sub="user-123"))
    bob = sig_key.sign(make_claims(sub="user-456"))

    async with run_aggregator_async(build_replica(mrtr_settings, provider)) as server:
        async with _client(server, alice, handler=_Prompts()) as client:
            first = await _first_leg(client)
        provider.linked = True
        async with _client(server, bob, handler=_Prompts()) as client:
            with pytest.raises((MCPError, ToolError)):
                await client.session.call_tool(
                    name="toy_seen_authorization",
                    arguments={},
                    input_responses=_accept(first),
                    request_state=first.request_state,
                )

    assert provider.issue_calls == 0


# ---------------------------------------------------------------------------
# Cross-replica: issued on replica A, retried on replica B
# ---------------------------------------------------------------------------


async def test_request_state_issued_on_one_replica_is_redeemable_on_another(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    token = sig_key.sign(make_claims())

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server_a,
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server_b,
    ):
        async with _client(server_a, token, handler=_Prompts()) as client_a:
            first = await _first_leg(client_a)
        provider.linked = True
        async with _client(server_b, token, handler=_Prompts()) as client_b:
            result = await client_b.session.call_tool(
                name="toy_seen_authorization",
                arguments={},
                input_responses=_accept(first),
                request_state=first.request_state,
            )

    assert isinstance(result, mcp_types.CallToolResult)
    assert not result.is_error
    assert result.structured_content == {"result": "Bearer minted-for-user-123"}


async def test_replica_with_a_different_state_key_refuses_the_state(
    mrtr_settings, build_replica, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    token = sig_key.sign(make_claims())
    other_settings = Settings(
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        broker_state_key=SecretStr(Fernet.generate_key().decode()),
    )

    async with (
        run_aggregator_async(build_replica(mrtr_settings, provider)) as server_a,
        run_aggregator_async(build_replica(other_settings, provider)) as server_b,
    ):
        async with _client(server_a, token, handler=_Prompts()) as client_a:
            first = await _first_leg(client_a)
        provider.linked = True
        async with _client(server_b, token, handler=_Prompts()) as client_b:
            with pytest.raises((MCPError, ToolError)):
                await client_b.session.call_tool(
                    name="toy_seen_authorization",
                    arguments={},
                    input_responses=_accept(first),
                    request_state=first.request_state,
                )


# ---------------------------------------------------------------------------
# The state codec itself: binding and expiry, without the transport's own
# sealing in front of it.
# ---------------------------------------------------------------------------


@pytest.fixture
def state() -> InputRequiredState:
    clock = {"now": 1_000_000.0}
    codec = InputRequiredState(
        Fernet(Fernet.generate_key()),
        issuer="https://broker.example",
        ttl_seconds=600,
        clock=lambda: clock["now"],
    )
    codec.clock_cell = clock  # type: ignore[attr-defined]
    return codec


def test_state_round_trips_for_the_bound_principal_tool_and_service(state) -> None:
    sealed = state.seal(subject="user-123", tool="toy_echo", service="toy")

    state.verify(sealed, subject="user-123", tool="toy_echo", service="toy")


@pytest.mark.parametrize(
    ("subject", "tool", "service"),
    [
        ("user-456", "toy_echo", "toy"),
        ("user-123", "toy_other", "toy"),
        ("user-123", "toy_echo", "rucio"),
    ],
    ids=["principal", "tool", "service"],
)
def test_state_bound_to_a_different_principal_tool_or_service_is_refused(
    state, subject, tool, service
) -> None:
    sealed = state.seal(subject="user-123", tool="toy_echo", service="toy")

    with pytest.raises(InvalidInputRequiredStateError):
        state.verify(sealed, subject=subject, tool=tool, service=service)


def test_expired_state_is_refused(state) -> None:
    sealed = state.seal(subject="user-123", tool="toy_echo", service="toy")
    state.clock_cell["now"] += 601  # type: ignore[attr-defined]

    with pytest.raises(InvalidInputRequiredStateError):
        state.verify(sealed, subject="user-123", tool="toy_echo", service="toy")


def test_garbage_state_is_refused(state) -> None:
    with pytest.raises(InvalidInputRequiredStateError):
        state.verify("not-a-token", subject="user-123", tool="toy_echo", service="toy")


def test_state_from_another_key_or_issuer_is_refused() -> None:
    cipher = Fernet(Fernet.generate_key())
    minted = InputRequiredState(cipher, issuer="https://a.example").seal(
        subject="u", tool="t", service="s"
    )

    with pytest.raises(InvalidInputRequiredStateError):
        InputRequiredState(cipher, issuer="https://b.example").verify(
            minted, subject="u", tool="t", service="s"
        )
    with pytest.raises(InvalidInputRequiredStateError):
        InputRequiredState(
            Fernet(Fernet.generate_key()), issuer="https://a.example"
        ).verify(minted, subject="u", tool="t", service="s")


# ---------------------------------------------------------------------------
# AuthorizationMiddleware's handling of an inbound request_state, with a fake
# request context so a state the transport would accept can be crafted
# directly (the integration tests above are stopped by the transport's own
# sealing before the broker's binding is ever consulted).
# ---------------------------------------------------------------------------


class _FakeFastMCPContext:
    def __init__(self, principal: Any, request_state: str | None) -> None:
        self._state = {"principal": principal}
        self.request_state = request_state

    async def get_state(self, key: str) -> Any:
        return self._state.get(key)

    async def set_state(
        self, key: str, value: Any, *, serializable: bool = True
    ) -> None:
        self._state[key] = value


class _FakeMiddlewareContext:
    def __init__(self, tool: str, fastmcp_context: _FakeFastMCPContext) -> None:
        self.message = mcp_types.CallToolRequestParams(name=tool, arguments={})
        self.fastmcp_context = fastmcp_context


class _CallNext:
    def __init__(self) -> None:
        self.called = False

    async def __call__(self, context: Any) -> ToolResult:
        self.called = True
        return ToolResult(content="ok")


@pytest.fixture
def middleware_with_state(policy):
    registry = ServiceRegistry()
    for name in ("toy", "other"):
        registry.register(
            ServiceSpec(
                name=name,
                prefix=name,
                url="http://backend.invalid/mcp",
                transport="http",
                required_permission="read_data",
                auth_type="none",
            )
        )
    clock = {"now": 1_000_000.0}
    state = InputRequiredState(
        Fernet(Fernet.generate_key()),
        issuer="https://broker.example",
        clock=lambda: clock["now"],
    )
    mw = authorization_mw.AuthorizationMiddleware(registry, policy)
    mw.input_required_state = state
    return mw, state, clock


@pytest.mark.parametrize(
    ("sealed_for", "called_as"),
    [
        (("sub-abc", "toy_x", "toy"), ("sub-other", "toy_x")),
        (("sub-abc", "toy_x", "toy"), ("sub-abc", "toy_y")),
        (("sub-abc", "other_x", "other"), ("sub-abc", "toy_x")),
    ],
    ids=["principal", "tool", "service"],
)
async def test_middleware_refuses_a_state_sealed_for_another_binding(
    middleware_with_state, make_principal, audits, sealed_for, called_as
) -> None:
    mw, state, _ = middleware_with_state
    subject, tool, service = sealed_for
    token = state.seal(subject=subject, tool=tool, service=service)
    caller, called_tool = called_as
    context = _FakeMiddlewareContext(
        called_tool,
        _FakeFastMCPContext(make_principal(groups=["atlas"], subject=caller), token),
    )
    call_next = _CallNext()

    with pytest.raises(MCPError, match="Invalid or expired requestState"):
        await mw.on_call_tool(context, call_next)

    assert call_next.called is False


async def test_middleware_refuses_an_expired_state(
    middleware_with_state, make_principal, audits
) -> None:
    mw, state, clock = middleware_with_state
    token = state.seal(subject="sub-abc", tool="toy_x", service="toy")
    clock["now"] += 601
    context = _FakeMiddlewareContext(
        "toy_x",
        _FakeFastMCPContext(make_principal(groups=["atlas"]), token),
    )
    call_next = _CallNext()

    with pytest.raises(MCPError, match="Invalid or expired requestState"):
        await mw.on_call_tool(context, call_next)

    assert call_next.called is False


async def test_middleware_accepts_a_state_sealed_for_this_binding(
    middleware_with_state, make_principal, audits
) -> None:
    mw, state, _ = middleware_with_state
    token = state.seal(subject="sub-abc", tool="toy_x", service="toy")
    context = _FakeMiddlewareContext(
        "toy_x",
        _FakeFastMCPContext(make_principal(groups=["atlas"]), token),
    )
    call_next = _CallNext()

    await mw.on_call_tool(context, call_next)

    assert call_next.called is True


async def test_middleware_passes_through_a_state_it_did_not_seal(
    middleware_with_state, make_principal, audits
) -> None:
    """A backend's own multi-round-trip continuation is relayed, not judged."""
    mw, _, _ = middleware_with_state
    context = _FakeMiddlewareContext(
        "toy_x",
        _FakeFastMCPContext(make_principal(groups=["atlas"]), "backend-state"),
    )
    call_next = _CallNext()

    await mw.on_call_tool(context, call_next)

    assert call_next.called is True

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest
from conftest import make_claims, run_aggregator_async
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_headers
from fastmcp.utilities.tests import run_server_async

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import (
    CredentialKind,
    CredentialProvider,
    CredentialRegistry,
    ExecutionModel,
    IssuedCredential,
    NeedsUnlock,
)
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from af_mcp_broker.identity import Principal

# ---------------------------------------------------------------------------
# End-to-end coverage for real credential injection through the aggregator:
# a real toy backend over a real HTTP server, real signed JWTs, and a real
# build_aggregator()/ProxyProvider/middleware stack, with only the
# credential provider faked. test_mcp_aggregator_integration.py covers the
# credential-free scaffold plumbing (namespacing, dead-backend tolerance);
# this file covers what PR B adds on top of it.
# ---------------------------------------------------------------------------


def _toy_backend() -> FastMCP:
    mcp = FastMCP(name="toy-backend")

    @mcp.tool
    def seen_authorization() -> str | None:
        """Returns the raw Authorization header this backend actually
        received, so tests can assert it is the *minted* credential, never
        the caller's inbound bearer token."""
        return get_http_headers(include={"authorization"}).get("authorization")

    return mcp


@pytest.fixture
async def toy_backend_url() -> AsyncIterator[str]:
    async with run_server_async(_toy_backend(), path="/mcp") as url:
        yield url


class _FakeProvider(CredentialProvider):
    """Mints a deterministic, per-uid token so tests can tell one
    principal's credential apart from another's, and can force the
    not-linked / needs-unlock error paths on demand."""

    cred_class = "fake"
    execution_model = ExecutionModel.DELEGATED

    def __init__(self, *, linked: bool = True, needs_unlock: bool = False) -> None:
        self.linked = linked
        self.needs_unlock = needs_unlock
        self.issue_calls: list[int] = []

    async def is_linked(self, principal: Principal) -> bool:
        return self.linked

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: Any = None,
    ) -> IssuedCredential:
        self.issue_calls.append(principal.uid)
        if self.needs_unlock:
            raise NeedsUnlock(
                target, "no cached proxy", unlock_endpoint="/v1/x509/proxy"
            )
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.BEARER,
            expires_at=time.time() + 3600,
            payload={"access_token": f"minted-for-{principal.uid}"},
            audit_id="test-audit",
            source="test",
            execution_model=self.execution_model,
        )


@pytest.fixture
def policy() -> EntitlementPolicy:
    return EntitlementPolicy(
        group_permissions={"atlas": ["read_data"], "__authenticated__": []},
    )


@pytest.fixture
def aggregator_app_url(settings, toy_backend_url, policy, static_principal_cache):
    """Builds a real aggregator (build_aggregator, no app.py involved) wired
    to the real toy backend above plus a second auth_type="none" backend
    sharing the same URL, and a CredentialRegistry holding only the fake
    provider registered for "toy".

    Most tests in this file share the same JWT `sub` ("user-123",
    `make_claims`' default); the per-user isolation test below is the
    deliberate exception, using two distinct subjects. The returned callable
    exposes ``.directory`` (issue #144 steps 3/3b's directory-backed
    groups/POSIX resolution) letting a test set ``groups_by_subject[sub]``/
    ``posix_by_subject[sub]`` to whatever identity/entitlement it needs
    before calling ``aggregator_app_url(provider)``.
    """
    principal_cache, directory = static_principal_cache
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
    registry.register(
        ServiceSpec(
            name="open",
            prefix="open",
            url=toy_backend_url,
            transport="http",
            required_permission="__none__",
            auth_type="none",
        )
    )

    async def _run(provider: _FakeProvider):
        credential_registry = CredentialRegistry()
        credential_registry.register("toy", provider)
        mcp = build_aggregator(
            registry,
            settings,
            policy,
            credential_registry,
            principal_cache=principal_cache,
        )
        async with run_aggregator_async(mcp, path="/mcp") as url:
            yield url

    _run.directory = directory
    return _run


def _bearer_client(url: str, token: str) -> Client:
    return Client(
        StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
    )


async def test_credential_injected_and_inbound_token_not_forwarded(
    aggregator_app_url, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider()
    aggregator_app_url.directory.groups_by_subject["user-123"] = ["atlas"]
    # POSIX identity now comes from the directory (issue #144 step 3b), not
    # the JWT's own `posix` claim -- see the fixture docstring above.
    aggregator_app_url.directory.posix_by_subject["user-123"] = {
        "uid": 501,
        "gid": 501,
        "unixname": "u501",
    }
    inbound_token = sig_key.sign(make_claims())

    async for base_url in aggregator_app_url(provider):
        async with _bearer_client(base_url, inbound_token) as client:
            result = await client.call_tool("toy_seen_authorization", {})

    assert result.data == "Bearer minted-for-501"
    assert result.data != f"Bearer {inbound_token}"
    # >= 1, not == 1: this principal is entitled+linked, so the aggregator's
    # own incidental tools/list-time minting (issue #121's fix -- see
    # aggregator.py's _bearer_factory) also mints for uid 501 in addition to
    # this explicit call, on top of whatever implicit listing the MCP client
    # itself performs. The security property under test -- only uid 501 is
    # ever minted for, never some other principal -- still holds regardless
    # of how many times.
    assert provider.issue_calls
    assert set(provider.issue_calls) == {501}


async def test_per_user_credential_isolation(
    aggregator_app_url, sig_key, prime_jwks
) -> None:
    """Alice and Bob must be genuinely distinct principals (different `sub`),
    not just different POSIX identities on a shared subject: since POSIX
    identity now comes from the directory keyed by subject (issue #144 step
    3b), a shared subject would resolve to a single, shared uid regardless
    of what the JWT itself claims -- exactly the disagreement this
    unification exists to make impossible."""
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider()
    aggregator_app_url.directory.groups_by_subject["user-alice"] = ["atlas"]
    aggregator_app_url.directory.groups_by_subject["user-bob"] = ["atlas"]
    aggregator_app_url.directory.posix_by_subject["user-alice"] = {
        "uid": 111,
        "gid": 111,
        "unixname": "alice",
    }
    aggregator_app_url.directory.posix_by_subject["user-bob"] = {
        "uid": 222,
        "gid": 222,
        "unixname": "bob",
    }
    alice_token = sig_key.sign(make_claims(sub="user-alice"))
    bob_token = sig_key.sign(make_claims(sub="user-bob"))

    async for base_url in aggregator_app_url(provider):
        async with _bearer_client(base_url, alice_token) as client:
            alice_result = await client.call_tool("toy_seen_authorization", {})
        async with _bearer_client(base_url, bob_token) as client:
            bob_result = await client.call_tool("toy_seen_authorization", {})

    assert alice_result.data == "Bearer minted-for-111"
    assert bob_result.data == "Bearer minted-for-222"
    # Not an exact count (see the comment in
    # test_credential_injected_and_inbound_token_not_forwarded above): the
    # isolation property under test is that only 111 and 222 ever get
    # minted for, each with their own token, never a mix-up between them.
    assert set(provider.issue_calls) == {111, 222}


async def test_unauthorized_principal_denied_before_credential_provider_touched(
    aggregator_app_url, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider()
    aggregator_app_url.directory.groups_by_subject["user-123"] = []  # lacks read_data
    token = sig_key.sign(make_claims())

    async for base_url in aggregator_app_url(provider):
        async with _bearer_client(base_url, token) as client:
            # A denied tools/call surfaces as a normal (though failed)
            # CallToolResult, not a transport-level protocol error -- the
            # client's call_tool() convenience method raises fastmcp's own
            # ToolError for that, distinct from mcp.shared.exceptions.McpError
            # (which the missing-bearer-entirely case in
            # test_mcp_aggregator_integration.py raises instead, since that
            # failure happens before a tools/call is even recognized as one).
            with pytest.raises(ToolError, match="Authorization denied"):
                await client.call_tool("toy_seen_authorization", {})

    assert provider.issue_calls == []


async def test_not_linked_surfaces_friendly_error(
    aggregator_app_url, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(linked=False)
    aggregator_app_url.directory.groups_by_subject["user-123"] = ["atlas"]
    token = sig_key.sign(make_claims())

    async for base_url in aggregator_app_url(provider):
        async with _bearer_client(base_url, token) as client:
            with pytest.raises(ToolError, match="not linked"):
                await client.call_tool("toy_seen_authorization", {})


async def test_needs_unlock_surfaces_portal_hint(
    aggregator_app_url, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider(needs_unlock=True)
    aggregator_app_url.directory.groups_by_subject["user-123"] = ["atlas"]
    token = sig_key.sign(make_claims())

    async for base_url in aggregator_app_url(provider):
        async with _bearer_client(base_url, token) as client:
            with pytest.raises(ToolError, match="portal"):
                await client.call_tool("toy_seen_authorization", {})


async def test_auth_type_none_skips_credential_resolution(
    aggregator_app_url, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    provider = _FakeProvider()
    token = sig_key.sign(make_claims())  # no permission needed for "open"

    async for base_url in aggregator_app_url(provider):
        async with _bearer_client(base_url, token) as client:
            result = await client.call_tool("open_seen_authorization", {})

    # "open" is auth_type="none" and not registered with the fake provider at
    # all -- succeeding here (with no Authorization header reaching the
    # backend) proves credential resolution was skipped entirely.
    assert result.data is None
    assert provider.issue_calls == []

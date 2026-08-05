from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from conftest import make_claims, run_aggregator_async
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.utilities.tests import run_server_async

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# ---------------------------------------------------------------------------
# End-to-end coverage for issue #138/#144 step 1: /mcp must answer a
# missing/invalid/expired bearer with a genuine HTTP 401 -- not the pre-fix
# HTTP 200 carrying a JSON-RPC -32602 error -- and must behave identically to
# before for an authenticated caller (including the local-dev bypass).
# test_mcp_middleware_identity.py already covers AsgiAuthMiddleware's logic
# directly against a bare ASGI scope; this file proves the same behavior
# through a real aggregator (build_aggregator + run_aggregator_async, the
# same wiring app.py uses to mount /mcp) behind a live uvicorn server -- the
# actual request/response shape a real MCP client sees.
# ---------------------------------------------------------------------------

_INIT_BODY = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}


async def _post(url: str, headers: dict[str, str]) -> httpx.Response:
    """POST a raw MCP initialize request, so a genuine HTTP 401 vs. a 200
    carrying a JSON-RPC error is directly inspectable -- fastmcp's own Client
    would otherwise turn either shape into some kind of raised exception,
    hiding exactly the distinction these tests exist to lock in."""
    full_headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        **headers,
    }
    async with httpx.AsyncClient() as client:
        return await client.post(url, json=_INIT_BODY, headers=full_headers)


def _open_backend() -> FastMCP:
    mcp = FastMCP(name="open-backend")

    @mcp.tool
    def ping() -> str:
        return "pong"

    return mcp


@pytest.fixture
async def open_backend_url() -> AsyncIterator[str]:
    async with run_server_async(_open_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
def policy() -> EntitlementPolicy:
    return EntitlementPolicy(group_capabilities={"__authenticated__": []})


@pytest.fixture
def registry(open_backend_url: str) -> BackendRegistry:
    registry = BackendRegistry()
    registry.register(
        BackendSpec(
            name="open",
            prefix="open",
            url=open_backend_url,
            transport="http",
            required_capability="__none__",
            auth_type="none",
        )
    )
    return registry


@pytest.fixture
async def aggregator_url(
    settings: Any, policy: EntitlementPolicy, registry: BackendRegistry
) -> AsyncIterator[str]:
    mcp = build_aggregator(registry, settings, policy, CredentialRegistry())
    async with run_aggregator_async(mcp, path="/mcp") as url:
        yield url


def _bearer_client(url: str, token: str) -> Client:
    return Client(
        StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
    )


async def test_missing_bearer_is_a_genuine_401_not_a_200_with_jsonrpc_error(
    aggregator_url: str,
) -> None:
    resp = await _post(aggregator_url, {})

    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"
    # The entire point of issue #138/#144 step 1: this is a plain 401
    # response, not a 200 carrying a JSON-RPC envelope with an error field.
    assert resp.status_code != 200
    body = resp.json()
    assert "jsonrpc" not in body
    assert body["detail"] == "Missing Authorization: Bearer <token> header"


async def test_expired_bearer_401_names_expiry_and_portal(
    aggregator_url: str, settings: Any, sig_key: Any, prime_jwks: Any
) -> None:
    prime_jwks([sig_key.jwk])
    now = int(time.time())
    token = sig_key.sign(make_claims(iat=now - 600, exp=now - 300))

    resp = await _post(aggregator_url, {"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"
    detail = resp.json()["detail"]
    assert "expired" in detail
    assert f"{settings.portal_url.rstrip('/')}/tokens" in detail


async def test_invalid_garbage_bearer_401_leaks_no_claim_or_issuer_detail(
    aggregator_url: str, settings: Any
) -> None:
    resp = await _post(aggregator_url, {"Authorization": "Bearer not-a-real-jwt"})

    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"
    detail = resp.json()["detail"]
    assert detail == "Invalid bearer token"
    # Deliberately vague -- assert the absence of anything that would help an
    # attacker: no claim name, issuer/audience, or JWKS/signature detail.
    for leaky in (
        settings.oidc_issuer,
        settings.oidc_audience,
        "kid",
        "JWKS",
        "signature",
        "claim",
        "posix",
    ):
        assert leaky not in detail


async def test_valid_bearer_tools_list_and_call_unchanged(
    aggregator_url: str, sig_key: Any, prime_jwks: Any
) -> None:
    """No behavior change for an authenticated caller: both tools/list and
    tools/call succeed exactly as before this fix."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(groups=[]))

    async with _bearer_client(aggregator_url, token) as client:
        names = {t.name for t in await client.list_tools()}
        assert "open_ping" in names
        result = await client.call_tool("open_ping", {})

    assert result.data == "pong"


async def test_pat_round_trip_tools_list_and_call(
    settings: Any, policy: EntitlementPolicy, registry: BackendRegistry
) -> None:
    """End-to-end coverage for issue #144 step 2a: mint a PAT through the
    same TokenRecord shape POST /v1/tokens produces, present it as a real
    Bearer against a live aggregator, and confirm it resolves a working
    Principal all the way through tools/list and tools/call -- both
    credential types now work on /mcp side by side (this test) and neither
    disturbs the other (every JWT-path test above is unmodified)."""
    from af_mcp_broker.pat import mint_pat
    from af_mcp_broker.principal_cache import (
        InMemoryPrincipalCacheBackend,
        PrincipalCache,
    )
    from af_mcp_broker.principal_directory import (
        PrincipalAttributes,
        PrincipalDirectory,
    )
    from af_mcp_broker.token_registry import InMemoryTokenRegistryBackend, TokenRecord

    class _FakeDirectory(PrincipalDirectory):
        async def resolve(self, principal_id: str) -> PrincipalAttributes:
            return PrincipalAttributes(
                uid=50123, gid=5000, unixname="auser", groups=[], email=""
            )

    pat_backend = InMemoryTokenRegistryBackend()
    plaintext, lookup_id, secret_hash = mint_pat()
    now = time.time()
    await pat_backend.add(
        TokenRecord(
            lookup_id=lookup_id,
            principal_id="kc-sub-pat-1",
            secret_hash=secret_hash,
            name="test-pat",
            created_at=now,
            expires_at=now + 3600,
            revoked_at=None,
            last_used_at=None,
        )
    )
    principal_cache = PrincipalCache(
        _FakeDirectory(),
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=1000.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )

    mcp = build_aggregator(
        registry,
        settings,
        policy,
        CredentialRegistry(),
        pat_backend=pat_backend,
        principal_cache=principal_cache,
    )

    async with (
        run_aggregator_async(mcp, path="/mcp") as url,
        _bearer_client(url, plaintext) as client,
    ):
        names = {t.name for t in await client.list_tools()}
        assert "open_ping" in names
        result = await client.call_tool("open_ping", {})

    assert result.data == "pong"

    record = await pat_backend.get_by_lookup_id(lookup_id)
    assert record is not None
    assert record.last_used_at is not None  # touched by the successful call(s)


async def test_dev_bypass_path_tools_list_and_call_still_work(
    settings: Any, policy: EntitlementPolicy, registry: BackendRegistry
) -> None:
    dev_settings = settings.model_copy(
        update={
            "dev_insecure_principal": json.dumps(
                {"uid": 1000, "gid": 1000, "unixname": "devuser", "groups": []}
            ),
            "oidc_issuer": "http://localhost:8081/realms/x",
        }
    )
    mcp = build_aggregator(registry, dev_settings, policy, CredentialRegistry())

    # No Authorization header at all -- the bypass must not even look.
    async with (
        run_aggregator_async(mcp, path="/mcp") as url,
        Client(StreamableHttpTransport(url)) as client,
    ):
        names = {t.name for t in await client.list_tools()}
        assert "open_ping" in names
        result = await client.call_tool("open_ping", {})

    assert result.data == "pong"

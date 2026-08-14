from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any

import pytest
from conftest import make_claims
from fastmcp.exceptions import AuthorizationError

from af_mcp_broker.mcp.middleware import identity_mw
from af_mcp_broker.mcp.middleware.identity_mw import (
    AsgiAuthMiddleware,
    IdentityMiddleware,
)
from af_mcp_broker.token_registry import (
    InMemoryTokenRegistryBackend,
    RevokedJtiCache,
    TokenRecord,
)

# ---------------------------------------------------------------------------
# AsgiAuthMiddleware -- the ASGI-layer identity check that runs in front of
# FastMCP's own message pipeline (issue #138/#144 step 1). These tests drive
# it directly with a bare ASGI scope/receive/send rather than a live uvicorn
# server -- no JSON-RPC dispatch is involved at this layer, so a raw ASGI
# harness exercises it faithfully; the real-server round trip (initialize,
# tools/list, tools/call through a live aggregator) is covered separately in
# test_mcp_list_time_credentials.py / test_mcp_aggregator_integration.py.
# ---------------------------------------------------------------------------


class _InnerApp:
    """Records the scope it was called with and answers a trivial 200."""

    def __init__(self) -> None:
        self.called = False
        self.scope: dict[str, Any] | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True
        self.scope = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _http_scope(headers: dict[str, str] | None = None) -> dict[str, Any]:
    headers = headers or {}
    return {
        "type": "http",
        "headers": [
            (k.lower().encode("latin-1"), v.encode("latin-1"))
            for k, v in headers.items()
        ],
    }


async def _run(
    middleware: AsgiAuthMiddleware, scope: dict[str, Any]
) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await middleware(scope, receive, send)
    return messages


def _status(messages: list[dict[str, Any]]) -> int:
    return next(m["status"] for m in messages if m["type"] == "http.response.start")


def _header(messages: list[dict[str, Any]], name: str) -> str | None:
    start = next(m for m in messages if m["type"] == "http.response.start")
    for key, value in start["headers"]:
        if key.decode("latin-1").lower() == name.lower():
            return value.decode("latin-1")
    return None


def _body(messages: list[dict[str, Any]]) -> bytes:
    return b"".join(m["body"] for m in messages if m["type"] == "http.response.body")


async def test_valid_bearer_stashes_principal_and_calls_inner_app(
    settings, sig_key, prime_jwks, static_principal_cache
):
    principal_cache, directory = static_principal_cache
    directory.posix_by_subject["user-123"] = {"uid": 50123, "unixname": "auser"}
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(
        inner, IdentityMiddleware(settings, principal_cache=principal_cache)
    )

    messages = await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    assert inner.called
    principal = inner.scope["state"]["principal"]
    assert principal.unixname == "auser"
    assert principal.uid == 50123
    assert _status(messages) == 200


async def test_missing_header_rejected_with_genuine_401(settings):
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(inner, IdentityMiddleware(settings))

    messages = await _run(middleware, _http_scope())

    assert not inner.called
    assert _status(messages) == 401
    assert _header(messages, "www-authenticate") == "Bearer"
    body = json.loads(_body(messages))
    assert body["detail"] == "Missing Authorization: Bearer <token> header"


async def test_non_bearer_scheme_rejected_with_genuine_401(settings):
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(inner, IdentityMiddleware(settings))

    messages = await _run(middleware, _http_scope({"authorization": "Basic deadbeef"}))

    assert not inner.called
    assert _status(messages) == 401
    assert _header(messages, "www-authenticate") == "Bearer"


async def test_invalid_signature_rejected_with_vague_message_leaking_nothing(
    settings, sig_key, enc_key, prime_jwks
):
    # Signing key is never published to the JWKS the middleware sees -> the
    # token's signature cannot be verified.
    prime_jwks([enc_key.jwk])
    token = sig_key.sign(make_claims())
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(inner, IdentityMiddleware(settings))

    messages = await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    assert not inner.called
    assert _status(messages) == 401
    assert _header(messages, "www-authenticate") == "Bearer"
    body = json.loads(_body(messages))
    detail = body["detail"]
    assert detail == "Invalid bearer token"
    # The entire point of the vague-message requirement: no claim name,
    # issuer/audience, or JWKS/kid detail leaks into the client-visible body.
    for leaky in (
        "kid",
        "sig-key",
        "enc-key",
        settings.oidc_issuer,
        settings.oidc_audience,
        "JWKS",
        "signature",
    ):
        assert leaky not in detail


async def test_expired_token_rejected_with_actionable_portal_message(
    settings, sig_key, prime_jwks
):
    prime_jwks([sig_key.jwk])
    now = int(time.time())
    token = sig_key.sign(make_claims(iat=now - 600, exp=now - 300))
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(inner, IdentityMiddleware(settings))

    messages = await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    assert not inner.called
    assert _status(messages) == 401
    assert _header(messages, "www-authenticate") == "Bearer"
    body = json.loads(_body(messages))
    detail = body["detail"]
    assert "expired" in detail
    assert f"{settings.portal_url.rstrip('/')}/tokens" in detail


async def test_dev_bypass_active_builds_principal_without_checking_headers(settings):
    dev_settings = settings.model_copy(
        update={
            "dev_insecure_principal": json.dumps(
                {"uid": 1000, "gid": 1000, "unixname": "devuser", "groups": ["atlas"]}
            ),
            "oidc_issuer": "http://localhost:8081/realms/x",
        }
    )
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(inner, IdentityMiddleware(dev_settings))

    # No Authorization header at all -- the bypass must not even look.
    messages = await _run(middleware, _http_scope())

    assert inner.called
    principal = inner.scope["state"]["principal"]
    assert principal.unixname == "devuser"
    assert principal.groups == ["atlas"]
    assert _status(messages) == 200


async def test_dev_bypass_refuses_non_local_issuer(settings):
    """Defense-in-depth: app.py's lifespan already refuses to start in this
    configuration, but this middleware must fail closed too if that
    invariant were ever violated some other way (e.g. exercised directly in
    a test). A server misconfiguration, not a client-fixable 401."""
    dev_settings = settings.model_copy(
        update={
            "dev_insecure_principal": json.dumps(
                {"uid": 1000, "gid": 1000, "unixname": "devuser"}
            ),
            "oidc_issuer": "https://auth.af.uchicago.edu/realms/connect",
        }
    )
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(inner, IdentityMiddleware(dev_settings))

    with pytest.raises(RuntimeError):
        await _run(middleware, _http_scope())
    assert not inner.called


async def test_non_http_scope_passes_through_untouched(settings):
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(inner, IdentityMiddleware(settings))

    async def receive() -> dict[str, Any]:
        return {}

    async def send(message: dict[str, Any]) -> None:
        pass

    await middleware({"type": "lifespan"}, receive, send)

    assert inner.called


# ---------------------------------------------------------------------------
# Revoked-jti enforcement (issue #115) — /mcp must reject a revoked token
# exactly like /v1 does, since both call identity.get_principal directly.
# ---------------------------------------------------------------------------


async def test_revoked_jti_rejected_on_mcp_path(settings, sig_key, prime_jwks):
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(jti="revoked-on-mcp"))

    backend = InMemoryTokenRegistryBackend()
    await backend.add(
        TokenRecord(
            lookup_id="revoked-on-mcp",
            principal_id="user-123",
            secret_hash="unused-in-this-test",
            name="test-token",
            created_at=time.time(),
            expires_at=time.time() + 3600,
            revoked_at=None,
            last_used_at=None,
        )
    )
    await backend.revoke("user-123", "revoked-on-mcp", revoked_at=time.time())
    cache = RevokedJtiCache(backend, refresh_interval_seconds=30.0)

    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(
        inner, IdentityMiddleware(settings, revoked_jti_cache=cache)
    )

    messages = await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    assert not inner.called
    assert _status(messages) == 401
    body = json.loads(_body(messages))
    assert body["detail"] == "Invalid bearer token"


async def test_active_jti_allowed_through_mcp_path_with_cache_configured(
    settings, sig_key, prime_jwks, static_principal_cache
):
    principal_cache, _directory = static_principal_cache
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims(jti="still-active"))

    cache = RevokedJtiCache(
        InMemoryTokenRegistryBackend(), refresh_interval_seconds=30.0
    )
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(
        inner,
        IdentityMiddleware(
            settings, revoked_jti_cache=cache, principal_cache=principal_cache
        ),
    )

    messages = await _run(middleware, _http_scope({"authorization": f"Bearer {token}"}))

    assert inner.called
    assert _status(messages) == 200


# ---------------------------------------------------------------------------
# Identity PAT recognition on /mcp (issue #144 step 2a). A non-mcp_pat_
# bearer always falls through to the existing JWT path above, unchanged
# (covered by every test above this section, all still passing unmodified).
# ---------------------------------------------------------------------------


async def test_valid_pat_stashes_principal_and_calls_inner_app(settings):
    from af_mcp_broker.pat import mint_pat
    from af_mcp_broker.principal_cache import (
        InMemoryPrincipalCacheBackend,
        PrincipalCache,
    )
    from af_mcp_broker.principal_directory import (
        PrincipalAttributes,
        PrincipalDirectory,
    )
    from af_mcp_broker.token_registry import TokenRecord

    class _FakeDirectory(PrincipalDirectory):
        async def resolve(self, principal_id: str) -> PrincipalAttributes:
            return PrincipalAttributes(
                uid=50123, gid=5000, unixname="auser", groups=["atlas"], email=""
            )

    backend = InMemoryTokenRegistryBackend()
    plaintext, lookup_id, secret_hash = mint_pat()
    await backend.add(
        TokenRecord(
            lookup_id=lookup_id,
            principal_id="user-123",
            secret_hash=secret_hash,
            name="test-token",
            created_at=time.time(),
            expires_at=time.time() + 3600,
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

    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(
        inner,
        IdentityMiddleware(
            settings, pat_backend=backend, principal_cache=principal_cache
        ),
    )

    messages = await _run(
        middleware, _http_scope({"authorization": f"Bearer {plaintext}"})
    )

    assert inner.called
    principal = inner.scope["state"]["principal"]
    assert principal.subject == "user-123"
    assert principal.uid == 50123
    assert _status(messages) == 200


async def test_pat_shaped_bearer_rejected_when_pat_support_not_configured(
    settings,
):
    """No pat_backend/principal_cache wired in (e.g. KEYCLOAK_ADMIN_CLIENT_ID
    unset) -- a mcp_pat_... bearer must be rejected the same vague way as any
    other invalid credential, not crash."""
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(inner, IdentityMiddleware(settings))

    messages = await _run(
        middleware, _http_scope({"authorization": "Bearer mcp_pat_abc123_secretvalue"})
    )

    assert not inner.called
    assert _status(messages) == 401
    body = json.loads(_body(messages))
    assert body["detail"] == "Invalid bearer token"


async def test_malformed_pat_rejected_with_vague_401(settings):
    from af_mcp_broker.principal_cache import (
        InMemoryPrincipalCacheBackend,
        PrincipalCache,
    )
    from af_mcp_broker.principal_directory import (
        PrincipalAttributes,
        PrincipalDirectory,
    )

    class _FakeDirectory(PrincipalDirectory):
        async def resolve(self, principal_id: str) -> PrincipalAttributes:
            raise AssertionError("must not be called for a malformed PAT")

    backend = InMemoryTokenRegistryBackend()
    principal_cache = PrincipalCache(
        _FakeDirectory(),
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=1000.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(
        inner,
        IdentityMiddleware(
            settings, pat_backend=backend, principal_cache=principal_cache
        ),
    )

    messages = await _run(
        middleware, _http_scope({"authorization": "Bearer mcp_pat_missing_secret_part"})
    )

    assert not inner.called
    assert _status(messages) == 401


async def test_unknown_pat_lookup_id_rejected(settings):
    from af_mcp_broker.pat import mint_pat
    from af_mcp_broker.principal_cache import (
        InMemoryPrincipalCacheBackend,
        PrincipalCache,
    )
    from af_mcp_broker.principal_directory import (
        PrincipalAttributes,
        PrincipalDirectory,
    )

    class _FakeDirectory(PrincipalDirectory):
        async def resolve(self, principal_id: str) -> PrincipalAttributes:
            raise AssertionError("must not be called for an unknown lookup_id")

    backend = InMemoryTokenRegistryBackend()  # never populated
    plaintext, _, _ = mint_pat()
    principal_cache = PrincipalCache(
        _FakeDirectory(),
        backend=InMemoryPrincipalCacheBackend(),
        refresh_interval_seconds=1000.0,
        max_staleness_seconds=3600.0,
        heartbeat_interval_seconds=3600.0,
    )
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(
        inner,
        IdentityMiddleware(
            settings, pat_backend=backend, principal_cache=principal_cache
        ),
    )

    messages = await _run(
        middleware, _http_scope({"authorization": f"Bearer {plaintext}"})
    )

    assert not inner.called
    assert _status(messages) == 401


async def test_expired_pat_rejected_with_actionable_portal_message(settings):
    from af_mcp_broker.pat import mint_pat
    from af_mcp_broker.principal_cache import (
        InMemoryPrincipalCacheBackend,
        PrincipalCache,
    )
    from af_mcp_broker.principal_directory import (
        PrincipalAttributes,
        PrincipalDirectory,
    )
    from af_mcp_broker.token_registry import TokenRecord

    class _FakeDirectory(PrincipalDirectory):
        async def resolve(self, principal_id: str) -> PrincipalAttributes:
            return PrincipalAttributes(uid=1, gid=1, unixname="u", groups=[], email="")

    backend = InMemoryTokenRegistryBackend()
    plaintext, lookup_id, secret_hash = mint_pat()
    await backend.add(
        TokenRecord(
            lookup_id=lookup_id,
            principal_id="user-123",
            secret_hash=secret_hash,
            name="test-token",
            created_at=time.time() - 7200,
            expires_at=time.time() - 3600,
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
    inner = _InnerApp()
    middleware = AsgiAuthMiddleware(
        inner,
        IdentityMiddleware(
            settings, pat_backend=backend, principal_cache=principal_cache
        ),
    )

    messages = await _run(
        middleware, _http_scope({"authorization": f"Bearer {plaintext}"})
    )

    assert not inner.called
    assert _status(messages) == 401
    body = json.loads(_body(messages))
    assert "expired" in body["detail"]
    assert f"{settings.portal_url.rstrip('/')}/tokens" in body["detail"]


# ---------------------------------------------------------------------------
# IdentityMiddleware -- now a thin hand-off inside FastMCP's own middleware
# pipeline. It does no JWT validation; it only republishes the Principal
# AsgiAuthMiddleware already stashed on the ASGI scope (reachable here via
# fastmcp's get_http_request().state) as FastMCP Context state, and fails
# closed if nothing was stashed.
# ---------------------------------------------------------------------------


class _FakeFastMCPContext:
    """Duck-types just enough of fastmcp.Context for IdentityMiddleware."""

    def __init__(self) -> None:
        self._state: dict[str, Any] = {}

    async def set_state(
        self, key: str, value: Any, *, serializable: bool = True
    ) -> None:
        self._state[key] = value

    async def get_state(self, key: str) -> Any:
        return self._state.get(key)


class _FakeMiddlewareContext:
    def __init__(self, fastmcp_context: _FakeFastMCPContext | None) -> None:
        self.fastmcp_context = fastmcp_context


async def _call_next(context: Any) -> str:
    return "ok"


def _set_stashed_principal(monkeypatch: pytest.MonkeyPatch, principal: Any) -> None:
    """AsgiAuthMiddleware stashes the Principal on scope["state"]; fastmcp's
    get_http_request() is the reader-side equivalent of that scope --
    patch it directly rather than building a real ASGI request."""
    fake_request = SimpleNamespace(state=SimpleNamespace(principal=principal))
    monkeypatch.setattr(identity_mw, "get_http_request", lambda: fake_request)


async def test_on_request_republishes_stashed_principal_as_context_state(
    settings, make_principal, monkeypatch
):
    principal = make_principal(unixname="auser", uid=50123)
    _set_stashed_principal(monkeypatch, principal)

    mw = IdentityMiddleware(settings)
    fake_ctx = _FakeFastMCPContext()
    context = _FakeMiddlewareContext(fake_ctx)

    result = await mw.on_request(context, _call_next)

    assert result == "ok"
    assert await fake_ctx.get_state("principal") is principal


async def test_on_request_fails_closed_when_nothing_was_stashed(settings, monkeypatch):
    """Should never happen in the real app -- AsgiAuthMiddleware always runs
    first and never calls into this pipeline without a validated Principal.
    Guards against a future embedding that forgets to install it."""
    fake_request = SimpleNamespace(state=SimpleNamespace())
    monkeypatch.setattr(identity_mw, "get_http_request", lambda: fake_request)

    mw = IdentityMiddleware(settings)
    context = _FakeMiddlewareContext(_FakeFastMCPContext())

    with pytest.raises(AuthorizationError):
        await mw.on_request(context, _call_next)


async def test_missing_fastmcp_context_fails_closed(settings, monkeypatch):
    mw = IdentityMiddleware(settings)
    context = _FakeMiddlewareContext(None)

    with pytest.raises(AuthorizationError):
        await mw.on_request(context, _call_next)

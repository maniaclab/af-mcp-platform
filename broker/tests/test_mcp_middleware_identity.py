from __future__ import annotations

import json
import time
from typing import Any

import pytest
from conftest import make_claims
from fastmcp.exceptions import AuthorizationError

from af_mcp_broker.mcp.middleware import identity_mw
from af_mcp_broker.mcp.middleware.identity_mw import IdentityMiddleware


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


def _set_headers(monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]) -> None:
    """IdentityMiddleware imports get_http_headers by name; patch that name
    directly rather than the real HTTP-request-scoped implementation, which
    only works inside an actual ASGI request (covered separately by the
    integration test)."""
    monkeypatch.setattr(identity_mw, "get_http_headers", lambda **kwargs: dict(headers))


async def test_valid_bearer_sets_principal(settings, sig_key, prime_jwks, monkeypatch):
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    _set_headers(monkeypatch, {"authorization": f"Bearer {token}"})

    mw = IdentityMiddleware(settings)
    fake_ctx = _FakeFastMCPContext()
    context = _FakeMiddlewareContext(fake_ctx)

    result = await mw.on_request(context, _call_next)

    assert result == "ok"
    principal = await fake_ctx.get_state("principal")
    assert principal.unixname == "auser"
    assert principal.uid == 50123


async def test_missing_header_rejected(settings, monkeypatch):
    _set_headers(monkeypatch, {})
    mw = IdentityMiddleware(settings)
    context = _FakeMiddlewareContext(_FakeFastMCPContext())

    with pytest.raises(AuthorizationError):
        await mw.on_request(context, _call_next)


async def test_non_bearer_scheme_rejected(settings, monkeypatch):
    _set_headers(monkeypatch, {"authorization": "Basic deadbeef"})
    mw = IdentityMiddleware(settings)
    context = _FakeMiddlewareContext(_FakeFastMCPContext())

    with pytest.raises(AuthorizationError):
        await mw.on_request(context, _call_next)


async def test_invalid_signature_rejected(
    settings, sig_key, enc_key, prime_jwks, monkeypatch
):
    # Signing key is never published to the JWKS the middleware sees -> the
    # token's signature cannot be verified.
    prime_jwks([enc_key.jwk])
    token = sig_key.sign(make_claims())
    _set_headers(monkeypatch, {"authorization": f"Bearer {token}"})

    mw = IdentityMiddleware(settings)
    context = _FakeMiddlewareContext(_FakeFastMCPContext())

    with pytest.raises(AuthorizationError):
        await mw.on_request(context, _call_next)


async def test_expired_token_rejected(settings, sig_key, prime_jwks, monkeypatch):
    prime_jwks([sig_key.jwk])
    now = int(time.time())
    token = sig_key.sign(make_claims(iat=now - 600, exp=now - 300))
    _set_headers(monkeypatch, {"authorization": f"Bearer {token}"})

    mw = IdentityMiddleware(settings)
    context = _FakeMiddlewareContext(_FakeFastMCPContext())

    with pytest.raises(AuthorizationError):
        await mw.on_request(context, _call_next)


async def test_dev_bypass_active_builds_principal_without_checking_headers(
    settings, monkeypatch
):
    dev_settings = settings.model_copy(
        update={
            "dev_insecure_principal": json.dumps(
                {"uid": 1000, "gid": 1000, "unixname": "devuser", "groups": ["atlas"]}
            ),
            "oidc_issuer": "http://localhost:8081/realms/x",
        }
    )
    # No Authorization header at all -- the bypass must not even look.
    _set_headers(monkeypatch, {})

    mw = IdentityMiddleware(dev_settings)
    fake_ctx = _FakeFastMCPContext()
    context = _FakeMiddlewareContext(fake_ctx)

    result = await mw.on_request(context, _call_next)

    assert result == "ok"
    principal = await fake_ctx.get_state("principal")
    assert principal.unixname == "devuser"
    assert principal.groups == ["atlas"]


async def test_dev_bypass_refuses_non_local_issuer(settings):
    """Defense-in-depth: app.py's lifespan already refuses to start in this
    configuration, but the middleware must fail closed too if it were ever
    exercised in isolation (e.g. a future embedding that skips app.py)."""
    dev_settings = settings.model_copy(
        update={
            "dev_insecure_principal": json.dumps(
                {"uid": 1000, "gid": 1000, "unixname": "devuser"}
            ),
            "oidc_issuer": "https://keycloak-prod.tempest.uchicago.edu/realms/connect",
        }
    )
    mw = IdentityMiddleware(dev_settings)
    context = _FakeMiddlewareContext(_FakeFastMCPContext())

    with pytest.raises(AuthorizationError):
        await mw.on_request(context, _call_next)


async def test_missing_fastmcp_context_fails_closed(
    settings, sig_key, prime_jwks, monkeypatch
):
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())
    _set_headers(monkeypatch, {"authorization": f"Bearer {token}"})

    mw = IdentityMiddleware(settings)
    context = _FakeMiddlewareContext(None)

    with pytest.raises(AuthorizationError):
        await mw.on_request(context, _call_next)

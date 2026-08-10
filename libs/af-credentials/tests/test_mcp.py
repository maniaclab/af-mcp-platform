"""Tests for the optional mcp SDK adapter (af_credentials.mcp).

Skipped entirely when the `mcp` package isn't installed -- af-credentials's
runtime dependencies are pyjwt[crypto] and httpx2 only; `mcp` is opt-in via
the `[mcp]` extra (see pyproject.toml and README.md for why the version
pinned there doesn't match what's actually exercised in this monorepo's
pixi environment right now).
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from af_credentials.verifier import BrokerClaims

if TYPE_CHECKING:
    from mcp.server.auth.provider import AccessToken

mcp = pytest.importorskip("mcp")

from af_credentials.mcp import mcp_token_verifier  # noqa: E402

_CLAIMS = BrokerClaims(sub="af|12345", jti="test-jti-0001", exp=1_700_000_600)


class _StubVerifier:
    """A minimal stand-in for BrokerTokenVerifier -- returns a fixed answer per token without any real JWT/JWKS machinery, since this adapter's own logic (not BrokerTokenVerifier's) is what's under test here."""

    def __init__(self, answer: BrokerClaims | None) -> None:
        self._answer = answer
        self.tokens_seen: list[str] = []

    async def verify(self, token: str) -> BrokerClaims | None:
        self.tokens_seen.append(token)
        return self._answer


class TestMcpTokenVerifier:
    async def test_valid_token_returns_access_token(self) -> None:
        stub = _StubVerifier(_CLAIMS)
        adapter = mcp_token_verifier(stub)  # type: ignore[arg-type]

        result: AccessToken | None = await adapter.verify_token("some-token")

        assert result is not None
        assert result.token == "some-token"
        assert result.client_id == _CLAIMS.sub
        assert result.scopes == []
        assert result.expires_at == _CLAIMS.exp

    async def test_invalid_token_returns_none(self) -> None:
        stub = _StubVerifier(None)
        adapter = mcp_token_verifier(stub)  # type: ignore[arg-type]

        assert await adapter.verify_token("bad-token") is None

    async def test_delegates_to_underlying_verifier(self) -> None:
        stub = _StubVerifier(replace(_CLAIMS, sub="af|other"))
        adapter = mcp_token_verifier(stub)  # type: ignore[arg-type]

        await adapter.verify_token("the-actual-token")

        assert stub.tokens_seen == ["the-actual-token"]

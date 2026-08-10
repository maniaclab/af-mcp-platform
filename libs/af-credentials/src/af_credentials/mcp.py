"""Optional adapter from BrokerTokenVerifier to the mcp SDK's TokenVerifier protocol.

Importing this module requires the ``mcp`` package (the ``[mcp]`` extra --
see pyproject.toml and README.md); af_credentials.verifier itself never
imports it, so a caller who only needs token verification (no MCP server)
pays no cost for this optional dependency. The guard below turns a missing
``mcp`` install into one clear error naming the extra to install, rather
than a bare ``ModuleNotFoundError`` pointing at this file's internals.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from af_credentials.verifier import BrokerTokenVerifier

try:
    from mcp.server.auth.provider import AccessToken, TokenVerifier
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    msg = (
        "af_credentials.mcp requires the 'mcp' package. Install it via the "
        "'mcp' extra: pip install af-credentials[mcp]"
    )
    raise ImportError(msg) from exc


class _BrokerTokenVerifierAdapter(TokenVerifier):
    """Adapts a BrokerTokenVerifier to the mcp SDK's TokenVerifier protocol.

    Never constructed directly by callers -- use ``mcp_token_verifier()``.
    Carries no authorization claims: ``scopes`` is always empty, matching
    the AF Broker Identity Token itself carrying none (see verifier.py's
    module docstring) -- an MCP server wanting authorization must resolve
    it itself from ``client_id`` (the token's ``sub``), not from this
    adapter's output.
    """

    def __init__(self, verifier: BrokerTokenVerifier) -> None:
        self._verifier = verifier

    async def verify_token(self, token: str) -> AccessToken | None:
        claims = await self._verifier.verify(token)
        if claims is None:
            return None
        return AccessToken(
            token=token,
            client_id=claims.sub,
            scopes=[],
            expires_at=claims.exp,
        )


def mcp_token_verifier(verifier: BrokerTokenVerifier) -> TokenVerifier:
    """Wrap *verifier* as an mcp SDK ``TokenVerifier`` for a FastMCP/mcp server's auth configuration."""
    return _BrokerTokenVerifierAdapter(verifier)

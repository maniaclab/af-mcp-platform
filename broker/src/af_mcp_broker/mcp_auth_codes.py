"""In-process, single-use authorization codes for the MCP OAuth bootstrap flow (issue #140).

The broker acts as an authorization server to MCP clients (``api/mcp_oauth.py``):
after Keycloak's callback proves who the user is, the broker mints a short-lived
opaque code and redirects the MCP client's browser back with it, exactly like any
OAuth 2.1 authorization-code response. The MCP client then redeems that code at
``/v1/oauth/token`` for a PAT.

The code's lifetime end-to-end is measured in seconds (a browser redirect plus
one follow-up POST), the same order of magnitude as ``oauth_state.py``'s nonce
cookie -- so, like that cookie, this is deliberately in-process rather than
Vault-backed: a broker restart mid-flow simply fails the pending authorization
(the MCP client retries the whole flow from ``/v1/oauth/authorize`), which is
no worse than a browser tab closed mid-flow. Persisting a few seconds of
throwaway state across replicas/restarts would add real infrastructure for a
failure mode this cheap to just retry.

Single-use: ``consume`` pops the record so a leaked/observed code (e.g. in a
proxy log) cannot be redeemed twice -- this is exactly why the PAT is minted
at ``/v1/oauth/token`` (on redemption) rather than eagerly at the Keycloak
callback (on issuance): the code, not the credential, is what a browser
history or referrer header could otherwise leak.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

# End-to-end lifetime: browser redirect from the Keycloak callback to the MCP
# client, plus that client's follow-up POST to /v1/oauth/token. Generous
# relative to the actual round trip, matching STATE_TOKEN_TTL_SECONDS's own
# "TTL, not a tight deadline" philosophy (oauth_state.py).
_CODE_TTL_SECONDS = 120

# 256-bit random code, matching pat.py's secret-generation size -- this code
# is a bearer credential for the duration of its short life (whoever presents
# it at /v1/oauth/token walks away with a PAT), so it gets the same entropy
# budget as a long-lived one.
_CODE_BYTES = 32


@dataclass(frozen=True)
class McpAuthCodeRecord:
    """Everything ``/v1/oauth/token`` needs to redeem a code minted by the Keycloak callback."""

    principal_id: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    # None when the MCP client's CIMD document had no client_name -- see
    # cimd_client.CimdClient's docstring for the same convention.
    client_name: str | None


@dataclass
class _Entry:
    record: McpAuthCodeRecord
    expires_at: float


class McpAuthCodeStore:
    """Process-local, single-use, TTL-bounded store for MCP bootstrap authorization codes.

    Not thread-safe beyond what a single asyncio event loop already
    guarantees (no ``await`` between the dict read/write in either method) --
    the same assumption ``pat_auth.LastUsedTracker`` and other in-process
    caches in this codebase already make.
    """

    def __init__(self, ttl_seconds: float = _CODE_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._entries: dict[str, _Entry] = {}

    def put(self, record: McpAuthCodeRecord) -> str:
        """Store *record* under a freshly generated opaque code and return it."""
        code = secrets.token_urlsafe(_CODE_BYTES)
        self._entries[code] = _Entry(
            record=record, expires_at=time.time() + self._ttl_seconds
        )
        return code

    def consume(self, code: str) -> McpAuthCodeRecord | None:
        """Pop and return the record for *code*, or None if unknown/expired/already used.

        Popping unconditionally (even when expired) means a second redemption
        attempt with the same code always sees "unknown" rather than "expired"
        -- indistinguishable from the caller's point of view, and one less
        reason to keep a dead entry around.
        """
        entry = self._entries.pop(code, None)
        if entry is None:
            return None
        if entry.expires_at <= time.time():
            return None
        return entry.record

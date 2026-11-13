"""Self-contained, single-use authorization codes for the MCP OAuth bootstrap flow (issues #140, #374).

The broker acts as an authorization server to MCP clients (``api/mcp_oauth.py``):
after Keycloak's callback proves who the user is, the broker mints a short-lived
opaque code and redirects the MCP client's browser back with it, exactly like any
OAuth 2.1 authorization-code response. The MCP client then redeems that code at
``/v1/oauth/token`` for a PAT.

Broker replicas share no session store and no affinity ties the client's
redemption POST to the replica that issued the code, so the code carries its
own record: it is an AEAD-encrypted (Fernet) token under the same
``BROKER_STATE_KEY`` cipher that carries the authorize-to-callback leg
(``oauth_state.py``). Any replica can open it; the client sees only opaque
bytes; a tampered or foreign code fails authentication.

What encryption cannot give is single use: a self-contained code is valid on
every replica until it expires. Each code embeds a random id, and redemption
first bumps a ``shared_state`` window counter keyed by that id (``mcp_auth_code:
<id>``) whose TTL is the code's remaining lifetime. Count 1 is the first
presentation; anything higher is a replay. The TTL retires the marker, so
nothing sweeps. This is why the PAT is minted at ``/v1/oauth/token`` (on
redemption) rather than at the Keycloak callback (on issuance): the code, not
the credential, is what a browser history or referrer header could otherwise
leak.

If the shared store cannot be reached, redemption is refused
(``SharedStateUnavailableError`` propagates). Unlike the unlock limiter there
is no per-replica fallback: a fallback would let a replayed code through on a
second replica, and RFC 6749 §4.1.2 requires authorization codes to be single
use. The client simply restarts the flow.
"""

from __future__ import annotations

import math
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from af_mcp_broker.oauth_state import StateTokenError, decrypt_claims, encrypt_claims

if TYPE_CHECKING:
    from collections.abc import Callable

    from cryptography.fernet import Fernet

    from af_mcp_broker.shared_state import SharedState

# End-to-end lifetime: browser redirect from the Keycloak callback to the MCP
# client, plus that client's follow-up POST to /v1/oauth/token. Generous
# relative to the actual round trip, matching STATE_TOKEN_TTL_SECONDS's own
# "TTL, not a tight deadline" philosophy (oauth_state.py). Also the upper
# bound on a single-use marker's TTL.
_CODE_TTL_SECONDS = 120

# 128-bit random code id, the same size as the state nonce. It only has to be
# unguessable-enough to never collide and to key the single-use marker; the
# code's secrecy comes from the encryption around it.
_CODE_ID_BYTES = 16

# Namespace for single-use markers in the shared store.
_MARKER_KEY_PREFIX = "mcp_auth_code:"

_CODE_FIELDS = (
    "iss",
    "aud",
    "code_id",
    "principal_id",
    "client_id",
    "redirect_uri",
    "code_challenge",
    "client_name",
    "iat",
    "exp",
)


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


class McpAuthCodeStore:
    """Issues and redeems self-contained MCP bootstrap authorization codes.

    *clock* returns seconds since the epoch; it is injectable so expiry can
    be tested without sleeping. *issuer* binds codes to this deployment, the
    same way state tokens are bound.
    """

    def __init__(
        self,
        cipher: Fernet,
        shared_state: SharedState,
        *,
        issuer: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._cipher = cipher
        self._shared_state = shared_state
        self._issuer = issuer
        self._clock = clock

    def put(self, record: McpAuthCodeRecord) -> str:
        """Return a fresh opaque code carrying *record*, valid for ``_CODE_TTL_SECONDS``."""
        return encrypt_claims(
            self._cipher,
            {
                "code_id": secrets.token_urlsafe(_CODE_ID_BYTES),
                "principal_id": record.principal_id,
                "client_id": record.client_id,
                "redirect_uri": record.redirect_uri,
                "code_challenge": record.code_challenge,
                # "" (never None -- the payload round-trips through JSON).
                "client_name": record.client_name or "",
            },
            iss=self._issuer,
            ttl_seconds=_CODE_TTL_SECONDS,
            now=int(self._clock()),
        )

    async def consume(self, code: str) -> McpAuthCodeRecord | None:
        """Return the record for *code*, or None if forged/expired/already used.

        A code that does not authenticate, has expired, or is not for this
        deployment is None without touching the store, so garbage cannot
        write markers. Raises ``SharedStateUnavailableError`` when the store
        cannot be reached: the caller must refuse redemption (see the module
        docstring). The code is not consumed in that case, so a retry after
        the store recovers still works.
        """
        now = int(self._clock())
        try:
            claims = decrypt_claims(
                self._cipher,
                code,
                fields=_CODE_FIELDS,
                expected_iss=self._issuer,
                ttl_seconds=_CODE_TTL_SECONDS,
                now=now,
            )
        except StateTokenError:
            return None

        # Whole seconds left on the code; the marker must live at least that
        # long so a replay inside the code's validity always sees count > 1.
        remaining = min(_CODE_TTL_SECONDS, max(1, math.ceil(claims["exp"] - now)))
        window = await self._shared_state.incr_window(
            _MARKER_KEY_PREFIX + str(claims["code_id"]), remaining
        )
        if window.count != 1:
            return None

        return McpAuthCodeRecord(
            principal_id=claims["principal_id"],
            client_id=claims["client_id"],
            redirect_uri=claims["redirect_uri"],
            code_challenge=claims["code_challenge"],
            client_name=claims["client_name"] or None,
        )

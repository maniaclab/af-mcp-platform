"""Broker identity-token verification with a cached JWKS (U1, U2, U5, U7, X2)."""

from __future__ import annotations

import logging
import time

import httpx2
import jwt
from fastmcp.server.auth import AccessToken, TokenVerifier

log = logging.getLogger(__name__)


class JwksCache:
    """Broker public keys by ``kid``.

    Verification is served from memory. The set is refetched when the TTL
    lapses, or early when a token names an unknown ``kid`` (a key rotation),
    at most once per ``min_refetch`` seconds so a forged ``kid`` cannot turn
    every request into a fetch. A failed refetch keeps the keys already held.
    """

    def __init__(
        self,
        uri: str,
        client: httpx2.AsyncClient,
        ttl: float = 3600.0,
        min_refetch: float = 30.0,
    ) -> None:
        self._uri, self._client = uri, client
        self._ttl, self._min_refetch = ttl, min_refetch
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at = float("-inf")

    async def key(self, kid: str) -> jwt.PyJWK:
        """Return the key for ``kid``; raise KeyError when the broker has no such key."""
        age = time.monotonic() - self._fetched_at
        if age > self._ttl or (kid not in self._keys and age > self._min_refetch):
            await self._refetch()
        return self._keys[kid]

    async def _refetch(self) -> None:
        self._fetched_at = time.monotonic()  # also rate-limits retries after a failure
        try:
            response = await self._client.get(self._uri)
            response.raise_for_status()
        except httpx2.HTTPError:
            log.warning("jwks.fetch_failed", exc_info=True)
            return
        keys = jwt.PyJWKSet.from_dict(response.json()).keys
        self._keys = {k.key_id: k for k in keys if k.key_id}


class BrokerTokenVerifier(TokenVerifier):
    """Accept only a broker identity token for this service's audience.

    Signature, ``iss``, ``aud`` and ``exp`` are checked; the token's identity
    claims are read and its (absent) authorization claims are not (U5).
    Returning None makes fastmcp answer HTTP 401 before any tool runs (X2).
    """

    def __init__(self, jwks: JwksCache, issuer: str, audience: str) -> None:
        super().__init__()
        self._jwks, self._issuer, self._audience = jwks, issuer, audience

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return the verified token, or None for any invalid one."""
        try:
            kid = jwt.get_unverified_header(token)["kid"]
            claims = jwt.decode(
                token,
                (await self._jwks.key(kid)).key,
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=self._audience,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except (jwt.PyJWTError, KeyError):
            return None
        return AccessToken(
            token=token,
            client_id=claims["sub"],
            scopes=[],
            expires_at=claims["exp"],
            claims=claims,
        )

"""Async verification of AF Broker Identity Tokens.

The token format is documented in docs/auth.md ("AF Broker Identity Token",
issue #162) and minted by ``af_mcp_broker.credentials.broker_issued``: an
identity assertion only -- ``iss``/``sub``/``aud``/``exp``/``iat``/``jti``
always present, ``uid``/``gid``/``unixname`` present only for targets whose
broker config sets ``include_posix``. Deliberately absent: capabilities,
groups, or any authorization claim -- this module surfaces nothing beyond
what the token itself carries.

This module has no dependency on af_mcp_broker or any web framework: it is
the client half of the contract, meant to be embedded in any backend that
trusts the broker as a token issuer (ami-mcp's broker mode, later
rucio-mcp), verifying against the broker's own published JWKS
(``GET /.well-known/jwks.json``) with a standard JWT library.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx2
import jwt
from jwt.algorithms import RSAAlgorithm


@dataclass(frozen=True)
class BrokerClaims:
    """Decoded, verified claims from an AF Broker Identity Token.

    Mirrors the claim set ``BrokerTokenIssuer.mint()`` signs: ``sub``,
    ``jti``, and ``exp`` are always present on a verified token; ``uid``/
    ``gid``/``unixname`` are ``None`` unless the issuing broker included
    POSIX identity claims for this token's audience.
    """

    sub: str
    jti: str
    exp: int
    uid: int | None = None
    gid: int | None = None
    unixname: str | None = None


class BrokerTokenVerifier:
    """Verifies AF Broker Identity Tokens (RS256) against a broker's published JWKS.

    JWKS keys are cached in-process for *cache_ttl* seconds, keyed by
    ``kid``. A token whose ``kid`` isn't in the current cache triggers
    exactly one refetch (to pick up a key rotated in since the last fetch,
    per docs/auth.md's rotation procedure) -- if the refetched JWKS still
    doesn't carry that ``kid``, verification fails without fetching again.

    ``verify()`` returns ``None`` for every way a token can be *invalid*
    (bad signature, wrong issuer/audience, expired, malformed, unknown
    key) so callers can treat "not authenticated" uniformly. It does NOT
    catch transport-level failures (a network error, or the JWKS endpoint
    itself returning a non-2xx status) -- those propagate as exceptions, so
    a caller can distinguish "the broker is unreachable" from "this token
    is bad" and respond accordingly (e.g. a 503 vs. a 401).
    """

    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        audience: str,
        *,
        cache_ttl: float = 300.0,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        """Construct a verifier for tokens issued by *issuer* naming *audience* as the audience.

        *http_client*, when given, is used for every JWKS fetch instead of
        a short-lived client created per fetch -- primarily a test seam
        (inject an ``httpx2.AsyncClient`` backed by ``httpx2.MockTransport``)
        but also usable by callers who want connection pooling across
        verifiers. The verifier never closes an injected client; it owns
        the lifecycle of one it creates itself, closing it after each
        fetch.
        """
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._audience = audience
        self._cache_ttl = cache_ttl
        self._http_client = http_client
        self._keys_by_kid: dict[str, dict[str, Any]] = {}
        self._fetched_at: float | None = None

    async def verify(self, token: str) -> BrokerClaims | None:
        """Verify *token* and return its claims, or ``None`` if it is not a currently-valid AF Broker Identity Token for this verifier's issuer/audience.

        Raises whatever ``httpx2`` raises (connection errors, timeouts, a
        non-2xx JWKS response) if a JWKS fetch is needed and fails -- see
        the class docstring on why that is deliberately not folded into a
        ``None`` return.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            return None
        kid = header.get("kid")
        if not isinstance(kid, str):
            return None

        key_data = await self._get_key(kid)
        if key_data is None:
            return None

        try:
            public_key = RSAAlgorithm.from_jwk(key_data)
            claims = jwt.decode(
                token,
                public_key,  # type: ignore[arg-type]  # JWKS only ever carries public keys
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=self._audience,
                options={"verify_exp": True},
            )
        except jwt.InvalidTokenError:
            return None

        return BrokerClaims(
            sub=claims["sub"],
            jti=claims["jti"],
            exp=claims["exp"],
            uid=claims.get("uid"),
            gid=claims.get("gid"),
            unixname=claims.get("unixname"),
        )

    async def _get_key(self, kid: str) -> dict[str, Any] | None:
        """Return the JWK for *kid*, refreshing the cache if it is stale or missing *kid* -- with at most one refetch for a *kid* the refreshed JWKS still doesn't carry."""
        now = time.monotonic()
        cache_is_stale = (
            self._fetched_at is None or (now - self._fetched_at) > self._cache_ttl
        )
        if cache_is_stale or kid not in self._keys_by_kid:
            await self._refresh()
        return self._keys_by_kid.get(kid)

    async def _refresh(self) -> None:
        """Refetch the JWKS unconditionally and replace the key cache with its contents."""
        keys = await self._fetch_jwks()
        self._keys_by_kid = {
            key_data["kid"]: key_data for key_data in keys if "kid" in key_data
        }
        self._fetched_at = time.monotonic()

    async def _fetch_jwks(self) -> list[dict[str, Any]]:
        if self._http_client is not None:
            response = await self._http_client.get(self._jwks_url)
            response.raise_for_status()
            return response.json()["keys"]  # type: ignore[no-any-return]

        async with httpx2.AsyncClient(timeout=10.0) as client:
            response = await client.get(self._jwks_url)
            response.raise_for_status()
            return response.json()["keys"]  # type: ignore[no-any-return]

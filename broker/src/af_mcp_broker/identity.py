from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Annotated, Any

import jwt
import structlog
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.http import get_http_client

logger = structlog.get_logger(__name__)

_bearer_scheme = HTTPBearer(auto_error=True)

# ---------------------------------------------------------------------------
# JWKS cache — one entry per JWKS URI, refreshed after TTL seconds.
# ---------------------------------------------------------------------------

_JWKS_CACHE_TTL_SECONDS = 300


@dataclass
class _JwksEntry:
    keys: list[dict[str, Any]]
    fetched_at: float


_jwks_cache: dict[str, _JwksEntry] = {}
# Single-flight: dedupe concurrent refreshes of the same URI. Locks are
# per-event-loop because asyncio.Lock binds to the loop that first uses it
# (tests run many short-lived loops in one process).
_jwks_locks: dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Lock]] = {}


def _get_jwks_lock(uri: str) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    entry = _jwks_locks.get(uri)
    if entry is None or entry[0] is not loop:
        entry = (loop, asyncio.Lock())
        _jwks_locks[uri] = entry
    return entry[1]


async def _fetch_jwks(jwks_uri: str) -> list[dict[str, Any]]:
    """Fetch JWKS from upstream, bypassing the TTL cache.

    Raises HTTPException(502) when the upstream is unreachable so callers
    higher up the stack can surface a useful error rather than a raw 500.
    """
    try:
        resp = await get_http_client().get(jwks_uri, timeout=10.0)
        resp.raise_for_status()
        return resp.json()["keys"]
    except Exception as exc:
        logger.error("jwks_fetch_failed", uri=jwks_uri, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to reach JWKS endpoint: {jwks_uri}",
        ) from exc


async def get_jwks(settings: Settings) -> list[dict[str, Any]]:
    """Return JWKS keys, using a 5-minute in-process TTL cache.

    Concurrent refreshes of the same URI are deduplicated, and a refresh
    failure falls back to the stale entry so a Keycloak blip does not take
    auth down with it.
    """
    uri = settings.keycloak_jwks_uri
    entry = _jwks_cache.get(uri)
    now = time.monotonic()

    if entry is not None and (now - entry.fetched_at) <= _JWKS_CACHE_TTL_SECONDS:
        return entry.keys

    async with _get_jwks_lock(uri):
        # Another request may have refreshed while we waited on the lock.
        entry = _jwks_cache.get(uri)
        now = time.monotonic()
        if entry is not None and (now - entry.fetched_at) <= _JWKS_CACHE_TTL_SECONDS:
            return entry.keys

        try:
            keys = await _fetch_jwks(uri)
        except HTTPException:
            if entry is not None:
                logger.warning("jwks_refresh_failed_serving_stale", uri=uri)
                return entry.keys
            raise
        _jwks_cache[uri] = _JwksEntry(keys=keys, fetched_at=now)
        logger.debug("jwks_cache_refreshed", uri=uri, key_count=len(keys))
        return keys


# ---------------------------------------------------------------------------
# Principal — immutable identity snapshot extracted from a validated JWT.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    subject: str
    email: str
    uid: int
    gid: int
    unixname: str
    groups: list[str]
    # Present when the user has linked an ATLAS IAM identity in Keycloak.
    iam_sub: str | None
    # Present when the user has linked a CERN identity in Keycloak.
    cern_sub: str | None
    # Keep the raw token for downstream credential flows; SecretStr prevents
    # accidental logging.
    raw_token: SecretStr = field(compare=False, repr=False)


# ---------------------------------------------------------------------------
# JWT validation helpers
# ---------------------------------------------------------------------------


def _extract_principal(claims: dict[str, Any], raw_token: str) -> Principal:
    """Map decoded JWT claims to a Principal.

    Raises ValueError with a descriptive message if required claims are absent
    so the caller can convert it to an appropriate HTTP error.
    """
    posix = claims.get("posix")
    if not posix:
        raise ValueError("JWT is missing required 'posix' claim")

    # A malformed 'posix' claim (missing uid/gid/unixname) is a client-side
    # invalid-token condition, not a server error — raise ValueError so the
    # caller returns 401 rather than letting a KeyError escape as a 500.
    missing = [k for k in ("uid", "gid", "unixname") if k not in posix]
    if missing:
        raise ValueError(f"JWT 'posix' claim is missing keys: {', '.join(missing)}")

    subject = claims.get("sub", "")
    email = claims.get("email", "")
    groups: list[str] = claims.get("groups", [])

    # Identity-brokered sub claims from federated providers are surfaced as
    # top-level string claims by the Keycloak mapper configuration.
    iam_sub: str | None = claims.get("atlas_iam_sub") or claims.get("iam_sub")
    cern_sub: str | None = claims.get("cern_sub")

    return Principal(
        subject=subject,
        email=email,
        uid=int(posix["uid"]),
        gid=int(posix["gid"]),
        unixname=str(posix["unixname"]),
        groups=groups,
        iam_sub=iam_sub,
        cern_sub=cern_sub,
        raw_token=SecretStr(raw_token),
    )


async def get_principal(token: str, settings: Settings) -> Principal:
    """Validate a Bearer token and return the extracted Principal.

    Raises HTTPException(401) on any validation failure so FastAPI can return
    a proper WWW-Authenticate response.
    """
    keys = await get_jwks(settings)

    error: Exception | str | None = None
    try:
        # Select the signing key by the token's `kid`. A JWKS commonly carries
        # more than one key (e.g. Keycloak publishes both a signature and an
        # encryption key); trying keys in list order and treating a signature
        # mismatch as fatal fails whenever the wrong key sorts first.
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key_data = _select_jwk(keys, kid)
        if key_data is None:
            error = f"no JWKS key matches token kid={kid!r}"
        else:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            claims = jwt.decode(
                token,
                public_key,  # type: ignore[arg-type]  # JWKS only has public keys
                algorithms=["RS256"],
                audience=settings.keycloak_audience,
                issuer=settings.keycloak_issuer,
                options={"verify_exp": True},
            )
            return _extract_principal(claims, token)
    except jwt.ExpiredSignatureError as exc:
        error = exc
        logger.info("jwt_expired", subject=_peek_sub(token))
    except jwt.InvalidTokenError as exc:
        error = exc
    except (ValueError, KeyError) as exc:
        error = exc

    logger.warning(
        "jwt_validation_failed",
        error=str(error) if error else "no matching key",
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _select_jwk(keys: list[dict[str, Any]], kid: str | None) -> dict[str, Any] | None:
    """Return the JWK matching ``kid``.

    When the token carries no ``kid`` and the JWKS publishes exactly one key,
    fall back to that key so single-key realms keep working.
    """
    if kid is not None:
        for key_data in keys:
            if key_data.get("kid") == kid:
                return key_data
        return None
    return keys[0] if len(keys) == 1 else None


def _peek_sub(token: str) -> str:
    """Decode the subject claim without signature verification for logging only."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("sub", "<unknown>")
    except Exception:
        return "<unparseable>"


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def keycloak_dependency(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    """FastAPI dependency that resolves to the authenticated Principal.

    Inject this into route handlers that require authentication:

        @router.get("/example")
        async def example(
            principal: Annotated[Principal, Depends(keycloak_dependency)],
        ):
            ...
    """
    return await get_principal(credentials.credentials, settings)

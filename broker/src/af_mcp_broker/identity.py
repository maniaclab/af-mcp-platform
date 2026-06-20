from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
import structlog
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from af_mcp_broker.config import Settings

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


async def _fetch_jwks(jwks_uri: str) -> list[dict[str, Any]]:
    """Fetch JWKS from upstream, bypassing the TTL cache.

    Raises HTTPException(502) when the upstream is unreachable so callers
    higher up the stack can surface a useful error rather than a raw 500.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            return resp.json()["keys"]
    except Exception as exc:
        logger.error("jwks_fetch_failed", uri=jwks_uri, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to reach JWKS endpoint: {jwks_uri}",
        ) from exc


async def get_jwks(settings: Settings) -> list[dict[str, Any]]:
    """Return JWKS keys, using a 5-minute in-process TTL cache."""
    uri = settings.keycloak_jwks_uri
    entry = _jwks_cache.get(uri)
    now = time.monotonic()

    if entry is None or (now - entry.fetched_at) > _JWKS_CACHE_TTL_SECONDS:
        keys = await _fetch_jwks(uri)
        _jwks_cache[uri] = _JwksEntry(keys=keys, fetched_at=now)
        logger.debug("jwks_cache_refreshed", uri=uri, key_count=len(keys))
    else:
        keys = entry.keys

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

    last_error: Exception | None = None
    for key_data in keys:
        try:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=settings.keycloak_audience,
                issuer=settings.keycloak_issuer,
                options={"verify_exp": True},
            )
            return _extract_principal(claims, token)
        except jwt.exceptions.InvalidKeyError:
            # This key is not the right one; try the next.
            continue
        except jwt.ExpiredSignatureError as exc:
            last_error = exc
            logger.info("jwt_expired", subject=_peek_sub(token))
            break
        except jwt.InvalidTokenError as exc:
            last_error = exc
            break
        except ValueError as exc:
            last_error = exc
            break

    logger.warning(
        "jwt_validation_failed",
        error=str(last_error) if last_error else "no matching key",
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


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
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    settings: Settings = Depends(Settings),
) -> Principal:
    """FastAPI dependency that resolves to the authenticated Principal.

    Inject this into route handlers that require authentication:

        @router.get("/example")
        async def example(principal: Principal = Depends(keycloak_dependency)):
            ...
    """
    return await get_principal(credentials.credentials, settings)

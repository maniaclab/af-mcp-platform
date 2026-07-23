from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Annotated, Any
from urllib.parse import urlparse

import jwt
import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.http import get_http_client

logger = structlog.get_logger(__name__)

# ``auto_error=False`` so we can decide the auth outcome ourselves — HTTPBearer
# would otherwise raise before the dev-bypass short-circuit gets a chance.
_bearer_scheme = HTTPBearer(auto_error=False)

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
        logger.exception("jwks_fetch_failed", uri=jwks_uri, error=str(exc))
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
                audience=settings.oidc_audience,
                issuer=settings.oidc_issuer,
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
    except Exception:  # noqa: BLE001  # log-only helper; never raises
        return "<unparseable>"


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def keycloak_dependency(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    """FastAPI dependency that resolves to the authenticated Principal.

    Inject this into route handlers that require authentication:

        @router.get("/example")
        async def example(
            principal: Annotated[Principal, Depends(keycloak_dependency)],
        ):
            ...

    When the local-dev auth bypass is active (see ``BROKER_DEV_INSECURE_PRINCIPAL``
    and the lifespan startup check), this returns the pre-parsed dev principal
    without inspecting the request. That path is unconditional: a real bearer
    token, if present, is ignored.
    """
    if getattr(request.app.state, "dev_bypass_active", False):
        dev_principal: Principal = request.app.state.dev_bypass_principal
        # Emit an audit-visible line on every bypassed request so the trail
        # captures every call that skipped real authentication.
        logger.info(
            "dev_auth_bypass_used",
            path=request.url.path,
            unixname=dev_principal.unixname,
            uid=dev_principal.uid,
        )
        return dev_principal

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await get_principal(credentials.credentials, settings)


# ---------------------------------------------------------------------------
# Local-development auth bypass helpers
# ---------------------------------------------------------------------------

# Hostnames that count as "obviously local" for the dev bypass. Exact-match
# set + a suffix list; anything else is treated as production.
_LOCAL_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})
_LOCAL_SUFFIXES: tuple[str, ...] = (".localhost", ".local", ".test")

# JSON keys we require in the BROKER_DEV_INSECURE_PRINCIPAL payload. Missing
# any of these fails the startup sanity check rather than crashing later at
# request time with a KeyError inside the dependency.
_DEV_PRINCIPAL_REQUIRED_KEYS: frozenset[str] = frozenset({"uid", "gid", "unixname"})


def issuer_is_local(issuer: str) -> bool:
    """Return True when the OIDC issuer clearly points at a dev machine.

    Local means either the URL's hostname is exactly one of ``localhost``,
    ``127.0.0.1``, ``::1``, or the hostname ends with ``.localhost``, ``.local``,
    or ``.test``. Anything else — including a real-looking domain — is
    treated as production for the purposes of the dev-bypass safety check.
    """
    try:
        hostname = urlparse(issuer).hostname
    except ValueError:
        return False
    if not hostname:
        return False
    host = hostname.lower()
    if host in _LOCAL_HOSTS:
        return True
    return any(host.endswith(sfx) for sfx in _LOCAL_SUFFIXES)


def build_dev_principal(payload_json: str) -> Principal:
    """Parse the ``BROKER_DEV_INSECURE_PRINCIPAL`` JSON into a Principal.

    Raises RuntimeError with a descriptive message when the payload is
    malformed or missing required keys, so the lifespan can fail loudly
    at startup instead of dying inside a request handler.
    """
    try:
        data = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        msg = (
            "BROKER_DEV_INSECURE_PRINCIPAL is not valid JSON: "
            f"{exc.msg} (line {exc.lineno}, column {exc.colno})"
        )
        raise RuntimeError(msg) from exc

    if not isinstance(data, dict):
        msg = (
            "BROKER_DEV_INSECURE_PRINCIPAL must be a JSON object, "
            f"got {type(data).__name__}"
        )
        raise RuntimeError(msg)  # noqa: TRY004 — uniform RuntimeError shape for lifespan

    missing = sorted(_DEV_PRINCIPAL_REQUIRED_KEYS - data.keys())
    if missing:
        msg = (
            "BROKER_DEV_INSECURE_PRINCIPAL is missing required keys: "
            f"{', '.join(missing)}"
        )
        raise RuntimeError(msg)

    try:
        uid = int(data["uid"])
        gid = int(data["gid"])
    except (TypeError, ValueError) as exc:
        msg = "BROKER_DEV_INSECURE_PRINCIPAL uid/gid must be integers"
        raise RuntimeError(msg) from exc

    unixname = str(data["unixname"])
    email = str(data.get("email", ""))
    groups_raw = data.get("groups", [])
    if not isinstance(groups_raw, list) or not all(
        isinstance(g, str) for g in groups_raw
    ):
        msg = "BROKER_DEV_INSECURE_PRINCIPAL 'groups' must be a list of strings"
        raise RuntimeError(msg)

    # Synthesise a subject that clearly identifies bypassed traffic in any
    # log line that carries it — production sub claims are Keycloak UUIDs
    # and never take this shape, so a grep for "dev-insecure:" turns up
    # every bypassed request unambiguously.
    subject = f"dev-insecure:{unixname}"

    return Principal(
        subject=subject,
        email=email,
        uid=uid,
        gid=gid,
        unixname=unixname,
        groups=list(groups_raw),
        iam_sub=None,
        cern_sub=None,
        raw_token=SecretStr(""),
    )

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Annotated, Any
from urllib.parse import urlparse

import jwt
import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.http import get_http_client
from af_mcp_broker.principal_cache import PrincipalUnavailableError

if TYPE_CHECKING:
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.token_registry import RevokedJtiCache

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
    uri = settings.oidc_jwks_uri
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
    """An authenticated caller's identity, as resolved from a JWT or a PAT.

    ``uid``/``gid``/``unixname`` are optional (issue #148): POSIX identity
    is only meaningful to backends that need a filesystem identity (x509/VOMS
    proxy minting -- see credentials/x509.py), not to the broker's identity
    or authorization layers themselves. ``None`` fields are used rather than
    an ``int | None`` default hiding behind a truthy-looking sentinel, so
    every call site that reads one of these three directly is forced (by
    mypy, since the shipped config enables strict optional checking) to
    handle the absent case rather than silently treating a missing identity
    as uid/gid 0 or an empty unixname. Every OTHER field remains required:
    ``subject`` is always present (a validated JWT's `sub` claim, or a PAT's
    stored owner id), so it -- not uid -- is the identifier incidental
    consumers (cache keys, audit fields, log context) should use.

    ``capability_grant`` (issue #144 step 4) is ``None`` for every JWT and
    every identity PAT -- the overwhelming majority of principals -- and is
    only ever set for a **capability PAT**: an explicit set of capability
    names copied from ``token_registry.TokenRecord.capability_grant`` by
    ``pat_auth._resolve_authority``. It is a RESTRICTION, never a source of
    authority: ``authorization.get_principal_capabilities`` intersects it
    with whatever capabilities the principal's *current* groups already
    grant, rather than substituting for that computation. Intersecting
    (not substituting) is what keeps a capability PAT killable by a group
    removal exactly like every other credential, and what makes it
    structurally impossible for a grant to hand out more than the principal
    currently holds, however it got into the record -- see that function's
    docstring for the mechanics.
    """

    subject: str
    email: str
    uid: int | None
    gid: int | None
    unixname: str | None
    groups: list[str]
    # Keep the raw token for downstream credential flows; SecretStr prevents
    # accidental logging.
    raw_token: SecretStr = field(compare=False, repr=False)
    capability_grant: frozenset[str] | None = None


# ---------------------------------------------------------------------------
# JWT validation helpers
# ---------------------------------------------------------------------------


def _extract_principal(claims: dict[str, Any], raw_token: str) -> Principal:
    """Map decoded JWT claims to a Principal.

    Neither ``groups`` nor ``posix`` is read from ``claims`` (issue #144
    steps 3 and 3b): a `groups` or `posix` claim, if the token happens to
    carry either, is ignored entirely rather than trusted. The token answers
    only "who is this?" -- `get_principal` answers "what groups/POSIX
    identity do they currently have?" by asking the `PrincipalDirectory`
    (via the principal cache), the same way it already did for PATs, so the
    two credential types cannot disagree about a principal's identity or
    authority. The `groups=[]`/`uid=None`/`gid=None`/`unixname=None` here are
    placeholders `get_principal` immediately replaces; they are never the
    values a caller actually sees. POSIX identity remains optional on
    `Principal` (issue #148) -- the point-of-use check still lives in
    credentials/x509.py, the one genuine consumer.
    """
    subject = claims.get("sub", "")
    email = claims.get("email", "")

    return Principal(
        subject=subject,
        email=email,
        uid=None,
        gid=None,
        unixname=None,
        groups=[],
        raw_token=SecretStr(raw_token),
    )


class TokenExpiredError(HTTPException):
    """HTTPException subclass raised when the token's signature has expired.

    Raised by get_principal specifically for this case -- see get_principal's
    docstring for why this exists and why it does not change /v1's behavior.
    """


class TokenAudienceError(HTTPException):
    """HTTPException subclass raised when a token is missing the expected audience.

    Raised when the token's signature, issuer, and expiry all check out but
    it lacks the audience ``settings.oidc_audience`` expects. Distinct from
    the plain ``HTTPException(401)`` this module otherwise raises for every
    other JWT-validation failure, for the same reason ``TokenExpiredError``
    is distinct (see that class's docstring): a missing audience reveals
    nothing about why any *other* token would be rejected, so it's safe to
    state explicitly. Unlike an expired token, though, this is not fixable
    by re-authenticating -- Keycloak only includes ``mcp-gateway`` in a
    token's ``aud`` for users whose group membership grants the scope's
    gating role (see docs/auth.md's "cascading failure" section), so every
    token this user mints is missing it until an administrator changes
    their group membership. ``detail`` is a dict, not a plain string,
    carrying a stable ``error`` discriminator (RFC 6750's
    ``insufficient_scope``) plus a ``correlation_id`` the caller can quote
    when contacting an administrator -- the same pattern
    ``api/capabilities.py``'s ``_backend_status`` already uses for
    ``capability_required``/``misconfigured``.
    """


class PrincipalDirectoryUnavailableError(HTTPException):
    """Raised by ``get_principal`` (issue #144 steps 3 and 3b) when a validated JWT's current groups/POSIX identity cannot be determined because the ``PrincipalDirectory`` has no answer for this subject -- no ``PrincipalCache`` configured at all, or one configured but currently unable to reach the directory with nothing fresh-enough cached to fall back on.

    Deliberately distinct from the plain ``HTTPException(401)`` this module
    otherwise raises for every JWT-validation failure. Those mean "these
    credentials are invalid" -- something re-authenticating fixes. This means
    the opposite: the token's signature, issuer, audience, and expiry all
    checked out, so the caller unambiguously proved who they are. What
    failed is the platform's ability to answer "what groups/POSIX identity
    do they have," which is not something the caller can fix by getting a
    new token. 503, not 401, and a detail that says so explicitly -- see
    this module's docstring on the availability regression this introduces
    for JWT callers, previously self-contained and therefore immune to a
    Keycloak outage.
    """


# Client-visible detail for PrincipalDirectoryUnavailableError -- deliberately
# says "platform" and "try again", not anything that reads like a bad
# credential, so a caller (or their client's error message) can tell this
# apart from every other 401 this module raises. See that exception's
# docstring and this module's docstring for the availability regression it
# names.
_DIRECTORY_UNAVAILABLE_DETAIL = (
    "Unable to determine your current group membership and POSIX identity "
    "right now -- the authorization directory is temporarily unavailable. "
    "This is a platform issue, not a problem with your credentials; please "
    "try again shortly."
)


async def _resolve_current_attributes(
    principal: Principal, principal_cache: PrincipalCache | None
) -> Principal:
    """Replace *principal*'s placeholder groups/POSIX fields with the ``PrincipalDirectory``'s current answer for its subject, via *principal_cache* -- the single point where a validated JWT's authority and POSIX identity are resolved (issue #144 steps 3 and 3b; see ``_extract_principal``'s docstring for why neither is ever read from the token itself).

    *principal_cache* being ``None`` means no directory is configured at
    all -- a startup misconfiguration ``app.py``'s lifespan is meant to
    refuse to start over (dev bypass aside), reached here only in a test or
    a future embedding that skips that check. Treated identically to the
    directory being unreachable: raises ``PrincipalDirectoryUnavailableError``
    rather than crashing on a ``None`` cache.
    """
    if principal_cache is None:
        raise PrincipalDirectoryUnavailableError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_DIRECTORY_UNAVAILABLE_DETAIL,
        )
    try:
        attributes = await principal_cache.get(principal.subject)
    except PrincipalUnavailableError as exc:
        raise PrincipalDirectoryUnavailableError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_DIRECTORY_UNAVAILABLE_DETAIL,
        ) from exc
    return replace(
        principal,
        uid=attributes.uid,
        gid=attributes.gid,
        unixname=attributes.unixname,
        groups=attributes.groups,
    )


async def get_principal(
    token: str,
    settings: Settings,
    principal_cache: PrincipalCache | None,
    revoked_jti_cache: RevokedJtiCache | None = None,
) -> Principal:
    """Validate a Bearer token and return the extracted Principal.

    Raises HTTPException(401) on any validation failure so FastAPI can return
    a proper WWW-Authenticate response. Raises the ``TokenExpiredError``
    subclass specifically when the signature has expired -- same
    status_code/detail/headers, so `/v1`'s `keycloak_dependency` (which lets
    HTTPException bubble to FastAPI's generic handler unchanged) sees no
    behavior difference, but `/mcp`'s ASGI-layer auth middleware
    (mcp/middleware/identity_mw.py) can catch it separately to give expiry a
    distinct, actionable message without this function leaking which claim
    failed for every other invalid-token cause (issue #138).

    *principal_cache* answers the second of two independent questions this
    function resolves (issue #144 steps 3 and 3b, mirroring the split
    ``pat_auth.resolve_pat_principal`` already uses for PATs): the JWT
    decode above answers "who is this?" (a signature-verified `sub` claim);
    *principal_cache* answers "what groups/POSIX identity do they currently
    have?", via the `PrincipalDirectory` it wraps -- never the token's own
    `groups`/`posix` claims, which are ignored even when present (see
    `_extract_principal`'s docstring). This is what makes removing someone
    from a Keycloak group a real kill switch regardless of which credential
    type they present, instead of the JWT and PAT paths being able to
    disagree about it. Raises `PrincipalDirectoryUnavailableError` (503)
    rather than 401 when that question cannot be answered -- see that
    exception's docstring for why, and for the availability regression this
    introduces: a JWT used to be self-contained, so a Keycloak outage never
    blocked authentication; now a principal this cache has never resolved
    before, hit during an outage, has no last-known value to fall back on
    and cannot authenticate at all.

    *revoked_jti_cache*, when provided, is consulted against the token's
    `jti` claim (issue #115) -- this is the single choke point both
    `keycloak_dependency` (/v1) and `/mcp`'s ASGI-layer auth middleware call,
    so enforcing revocation here covers both surfaces. A token with no `jti`
    claim, or one whose `jti` was never minted through the manual bearer
    registry, is never affected -- only jtis the registry actually knows
    about can be revoked (see token_registry.RevokedJtiCache).
    """
    keys = await get_jwks(settings)

    error: Exception | str | None = None
    expired = False
    wrong_audience = False
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
            jti = claims.get("jti")
            if (
                jti
                and revoked_jti_cache is not None
                and await revoked_jti_cache.is_revoked(jti)
            ):
                _raise_revoked(jti)
            identity_principal = _extract_principal(claims, token)
            return await _resolve_current_attributes(
                identity_principal, principal_cache
            )
    except jwt.ExpiredSignatureError as exc:
        error = exc
        expired = True
        logger.info("jwt_expired", subject=_peek_sub(token))
    except jwt.InvalidAudienceError as exc:
        # Caught ahead of the broader InvalidTokenError below -- it's a
        # subclass, so ordering matters. Everything else about the token
        # checked out; only the audience is wrong/missing, which is a
        # distinct, admin-actionable failure (see TokenAudienceError).
        error = exc
        wrong_audience = True
    except jwt.InvalidTokenError as exc:
        error = exc
    except (ValueError, KeyError) as exc:
        error = exc

    logger.warning(
        "jwt_validation_failed",
        error=str(error) if error else "no matching key",
    )
    if wrong_audience:
        correlation_id = uuid.uuid4().hex
        logger.warning(
            "jwt_audience_mismatch",
            subject=_peek_sub(token),
            correlation_id=correlation_id,
        )
        raise TokenAudienceError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "insufficient_scope",
                "message": (
                    "Your account is not authorized to use this platform "
                    "yet. Contact your AF administrators and quote this "
                    f"ID: {correlation_id}"
                ),
                "correlation_id": correlation_id,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    exc_cls = TokenExpiredError if expired else HTTPException
    raise exc_cls(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _raise_revoked(jti: str) -> None:
    """Raise a revoked-token ``ValueError`` from inside get_principal's try block -- caught by the same ``except (ValueError, KeyError)`` branch below, so a revoked jti maps to 401 the same way as any other JWT-validation failure."""
    raise ValueError(f"token jti={jti!r} has been revoked")


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
    # Absent (getattr default None) whenever the token registry isn't wired
    # up at all -- e.g. tests that construct a bare app.state -- in which
    # case get_principal simply skips the revocation check, same as before
    # issue #115.
    revoked_jti_cache = getattr(request.app.state, "revoked_jti_cache", None)
    # Absent (getattr default None) only in a bare app.state; in a properly
    # started app this is never None here -- app.py's lifespan refuses to
    # start without either a configured PrincipalDirectory or the dev bypass
    # (issue #144 step 3), and the bypass check above already returned. A
    # None cache reaching get_principal is therefore always either a test
    # double or an actual misconfiguration that slipped past the startup
    # check; either way get_principal surfaces it as
    # PrincipalDirectoryUnavailableError rather than crashing.
    principal_cache = getattr(request.app.state, "principal_cache", None)
    return await get_principal(
        credentials.credentials, settings, principal_cache, revoked_jti_cache
    )


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
        raw_token=SecretStr(""),
    )

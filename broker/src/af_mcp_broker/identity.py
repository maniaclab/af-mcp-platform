from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import jwt
import structlog
from pydantic import SecretStr

from af_mcp_broker.config import (
    Settings,  # noqa: TC001 -- FastAPI resolves the dependency annotations at runtime
)
from af_mcp_broker.errors import BrokerError
from af_mcp_broker.logging import bind_subject, current_correlation_id
from af_mcp_broker.principal import Principal
from af_mcp_broker.principal_cache import (
    PrincipalRejectedError,
    PrincipalUnavailableError,
)

if TYPE_CHECKING:
    import httpx2

    from af_mcp_broker.principal_cache import PrincipalCache

logger = structlog.get_logger(__name__)

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


async def _fetch_jwks(
    jwks_uri: str, http_client: httpx2.AsyncClient
) -> list[dict[str, Any]]:
    """Fetch JWKS from upstream, bypassing the TTL cache.

    Raises ``JwksUnavailableError`` when the upstream is unreachable so callers
    higher up the stack can surface a useful error rather than a raw 500.
    """
    try:
        resp = await http_client.get(jwks_uri, timeout=10.0)
        resp.raise_for_status()
        return resp.json()["keys"]
    except Exception as exc:
        logger.exception("jwks_fetch_failed", uri=jwks_uri, error=str(exc))
        raise JwksUnavailableError(
            f"Unable to reach JWKS endpoint: {jwks_uri}"
        ) from exc


async def get_jwks(
    settings: Settings, http_client: httpx2.AsyncClient
) -> list[dict[str, Any]]:
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
            keys = await _fetch_jwks(uri, http_client)
        except JwksUnavailableError:
            if entry is not None:
                logger.warning("jwks_refresh_failed_serving_stale", uri=uri)
                return entry.keys
            raise
        _jwks_cache[uri] = _JwksEntry(keys=keys, fetched_at=now)
        logger.debug("jwks_cache_refreshed", uri=uri, key_count=len(keys))
        return keys


# ---------------------------------------------------------------------------
# JWT validation helpers
# ---------------------------------------------------------------------------


def decode_broker_bearer(
    token: str, keys: list[dict[str, Any]], settings: Settings
) -> dict[str, Any]:
    """Decode *token* against *keys* and return its claims, enforcing the broker's resource-server audience (``settings.oidc_audience``), issuer, and expiry.

    This is the single audience-gate implementation: ``get_principal`` runs
    every JWT presented on ``/v1`` and ``/mcp`` through it, and the MCP
    OAuth bootstrap callback (``api/mcp_oauth.py``) runs the Keycloak login
    exchange's access token through it before an authorization code (and
    thus a PAT) can be minted (issue #245) -- so "carries the broker
    audience" means exactly the same thing on every admission path.

    Raises ``jwt.InvalidTokenError`` (or a subclass -- notably
    ``jwt.InvalidAudienceError`` for the missing/wrong-audience case) on any
    decode failure, and ``ValueError`` when no JWKS key matches the token's
    ``kid``; callers map those to their own surface's error shape.
    """
    # Select the signing key by the token's `kid`. A JWKS commonly carries
    # more than one key (e.g. Keycloak publishes both a signature and an
    # encryption key); trying keys in list order and treating a signature
    # mismatch as fatal fails whenever the wrong key sorts first.
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    key_data = _select_jwk(keys, kid)
    if key_data is None:
        raise ValueError(f"no JWKS key matches token kid={kid!r}")
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
    return jwt.decode(
        token,
        public_key,  # type: ignore[arg-type]  # JWKS only has public keys
        algorithms=["RS256"],
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer,
        options={"verify_exp": True},
    )


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


class IdentityError(BrokerError):
    """Base of the credential-resolution failures that carry a client-visible *detail*.

    *detail* is exactly what the caller is allowed to see: a plain string, or
    a dict for a failure with a stable ``error`` discriminator. Each surface
    maps the subclass onto its own response -- ``app.py``'s exception
    handlers for /v1 (status code, headers), ``mcp/middleware/identity_mw.py``
    for /mcp -- so this module stays free of transport concerns.
    """

    def __init__(self, detail: str | dict[str, str]) -> None:
        super().__init__(detail)
        self.detail = detail


class TokenExpiredError(IdentityError):
    """Raised when the token's signature has expired (a JWT) or its own ``expires_at`` has passed (a PAT).

    Raised by get_principal specifically for this case -- see get_principal's
    docstring for why this exists and why it does not change /v1's behavior.
    """


class TokenAudienceError(IdentityError):
    """Raised when a token is missing the expected audience.

    Raised when the token's signature, issuer, and expiry all check out but
    it lacks the audience ``settings.oidc_audience`` expects. Distinct from
    the plain ``InvalidTokenError`` this module otherwise raises for every
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
    ``service_status.py``'s ``service_status`` already uses for
    ``permission_required``/``misconfigured``.
    """


class InvalidTokenError(IdentityError):
    """Raised for every credential-validation failure that is not an expiry, a missing audience or an unavailable directory.

    Deliberately vague: the *detail* never says which claim failed or why a
    token was rejected (see this module's docstring), and /v1 answers it with
    a ``WWW-Authenticate: Bearer`` challenge.
    """


class JwksUnavailableError(IdentityError):
    """Raised when the issuer's JWKS cannot be fetched and no cached copy can stand in for it."""


class NotAuthenticatedError(IdentityError):
    """Raised by ``keycloak_dependency`` when a /v1 request carries no bearer credential at all."""


class AdminRequiredError(IdentityError):
    """Raised by ``require_admin`` when the caller is not a member of the admin group."""


class PrincipalDirectoryUnavailableError(IdentityError):
    """Raised by ``get_principal`` (issue #144 steps 3 and 3b) when a validated JWT's current groups/POSIX identity cannot be determined because the ``PrincipalDirectory`` has no answer for this subject -- no ``PrincipalCache`` configured at all, or one configured but currently unable to reach the directory with nothing fresh-enough cached to fall back on.

    Deliberately distinct from the plain ``InvalidTokenError`` this module
    otherwise raises for every JWT-validation failure. Those mean "these
    credentials are invalid" -- something re-authenticating fixes. This means
    the opposite: the token's signature, issuer, audience, and expiry all
    checked out, so the caller unambiguously proved who they are. What
    failed is the platform's ability to answer "what groups/POSIX identity
    do they have," which is not something the caller can fix by getting a
    new token. 503, not 401, and a detail that says so explicitly -- see
    this module's docstring on the availability regression this introduces
    for JWT callers, which would otherwise be self-contained and therefore
    immune to a Keycloak outage.
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

# Client-visible detail for every JWT-validation failure that is not a missing
# audience or an unavailable directory -- deliberately vague, never which
# claim failed. The expired case (TokenExpiredError) carries the same text so
# /v1 shows an expired token exactly as it shows any other invalid one.
_INVALID_TOKEN_DETAIL = "Invalid or expired token"  # noqa: S105 -- error message text, not a secret


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
        raise PrincipalDirectoryUnavailableError(_DIRECTORY_UNAVAILABLE_DETAIL)
    try:
        attributes = await principal_cache.get(principal.subject)
    except PrincipalRejectedError as exc:
        # The directory refused this subject (deleted or disabled): a bad
        # identity, not an outage, so it takes the vague 401 path through
        # get_principal's ValueError handling -- never the reason.
        raise ValueError(
            f"subject {principal.subject!r} rejected by directory"
        ) from exc
    except PrincipalUnavailableError as exc:
        raise PrincipalDirectoryUnavailableError(_DIRECTORY_UNAVAILABLE_DETAIL) from exc
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
    http_client: httpx2.AsyncClient,
    caller_path: str | None = None,
) -> Principal:
    """Validate a Bearer token and return the extracted Principal.

    Raises ``InvalidTokenError`` on any validation failure so /v1 can return
    a proper WWW-Authenticate response. Raises ``TokenExpiredError``
    specifically when the signature has expired -- ``app.py``'s exception
    handler turns it into the same status_code/detail/headers, so `/v1` sees
    no behavior difference, but `/mcp`'s ASGI-layer auth middleware
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
    introduces: a JWT alone would be self-contained, so a Keycloak outage
    would never block authentication; with the directory in the loop, a
    principal this cache has never resolved before, hit during an outage,
    has no last-known value to fall back on and cannot authenticate at all.

    *caller_path* is purely diagnostic: the request path this validation is
    gating, attached to the ``jwt_validation_failed`` log line below so a
    rejection here can be told apart from an unrelated one logged moments
    later by a different concurrent request -- this function otherwise gives
    no indication of which endpoint invoked it. Never affects the outcome.
    """
    keys = await get_jwks(settings, http_client)

    error: Exception | str | None = None
    expired = False
    wrong_audience = False
    try:
        claims = decode_broker_bearer(token, keys, settings)
        identity_principal = _extract_principal(claims, token)
        principal = await _resolve_current_attributes(
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
    else:
        bind_subject(principal.subject)
        return principal

    logger.warning(
        "jwt_validation_failed",
        error=str(error) if error else "no matching key",
        caller_path=caller_path,
    )
    if wrong_audience:
        correlation_id = current_correlation_id()
        logger.warning(
            "jwt_audience_mismatch",
            subject=_peek_sub(token),
            correlation_id=correlation_id,
            actual_audience=_peek_aud(token),
            expected_audience=settings.oidc_audience,
        )
        raise TokenAudienceError(
            {
                "error": "insufficient_scope",
                "message": (
                    "Your account is not authorized to use this platform "
                    "yet. Contact your AF administrators and quote this "
                    f"ID: {correlation_id}"
                ),
                "correlation_id": correlation_id,
            }
        )
    if expired:
        raise TokenExpiredError(_INVALID_TOKEN_DETAIL)
    raise InvalidTokenError(_INVALID_TOKEN_DETAIL)


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


def _peek_aud(token: str) -> str | list[str] | None:
    """Decode the audience claim without signature verification for logging only -- see _peek_sub."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("aud")
    except Exception:  # noqa: BLE001  # log-only helper; never raises
        return "<unparseable>"


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

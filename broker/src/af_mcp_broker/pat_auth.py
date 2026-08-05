"""Resolves a Principal from a presented PAT (issue #144 step 2a).

This module is the PAT counterpart to ``identity.get_principal`` (which does
the same job for a Keycloak JWT). Both answer two independent questions, and
answering them separately -- rather than as one blended validation pass --
is the whole point of this design (see #144's "authorization is an
attribute of the principal, not the token" resolution):

1. **Who does this token represent?** For a JWT this is "decode the
   signature-verified claims"; for a PAT it is ``parse_pat`` + a
   ``lookup_id`` fetch against the PAT store (``token_registry.py``) +
   a constant-time secret comparison. Either way, the answer is a
   *principal id* -- nothing more.

2. **What authority does it carry?** For a JWT this is "read uid/gid/
   unixname/groups straight off the claims" -- self-contained, re-validated
   every request. For every PAT -- identity or capability alike -- it is
   *always* deferred to ``principal_cache.PrincipalCache``, keyed by the
   principal id question 1 just answered. This is the seam #144 step 4's
   **capability PAT** uses (``_resolve_authority`` below): an identity PAT
   carries no authority of its own, full stop, so the cache's answer is the
   whole story; a capability PAT ALSO carries an explicit grant
   (``TokenRecord.capability_grant``) -- but that grant is a RESTRICTION
   layered on top of the cache's answer, never a substitute for consulting
   it. Reading the grant *instead of* the cache would let a capability PAT
   outlive a group removal, reintroducing exactly the staleness problem
   group-snapshotting was rejected for; see ``_resolve_authority``'s
   docstring for the mechanics and ``authorization.get_principal_capabilities``
   for where the actual intersection happens. Question 1's resolution (and
   anything upstream of it, e.g. ``pat.parse_pat``/hashing) is unchanged
   either way.

Mirrors ``identity.get_principal``'s error shape so ``AsgiAuthMiddleware``
(``mcp/middleware/identity_mw.py``) can share its existing except-clause
structure unchanged: ``identity.TokenExpiredError`` for an expired PAT (same
class a JWT's expiry raises, so the existing actionable "mint a new one at
.../tokens" message applies to a stale PAT too), and a plain
``HTTPException(401)`` -- deliberately as vague as every JWT-path failure --
for everything else: malformed token, unknown lookup_id, wrong secret,
revoked, or a principal_cache resolution failure. Not distinguishing "no
such lookup_id" from "wrong secret" prevents an attacker from using response
shape to enumerate valid lookup_ids; not distinguishing "revoked" or "cache
unavailable" from those matches the same "reveal nothing about why" posture
``identity.get_principal``'s JWT path already takes (see its module
docstring) -- and matches existing precedent one layer up:
``AsgiAuthMiddleware`` already collapses *any* ``HTTPException`` raised
during JWT validation (including a 502 from an unreachable JWKS endpoint)
into the same blanket "Invalid bearer token" 401, so a principal_cache
outage surfacing the same way here is consistent, not a new carve-out.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog
from fastapi import HTTPException, status
from pydantic import SecretStr

from af_mcp_broker.identity import Principal, TokenExpiredError
from af_mcp_broker.pat import parse_pat, verify_secret
from af_mcp_broker.principal_cache import PrincipalUnavailableError

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.principal_cache import PrincipalCache
    from af_mcp_broker.principal_directory import PrincipalAttributes
    from af_mcp_broker.token_registry import TokenRecord, TokenRegistryBackend

logger = structlog.get_logger(__name__)

# Throttle for TokenRecord.last_used_at writes: at most once per this many
# seconds per lookup_id. A write on every single /mcp request would hammer
# the KV store for a field that only needs coarse ("roughly when") accuracy
# on the portal's token list -- same in-process-only tradeoff as
# api/tokens.py's mint-rate-limiter (see that module's docstring).
_LAST_USED_THROTTLE_SECONDS = 5 * 60

_VAGUE_DETAIL = "Invalid bearer token"


def _vague_401() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_VAGUE_DETAIL,
        headers={"WWW-Authenticate": "Bearer"},
    )


class LastUsedTracker:
    """Per-process throttle deciding whether a PAT's ``last_used_at`` is due for a write -- see the module-level constant above for why this is throttled at all.

    Approximate across broker replicas (each replica throttles
    independently, same as the mint-rate-limiter), which is fine: this field
    is display-only, never an authorization or security control.
    """

    def __init__(self, throttle_seconds: float = _LAST_USED_THROTTLE_SECONDS) -> None:
        self._throttle_seconds = throttle_seconds
        self._last_touch: dict[str, float] = {}

    def due(self, lookup_id: str) -> bool:
        """Return True (and record this call as the latest touch) if *lookup_id* hasn't been touched within the throttle window."""
        now = time.monotonic()
        last = self._last_touch.get(lookup_id)
        if last is not None and (now - last) < self._throttle_seconds:
            return False
        self._last_touch[lookup_id] = now
        return True


async def resolve_pat_principal(
    token: str,
    settings: Settings,
    pat_backend: TokenRegistryBackend,
    principal_cache: PrincipalCache,
    last_used_tracker: LastUsedTracker,
) -> Principal:
    """Validate an ``mcp_pat_...`` bearer and return the current Principal.

    See this module's docstring for the two-question split this
    implements. Raises ``TokenExpiredError`` when the PAT's own
    ``expires_at`` has passed; ``HTTPException(401)`` for every other
    failure.
    """
    # --- Question 1: who does this token represent? ------------------------
    parsed = parse_pat(token)
    if parsed is None:
        raise _vague_401()
    lookup_id, secret = parsed

    record = await pat_backend.get_by_lookup_id(lookup_id)
    if record is None or not verify_secret(secret, record.secret_hash):
        # Identical error for "no such lookup_id" and "wrong secret" --
        # see the module docstring.
        raise _vague_401()

    if record.revoked_at is not None:
        raise _vague_401()

    now = time.time()
    if record.expires_at is not None and record.expires_at <= now:
        portal = settings.portal_url.rstrip("/")
        raise TokenExpiredError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Your access token has expired — mint a new one at {portal}/tokens"
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )

    if last_used_tracker.due(lookup_id):
        await pat_backend.touch_last_used(record.principal_id, lookup_id, now)

    # --- Question 2: what authority does it carry? --------------------------
    # Always deferred to the principal cache -- see the module docstring and
    # _resolve_authority's docstring for why a capability PAT's grant, when
    # present, does not change that.
    try:
        attributes = await _resolve_authority(record, principal_cache)
    except PrincipalUnavailableError:
        raise _vague_401() from None

    return Principal(
        subject=record.principal_id,
        email=attributes.email,
        uid=attributes.uid,
        gid=attributes.gid,
        unixname=attributes.unixname,
        groups=attributes.groups,
        raw_token=SecretStr(token),
        capability_grant=record.capability_grant,
    )


async def _resolve_authority(
    record: TokenRecord, principal_cache: PrincipalCache
) -> PrincipalAttributes:
    """Answer question 2: the principal cache's current view -- identically for an identity PAT and a capability PAT.

    Takes the full *record* (not just ``record.principal_id``) so this is
    visibly the one seam issue #144 flagged for a future capability PAT, but
    the lookup itself never changes shape: ``record.capability_grant`` is
    NOT read here, and never substitutes for this call. A capability PAT
    still needs the principal cache's CURRENT groups -- the grant is a
    restriction applied on top of them, not a replacement for asking what
    they currently are. Substituting the grant instead would let a capability
    PAT keep working after its owner lost the underlying group, reintroducing
    exactly the staleness problem group-snapshotting was rejected for.

    The grant itself is carried through unchanged by ``resolve_pat_principal``
    onto the returned ``Principal.capability_grant``; the actual intersection
    against these attributes' groups happens downstream, in
    ``authorization.get_principal_capabilities``, once a policy is available
    to derive capabilities from groups in the first place -- see that
    function's docstring.
    """
    return await principal_cache.get(record.principal_id)

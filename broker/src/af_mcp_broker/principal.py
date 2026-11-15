from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic import SecretStr


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

    ``permission_grant`` (issue #144 step 4) is ``None`` for every JWT and
    every identity PAT -- the overwhelming majority of principals -- and is
    only ever set for a **permission PAT**: an explicit set of permission
    names copied from ``token_registry.TokenRecord.permission_grant`` by
    ``pat_auth._resolve_authority``. It is a RESTRICTION, never a source of
    authority: ``authorization.get_principal_permissions`` intersects it
    with whatever permissions the principal's *current* groups already
    grant, rather than substituting for that computation. Intersecting
    (not substituting) is what keeps a permission PAT killable by a group
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
    permission_grant: frozenset[str] | None = None
    # Which token made the call (issue #247): the presenting PAT's public,
    # non-secret lookup_id (the same registry index touch_last_used keys
    # on), set only by pat_auth.resolve_pat_principal. None for every JWT
    # -- a session JWT is not a distinct long-lived credential worth
    # attributing separately from ``subject``. NEVER secret material or the
    # full token.
    token_id: str | None = None

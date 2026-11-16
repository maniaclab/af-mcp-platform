"""Admin user search over the users the platform has seen (``GET /v1/admin/users``).

The population is the usage store's subjects (``UsageStore.list_subject_activity``):
the people with recorded broker activity, never the whole Keycloak realm. The
token registry is not a second source: it can only be enumerated by a Vault
LIST of every principal and carries no last-activity time, and a PAT is only
useful once used, which is exactly what creates a usage row.

Usage rows hold bare Keycloak subjects, so matching on a name or an email needs
each subject's profile (``UserProfileDirectory.profile``: one Keycloak
``GET /users/{id}``, no group lookup). Profiles are fetched lazily and cached
per process for ``ttl_seconds``:

* The walk is in most-recently-seen order and stops as soon as ``limit + 1``
  subjects match, so a search asks Keycloak only for as many users as it takes
  to fill a page.
* At most ``max_lookups`` profiles are fetched per search, ``concurrency`` at a
  time. Once the budget is spent the remaining subjects are matched on the
  subject id alone and the result is flagged ``partial``, so the caller can say
  "directory still warming up, retry".
* Over the realm's users that is one cold fill of the cache per replica per
  TTL, amortised across searches, instead of any per-request fan-out.

A user the directory does not know (deleted) is cached as unknown and stays
searchable by subject; a failed lookup is not cached and is retried by the next
search.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from af_mcp_broker.principal_directory import (
    PrincipalNotFoundError,
    UserProfile,
    UserProfileDirectory,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from af_mcp_broker.usage import SubjectActivity

log = structlog.get_logger(__name__)

DEFAULT_PROFILE_TTL_SECONDS = 3600.0
DEFAULT_MAX_LOOKUPS_PER_SEARCH = 200
DEFAULT_LOOKUP_CONCURRENCY = 10


@dataclass(frozen=True)
class UserMatch:
    """One search hit. ``username`` is the POSIX unix name when the user has one, else the directory username; all three profile fields are empty for a user the directory does not know."""

    subject: str
    username: str
    email: str
    display_name: str
    last_seen: datetime


@dataclass(frozen=True)
class UserSearchResult:
    """Up to ``limit`` hits, whether more matched, and whether some subjects could not be checked against their profile (budget spent or directory failure)."""

    users: list[UserMatch]
    more: bool
    partial: bool


class _Missing:
    """Marker type for a subject whose profile is not cached."""


_MISSING = _Missing()


class UserSearch:
    """Case-insensitive substring search over seen users' username, email, display name and subject; see this module's docstring for the cost model."""

    def __init__(
        self,
        profiles: UserProfileDirectory | None,
        *,
        ttl_seconds: float = DEFAULT_PROFILE_TTL_SECONDS,
        max_lookups: int = DEFAULT_MAX_LOOKUPS_PER_SEARCH,
        concurrency: int = DEFAULT_LOOKUP_CONCURRENCY,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._profiles = profiles
        self._ttl = ttl_seconds
        self._max_lookups = max_lookups
        self._concurrency = concurrency
        self._clock = clock
        # subject -> (expiry on self._clock, profile); None is a user the
        # directory does not know.
        self._cache: dict[str, tuple[float, UserProfile | None]] = {}

    def _cached(self, subject: str) -> UserProfile | None | _Missing:
        entry = self._cache.get(subject)
        if entry is None or entry[0] <= self._clock():
            return _MISSING
        return entry[1]

    async def _fetch(self, subject: str, profiles: UserProfileDirectory) -> None:
        try:
            profile: UserProfile | None = await profiles.profile(subject)
        except PrincipalNotFoundError:
            profile = None
        except Exception:  # noqa: BLE001 -- one failed lookup must not fail the search; the subject stays searchable by id and is retried next time
            log.warning(
                "user_search.profile_lookup_failed", subject=subject, exc_info=True
            )
            return
        self._cache[subject] = (self._clock() + self._ttl, profile)

    async def search(
        self, activity: list[SubjectActivity], text: str, *, limit: int
    ) -> UserSearchResult:
        """Return the subjects of *activity* (most recently seen first) matching *text*; an empty *text* matches every subject."""
        needle = text.strip().casefold()
        users: list[UserMatch] = []
        partial = False
        lookups = 0
        for start in range(0, len(activity), self._concurrency):
            chunk = activity[start : start + self._concurrency]
            if self._profiles is not None:
                uncached = [
                    a.subject for a in chunk if self._cached(a.subject) is _MISSING
                ]
                to_fetch = uncached[: self._max_lookups - lookups]
                lookups += len(to_fetch)
                await asyncio.gather(
                    *(self._fetch(s, self._profiles) for s in to_fetch)
                )
            for seen in chunk:
                cached = self._cached(seen.subject)
                if isinstance(cached, _Missing):
                    profile = None
                    partial = partial or self._profiles is not None
                else:
                    profile = cached
                match = _to_match(seen, profile)
                if needle in _haystack(match, profile):
                    users.append(match)
                    if len(users) > limit:
                        return UserSearchResult(
                            users=users[:limit], more=True, partial=partial
                        )
        return UserSearchResult(users=users, more=False, partial=partial)


def _to_match(seen: SubjectActivity, profile: UserProfile | None) -> UserMatch:
    if profile is None:
        return UserMatch(
            subject=seen.subject,
            username="",
            email="",
            display_name="",
            last_seen=seen.last_seen,
        )
    return UserMatch(
        subject=seen.subject,
        username=profile.unixname or profile.username,
        email=profile.email,
        display_name=profile.display_name,
        last_seen=seen.last_seen,
    )


def _haystack(match: UserMatch, profile: UserProfile | None) -> str:
    """Join the lower-cased fields a search text is matched against with newlines, so a text cannot match across two fields."""
    fields = [match.subject, match.username, match.email, match.display_name]
    if profile is not None:
        fields.append(profile.username)
    return "\n".join(fields).casefold()

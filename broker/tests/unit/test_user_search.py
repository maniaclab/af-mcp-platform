"""Tests for ``UserSearch`` -- the admin user search over the users the platform has seen.

Profiles come from a test-controlled ``UserProfileDirectory``; the point of
the suite is what is (and is not) asked of it: matching is server-side over
profile fields, and the number of directory lookups per search is bounded.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from af_mcp_broker.principal_directory import (
    PrincipalNotFoundError,
    UserProfile,
    UserProfileDirectory,
)
from af_mcp_broker.usage import SubjectActivity
from af_mcp_broker.user_search import UserSearch

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


class _FakeProfiles(UserProfileDirectory):
    def __init__(self, profiles: dict[str, UserProfile]) -> None:
        self.profiles = profiles
        self.calls: list[str] = []
        self.failing: set[str] = set()

    async def profile(self, principal_id: str) -> UserProfile:
        self.calls.append(principal_id)
        if principal_id in self.failing:
            raise RuntimeError("directory down")
        try:
            return self.profiles[principal_id]
        except KeyError:
            raise PrincipalNotFoundError(principal_id) from None


def _profile(username: str, *, email: str = "", name: str = "") -> UserProfile:
    return UserProfile(
        username=username, unixname=None, email=email, display_name=name or username
    )


def _activity(*subjects: str) -> list[SubjectActivity]:
    """Subjects given most recently seen first."""
    return [
        SubjectActivity(subject=s, last_seen=_NOW - timedelta(hours=i))
        for i, s in enumerate(subjects)
    ]


@pytest.fixture
def profiles() -> _FakeProfiles:
    return _FakeProfiles(
        {
            "sub-1": _profile("ada", email="ada@example.org", name="Ada Lovelace"),
            "sub-2": _profile("grace", email="grace@example.org", name="Grace Hopper"),
            "sub-3": _profile("alan", email="alan@example.org", name="Alan Turing"),
        }
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("lovelace", ["sub-1"]),  # display name, case-insensitive
        ("GRACE@EXAMPLE", ["sub-2"]),  # email
        ("alan", ["sub-3"]),  # username
        ("SUB-2", ["sub-2"]),  # subject
        ("example.org", ["sub-1", "sub-2", "sub-3"]),  # most recently seen first
        ("nobody", []),
    ],
)
async def test_matches_substring_across_fields(
    profiles: _FakeProfiles, text: str, expected: list[str]
) -> None:
    search = UserSearch(profiles)

    result = await search.search(_activity("sub-1", "sub-2", "sub-3"), text, limit=20)

    assert [u.subject for u in result.users] == expected
    assert result.more is False


async def test_row_carries_profile_and_last_seen(profiles: _FakeProfiles) -> None:
    result = await UserSearch(profiles).search(_activity("sub-1"), "ada", limit=20)

    (row,) = result.users
    assert (row.username, row.email, row.display_name) == (
        "ada",
        "ada@example.org",
        "Ada Lovelace",
    )
    assert row.last_seen == _NOW


async def test_unixname_is_the_username_shown_and_matched() -> None:
    profiles = _FakeProfiles(
        {
            "sub-1": UserProfile(
                username="ada@example.org",
                unixname="alovelace",
                email="",
                display_name="Ada",
            )
        }
    )

    result = await UserSearch(profiles).search(_activity("sub-1"), "alovel", limit=20)

    assert [u.username for u in result.users] == ["alovelace"]


async def test_truncates_to_limit_and_reports_more(profiles: _FakeProfiles) -> None:
    result = await UserSearch(profiles).search(
        _activity("sub-1", "sub-2", "sub-3"), "example.org", limit=2
    )

    assert [u.subject for u in result.users] == ["sub-1", "sub-2"]
    assert result.more is True


async def test_stops_looking_up_profiles_once_the_page_is_full(
    profiles: _FakeProfiles,
) -> None:
    """Only as many profiles are fetched as it takes to prove there is more."""
    many = {f"s{i}": _profile(f"user{i}") for i in range(100)}
    directory = _FakeProfiles(many)

    result = await UserSearch(directory, concurrency=1).search(
        _activity(*many), "user", limit=5
    )

    assert len(result.users) == 5
    assert result.more is True
    assert len(directory.calls) == 6


async def test_lookups_per_search_are_bounded_and_flagged_partial() -> None:
    many = {f"s{i}": _profile(f"user{i}") for i in range(50)}
    directory = _FakeProfiles(many)
    search = UserSearch(directory, max_lookups=10, concurrency=5)

    result = await search.search(_activity(*many), "user49", limit=20)

    assert len(directory.calls) == 10
    assert result.partial is True
    assert result.users == []


async def test_profiles_are_cached_across_searches(profiles: _FakeProfiles) -> None:
    search = UserSearch(profiles)
    activity = _activity("sub-1", "sub-2", "sub-3")

    await search.search(activity, "ada", limit=20)
    result = await search.search(activity, "grace", limit=20)

    assert sorted(profiles.calls) == ["sub-1", "sub-2", "sub-3"]
    assert [u.subject for u in result.users] == ["sub-2"]
    assert result.partial is False


async def test_cache_entries_expire() -> None:
    clock = [0.0]
    directory = _FakeProfiles({"sub-1": _profile("ada")})
    search = UserSearch(directory, ttl_seconds=60, clock=lambda: clock[0])

    await search.search(_activity("sub-1"), "ada", limit=20)
    clock[0] = 61.0
    await search.search(_activity("sub-1"), "ada", limit=20)

    assert directory.calls == ["sub-1", "sub-1"]


async def test_unknown_user_is_matched_by_subject_only_and_not_refetched() -> None:
    directory = _FakeProfiles({})
    search = UserSearch(directory)
    activity = _activity("deleted-user")

    by_subject = await search.search(activity, "deleted", limit=20)
    await search.search(activity, "deleted", limit=20)

    assert [u.subject for u in by_subject.users] == ["deleted-user"]
    assert by_subject.users[0].username == ""
    assert directory.calls == ["deleted-user"]


async def test_failed_lookup_is_partial_and_retried(profiles: _FakeProfiles) -> None:
    profiles.failing.add("sub-1")
    search = UserSearch(profiles)

    first = await search.search(_activity("sub-1"), "sub-1", limit=20)
    profiles.failing.clear()
    second = await search.search(_activity("sub-1"), "lovelace", limit=20)

    assert first.partial is True
    assert [u.subject for u in first.users] == ["sub-1"]  # still matches by subject
    assert second.partial is False
    assert [u.subject for u in second.users] == ["sub-1"]


async def test_without_a_directory_only_subjects_are_searchable() -> None:
    result = await UserSearch(None).search(_activity("abc", "xyz"), "xy", limit=20)

    assert [u.subject for u in result.users] == ["xyz"]
    assert result.partial is False

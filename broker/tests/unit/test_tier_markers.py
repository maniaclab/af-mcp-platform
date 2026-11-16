"""The tier a test belongs to is its directory, applied as a marker at collection."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

_TESTS_DIR = Path(__file__).resolve().parents[1]
_TIERS = {"unit", "integration", "e2e"}


def _tier_markers(item: pytest.Item) -> set[str]:
    return {mark.name for mark in item.iter_markers()} & _TIERS


def test_each_collected_test_carries_exactly_its_directory_tier(
    request: pytest.FixtureRequest,
) -> None:
    mismatched = {}
    for item in request.session.items:
        parts = item.path.relative_to(_TESTS_DIR).parts
        if parts[0] in _TIERS and _tier_markers(item) != {parts[0]}:
            mismatched[item.nodeid] = _tier_markers(item)
    assert mismatched == {}


def test_this_module_is_marked_unit(request: pytest.FixtureRequest) -> None:
    assert _tier_markers(request.node) == {"unit"}

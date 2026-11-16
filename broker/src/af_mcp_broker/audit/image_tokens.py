"""Claude vision token estimate for an image of known pixel dimensions.

Rule (Anthropic, "Resolution and token cost"):
https://platform.claude.com/docs/en/build-with-claude/vision -- an image
costs ``ceil(width / 28) * ceil(height / 28)`` visual tokens (one per 28x28
patch), after being downscaled to fit the model tier's long-edge and
visual-token limits. The exact resize rule and its reference implementation
are in "How Claude resizes and pads images":
https://platform.claude.com/docs/en/build-with-claude/vision-coordinates --
:func:`resized_size` follows that implementation.

The broker cannot know which model the client runs, so the tier is a fixed
assumption, :data:`ASSUMED_TIER` (high resolution: Claude 4.7 and later). The
estimate is therefore an upper-leaning estimate for standard-tier models;
switching tiers is a one-line change here.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class ImageTier:
    """A model resolution tier's image limits."""

    max_edge: int  # px, per side, after padding up to a patch multiple
    max_tokens: int  # visual tokens


STANDARD_TIER = ImageTier(max_edge=1568, max_tokens=1568)
HIGH_RES_TIER = ImageTier(max_edge=2576, max_tokens=4784)
ASSUMED_TIER = HIGH_RES_TIER

_PATCH = 28


def count_image_tokens(width: int, height: int) -> int:
    """Visual tokens of an image of *width* x *height*: one per 28x28 patch."""
    return math.ceil(width / _PATCH) * math.ceil(height / _PATCH)


def _fits(width: int, height: int, tier: ImageTier) -> bool:
    return (
        math.ceil(width / _PATCH) * _PATCH <= tier.max_edge
        and math.ceil(height / _PATCH) * _PATCH <= tier.max_edge
        and count_image_tokens(width, height) <= tier.max_tokens
    )


def resized_size(
    width: int, height: int, tier: ImageTier = ASSUMED_TIER
) -> tuple[int, int]:
    """Return the ``(width, height)`` Claude downscales an image to before padding.

    An image that already fits *tier* is returned unchanged.
    """
    if _fits(width, height, tier):
        return width, height
    if height > width:
        resized_h, resized_w = resized_size(height, width, tier)
        return resized_w, resized_h
    # Binary search along the long edge for the largest aspect-preserving
    # size that fits. round() is half-to-even, as the reference implementation
    # specifies. Invariant: lo fits, hi does not.
    aspect_ratio = width / height
    lo, hi = 1, width
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if _fits(mid, max(round(mid / aspect_ratio), 1), tier):
            lo = mid
        else:
            hi = mid
    return lo, max(round(lo / aspect_ratio), 1)


def estimate_image_tokens(
    width: int, height: int, tier: ImageTier = ASSUMED_TIER
) -> int:
    """Estimated visual tokens for a *width* x *height* image on *tier*."""
    return count_image_tokens(*resized_size(width, height, tier))

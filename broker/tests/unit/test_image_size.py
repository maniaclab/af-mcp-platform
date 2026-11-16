"""Unit tests for ``audit/image_header.py`` and ``audit/image_tokens.py``.

Image headers are built by hand (struct/zlib), so the suite needs no imaging
library and no fixture files.
"""

from __future__ import annotations

import base64

import pytest
from image_builders import gif, jpeg, png, webp_extended, webp_lossless, webp_lossy

from af_mcp_broker.audit import image_header, image_tokens


@pytest.mark.parametrize(
    "builder",
    [png, gif, jpeg, webp_lossy, webp_lossless, webp_extended],
)
def test_image_dimensions_per_format(builder) -> None:  # type: ignore[no-untyped-def]
    assert image_header.image_dimensions(builder(640, 480)) == (640, 480)
    assert image_header.image_dimensions(builder(7, 3000)) == (7, 3000)


def test_real_one_pixel_images() -> None:
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA"
        "60e6kgAAAABJRU5ErkJggg=="
    )
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    assert image_header.image_dimensions(png) == (1, 1)
    assert image_header.image_dimensions(gif) == (1, 1)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not an image at all",
        b"\x89PNG\r\n\x1a\n",  # truncated before IHDR
        b"\xff\xd8\xff\xd9",  # JPEG with no frame header
        png(0, 10),  # zero dimension
        b"RIFF\x00\x00\x00\x00WEBPVP8 ",  # truncated WebP
    ],
)
def test_unreadable_images_raise_value_error(data: bytes) -> None:
    with pytest.raises(ValueError, match="image"):
        image_header.image_dimensions(data)


@pytest.mark.parametrize(
    ("width", "height", "tokens"),
    [
        # The worked rows of the high-resolution tier in Anthropic's vision
        # docs ("Resolution and token cost").
        (200, 200, 64),
        (1000, 1000, 1296),
        (1092, 1092, 1521),
        (1920, 1080, 2691),
        (2000, 1500, 3888),
        (3840, 2160, 4784),
        # The 640x480 PNG seen in production: 23 x 18 patches.
        (640, 480, 414),
    ],
)
def test_high_resolution_tier_matches_documented_rows(
    width: int, height: int, tokens: int
) -> None:
    assert image_tokens.estimate_image_tokens(width, height) == tokens


@pytest.mark.parametrize(
    ("width", "height", "tokens"),
    [
        (200, 200, 64),
        (1000, 1000, 1296),
        (1092, 1092, 1521),
        (1920, 1080, 1560),
        (2000, 1500, 1564),
        (3840, 2160, 1560),
    ],
)
def test_standard_tier_matches_documented_rows(
    width: int, height: int, tokens: int
) -> None:
    assert (
        image_tokens.estimate_image_tokens(width, height, image_tokens.STANDARD_TIER)
        == tokens
    )


def test_resized_size_documented_examples() -> None:
    standard = image_tokens.STANDARD_TIER
    # The A4 scan from "How Claude resizes and pads images".
    assert image_tokens.resized_size(1075, 1520, standard) == (924, 1307)
    assert image_tokens.resized_size(1920, 1080, standard) == (1456, 819)
    assert image_tokens.resized_size(3840, 2160, image_tokens.HIGH_RES_TIER) == (
        2576,
        1449,
    )
    # Portrait images are the transposed landscape case.
    assert image_tokens.resized_size(1520, 1075, standard) == (1307, 924)


def test_extreme_aspect_ratio_never_exceeds_the_tier_cap() -> None:
    tier = image_tokens.HIGH_RES_TIER
    assert image_tokens.estimate_image_tokens(100_000, 10, tier) <= tier.max_tokens
    assert image_tokens.estimate_image_tokens(1, 1, tier) == 1

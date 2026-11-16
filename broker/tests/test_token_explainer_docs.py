"""The token-counting explanation (docs and portal tooltip) must match the code.

Fails when an image-tier constant or the default text encoding changes without
``docs/observability.md`` ("How token counts are estimated") and
``portal/src/lib/tokenExplainer.ts`` changing with it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from af_mcp_broker.audit import image_tokens
from af_mcp_broker.config import Settings
from af_mcp_broker.usage.summary import TOKEN_ESTIMATE_CAVEAT

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HEADING = "## How token counts are estimated"


def _doc_section() -> str:
    text = (_REPO_ROOT / "docs" / "observability.md").read_text()
    assert _HEADING in text
    section = text.split(_HEADING, 1)[1]
    return section.split("\n## ", 1)[0]


def _tooltip_source() -> str:
    return (_REPO_ROOT / "portal" / "src" / "lib" / "tokenExplainer.ts").read_text()


def _example_tokens() -> int:
    return image_tokens.estimate_image_tokens(640, 480)


def test_the_documented_example_is_what_the_code_computes() -> None:
    assert _example_tokens() == 414


@pytest.mark.parametrize("tier", [image_tokens.ASSUMED_TIER])
def test_docs_state_the_assumed_tier_limits(tier: image_tokens.ImageTier) -> None:
    section = _doc_section()
    assert f"{tier.max_edge:,}" in section
    assert f"{tier.max_tokens:,}" in section


def test_docs_state_the_standard_tier_alternative() -> None:
    section = _doc_section()
    assert f"{image_tokens.STANDARD_TIER.max_edge:,}" in section
    assert f"{image_tokens.STANDARD_TIER.max_tokens:,}" in section


def test_docs_and_tooltip_state_the_patch_size_example_and_encoding() -> None:
    encoding = Settings.model_fields["token_estimate_encoding"].default
    for text in (_doc_section(), _tooltip_source()):
        assert encoding in text
        assert str(_example_tokens()) in text
        assert "640" in text
        assert "28" in text


def test_tooltip_states_the_assumed_tier_limits() -> None:
    source = _tooltip_source()
    assert str(image_tokens.ASSUMED_TIER.max_edge) in source
    assert str(image_tokens.ASSUMED_TIER.max_tokens) in source


def test_the_tier_is_still_the_documented_high_resolution_one() -> None:
    assert image_tokens.ASSUMED_TIER is image_tokens.HIGH_RES_TIER


def test_usage_caveat_states_the_rules_the_docs_state() -> None:
    encoding = Settings.model_fields["token_estimate_encoding"].default
    tier = image_tokens.ASSUMED_TIER
    for expected in (
        "ESTIMATE",
        "not provider-reported",
        encoding,
        "28x28",
        str(tier.max_edge),
        str(tier.max_tokens),
        "by_content_type",
    ):
        assert expected in TOKEN_ESTIMATE_CAVEAT


def test_usage_caveat_says_the_breakdown_can_sum_to_less_than_the_totals() -> None:
    assert "less than" in TOKEN_ESTIMATE_CAVEAT

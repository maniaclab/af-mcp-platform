"""Unit tests for the area ``test_metrics.py`` covers; the integration tests live in ``integration/test_metrics.py``."""

from __future__ import annotations

from af_mcp_broker.metrics import tool_mapping_drift_total


def test_tool_mapping_drift_help_describes_stale_keys_in_the_present_tense() -> None:
    help_text = tool_mapping_drift_total.describe()[0].documentation

    assert "no longer" not in help_text
    assert "a mapped key the backend does not advertise" in help_text

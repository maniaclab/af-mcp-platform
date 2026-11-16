"""Integration tests for the area ``test_policy_absent.py`` covers; the unit tests live in ``unit/test_policy_absent.py``."""

from __future__ import annotations

import pytest


def test_request_without_published_state_fails_instead_of_using_an_empty_policy(
    app_client,
) -> None:
    client, _state = app_client
    del client.app.state.broker

    with pytest.raises(RuntimeError, match="BrokerState is not published"):
        client.get("/v1/entitlements")

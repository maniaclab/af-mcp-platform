"""Integration tests for the area ``test_wiring_http_client.py`` covers; the unit tests live in ``unit/test_wiring_http_client.py``."""

from __future__ import annotations


def test_the_running_app_holds_the_client_its_lifespan_built(app_client) -> None:
    client, _state = app_client

    assert not client.app.state.broker.http_client.is_closed

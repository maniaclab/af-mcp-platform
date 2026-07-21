"""Metrics are served on a dedicated port (issue #11), not the API port.

The chart's ServiceMonitor and NetworkPolicy point Prometheus at port 9090;
the API port (8080) must not expose /metrics.
"""

from __future__ import annotations

import urllib.request


def test_metrics_not_on_api_port(app_client) -> None:
    client, _ = app_client
    assert client.get("/metrics").status_code == 404


def test_metrics_served_on_dedicated_port(app_client) -> None:
    client, _ = app_client
    port = client.app.state.metrics_port
    assert isinstance(port, int)
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics") as resp:
        assert resp.status == 200
        body = resp.read().decode()
    assert "# HELP" in body


def test_metrics_disabled_with_negative_port(monkeypatch, app_client_factory) -> None:
    monkeypatch.setenv("METRICS_PORT", "-1")
    with app_client_factory() as (client, _):
        assert client.app.state.metrics_port is None

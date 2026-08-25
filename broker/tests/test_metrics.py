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


def test_http_metrics_use_af_mcp_namespace(app_client) -> None:
    """The Grafana dashboard (issue #226) queries af_mcp_http_requests_total
    and af_mcp_http_request_duration_seconds_bucket labeled by handler — the
    instrumentator must emit exactly those series names and labels.
    """
    client, _ = app_client
    assert client.get("/v1/healthz").status_code == 200
    port = client.app.state.metrics_port
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics") as resp:
        body = resp.read().decode()
    assert 'af_mcp_http_requests_total{handler="/v1/healthz"' in body
    assert 'af_mcp_http_request_duration_seconds_bucket{handler="/v1/healthz"' in body

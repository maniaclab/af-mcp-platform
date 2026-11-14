"""The OTel ``Resource`` every broker signal (traces, metrics, usage events) carries."""

from __future__ import annotations

from opentelemetry.sdk.resources import Resource

from af_mcp_broker._version import version as __version__


def broker_resource() -> Resource:
    """Resource identifying this service and version on every exported signal."""
    return Resource.create(
        {"service.name": "af-mcp-broker", "service.version": __version__}
    )

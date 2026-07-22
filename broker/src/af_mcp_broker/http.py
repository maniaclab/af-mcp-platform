"""Process-wide shared httpx client.

One pooled ``AsyncClient`` serves all outbound broker HTTP (JWKS fetches,
Keycloak token calls, loopback /v1 calls) instead of a new client — and a
new connection pool — per request. The lifespan closes it on shutdown.
"""

from __future__ import annotations

import httpx

_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Return the shared client, creating it on first use."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=10.0)
    return _client


async def aclose_http_client() -> None:
    """Close the shared client (lifespan shutdown)."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None

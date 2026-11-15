"""Builder for the process-wide pooled outbound HTTP client."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx2

if TYPE_CHECKING:
    from contextlib import AsyncExitStack


def build_http_client(stack: AsyncExitStack) -> httpx2.AsyncClient:
    """Open the one pooled ``AsyncClient`` serving all outbound broker HTTP and register its close on *stack*.

    JWKS fetches, Keycloak token and admin calls, Vault, the credential
    services and the loopback /v1 calls share one connection pool instead of
    a new client per request. Consumers receive it as an explicit argument
    (the builders pass it on; routes read ``BrokerState.http_client``).
    """
    client = httpx2.AsyncClient(timeout=10.0)
    stack.push_async_callback(client.aclose)
    return client

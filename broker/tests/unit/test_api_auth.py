"""Tests that ``api.auth.keycloak_dependency`` fails closed when no dev bypass is configured.

The bypass is the one path that skips credential validation, so its absence
must never admit a request: only a ``BrokerState`` carrying a dev principal
may short-circuit authentication.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from broker_state_helpers import make_broker_state

from af_mcp_broker.api.auth import keycloak_dependency
from af_mcp_broker.identity import InvalidTokenError, NotAuthenticatedError


def _request(**state_fields: object) -> SimpleNamespace:
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(broker=make_broker_state(**state_fields))
        ),
        url=SimpleNamespace(path="/v1/identities"),
    )


async def test_no_bypass_principal_and_no_credentials_is_not_authenticated(
    settings,
) -> None:
    request = _request(dev_bypass_principal=None)

    with pytest.raises(NotAuthenticatedError):
        await keycloak_dependency(request, None, settings)


async def test_no_bypass_principal_still_validates_a_presented_token(
    settings, prime_jwks, static_principal_cache
) -> None:
    principal_cache, _directory = static_principal_cache
    prime_jwks([])
    request = _request(dev_bypass_principal=None, principal_cache=principal_cache)

    with pytest.raises(InvalidTokenError):
        await keycloak_dependency(
            request, SimpleNamespace(credentials="not-a-jwt"), settings
        )


async def test_missing_broker_state_does_not_authenticate(settings) -> None:
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace()),
        url=SimpleNamespace(path="/v1/identities"),
    )

    with pytest.raises(RuntimeError, match="BrokerState is not published"):
        await keycloak_dependency(request, None, settings)

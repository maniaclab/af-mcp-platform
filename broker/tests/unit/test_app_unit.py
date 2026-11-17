"""Unit tests for the area ``test_app.py`` covers; the integration tests live in ``integration/test_app.py``."""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import structlog

import af_mcp_broker.app as app_module
from af_mcp_broker.config import (
    KeycloakBrokeredProviderConfig,
    OAuth21DirectProviderConfig,
    X509ProviderConfig,
)
from af_mcp_broker.wiring.checks import build_target_to_alias


def test_build_target_to_alias_covers_all_auth_shapes() -> None:
    """target_to_alias (issue #90) joins backend targets to whichever
    credential provider services them, uniformly from the configured
    `identity_providers` list: x509 targets get their entry's alias
    (every auth_type: x509 backend needs an explicit entry, so this helper
    does not special-case x509 at all), keycloak-brokered/oauth21-direct targets get
    their configured alias, and auth_type "none" targets (e.g. "docs") are
    simply absent — no user credential is needed for them.
    """
    identity_providers_cfgs = [
        KeycloakBrokeredProviderConfig(alias="atlas-oidc", targets=["rucio"]),
        OAuth21DirectProviderConfig(
            alias="rucio-mcp-atlas",
            targets=["rucio-mcp-atlas"],
            authorization_endpoint="https://backend-as.example/authorize",
            token_endpoint="https://backend-as.example/token",
            issuer="https://backend-as.example",
        ),
        X509ProviderConfig(
            voms="atlas",
            alias="x509",
            targets=["ami"],
            service_url="http://voms-token-service.invalid",
        ),
    ]

    mapping = build_target_to_alias(identity_providers_cfgs)

    assert mapping == {
        "rucio": "atlas-oidc",
        "rucio-mcp-atlas": "rucio-mcp-atlas",
        "ami": "x509",
    }
    assert "docs" not in mapping


def test_build_target_to_alias_uses_the_real_x509_entry_alias() -> None:
    """An operator-chosen x509 alias flows through to /v1/catalog's
    credential_provider — no synthetic "x509" alias is hardcoded."""
    mapping = build_target_to_alias(
        [
            X509ProviderConfig(
                voms="atlas",
                alias="grid-cert-atlas",
                targets=["ami", "panda"],
                service_url="http://voms-token-service.invalid",
            )
        ]
    )

    assert mapping == {"ami": "grid-cert-atlas", "panda": "grid-cert-atlas"}


# ---------------------------------------------------------------------------
# Tracing wiring (observability roadmap PR D): off by default -- with
# OTEL_EXPORTER_OTLP_ENDPOINT unset at import time, module-scope
# instrument_fastapi() must have been a no-op; and the lifespan teardown must
# flush whatever provider init_tracing() installed (a no-op when none was).
# ---------------------------------------------------------------------------


async def test_bind_request_logging_context_binds_a_fresh_request_id() -> None:
    """Issue #281: the only /v1 middleware that runs before keycloak_dependency
    resolves identity, so this is where every request -- even one whose
    credentials never validate -- gets a request_id to log by."""
    structlog.contextvars.clear_contextvars()
    # A SimpleNamespace stand-in for Request is enough here: issue #322's
    # http.request.received/finished logging (exercised in full by
    # test_request_logging.py) only reads request.method/request.url.path/
    # request.scope, never anything requiring a real Starlette Request.
    request = SimpleNamespace(
        method="GET", url=SimpleNamespace(path="/v1/whoami"), scope={}
    )
    response = SimpleNamespace(status_code=200)

    async def call_next(request: Any) -> Any:
        return response

    result = await app_module._bind_request_logging_context(request, call_next)

    assert result is response
    assert structlog.contextvars.get_contextvars()["request_id"]


def test_app_not_instrumented_by_default() -> None:
    assert not getattr(app_module.app, "_is_instrumented_by_opentelemetry", False)


def test_missing_instrumentator_fails_the_app_import() -> None:
    """prometheus-fastapi-instrumentator is a required dependency: an
    environment without it must fail at import, not boot without HTTP metrics.
    A child interpreter is used because ``af_mcp_broker.app`` builds the app
    at import time and is already cached in this process."""
    blocked_import = (
        "import sys; sys.modules['prometheus_fastapi_instrumentator'] = None; "
        "import af_mcp_broker.app"
    )

    result = subprocess.run(
        [sys.executable, "-c", blocked_import],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "prometheus_fastapi_instrumentator" in result.stderr

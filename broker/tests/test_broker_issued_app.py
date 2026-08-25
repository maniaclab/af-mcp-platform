"""App-level wiring for the AF Broker Identity Token (issue #162).

Covers: provider registration from an ``identity_providers`` broker-issued
entry, the startup fail-closed check (a broker-issued entry with no signing
key must refuse to boot; the feature being unconfigured entirely must boot
cleanly), an end-to-end stub-verifier flow (mint via ``POST /v1/credential``,
verify against the app's own ``/.well-known/jwks.json``), and an
aggregator-level flow (a real toy backend receives the minted token over the
existing ``bearer`` branch). The issuer core and provider unit tests live in
test_broker_issued.py; the JWKS endpoint's own behavior lives in
test_wellknown_jwks.py.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.dependencies import get_http_headers
from fastmcp.utilities.tests import run_server_async
from test_broker_issued import (
    _BASE_CLAIMS,
    _make_rsa_key,
    _private_pem,
    verify_against_jwks,
)
from test_mcp_aggregator import _FakeFastMCPContext

import af_mcp_broker.app as app_module
from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.config import BrokerIssuedTargetOptions
from af_mcp_broker.credentials import (
    BrokerIssuedProvider,
    BrokerTokenIssuer,
    CredentialCache,
    CredentialRegistry,
)
from af_mcp_broker.mcp import aggregator as aggregator_module
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

from conftest import make_claims, run_aggregator_async

_BROKER_ISSUED_PROVIDERS = [
    {
        "type": "broker-issued",
        "alias": "af-native",
        "display_name": "AF-native services",
        "targets": ["condor-token-service"],
    }
]

_BACKENDS_YAML = (
    "services:\n"
    "  - name: condor-token-service\n"
    "    prefix: condor\n"
    "    url: http://condor-token-service.invalid/mcp\n"
    "    auth_type: bearer\n"
    "    required_capability: read_data\n"
)


@pytest.fixture
def broker_issued_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Point the app at a broker-issued identity provider and (optionally) a real signing key on disk."""

    def _apply(*, with_signing_key: bool = True) -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(_BACKENDS_YAML)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(_BROKER_ISSUED_PROVIDERS))
        monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
        if with_signing_key:
            key_file = tmp_path / "signing-key.pem"
            key_file.write_bytes(_private_pem(_make_rsa_key()))
            monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))

    return _apply


# ---------------------------------------------------------------------------
# Startup wiring + fail-closed check
# ---------------------------------------------------------------------------


def test_broker_issued_provider_registered_from_config(
    broker_issued_env, app_client_factory
) -> None:
    broker_issued_env()

    with app_client_factory() as (client, _):
        state = client.app.state
        assert state.broker_token_issuer is not None
        assert isinstance(state.identity_providers["af-native"], BrokerIssuedProvider)
        provider = asyncio.run(
            state.credential_registry.resolve("condor-token-service")
        )
        assert isinstance(provider, BrokerIssuedProvider)
        # issue #90's catalog join: the target maps to the configured alias.
        assert state.target_to_alias["condor-token-service"] == "af-native"


def test_broker_issued_entry_without_signing_key_refuses_to_start(
    broker_issued_env, app_client_factory
) -> None:
    """Fail-closed, like unreachable_capabilities/ungated_services: a
    backend wired to broker-issued with no signing key configured would
    otherwise fail at first request instead of at boot."""
    broker_issued_env(with_signing_key=False)

    with pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"):  # noqa: SIM117
        with app_client_factory():
            pass


def test_unconfigured_feature_boots_cleanly(app_client_factory) -> None:
    """No broker-issued entry and no signing key: local dev must degrade
    gracefully, exactly as before this feature existed."""
    with app_client_factory() as (client, _):
        resp = client.get("/v1/healthz")
        assert resp.status_code == 200, resp.text
        assert client.app.state.broker_token_issuer is None


def test_signing_key_without_broker_issued_entry_boots_and_serves_jwks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, app_client_factory
) -> None:
    """The key being configured ahead of the first broker-issued entry (the
    publish-before-use half of the rotation story) is a valid state: the
    issuer loads and the JWKS is served even with no provider wired yet."""
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(_private_pem(_make_rsa_key()))
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")

    with app_client_factory() as (client, _):
        resp = client.get("/.well-known/jwks.json")

    assert resp.status_code == 200, resp.text
    assert resp.json()["keys"]


# ---------------------------------------------------------------------------
# End-to-end: a stub verifier fetches the JWKS from the app and validates a
# token minted through the real /v1 credential flow.
# ---------------------------------------------------------------------------


def test_minted_credential_verifies_against_apps_own_jwks(
    broker_issued_env, app_client_factory
) -> None:
    broker_issued_env()

    with app_client_factory() as (client, _):
        cred_resp = client.post(
            "/v1/credential", json={"target": "condor-token-service"}
        )
        jwks_resp = client.get("/.well-known/jwks.json")

    assert cred_resp.status_code == 200, cred_resp.text
    assert jwks_resp.status_code == 200, jwks_resp.text
    body = cred_resp.json()
    assert body["kind"] == "bearer"
    assert body["credential_type"] == "broker_issued"

    claims = verify_against_jwks(
        body["token"],
        jwks_resp.json(),
        audience="condor-token-service",
        issuer="https://mcp.example.com",
    )
    # app_client_factory's default principal (conftest make_principal).
    assert claims["sub"] == "sub-abc"
    assert set(claims) == _BASE_CLAIMS


# ---------------------------------------------------------------------------
# Aggregator-level: a real toy backend behind a real build_aggregator()
# stack receives the AF Broker Identity Token over the existing bearer
# branch -- no aggregator changes (issue #162). Mirrors
# test_mcp_credential_injection_integration.py's harness with the real
# provider instead of a fake.
# ---------------------------------------------------------------------------

_AGG_ISSUER_URL = "https://mcp.example.com"


def _toy_backend() -> FastMCP:
    mcp = FastMCP(name="toy-backend")

    @mcp.tool
    def seen_authorization() -> str | None:
        """Returns the raw Authorization header this backend actually received."""
        return get_http_headers(include={"authorization"}).get("authorization")

    return mcp


@pytest.fixture
async def toy_backend_url() -> AsyncIterator[str]:
    async with run_server_async(_toy_backend(), path="/mcp") as url:
        yield url


async def test_aggregator_injects_broker_identity_token(
    settings, toy_backend_url, static_principal_cache, sig_key, prime_jwks
) -> None:
    prime_jwks([sig_key.jwk])
    principal_cache, directory = static_principal_cache
    directory.groups_by_subject["user-123"] = ["atlas"]

    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="toy",
            prefix="toy",
            url=toy_backend_url,
            transport="http",
            required_capability="read_data",
            auth_type="bearer",
        )
    )
    issuer = BrokerTokenIssuer(
        private_key_pem=_private_pem(_make_rsa_key()), issuer=_AGG_ISSUER_URL
    )
    provider = BrokerIssuedProvider(
        issuer=issuer,
        cache=CredentialCache(),
        alias="af-native",
        targets=frozenset({"toy"}),
        target_options={"toy": BrokerIssuedTargetOptions(audience="toy-svc")},
    )
    credential_registry = CredentialRegistry()
    credential_registry.register("toy", provider)
    policy = EntitlementPolicy(group_capabilities={"atlas": ["read_data"]})
    mcp = build_aggregator(
        registry,
        settings,
        policy,
        credential_registry,
        principal_cache=principal_cache,
    )
    inbound_token = sig_key.sign(make_claims())

    async with run_aggregator_async(mcp, path="/mcp") as base_url:
        transport = StreamableHttpTransport(
            base_url, headers={"Authorization": f"Bearer {inbound_token}"}
        )
        async with Client(transport) as client:
            result = await client.call_tool("toy_seen_authorization", {})

    seen: str = result.data
    assert seen is not None
    assert seen.startswith("Bearer ")
    minted = seen.removeprefix("Bearer ")
    # Never the caller's inbound Keycloak JWT -- always the minted assertion.
    assert minted != inbound_token
    claims = verify_against_jwks(
        minted, issuer.jwks(), audience="toy-svc", issuer=_AGG_ISSUER_URL
    )
    assert claims["sub"] == "user-123"
    assert set(claims) == _BASE_CLAIMS


# ---------------------------------------------------------------------------
# /v1/identities surfaces a broker-issued provider as always linked.
# ---------------------------------------------------------------------------


def test_identities_lists_broker_issued_provider_as_linked(
    broker_issued_env, app_client_factory
) -> None:
    broker_issued_env()

    with app_client_factory() as (client, _):
        resp = client.get("/v1/identities")

    assert resp.status_code == 200, resp.text
    rows: list[dict[str, Any]] = resp.json()["providers"]
    (row,) = [r for r in rows if r["id"] == "af-native"]
    assert row["type"] == "broker-issued"
    assert row["linked"] is True
    assert row["link_url"] is None


# ---------------------------------------------------------------------------
# Lifespan -> aggregator wiring: app.py builds the aggregator eagerly, before
# the signing key is loaded, so the lifespan's populate_aggregator() call is
# the only way the real issuer can reach the x509 client factories (issue
# #112's injection path). If it never arrives, every `auth_type: x509`
# backend connects with no Authorization header at list time (the backend
# 401s and is dropped as "unavailable") and an authorized tools/call raises a
# ToolError claiming no signing key is configured -- even though
# app.state.broker_token_issuer loaded fine and the /v1 redeem endpoint uses
# it happily.
# ---------------------------------------------------------------------------


def _find_service_provider(mcp: FastMCP, service_name: str) -> Any:
    """Fish one backend's _ObservableProxyProvider out of the aggregator.

    Namespaced providers sit behind fastmcp's ``_WrappedProvider`` (its
    ``_inner`` attribute holds ours) -- private internals, same caveat as
    ``_ObservableProxyProvider``'s docstring: re-check on a fastmcp bump.
    """
    for provider in mcp.providers:
        inner = getattr(provider, "_inner", provider)
        if (
            isinstance(inner, aggregator_module._ObservableProxyProvider)
            and inner._service_name == service_name
        ):
            return inner
    raise AssertionError(f"no provider registered for backend {service_name!r}")


def test_lifespan_threads_issuer_into_x509_client_factory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Any,
    make_principal: Any,
) -> None:
    """The x509 client factory the lifespan wires up must mint with the same
    issuer the lifespan loaded onto ``app.state.broker_token_issuer``."""
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(_private_pem(_make_rsa_key()))
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")

    with app_client_factory() as (client, _):
        issuer = client.app.state.broker_token_issuer
        assert issuer is not None
        # SHIPPED_SERVICES' "ami" is its auth_type: x509 entry.
        ami_provider = _find_service_provider(app_module._mcp_aggregator, "ami")
        # A list-time invocation (no authorized_call_target) by an entitled
        # principal: the factory attaches the identity header best-effort --
        # exactly the connection that goes out bare and 401s in production
        # when the issuer never reaches the aggregator.
        ctx = _FakeFastMCPContext(
            make_principal(subject="sub-abc", groups=["atlas"]), None
        )
        monkeypatch.setattr(aggregator_module, "get_context", lambda: ctx)
        backend_client = asyncio.run(ami_provider.client_factory())

    auth = backend_client.transport.headers.get("Authorization")
    assert auth is not None, "x509 list-time connection carried no identity token"
    claims = issuer.verify(auth.removeprefix("Bearer "))
    assert claims is not None
    assert claims["sub"] == "sub-abc"
    assert claims["aud"] == "ami"

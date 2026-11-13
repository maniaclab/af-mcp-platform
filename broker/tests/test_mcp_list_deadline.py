from __future__ import annotations

import asyncio
import gc
import logging
import time
from typing import TYPE_CHECKING, Any

import pytest
from conftest import (
    AUDIENCE,
    ISSUER,
    HungBackend,
    make_claims,
    run_aggregator_async,
    run_inprocess_asgi_app,
    run_inprocess_server,
)
from fastmcp import Client, FastMCP

from af_mcp_broker.api.permissions import _service_status
from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import (
    CredentialProvider,
    CredentialRegistry,
    ExecutionModel,
)
from af_mcp_broker.mcp import aggregator as aggregator_module
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.errors import ListDeadlineExceededError
from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from fastmcp.utilities.tests import ASGIServer

# ---------------------------------------------------------------------------
# One backend that accepts the connection and never answers (a pod on an
# unreachable node whose endpoint is still in the Service) must not hold the
# whole tools/list past the broker-wide listing deadline, nor hide the tools
# of the backends that answered (issue #335). The per-service
# ServiceSpec.timeout_seconds is set far above the deadline here so only the
# deadline can end the listing early.
# ---------------------------------------------------------------------------

_LIST_DEADLINE_SECONDS = 0.5
_SERVICE_TIMEOUT_SECONDS = 20.0
# Generous slack over the deadline for a loaded CI machine, still far below
# _SERVICE_TIMEOUT_SECONDS so a missing deadline fails the assertion.
_MAX_LIST_SECONDS = 8.0


def _open_backend() -> FastMCP:
    mcp = FastMCP(name="open-backend")

    @mcp.tool
    def ping() -> str:
        return "pong"

    return mcp


@pytest.fixture
def list_failure_logs(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Every ``aggregator.service_list_failed`` event the aggregator logs.

    The logger is patched rather than captured with structlog's
    ``capture_logs``: a logger already bound earlier in the session ignores
    that context manager.
    """
    events: list[dict[str, Any]] = []

    def _record(event: str, **kwargs: Any) -> None:
        if event == "aggregator.service_list_failed":
            events.append(kwargs)

    monkeypatch.setattr(aggregator_module.logger, "warning", _record)
    monkeypatch.setattr(aggregator_module.logger, "info", _record)
    return events


@pytest.fixture
def hung_backend() -> HungBackend:
    return HungBackend()


@pytest.fixture
def list_registry() -> ServiceRegistry:
    return ServiceRegistry()


@pytest.fixture
async def deadline_aggregator_server(
    hung_backend: HungBackend,
    list_registry: ServiceRegistry,
    static_principal_cache: Any,
) -> AsyncIterator[ASGIServer]:
    principal_cache, _directory = static_principal_cache
    settings = Settings(
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        mcp_list_timeout_seconds=_LIST_DEADLINE_SECONDS,
    )
    async with (
        run_inprocess_server(_open_backend(), path="/mcp") as open_url,
        run_inprocess_asgi_app(hung_backend) as hung_url,
    ):
        for name, url in (("open", open_url), ("hung", f"{hung_url}/mcp")):
            list_registry.register(
                ServiceSpec(
                    name=name,
                    prefix=name,
                    url=url,
                    transport="http",
                    required_permission="__none__",
                    auth_type="none",
                    timeout_seconds=_SERVICE_TIMEOUT_SECONDS,
                )
            )
        mcp = build_aggregator(
            list_registry,
            settings,
            EntitlementPolicy(),
            CredentialRegistry(),
            principal_cache=principal_cache,
        )
        async with run_aggregator_async(mcp, path="/mcp") as server:
            yield server


def _client(server: ASGIServer, token: str) -> Client:
    return server.client(headers={"Authorization": f"Bearer {token}"})


@pytest.fixture
def token(sig_key: Any, prime_jwks: Any) -> str:
    prime_jwks([sig_key.jwk])
    return sig_key.sign(make_claims())


async def test_hung_backend_neither_delays_nor_hides_healthy_backends(
    deadline_aggregator_server: ASGIServer,
    token: str,
    list_registry: ServiceRegistry,
    list_failure_logs: list[dict[str, Any]],
) -> None:
    started = time.monotonic()
    async with _client(deadline_aggregator_server, token) as client:
        names = {t.name for t in await client.list_tools()}
    elapsed = time.monotonic() - started

    assert elapsed < _MAX_LIST_SECONDS
    assert "open_ping" in names
    assert not any(n.startswith("hung_") for n in names)
    assert [(e["service"], e["reason"]) for e in list_failure_logs] == [
        ("hung", "unavailable")
    ]
    assert list_registry.recent_list_failure("hung", "user-123") == "unavailable"


async def test_deadline_miss_is_negative_cached_for_the_same_caller(
    deadline_aggregator_server: ASGIServer, token: str, hung_backend: HungBackend
) -> None:
    async with _client(deadline_aggregator_server, token) as client:
        await client.list_tools()
    assert hung_backend.requests >= 1
    requests_after_first = hung_backend.requests

    started = time.monotonic()
    async with _client(deadline_aggregator_server, token) as client:
        names = {t.name for t in await client.list_tools()}
    elapsed = time.monotonic() - started

    assert "open_ping" in names
    assert hung_backend.requests == requests_after_first
    assert elapsed < _LIST_DEADLINE_SECONDS


async def test_abandoned_backend_request_is_closed_without_leaked_tasks(
    deadline_aggregator_server: ASGIServer,
    token: str,
    hung_backend: HungBackend,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="asyncio")
    before = asyncio.all_tasks()

    async with _client(deadline_aggregator_server, token) as client:
        await client.list_tools()
    # The backend sees the broker's connection go away rather than lingering.
    for _ in range(100):
        if hung_backend.disconnects:
            break
        await asyncio.sleep(0.05)
    assert hung_backend.disconnects >= 1

    await asyncio.sleep(0.2)
    # Tasks the abandoned backend client started (fastmcp / mcp SDK
    # transport) must be gone, as must the in-process backend's request handler
    # (it ends with the client's transport).
    leaked = [
        t
        for t in asyncio.all_tasks() - before
        if not t.done() and ("/mcp/" in _coro_file(t) or "/fastmcp/" in _coro_file(t))
    ]
    gc.collect()
    assert leaked == []
    assert [r.getMessage() for r in caplog.records if r.name == "asyncio"] == []


# Credential setup runs inside the same deadline: a list-time credential
# lookup that hangs (e.g. a Vault read) is an operational failure, never a
# statement about the caller's linkage.


async def test_deadline_covers_hung_credential_setup_and_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    make_principal: Any,
    list_failure_logs: list[dict[str, Any]],
) -> None:
    async def _hanging_factory() -> Client:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    ctx = _FakeContext(make_principal(subject="alice"))
    # What _bearer_factory records before a connection attempt for a caller
    # whose mint was skipped: it must not win over a deadline miss.
    ctx.state["__list_credential_status__:example"] = (False, "not_linked")
    monkeypatch.setattr(aggregator_module, "get_context", lambda: ctx)

    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="example",
            prefix="example",
            url="http://example.invalid/mcp",
            transport="http",
            required_permission="__none__",
        )
    )
    provider = aggregator_module._ObservableProxyProvider(
        "example",
        _hanging_factory,
        registry=registry,
        list_timeout_seconds=_LIST_DEADLINE_SECONDS,
    )

    with pytest.raises(ListDeadlineExceededError):
        await provider._list_tools()

    assert registry.recent_list_failure("example", "alice") == "unavailable"
    [failure] = list_failure_logs
    assert failure["reason"] == "unavailable"


async def test_deadline_miss_shows_unavailable_service_wide_in_catalog(
    monkeypatch: pytest.MonkeyPatch, make_principal: Any
) -> None:
    async def _hanging_factory() -> Client:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    alice = make_principal(subject="alice")
    monkeypatch.setattr(aggregator_module, "get_context", lambda: _FakeContext(alice))
    spec = ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
        auth_type="bearer",
    )
    registry = ServiceRegistry()
    registry.register(spec)
    credential_registry = CredentialRegistry()
    credential_registry.register("example", _LinkedProvider())
    provider = aggregator_module._ObservableProxyProvider(
        "example",
        _hanging_factory,
        registry=registry,
        list_timeout_seconds=_LIST_DEADLINE_SECONDS,
    )

    with pytest.raises(ListDeadlineExceededError):
        await provider._list_tools()

    # Every caller sees the service-wide record, not only the one whose
    # listing missed the deadline.
    status, _detail, _correlation_id, link_state = await _service_status(
        spec,
        make_principal(subject="someone-else"),
        set(),
        credential_registry,
        registry,
    )
    assert status == "unavailable"
    assert link_state is None


class _LinkedProvider(CredentialProvider):
    cred_class = "fake"
    execution_model = ExecutionModel.DELEGATED

    async def is_linked(self, principal: Any) -> bool:
        return True

    async def issue(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("not minted in this test")


def _coro_file(task: asyncio.Task[Any]) -> str:
    coro = task.get_coro()
    code = getattr(coro, "cr_code", None)
    return code.co_filename if code is not None else ""


class _FakeContext:
    def __init__(self, principal: Any) -> None:
        self.state: dict[str, Any] = {"principal": principal}

    async def get_state(self, key: str) -> Any:
        return self.state.get(key)

    async def set_state(
        self, key: str, value: Any, *, serializable: bool = True
    ) -> None:
        self.state[key] = value

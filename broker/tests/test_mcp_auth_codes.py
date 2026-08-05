"""Tests for the in-process MCP OAuth bootstrap authorization code store (issue #140)."""

from __future__ import annotations

import time

from af_mcp_broker.mcp_auth_codes import McpAuthCodeRecord, McpAuthCodeStore


def _record(**overrides: object) -> McpAuthCodeRecord:
    kwargs: dict[str, object] = {
        "principal_id": "sub-abc",
        "client_id": "https://client.example/.well-known/cimd",
        "redirect_uri": "http://localhost:12345/callback",
        "code_challenge": "challenge-abc",
        "client_name": "Test Client",
    }
    kwargs.update(overrides)
    return McpAuthCodeRecord(**kwargs)  # type: ignore[arg-type]


def test_put_then_consume_round_trip() -> None:
    store = McpAuthCodeStore()
    record = _record()

    code = store.put(record)
    consumed = store.consume(code)

    assert consumed == record


def test_consume_is_single_use() -> None:
    store = McpAuthCodeStore()
    code = store.put(_record())

    assert store.consume(code) is not None
    assert store.consume(code) is None


def test_consume_unknown_code_returns_none() -> None:
    store = McpAuthCodeStore()

    assert store.consume("never-issued") is None


def test_consume_expired_code_returns_none() -> None:
    store = McpAuthCodeStore(ttl_seconds=0.01)
    code = store.put(_record())
    time.sleep(0.02)

    assert store.consume(code) is None


def test_codes_are_unique() -> None:
    store = McpAuthCodeStore()
    codes = {store.put(_record()) for _ in range(50)}

    assert len(codes) == 50

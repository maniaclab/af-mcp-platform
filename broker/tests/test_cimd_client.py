"""Tests for the broker's CIMD client resolution (issue #140).

Mirrors rucio-mcp's ``auth/cimd.py`` test coverage (the in-house reference
this module ports) adapted to the broker's ``CimdClient`` shape: self-
reference check, SSRF guard, port-agnostic loopback redirect_uri matching.
"""

from __future__ import annotations

import socket
from typing import Any

import httpx
import pytest

from af_mcp_broker.cimd_client import (
    CimdError,
    assert_safe_url,
    build_client_from_document,
    fetch_client_document,
    is_cimd_client_id,
    redirect_uri_matches,
    resolve_cimd_client,
)

_CLIENT_URL = "https://93.184.216.34/.well-known/oauth-client"


def _document(**overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "client_id": _CLIENT_URL,
        "redirect_uris": ["http://localhost/callback"],
        "client_name": "Test Client",
    }
    doc.update(overrides)
    return doc


@pytest.mark.parametrize(
    ("client_id", "expected"),
    [
        ("https://claude.ai/.well-known/oauth-client", True),
        ("https://example.com/client", True),
        ("be659aca-1234-5678-9abc-def012345678", False),
        ("http://example.com/client", False),
        ("ftp://example.com/client", False),
        ("not a url", False),
        ("", False),
    ],
)
def test_is_cimd_client_id(client_id: str, expected: bool) -> None:
    assert is_cimd_client_id(client_id) is expected


@pytest.mark.parametrize(
    ("requested", "declared", "expected"),
    [
        ("http://localhost/callback", "http://localhost/callback", True),
        ("http://localhost:54321/callback", "http://localhost/callback", True),
        ("http://localhost:1/callback", "http://localhost:2/callback", True),
        ("http://localhost/other", "http://localhost/callback", False),
        ("https://localhost/callback", "http://localhost/callback", False),
        ("http://example.com/callback", "http://localhost/callback", False),
        # Loopback port is ignored, but host identity (127.0.0.1 vs localhost)
        # still must match exactly -- only the port is loosened.
        ("http://127.0.0.1:1/callback", "http://localhost:2/callback", False),
        ("http://127.0.0.1:1/callback", "http://127.0.0.1:2/callback", True),
    ],
)
def test_redirect_uri_matches(requested: str, declared: str, expected: bool) -> None:
    assert redirect_uri_matches(requested, declared) is expected


class TestAssertSafeUrl:
    async def test_rejects_non_https(self) -> None:
        with pytest.raises(CimdError, match="https"):
            await assert_safe_url("http://example.com/client")

    async def test_rejects_no_host(self) -> None:
        with pytest.raises(CimdError):
            await assert_safe_url("https:///client")

    async def test_rejects_literal_private_ip(self) -> None:
        with pytest.raises(CimdError, match="not a public address"):
            await assert_safe_url("https://10.0.0.5/client")

    async def test_rejects_literal_loopback_ip(self) -> None:
        with pytest.raises(CimdError):
            await assert_safe_url("https://127.0.0.1/client")

    async def test_accepts_literal_public_ip(self) -> None:
        await assert_safe_url("https://93.184.216.34/client")

    async def test_rejects_resolved_private_address(self) -> None:
        def fake_resolver(host: str, port: int, **_: Any) -> list[Any]:
            return [(socket.AF_INET, None, None, "", ("10.1.2.3", port))]

        with pytest.raises(CimdError, match="non-public address"):
            await assert_safe_url(
                "https://internal.example/client", resolver=fake_resolver
            )

    async def test_accepts_resolved_public_address(self) -> None:
        def fake_resolver(host: str, port: int, **_: Any) -> list[Any]:
            return [(socket.AF_INET, None, None, "", ("93.184.216.34", port))]

        await assert_safe_url("https://public.example/client", resolver=fake_resolver)

    async def test_dns_failure_raises_cimd_error(self) -> None:
        def fake_resolver(host: str, port: int, **_: Any) -> list[Any]:
            raise socket.gaierror("nope")

        with pytest.raises(CimdError, match="cannot resolve"):
            await assert_safe_url(
                "https://nowhere.invalid/client", resolver=fake_resolver
            )


class TestBuildClientFromDocument:
    def test_valid_document(self) -> None:
        client = build_client_from_document(_document(), _CLIENT_URL)
        assert client.client_id == _CLIENT_URL
        assert client.redirect_uris == ["http://localhost/callback"]
        assert client.client_name == "Test Client"

    def test_missing_client_name_is_none(self) -> None:
        doc = _document()
        del doc["client_name"]
        client = build_client_from_document(doc, _CLIENT_URL)
        assert client.client_name is None

    def test_non_self_referential_rejected(self) -> None:
        with pytest.raises(CimdError, match="self-referential"):
            build_client_from_document(
                _document(client_id="https://other.example"), _CLIENT_URL
            )

    def test_missing_redirect_uris_rejected(self) -> None:
        doc = _document()
        del doc["redirect_uris"]
        with pytest.raises(CimdError, match="redirect_uris"):
            build_client_from_document(doc, _CLIENT_URL)

    def test_empty_redirect_uris_rejected(self) -> None:
        with pytest.raises(CimdError, match="redirect_uris"):
            build_client_from_document(_document(redirect_uris=[]), _CLIENT_URL)

    def test_non_string_redirect_uris_rejected(self) -> None:
        with pytest.raises(CimdError, match="strings"):
            build_client_from_document(_document(redirect_uris=[123]), _CLIENT_URL)


class TestFetchClientDocument:
    async def test_fetches_and_parses_json(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_document())

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            doc = await fetch_client_document(_CLIENT_URL, client=client)
        assert doc["client_id"] == _CLIENT_URL

    async def test_http_error_raises_cimd_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(CimdError, match="failed to fetch"):
                await fetch_client_document(_CLIENT_URL, client=client)

    async def test_non_json_raises_cimd_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not json")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(CimdError, match="not valid JSON"):
                await fetch_client_document(_CLIENT_URL, client=client)

    async def test_non_object_json_raises_cimd_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[1, 2, 3])

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(CimdError, match="JSON object"):
                await fetch_client_document(_CLIENT_URL, client=client)

    async def test_oversized_document_raises_cimd_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_document(padding="x" * 1000))

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(CimdError, match="too large"):
                await fetch_client_document(_CLIENT_URL, client=client, max_bytes=100)


class TestResolveCimdClient:
    async def test_full_resolution(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == _CLIENT_URL
            return httpx.Response(200, json=_document())

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            resolved = await resolve_cimd_client(_CLIENT_URL, client=client)
        assert resolved.client_id == _CLIENT_URL
        assert resolved.client_name == "Test Client"

    async def test_unsafe_url_never_fetched(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(200, json=_document())

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(CimdError):
                await resolve_cimd_client("https://127.0.0.1/client", client=client)
        assert calls == []

"""Broker-side CIMD (Client ID Metadata Document) client resolution (issue #140).

The broker already *advertises* its own CIMD document at ``/.well-known/cimd``
(api/wellknown.py) so backend OAuth 2.1 authorization servers can identify it
without Dynamic Client Registration. This module is the mirror image: the
broker's own ``/v1/oauth/authorize`` (api/mcp_oauth.py) now acts as an
authorization server for MCP clients, and those clients register the same
way -- ``client_id`` is an ``https://`` URL the broker dereferences at
authorize time, per ``draft-ietf-oauth-client-id-metadata-document``. There
is no ``/register`` endpoint and no per-client database, mirroring
rucio-mcp's in-house reference implementation
(``rucio_mcp/auth/cimd.py``) -- same self-reference check, same SSRF guard,
same port-agnostic loopback redirect_uri matching for native/CLI clients that
bind an ephemeral port at runtime (RFC 8252 §7.3).
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

log = structlog.get_logger(__name__)

# Guards for the server-side fetch of an attacker-influenceable URL.
_MAX_DOC_BYTES = 64 * 1024
_FETCH_TIMEOUT = 10.0

# socket.getaddrinfo-compatible resolver; injectable so SSRF checks are
# testable without real DNS. The result may be a plain list (sync test
# resolver) or an awaitable (the default asyncio loop.getaddrinfo);
# assert_safe_url handles both.
Resolver = Callable[..., Any]

_LOOPBACK_HOSTS = frozenset({"localhost"})


class CimdError(Exception):
    """Raised when an MCP client's CIMD ``client_id`` URL or document is invalid or unsafe."""


@dataclass(frozen=True)
class CimdClient:
    """The subset of a fetched CIMD document ``/v1/oauth/authorize`` needs."""

    client_id: str
    redirect_uris: list[str]
    # None when the document has no client_name -- used as the default PAT
    # name at bootstrap (see api/mcp_oauth.py); "" would look like a
    # deliberately blank name rather than "absent".
    client_name: str | None


def is_cimd_client_id(client_id: str) -> bool:
    """Return True if *client_id* is an ``https://`` URL (CIMD), not a pre-registered id."""
    try:
        parsed = urlparse(client_id)
    except ValueError:
        return False
    return parsed.scheme == "https" and bool(parsed.netloc)


def _is_loopback_host(host: str | None) -> bool:
    if host is None:
        return False
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def redirect_uri_matches(requested: str, declared: str) -> bool:
    """Return True if *requested* matches *declared*, ignoring the port for loopback.

    Exact string equality always matches. For loopback / ``localhost``
    redirect URIs the port is ignored (RFC 8252 §7.3): native/CLI MCP clients
    bind an ephemeral loopback port at runtime, so the document can only ever
    declare a fixed placeholder. Host identity, scheme, and path must still
    match.
    """
    if requested == declared:
        return True
    rp = urlparse(requested)
    dp = urlparse(declared)
    if not (_is_loopback_host(rp.hostname) and _is_loopback_host(dp.hostname)):
        return False
    return rp.scheme == dp.scheme and rp.hostname == dp.hostname and rp.path == dp.path


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def assert_safe_url(
    client_id_url: str, *, resolver: Resolver | None = None
) -> None:
    """Raise :class:`CimdError` unless *client_id_url* is safe to fetch server-side.

    The broker dereferences a URL the client controls, so this is the SSRF
    guard: requires ``https``, and rejects hosts that are -- or resolve to --
    private, loopback, link-local, multicast, reserved, or unspecified
    addresses.

    DNS resolution is offloaded to the event loop's resolver
    (``loop.getaddrinfo``) so a blackholed nameserver cannot stall the event
    loop for the OS resolver timeout. Tests inject a synchronous *resolver*.
    """
    parsed = urlparse(client_id_url)
    if parsed.scheme != "https":
        msg = "CIMD client_id must be an https URL"
        raise CimdError(msg)
    host = parsed.hostname
    if not host:
        msg = "CIMD client_id URL has no host"
        raise CimdError(msg)

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _ip_blocked(literal):
            msg = f"CIMD client_id host {host} is not a public address"
            raise CimdError(msg)
        return

    if resolver is None:
        resolver = asyncio.get_running_loop().getaddrinfo
    try:
        result = resolver(host, parsed.port or 443, type=socket.SOCK_STREAM)
        infos = await result if inspect.isawaitable(result) else result
    except socket.gaierror as exc:
        msg = f"cannot resolve CIMD host {host}: {exc}"
        raise CimdError(msg) from exc
    for info in infos:
        addr = info[4][0]
        if _ip_blocked(ipaddress.ip_address(addr)):
            msg = f"CIMD host {host} resolves to non-public address {addr}"
            raise CimdError(msg)


async def fetch_client_document(
    client_id_url: str,
    *,
    client: httpx.AsyncClient,
    timeout: float = _FETCH_TIMEOUT,
    max_bytes: int = _MAX_DOC_BYTES,
) -> dict[str, Any]:
    """Fetch and JSON-parse the CIMD document at *client_id_url*.

    Redirects are not followed by the shared client (see http.py) -- a
    redirect after the SSRF check below could bypass the resolved-address
    guard, and the self-reference check in ``build_client_from_document``
    assumes the document came from the exact requested URL. Raises
    :class:`CimdError` on any network, size, or parse failure.
    """
    try:
        response = await client.get(
            client_id_url, headers={"Accept": "application/json"}, timeout=timeout
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        msg = f"failed to fetch CIMD document: {exc}"
        raise CimdError(msg) from exc

    if len(response.content) > max_bytes:
        msg = "CIMD document too large"
        raise CimdError(msg)
    try:
        parsed = response.json()
    except ValueError as exc:
        msg = f"CIMD document is not valid JSON: {exc}"
        raise CimdError(msg) from exc
    if not isinstance(parsed, dict):
        msg = "CIMD document is not a JSON object"
        raise CimdError(msg)
    return parsed


def build_client_from_document(doc: dict[str, Any], client_id_url: str) -> CimdClient:
    """Build a :class:`CimdClient` from a fetched CIMD document.

    Verifies the document is self-referential (its ``client_id`` equals the
    URL it was served from) and declares at least one ``redirect_uris``
    entry.
    """
    if doc.get("client_id") != client_id_url:
        msg = "CIMD document is not self-referential (client_id mismatch)"
        raise CimdError(msg)
    declared = doc.get("redirect_uris")
    if not declared or not isinstance(declared, list):
        msg = "CIMD document has no redirect_uris"
        raise CimdError(msg)
    if not all(isinstance(u, str) for u in declared):
        msg = "CIMD document redirect_uris must be strings"
        raise CimdError(msg)

    client_name = doc.get("client_name")
    return CimdClient(
        client_id=client_id_url,
        redirect_uris=list(declared),
        client_name=client_name
        if isinstance(client_name, str) and client_name
        else None,
    )


async def resolve_cimd_client(
    client_id: str,
    *,
    client: httpx.AsyncClient,
    timeout: float = _FETCH_TIMEOUT,
    resolver: Resolver | None = None,
) -> CimdClient:
    """Resolve a CIMD ``client_id`` URL to a :class:`CimdClient`.

    Validates the URL is safe to fetch, dereferences it, and builds a client
    carrying the document's declared ``redirect_uris``/``client_name``.
    Raises :class:`CimdError` on any failure.
    """
    await assert_safe_url(client_id, resolver=resolver)
    doc = await fetch_client_document(client_id, client=client, timeout=timeout)
    resolved = build_client_from_document(doc, client_id)
    log.info("cimd_client_resolved", client_id=client_id)
    return resolved

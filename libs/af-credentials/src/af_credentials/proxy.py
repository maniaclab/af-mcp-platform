"""Client for redeeming a brokered x509/VOMS proxy.

Codes against a redeem contract the broker does not implement yet (issue
#112): ``POST {broker_url}/v1/credentials/x509/redeem``, bearer-authenticated
with an AF Broker Identity Token (see verifier.py), empty JSON body. A 200
response is::

    {
      "pem": "<PEM-encoded proxy certificate + key>",
      "dn": "<VOMS proxy subject DN>",
      "voms_attributes": ["<VOMS FQAN>", ...],
      "expires_at": "<ISO-8601 timestamp>",
      "remaining_seconds": <int>
    }

Mirrors the broker's own credential-brokering shape (x509/VOMS proxies
minted via ephemeral k8s Jobs, docs/auth.md's "Critical auth constraint"
section) without importing anything broker-side: this client only ever
talks HTTP to ``{broker_url}``.
"""

from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import httpx2

if TYPE_CHECKING:
    from types import TracebackType

_REDEEM_PATH = "/v1/credentials/x509/redeem"


class ProxyNotAvailableError(Exception):
    """No usable proxy is available for this caller right now.

    Raised when the broker answers 404 (e.g. the caller has no linked
    ``.globus`` credential to mint a proxy from) or when it did mint one
    but its remaining validity is below the caller's ``min_remaining``
    floor -- in both cases the caller's fix is "try a different credential
    or come back later," not "retry this exact call," which is what
    distinguishes this from ``ProxyRedeemError``.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ProxyRedeemError(Exception):
    """The broker rejected or failed the redeem call for a reason other than "no proxy available" (a non-404, non-200 response)."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"proxy redeem failed with status {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


def _parse_iso8601(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, accepting a trailing Z on Python 3.10.

    ``datetime.fromisoformat`` only learned the ``Z`` suffix in 3.11; the
    broker emits ``+00:00`` offsets today, but a UTC designator from another
    issuer must not break the oldest supported interpreter.
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


@dataclass
class ProxyHandle:
    """A materialized x509/VOMS proxy on disk.

    A context manager: ``__exit__``/``close()`` deletes the underlying
    file. Not cached by ``ProxyClient`` -- every ``proxy_file()`` call
    returns its own handle over its own file (the broker itself caches the
    proxy; this client does not cache handles across calls).
    """

    path: Path
    dn: str
    expires_at: datetime
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        """Delete the underlying file. Safe to call more than once."""
        if not self._closed:
            self.path.unlink(missing_ok=True)
            self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class ProxyClient:
    """Redeems brokered x509/VOMS proxies from an AF MCP broker.

    Materialized proxy files live under a private, 0700 directory created
    lazily on first use (one per ``ProxyClient`` instance, reused across
    calls); each file inside it is written 0600. *min_remaining* rejects a
    freshly-redeemed proxy whose ``remaining_seconds`` is already below a
    useful floor -- a caller who then retried "the credential I just got"
    would just get the same near-expired proxy back (the broker caches it),
    so this is reported as ``ProxyNotAvailableError`` rather than handed to
    the caller as if it were usable.
    """

    def __init__(
        self,
        broker_url: str,
        *,
        timeout: float = 10.0,
        min_remaining: float = 60.0,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        """Construct a client against *broker_url* (e.g. ``https://mcp.af.uchicago.edu``).

        *http_client*, when given, is used for the redeem call instead of a
        short-lived client created per call -- primarily a test seam
        (inject an ``httpx2.AsyncClient`` backed by ``httpx2.MockTransport``)
        but also usable by callers who want connection pooling. The client
        never closes an injected ``http_client``.
        """
        self._broker_url = broker_url.rstrip("/")
        self._timeout = timeout
        self._min_remaining = min_remaining
        self._http_client = http_client
        self._dir: Path | None = None

    async def proxy_file(self, bearer: str) -> ProxyHandle:
        """Redeem a proxy and materialize it as a private 0600 file, returning a handle whose ``close()`` deletes it."""
        data = await self._redeem(bearer)
        directory = self._ensure_dir()
        fd, raw_path = tempfile.mkstemp(dir=directory, prefix="proxy-", suffix=".pem")
        path = Path(raw_path)
        try:
            with os.fdopen(fd, "w") as pem_file:
                pem_file.write(data["pem"])
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            path.unlink(missing_ok=True)
            raise
        return ProxyHandle(
            path=path,
            dn=data["dn"],
            expires_at=_parse_iso8601(data["expires_at"]),
        )

    async def pem_bytes(self, bearer: str) -> bytes:
        """Redeem a proxy and return its PEM material in-memory, without writing a file."""
        data = await self._redeem(bearer)
        pem: str = data["pem"]
        return pem.encode()

    def _ensure_dir(self) -> Path:
        if self._dir is None:
            self._dir = Path(tempfile.mkdtemp(prefix="af-credentials-proxy-"))
            self._dir.chmod(
                stat.S_IRWXU
            )  # 0700 -- belt-and-suspenders over mkdtemp's default
        return self._dir

    async def _redeem(self, bearer: str) -> dict[str, Any]:
        url = f"{self._broker_url}{_REDEEM_PATH}"
        headers = {"Authorization": f"Bearer {bearer}"}
        if self._http_client is not None:
            response = await self._http_client.post(
                url, headers=headers, json={}, timeout=self._timeout
            )
        else:
            async with httpx2.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(url, headers=headers, json={})

        if response.status_code == 404:
            raise ProxyNotAvailableError(self._extract_detail(response))
        if response.status_code != 200:
            raise ProxyRedeemError(response.status_code, self._extract_detail(response))

        data: dict[str, Any] = response.json()
        remaining = data["remaining_seconds"]
        if remaining < self._min_remaining:
            raise ProxyNotAvailableError(
                f"redeemed proxy has only {remaining}s remaining "
                f"(minimum {self._min_remaining}s required)"
            )
        return data

    @staticmethod
    def _extract_detail(response: httpx2.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            return response.text
        if isinstance(body, dict) and "detail" in body:
            detail: str = body["detail"]
            return detail
        return response.text

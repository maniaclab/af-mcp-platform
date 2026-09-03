"""HTTP client for krb5-token-service's ``POST /v1/mint`` (issue #274).

krb5-token-service (maniaclab/krb5-token-service) is a sibling of
voms-token-service and condor-token-service: it receives a CERN username and
password over HTTPS, runs ``kinit`` against CERN's realm, and returns the
resulting credential cache (ccache, base64-encoded) in the response body.
Unlike condor-token-service, there is no standing broker-side secret to
redeem -- the password on the wire IS the entire credential, supplied fresh
on every mint call (see ``credentials/krb5.py``'s module docstring for how
the provider surfaces that as ``NeedsUnlock``).

This client authenticates to it with an AF Broker Identity Token
(``aud=audience`` -- issue #162's internal protocol, the same one
condor-token-service and voms-token-service consume) minted via the
existing ``BrokerTokenIssuer``.

Response bodies are never logged or relayed verbatim to callers (same
discipline as ``voms_service.py``): every error below carries a fixed,
generic message, not the service's own ``detail``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
import structlog

from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from pydantic import SecretStr

    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer

log = structlog.get_logger(__name__)


class Krb5TokenMintError(RuntimeError):
    """Raised for a failure that is NOT the caller's CERN credential (unreachable, timeout, 401, 5xx).

    A broker<->service infra/contract failure, not a client-actionable
    signal -- the message never carries the service's response body.
    """


class Krb5TokenBadCredentialError(ValueError):
    """Raised when the service answered 400: the CERN username/password was wrong."""

    def __init__(self) -> None:
        super().__init__(
            "krb5-token-service rejected the given CERN username/password."
        )


class Krb5TokenAccountError(ValueError):
    """Raised when the service answered 403: the CERN account is revoked or its password has expired."""

    def __init__(self) -> None:
        super().__init__(
            "The CERN account is revoked or its password has expired. "
            "Contact CERN account support."
        )


class Krb5TokenInvalidRequestError(ValueError):
    """Raised when the service answered 422: the username or lifetime value was malformed."""

    def __init__(self) -> None:
        super().__init__("The given CERN username or ticket lifetime was invalid.")


class Krb5TokenRateLimitedError(RuntimeError):
    """Raised when the service answered 429: too many recent failed passwords for this username.

    ``retry_after`` carries the service's ``Retry-After`` header verbatim
    (``None`` if absent) so callers can pass it through, same as
    ``CondorTokenProvider``'s 429 handling.
    """

    def __init__(self, retry_after: str | None) -> None:
        self.retry_after = retry_after
        super().__init__("krb5-token-service rate-limited this request.")


@dataclass(frozen=True)
class MintedTicket:
    """A Kerberos ticket minted by krb5-token-service, with its parsed metadata.

    ``not_after``/``renew_until`` are epoch seconds (UTC), converted from the
    service's ISO-8601 ``expires_at``/``renew_until``. ``renew_until`` stays
    ``None`` when the service reports the ticket isn't renewable.
    """

    ccache_b64: str
    principal: str
    realm: str
    not_after: float
    renew_until: float | None


class Krb5TokenServiceClient:
    """Mints Kerberos tickets at krb5-token-service's ``POST /v1/mint``.

    Composes the same ``BrokerTokenIssuer`` as ``CondorTokenProvider``/
    ``VomsTokenServiceClient``: each mint call carries a fresh short-TTL
    identity assertion with ``aud=audience``. The CERN username/password
    travel in the request body, never the token -- this service derives no
    authorization from token claims (see its README).
    """

    def __init__(
        self,
        *,
        issuer: BrokerTokenIssuer,
        service_url: str,
        audience: str = "krb5-token-service",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._issuer = issuer
        # AnyHttpUrl normalizes a bare origin to a trailing-slash form;
        # strip it so the endpoint join below never produces "//v1/mint"
        # (same guard as condor.py/voms_service.py).
        self._mint_endpoint = f"{service_url.rstrip('/')}/v1/mint"
        self._audience = audience
        self._http_client = http_client
        self._log = structlog.get_logger(__name__).bind(
            component="Krb5TokenServiceClient"
        )

    def _http(self) -> httpx.AsyncClient:
        return self._http_client if self._http_client is not None else get_http_client()

    async def mint(
        self,
        *,
        subject: str,
        username: str,
        password: SecretStr,
        lifetime: str | None = None,
        renewable_lifetime: str | None = None,
    ) -> MintedTicket:
        """Mint a Kerberos ticket for *username*@CERN.CH on behalf of *subject*.

        Raises:
            Krb5TokenBadCredentialError: 400 -- wrong password or unknown principal.
            Krb5TokenAccountError: 403 -- CERN account revoked or password expired.
            Krb5TokenInvalidRequestError: 422 -- malformed username/lifetime.
            Krb5TokenRateLimitedError: 429 -- too many recent failed passwords.
            Krb5TokenMintError: any other failure (unreachable, timeout, 401, 5xx).

        """
        broker_token, _ = self._issuer.mint(subject, self._audience)
        body: dict[str, str] = {
            "username": username,
            # Revealed only here, inside the call expression -- see the
            # module docstring's handling notes (same discipline as
            # voms_service.py's passphrase).
            "password": password.get_secret_value(),
        }
        if lifetime is not None:
            body["lifetime"] = lifetime
        if renewable_lifetime is not None:
            body["renewable_lifetime"] = renewable_lifetime

        try:
            resp = await self._http().post(
                self._mint_endpoint,
                headers={"Authorization": f"Bearer {broker_token}"},
                json=body,
                timeout=30.0,
            )
        except httpx.HTTPError as exc:
            self._log.warning(
                "krb5_token.mint.unreachable", subject=subject, error=str(exc)
            )
            raise Krb5TokenMintError(
                "krb5-token-service could not be reached."
            ) from exc

        if resp.status_code == httpx.codes.BAD_REQUEST:
            raise Krb5TokenBadCredentialError
        if resp.status_code == httpx.codes.FORBIDDEN:
            raise Krb5TokenAccountError
        if resp.status_code == httpx.codes.UNPROCESSABLE_ENTITY:
            raise Krb5TokenInvalidRequestError
        if resp.status_code == httpx.codes.TOO_MANY_REQUESTS:
            raise Krb5TokenRateLimitedError(resp.headers.get("Retry-After"))
        if resp.status_code != httpx.codes.OK:
            # Status code only -- the response body may carry service
            # internals and must reach neither the log nor the caller.
            self._log.warning(
                "krb5_token.mint.failed",
                subject=subject,
                upstream_status=resp.status_code,
            )
            raise Krb5TokenMintError(
                f"krb5-token-service mint failed (status {resp.status_code})."
            )

        data = resp.json()
        # The contract pins expires_at/renew_until to ISO8601 UTC; interpret
        # a naive timestamp as UTC rather than broker-local time (same as
        # condor.py/voms_service.py).
        not_after = _parse_iso_utc(data["expires_at"])
        # Required key (renew_until is null when not renewable, but always
        # present) -- Giordon owns the deploy of both this broker and
        # krb5-token-service, so a missing key is a service bug to surface
        # loudly (KeyError), not skew to tolerate. A present-but-null value
        # stays legitimate (same doctrine as voms_service.py's nickname).
        renew_until_raw = data["renew_until"]
        renew_until = (
            _parse_iso_utc(renew_until_raw) if renew_until_raw is not None else None
        )
        return MintedTicket(
            ccache_b64=data["ccache_b64"],
            principal=data["principal"],
            realm=data["realm"],
            not_after=not_after,
            renew_until=renew_until,
        )


def _parse_iso_utc(value: str) -> float:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()

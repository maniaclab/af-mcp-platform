"""HTTP client for servicex-token-service's ``POST /v1/redeem`` (issue #295).

servicex-token-service (maniaclab/servicex-token-service) exchanges a
caller-supplied ServiceX personal refresh token for a short-lived ServiceX
access token via ``ServiceXAdapter``'s own ``POST {backend}/token/refresh``
call -- it holds no local secret material of its own, and this service's
only genuinely new credential is the refresh token forwarded in the request
body. This client authenticates to it with an AF Broker Identity Token
(``aud=servicex-token-service`` -- issue #162's internal protocol, the same
one condor-token-service/krb5-token-service/voms-token-service consume)
minted via the existing ``BrokerTokenIssuer``.

Two failure classes matter to callers: a 400 from the service means ServiceX
itself rejected the refresh token (``ServiceXBadRefreshTokenError`` -- the
link is stale, so the caller should unlink and prompt a re-paste, the same
distinction ``VomsServiceBadPassphraseError`` draws for a bad Globus
passphrase); while 401/403/429/5xx, timeouts, and connection failures are
infra failures (``ServiceXServiceMintError``) that must NOT unlink the
stored refresh token.

Refresh token handling: the token arrives as a pydantic ``SecretStr`` (out of
repr/logs by construction) and is revealed only at the JSON-body build inside
:meth:`ServiceXTokenServiceClient.redeem`, never bound to a longer-lived
name, never logged, and never echoed into an exception message -- the same
discipline ``voms_service.py`` documents for the Globus passphrase.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
import structlog

from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from pydantic import SecretStr

    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer

log = structlog.get_logger(__name__)


class ServiceXServiceMintError(RuntimeError):
    """Raised when a redeem failed for a reason other than a bad refresh token (service unreachable, timeout, 401/403/429/5xx).

    An infra failure, not a refresh-token signal -- callers must NOT unlink
    the stored refresh token over this. The message never carries the
    service's response body (it may reference ServiceX backend internals).
    """


class ServiceXBadRefreshTokenError(ValueError):
    """Raised when the service answered 400: ServiceX itself rejected the refresh token.

    Subclasses ``ValueError`` for the same reason
    ``VomsServiceBadPassphraseError`` does -- callers unlink the stored
    refresh token on this (and only this), prompting a re-paste.
    """

    def __init__(self) -> None:
        super().__init__(
            "servicex-token-service rejected the refresh token -- it may "
            "have been revoked or expired; re-link required."
        )


@dataclass(frozen=True)
class RedeemedServiceXToken:
    """A ServiceX access token redeemed from servicex-token-service.

    ``expires_at`` is epoch seconds (UTC), computed from the service's
    ``expires_in`` (a relative offset in seconds) at redeem time.
    """

    access_token: str
    expires_at: float


class ServiceXTokenServiceClient:
    """Redeems ServiceX access tokens at servicex-token-service's ``POST /v1/redeem``.

    Composes the same ``BrokerTokenIssuer`` as ``VomsTokenServiceClient``/
    ``CondorTokenProvider``: each redeem call carries a fresh short-TTL
    identity assertion with ``aud=audience``. The refresh token to redeem
    travels in the request body, not the token -- the token's only job is
    proving the call genuinely came from the broker (see the service's
    README).
    """

    def __init__(
        self,
        *,
        issuer: BrokerTokenIssuer,
        service_url: str,
        audience: str = "servicex-token-service",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._issuer = issuer
        # AnyHttpUrl normalizes a bare origin to a trailing-slash form;
        # strip it so the endpoint join below never produces "//v1/redeem"
        # (same guard as condor.py/voms_service.py).
        self._base_url = service_url.rstrip("/")
        self._redeem_endpoint = f"{self._base_url}/v1/redeem"
        self._audience = audience
        self._http_client = http_client
        self._log = structlog.get_logger(__name__).bind(
            component="ServiceXTokenServiceClient"
        )

    def _http(self) -> httpx.AsyncClient:
        return self._http_client if self._http_client is not None else get_http_client()

    async def redeem(
        self, *, subject: str, refresh_token: SecretStr
    ) -> RedeemedServiceXToken:
        """Redeem *refresh_token* for a short-lived ServiceX access token on behalf of *subject*.

        Raises:
            ServiceXBadRefreshTokenError: the service answered 400 -- the
                refresh token was rejected by ServiceX. Callers should
                unlink the stored refresh token and prompt a re-paste.
            ServiceXServiceMintError: any other failure (unreachable,
                timeout, 401/403/429/5xx). Do NOT unlink on this.

        """
        broker_token, _ = self._issuer.mint(subject, self._audience)
        try:
            resp = await self._http().post(
                self._redeem_endpoint,
                headers={"Authorization": f"Bearer {broker_token}"},
                # The refresh token is revealed only here, inside the call
                # expression -- see the module docstring's handling notes.
                json={"refresh_token": refresh_token.get_secret_value()},
                timeout=30.0,
            )
        except httpx.HTTPError as exc:
            self._log.warning(
                "servicex_service.redeem.unreachable", subject=subject, error=str(exc)
            )
            raise ServiceXServiceMintError(
                "servicex-token-service could not be reached."
            ) from exc

        if resp.status_code == httpx.codes.BAD_REQUEST:
            raise ServiceXBadRefreshTokenError
        if resp.status_code != httpx.codes.OK:
            # Status code only -- the response body may carry service
            # internals and must reach neither the log nor the caller.
            self._log.warning(
                "servicex_service.redeem.failed",
                subject=subject,
                upstream_status=resp.status_code,
            )
            raise ServiceXServiceMintError(
                f"servicex-token-service redeem failed (status {resp.status_code})."
            )

        data = resp.json()
        return RedeemedServiceXToken(
            access_token=data["access_token"],
            expires_at=time.time() + float(data["expires_in"]),
        )

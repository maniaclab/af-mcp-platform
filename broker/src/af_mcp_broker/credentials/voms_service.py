"""HTTP client for voms-token-service's ``POST /v1/mint`` (issue #112 follow-up).

voms-token-service (maniaclab/voms-token-service) is the one component in
the platform that mounts user home directories: it receives a user's POSIX
identity (asserted by the broker, which resolved it from the directory) plus
their Globus passphrase, runs ``voms-proxy-init`` against that user's own
``~/.globus`` certificate pair, and returns the proxy PEM in the response
body. This client authenticates to it with an AF Broker Identity Token
(``aud=voms-token-service`` — issue #162's internal protocol, the same one
condor-token-service consumes) minted via the existing ``BrokerTokenIssuer``.

Three failure classes matter to callers: a 400 from the service means the
passphrase was wrong (``VomsServiceBadPassphraseError`` — count it against
the unlock rate limiter, the same distinction the legacy mint path's
``ProxyHarvestError`` draws); a 422 means the request itself was rejected
for a specific, user-actionable, non-passphrase reason — an expired
certificate, bad key file permissions, an out-of-policy ``valid``/``voms``
— none of which the caller can fix by retrying or re-entering their
passphrase (``VomsServiceRejectedError``); while 401/403/5xx, timeouts, and
connection failures are infra failures (``VomsServiceMintError``) that must
NOT consume the user's unlock budget.

Passphrase handling: the passphrase arrives as a pydantic ``SecretStr`` (out
of repr/logs by construction) and is revealed only at the JSON-body build
inside :meth:`VomsTokenServiceClient.mint`, never bound to a longer-lived
name, never logged, and never echoed into an exception message. A JSON wire
format means immutable ``str`` copies exist transiently during
serialization; unlike the k8s-Job path's stdin bytearray there is no buffer
this code owns to zero, so keeping the reveal window minimal is the whole
discipline here (the same trade voms-token-service itself makes receiving
it).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx
import structlog

from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from pydantic import SecretStr

    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer

log = structlog.get_logger(__name__)


class VomsServiceMintError(RuntimeError):
    """Raised when a mint failed for a reason other than a bad passphrase (service unreachable, timeout, 401/403/5xx).

    An infra failure, not a passphrase signal — callers must NOT count it
    against the unlock rate limiter, the same distinction the legacy mint
    path's ``ProxyHarvestError`` draws. The message never carries the
    service's response body (it may reference VOMS hostnames or paths).
    """


class VomsServicePreflightError(RuntimeError):
    """Raised when the credential-readiness checklist could not be fetched (service unreachable, timeout, or any non-200 answer).

    Purely an availability signal — the preflight endpoint never signals a
    bad passphrase (it takes none), so there is no per-status branching to
    do. The message never carries the service's response body (it may
    reference home-directory paths).
    """


class VomsServiceBadPassphraseError(ValueError):
    """Raised when the service answered 400: the Globus key passphrase was wrong.

    Subclasses ``ValueError`` so existing bad-passphrase call sites (the
    legacy mint path raises plain ``ValueError``) keep catching it; callers
    count this — and only this — against the unlock rate limiter.
    """

    def __init__(self) -> None:
        super().__init__(
            "voms-token-service rejected the Globus key passphrase — check "
            "the passphrase and certificate validity."
        )


_REJECTED_FALLBACK_DETAIL = (
    "voms-token-service rejected the request. Check your grid certificate "
    "and the requested voms/valid, then try again."
)


class VomsServiceRejectedError(ValueError):
    """Raised when the service answered 422: the request was rejected for a specific, user-actionable, non-passphrase reason.

    voms-token-service returns 422 for several distinct causes that all
    share the same shape — none is a passphrase problem (must NOT count
    against the unlock rate limiter, unlike ``VomsServiceBadPassphraseError``)
    and none is an infra failure either (retrying cannot help until the
    user or an operator acts, unlike ``VomsServiceMintError``): the user's
    own end-entity certificate (``~/.globus/usercert.pem``) has expired
    (``CertificateExpiredError``, maniaclab/voms-token-service#16 —
    af-mcp-platform#288's original repro), the key file's ownership/mode is
    wrong (``CredentialPermissionsError``), or the caller-supplied
    ``valid``/``voms`` violates the service's mint policy
    (``ValidTooLongError``/``VomsNotAllowedError``,
    maniaclab/voms-token-service#18). This class does not distinguish
    between them — see below.

    Unlike every other failure in this module, the service's own ``detail``
    IS safe to relay to the caller verbatim for every one of these causes:
    each is a fixed or template-built, non-sensitive, user-actionable
    string by design, never voms-proxy-init's raw stderr (which, for the
    expired-certificate case, would include the certificate's exact expiry
    timestamp).
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class MintedProxy:
    """A proxy minted by voms-token-service, with its parsed metadata.

    ``not_after`` is epoch seconds (UTC), converted from the service's
    ISO-8601 ``expires_at``. ``nickname`` is the VOMS ``nickname`` attribute
    (issue #191) — the subject's CERN/Rucio account, which AF unixnames do
    not match. Typed ``str | None`` because a genuinely null nickname (VOMS
    attribute extraction failing for a real user) is a legitimate value —
    but the *key* is always present: Giordon owns the deploy of both the
    broker and voms-token-service, so there is no scenario where an older
    service omits it, and this dataclass carries no default for that reason
    (see ``mint()``, which reads it with ``data["nickname"]``, not ``.get``).
    """

    pem: str
    dn: str
    voms_attributes: list[str]
    not_after: float
    nickname: str | None


class VomsTokenServiceClient:
    """Mints VOMS proxies at voms-token-service's ``POST /v1/mint``.

    Composes the same ``BrokerTokenIssuer`` as ``CondorTokenProvider``: each
    mint call carries a fresh short-TTL identity assertion with
    ``aud=voms-token-service``. Unlike condor-token-service, the POSIX
    identity to mint for travels in the request body, not the token — the
    broker resolved it from the directory, so the token's only job is
    proving the call genuinely came from the broker (see the service's
    README).
    """

    def __init__(
        self,
        *,
        issuer: BrokerTokenIssuer,
        service_url: str,
        audience: str = "voms-token-service",
        voms: str = "atlas",
        valid: str = "192:00",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._issuer = issuer
        # AnyHttpUrl normalizes a bare origin to a trailing-slash form;
        # strip it so the endpoint joins below never produce "//v1/..."
        # (same guard as condor.py).
        self._base_url = service_url.rstrip("/")
        self._mint_endpoint = f"{self._base_url}/v1/mint"
        self._audience = audience
        self._voms = voms
        self._valid = valid
        self._http_client = http_client
        self._log = structlog.get_logger(__name__).bind(
            component="VomsTokenServiceClient"
        )

    def _http(self) -> httpx.AsyncClient:
        return self._http_client if self._http_client is not None else get_http_client()

    async def mint(
        self,
        *,
        subject: str,
        unixname: str,
        uid: int,
        gid: int,
        passphrase: SecretStr,
    ) -> MintedProxy:
        """Mint a VOMS proxy for *(unixname, uid, gid)* on behalf of *subject*.

        Takes plain POSIX fields rather than a ``Principal`` so hands-free
        renewal paths (which hold only the Vault-stored link record, not a
        live principal) can call it too.

        Raises:
            VomsServiceBadPassphraseError: the service answered 400 — the
                passphrase was wrong. Count against the unlock rate limiter.
            VomsServiceRejectedError: the service answered 422 — a
                specific, user-actionable, non-passphrase reason (expired
                certificate, bad key permissions, an out-of-policy
                valid/voms — see the class docstring). Not a passphrase
                problem and not an infra failure; do NOT count against the
                rate limiter.
            VomsServiceMintError: any other failure (unreachable, timeout,
                401/403/5xx). Do NOT count against the rate limiter.

        """
        broker_token, _ = self._issuer.mint(subject, self._audience)
        try:
            resp = await self._http().post(
                self._mint_endpoint,
                headers={"Authorization": f"Bearer {broker_token}"},
                # The passphrase is revealed only here, inside the call
                # expression — see the module docstring's handling notes.
                json={
                    "unixname": unixname,
                    "uid": uid,
                    "gid": gid,
                    "passphrase": passphrase.get_secret_value(),
                    "voms": self._voms,
                    "valid": self._valid,
                },
                timeout=90.0,
            )
        except httpx.HTTPError as exc:
            self._log.warning(
                "voms_service.mint.unreachable", subject=subject, error=str(exc)
            )
            raise VomsServiceMintError(
                "voms-token-service could not be reached."
            ) from exc

        if resp.status_code == httpx.codes.BAD_REQUEST:
            raise VomsServiceBadPassphraseError
        if resp.status_code == httpx.codes.UNPROCESSABLE_ENTITY:
            # Unlike every other non-200 branch here, this body's `detail`
            # is safe to read and relay -- see VomsServiceRejectedError's
            # docstring. A malformed or unexpected body still degrades to a
            # safe fixed string rather than raising here.
            try:
                detail = resp.json().get("detail")
            except ValueError:
                detail = None
            raise VomsServiceRejectedError(
                detail if isinstance(detail, str) else _REJECTED_FALLBACK_DETAIL
            )
        if resp.status_code != httpx.codes.OK:
            # Status code only — the response body may carry service
            # internals and must reach neither the log nor the caller.
            self._log.warning(
                "voms_service.mint.failed",
                subject=subject,
                upstream_status=resp.status_code,
            )
            raise VomsServiceMintError(
                f"voms-token-service mint failed (status {resp.status_code})."
            )

        data = resp.json()
        # The contract pins expires_at to ISO8601 UTC; interpret a naive
        # timestamp as UTC rather than broker-local time (same as condor.py).
        expires_dt = datetime.fromisoformat(data["expires_at"])
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=UTC)
        return MintedProxy(
            pem=data["pem"],
            dn=data["dn"],
            voms_attributes=list(data["voms_attributes"]),
            not_after=expires_dt.timestamp(),
            # Required key (issue #191) — Giordon owns the deploy of both
            # this broker and voms-token-service, so a missing key is a
            # service bug to surface loudly (KeyError), not skew to
            # tolerate. A present-but-null value stays legitimate.
            nickname=data["nickname"],
        )

    async def preflight(self, *, subject: str, unixname: str) -> dict[str, Any]:
        """Fetch *unixname*'s credential-readiness checklist (``GET /v1/preflight/{unixname}``) on behalf of *subject*.

        The body is returned verbatim as parsed JSON — the broker's own
        preflight route passes it straight through to the portal, so this
        client deliberately does not model the checklist shape (the service
        README owns that contract).

        Raises:
            VomsServicePreflightError: the service was unreachable, timed
                out, or answered anything but 200 (the endpoint is always
                200 once authenticated — per-check failures are data in the
                body, not HTTP errors).

        """
        broker_token, _ = self._issuer.mint(subject, self._audience)
        try:
            resp = await self._http().get(
                f"{self._base_url}/v1/preflight/{unixname}",
                headers={"Authorization": f"Bearer {broker_token}"},
                timeout=15.0,
            )
        except httpx.HTTPError as exc:
            self._log.warning(
                "voms_service.preflight.unreachable", subject=subject, error=str(exc)
            )
            raise VomsServicePreflightError(
                "voms-token-service could not be reached."
            ) from exc

        if resp.status_code != httpx.codes.OK:
            # Status code only — the response body may carry service
            # internals (home-directory paths) and must reach neither the
            # log nor the caller.
            self._log.warning(
                "voms_service.preflight.failed",
                subject=subject,
                upstream_status=resp.status_code,
            )
            raise VomsServicePreflightError(
                f"voms-token-service preflight failed (status {resp.status_code})."
            )
        result: dict[str, Any] = resp.json()
        return result

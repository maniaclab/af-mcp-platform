from __future__ import annotations

from typing import TYPE_CHECKING

from af_mcp_broker.errors import BrokerError

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings


class NeedsUnlockError(BrokerError):
    """Raised when a credential requires user interaction (e.g. passphrase entry) before it can be issued.

    The caller should surface `unlock_endpoint` to the user so they know where to POST the passphrase.
    """

    def __init__(
        self,
        target: str,
        reason: str,
        unlock_endpoint: str = "/v1/x509/proxy",
    ) -> None:
        self.target = target
        self.reason = reason
        self.unlock_endpoint = unlock_endpoint
        super().__init__(
            f"Credential for {target!r} needs unlock ({reason}); "
            f"POST passphrase to {unlock_endpoint}"
        )


class UnlockRateLimitError(BrokerError):
    """Raised when a principal exceeds the allowed number of failed cache lookups.

    *retry_after_seconds* is how long until the current fixed window closes
    and the uid is allowed to try again — ``max(0, window_start +
    unlock_window_seconds - now)``. The API layer's exception handler formats
    this into a ``Retry-After`` header and JSON body (see ``app.py``).
    """

    def __init__(self, message: str, *, retry_after_seconds: int) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class VersionConflictError(BrokerError):
    """Raised by ``TokenStore.write_cas`` when ``expected_version`` is stale."""


class Krb5TokenMintError(BrokerError):
    """Raised for a failure that is NOT the caller's CERN credential (unreachable, timeout, 401, 5xx).

    A broker<->service infra/contract failure, not a client-actionable
    signal -- the message never carries the service's response body.
    """


class Krb5TokenBadCredentialError(BrokerError):
    """Raised when the service answered 400: the CERN username/password was wrong."""

    def __init__(self) -> None:
        super().__init__(
            "krb5-token-service rejected the given CERN username/password."
        )


class Krb5TokenAccountError(BrokerError):
    """Raised when the service answered 403: the CERN account is revoked or its password has expired."""

    def __init__(self) -> None:
        super().__init__(
            "The CERN account is revoked or its password has expired. "
            "Contact CERN account support."
        )


class Krb5TokenInvalidRequestError(BrokerError):
    """Raised when the service answered 422: the username or lifetime value was malformed."""

    def __init__(self) -> None:
        super().__init__("The given CERN username or ticket lifetime was invalid.")


class Krb5TokenRateLimitedError(BrokerError):
    """Raised when the service answered 429: too many recent failed passwords for this username.

    ``retry_after`` carries the service's ``Retry-After`` header verbatim
    (``None`` if absent) so callers can pass it through, same as
    ``CondorTokenProvider``'s 429 handling.
    """

    def __init__(self, retry_after: str | None) -> None:
        self.retry_after = retry_after
        super().__init__("krb5-token-service rate-limited this request.")


class Krb5TokenInvalidCcacheError(BrokerError):
    """Raised when ``renew()`` answered 422: the stored ccache was malformed.

    This is built from OUR OWN stored value, not user input -- unlike
    ``Krb5TokenInvalidRequestError`` (a 422 callers may treat as
    user-actionable), this signals internal corruption of the stored
    ccache.
    """

    def __init__(self) -> None:
        super().__init__("The stored Kerberos credential cache was invalid.")


class Krb5TokenRenewalWindowClosedError(BrokerError):
    """Raised when ``renew()`` answered 400: the ccache is past its renewable window.

    An EXPECTED, recoverable condition -- callers catch this and fall
    through to a fresh keytab/password mint, never surface it as an error.
    """

    def __init__(self) -> None:
        super().__init__("The Kerberos credential cache is past its renewable window.")


class ServiceXServiceMintError(BrokerError):
    """Raised when a redeem failed for a reason other than a bad refresh token (service unreachable, timeout, 401/403/429/5xx).

    An infra failure, not a refresh-token signal -- callers must NOT unlink
    the stored refresh token over this. The message never carries the
    service's response body (it may reference ServiceX backend internals).
    """


class ServiceXBadRefreshTokenError(BrokerError):
    """Raised when the service answered 400: ServiceX itself rejected the refresh token.

    Callers unlink the stored refresh token on this (and only this),
    prompting a re-paste -- the same distinction
    ``VomsServiceBadPassphraseError`` draws for a bad Globus passphrase.
    """

    def __init__(self) -> None:
        super().__init__(
            "ServiceX rejected this token. Generate a new token from your "
            "ServiceX profile page and re-link."
        )


class VomsServiceMintError(BrokerError):
    """Raised when a mint failed for a reason other than a bad passphrase (service unreachable, timeout, 401/403/5xx).

    An infra failure, not a passphrase signal — callers must NOT count it
    against the unlock rate limiter, the same distinction the legacy mint
    path's ``ProxyHarvestError`` draws. The message never carries the
    service's response body (it may reference VOMS hostnames or paths).
    """


class VomsServicePreflightError(BrokerError):
    """Raised when the credential-readiness checklist could not be fetched (service unreachable, timeout, or any non-200 answer).

    Purely an availability signal — the preflight endpoint never signals a
    bad passphrase (it takes none), so there is no per-status branching to
    do. The message never carries the service's response body (it may
    reference home-directory paths).
    """


class VomsServiceBadPassphraseError(BrokerError):
    """Raised when the service answered 400: the Globus key passphrase was wrong.

    Callers count this — and only this — against the unlock rate limiter.
    """

    def __init__(self) -> None:
        super().__init__(
            "voms-token-service rejected the Globus key passphrase — check "
            "the passphrase and certificate validity."
        )


class VomsServiceRejectedError(BrokerError):
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


class PosixIdentityRequiredError(BrokerError):
    """Raised when x509 proxy minting is attempted for a principal with no POSIX identity.

    Issue #148 made ``Principal.uid``/``gid``/``unixname`` optional -- almost
    nothing in the broker needs them, but x509 genuinely does (the mint
    Job's NFS home subPath and ``runAsUser``/``runAsGroup`` all require real
    values). Rather than reject such a principal at the door for every
    backend (the old JWT-level behavior this issue removes), the requirement
    moves to this point of use, naming *target* so the resulting error is
    actionable: "this service needs a grid identity your account doesn't
    have" rather than an opaque failure.
    """

    def __init__(self, target: str, *, settings: Settings) -> None:
        self.target = target
        super().__init__(
            f"Service {target!r} requires an x509/VOMS proxy, which needs a "
            "POSIX (grid) identity your account does not have. The broker "
            "looked for the Keycloak profile attributes "
            f"{settings.posix_uid_attribute!r}/{settings.posix_gid_attribute!r}/"
            f"{settings.posix_unixname_attribute!r} and found none of them "
            "set. Contact your Analysis Facility operator to request a grid "
            "identity."
        )


class ProxyHarvestError(BrokerError):
    """Raised when a mint Job SUCCEEDED but its proxy could not be harvested from the pod log (truncated log, kubelet log-size limits, transient read issue).

    This is an infra failure, not a bad-passphrase signal, so callers
    must NOT count it against the passphrase rate limiter the way a genuine
    Job failure is. ``_mint_kubernetes`` catches it separately from the
    ``ValueError`` a failed Job raises.
    """

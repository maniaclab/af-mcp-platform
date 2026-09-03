# KrbTokenProvider Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `krb5-token` identity-provider type so `af-mcp-platform` can exchange a caller-supplied CERN username/password for a Kerberos ccache at the already-deployed krb5-token-service, closing [maniaclab/af-mcp-platform#274](https://github.com/maniaclab/af-mcp-platform/issues/274).

**Architecture:** krb5-token-service needs a live CERN username+password on every `POST /v1/mint` call — unlike `condor-token` (broker-authoritative, no external secret) it has no standing linkage to redeem. Architecturally it is closer to `X509Provider`/`VomsTokenServiceClient` (issue #112): a thin HTTP client (`Krb5TokenServiceClient`, mirrors `VomsTokenServiceClient`) that mints an AF Broker Identity Token and POSTs the caller's secret, plus a `CredentialProvider` (`KrbTokenProvider`) that owns caching and raises `NeedsUnlock` until a **new** `POST /v1/krb5/ticket` endpoint (mirrors `POST /v1/x509/proxy`) supplies fresh username+password. Nothing is persisted at rest — no Vault, no "remember" — every ticket is minted per-call and cached only until it expires, since (per krb5-token-service's own README) the CERN password is a live, non-recoverable secret, not a passphrase that merely unlocks an already-stored credential.

**Explicitly out of scope** (per the issue and this session's discussion with Giordon):
- Choosing the downstream `aggregator.services` consumer / wiring aggregator delivery of the minted ccache to a backend service. `targets: []` ships empty; the new `CredentialKind.KRB5_CCACHE` is defined but no aggregator forwarding branch is added for it yet.
- Portal (Vue) UI for the new two-field (username+password) unlock form. Precedent: `condor-token` itself isn't even in `portal/src/lib/api.ts`'s `ProviderType` union today, so a backend-only landing is consistent with how prior native providers shipped.
- Broker-side brute-force rate limiting on the new endpoint (`CredentialCache.check_unlock_rate_limit`/`record_failed_unlock`, uid-keyed). krb5-token-service already rate-limits per-username server-side (`FAILED_AUTH_MAX_ATTEMPTS`); the uid-keyed limiter also requires POSIX identity, which krb5 callers aren't guaranteed to have. `POST /v1/krb5/ticket` passes through the service's own 429 (with `Retry-After`), matching `condor-token`'s existing doctrine.

**Tech Stack:** FastAPI, pydantic v2, httpx, structlog, pytest + pytest-asyncio (existing broker stack — no new dependencies).

---

## Reference material already gathered this session

- Issue #274 body (config.py has exactly 5 provider types today: `keycloak-brokered`, `oauth21-direct`, `broker-issued`, `condor-token`, `x509`; wants a `KrbTokenProviderConfig`/`KrbTokenProvider` pair).
- krb5-token-service README (`gh api repos/maniaclab/krb5-token-service/readme`): `POST /v1/mint`, `Authorization: Bearer <AF Broker Identity Token>`, body `{"username": str, "password": str, "lifetime": str?, "renewable_lifetime": str?}`, response `{"ccache_b64", "principal", "realm", "expires_at", "renew_until"}` (`renew_until` null when not renewable). Errors: 400 `{"detail": "bad password"}` / `{"detail": "unknown principal"}`; 403 revoked/expired account; 422 invalid `username`/`lifetime`; 429 after too many recent failed passwords (rate-limited per username); 401 invalid/missing broker token; 502 other minting failure. Response bodies are never to be logged or relayed verbatim (matches this repo's existing doctrine for voms-token-service/condor-token-service).
- `broker/src/af_mcp_broker/credentials/voms_service.py` — the client-layer template (`VomsTokenServiceClient`, `MintedProxy`, `VomsServiceBadPassphraseError`/`VomsServiceMintError`).
- `broker/src/af_mcp_broker/credentials/x509.py` / `broker/src/af_mcp_broker/api/credentials.py`'s `create_proxy` — the provider + endpoint template for a per-call-secret native provider (`NeedsUnlock`, `ProxyRequest`/`ProxyMetadata`, `_resolve_x509_target`/`_x509_provider`).
- `broker/src/af_mcp_broker/credentials/condor.py` — caching/single-flight (`get_or_mint`) and metrics-counter conventions for a native DELEGATED provider.
- `broker/src/af_mcp_broker/app.py` — provider-registration switch (~line 514+), the broker-signing-key fail-closed check (~line 438-451), `x509_targets` app-state wiring (~line 322, 338, 838).
- `broker/src/af_mcp_broker/api/identities.py` — `ProviderType`/`LinkMechanism` literals and `_LINK_MECHANISM_BY_TYPE`.

---

### Task 1: `CredentialKind.KRB5_CCACHE`

**Files:**
- Modify: `broker/src/af_mcp_broker/credentials/base.py`
- Test: `broker/tests/test_config.py` (no new test needed here — this is a one-line enum addition exercised by Task 3's tests)

**Step 1: Add the enum member**

In `CredentialKind` (base.py), add a member alongside `X509_PROXY_REF`/`X509_PROXY_REDEEM`:

```python
class CredentialKind(StrEnum):
    BEARER = "bearer"
    X509_PROXY_REF = "x509_proxy_ref"
    X509_PROXY_REDEEM = "x509_proxy_redeem"
    # A Kerberos credential cache (ccache), base64-encoded in the payload.
    # No aggregator delivery branch exists yet -- issue #274 covers only the
    # provider-type plumbing; the downstream aggregator.services consumer is
    # a separate, not-yet-made decision (see the provider-type's own docs).
    KRB5_CCACHE = "krb5_ccache"
    NONE = "none"
```

Update the `IssuedCredential.payload` comment a few lines up to document the new shape:

```python
    # bearer: {"access_token": ..., "token_type": "Bearer"}
    # x509 (proxy_ref):    {"proxy_handle": ..., "proxy_path": ..., "delivery": "direct"}
    # x509 (proxy_redeem): {"proxy_handle": ..., "delivery": "redeem"}
    # service:{"access_token": ..., "on_behalf_of": ..., "token_type": "Bearer"}
    # krb5_ccache: {"ccache_b64": ..., "principal": ..., "realm": ..., "renew_until": float | None}
    payload: dict
```

**Step 2: Commit**

```bash
git add broker/src/af_mcp_broker/credentials/base.py
git commit -m "feat(broker): add CredentialKind.KRB5_CCACHE"
```

---

### Task 2: `Krb5TokenServiceClient` (HTTP client)

**Files:**
- Create: `broker/src/af_mcp_broker/credentials/krb5_service.py`
- Test: Create `broker/tests/test_krb5_service_client.py`

Mirror `voms_service.py` exactly in structure. Use a fake `httpx.AsyncClient` the way `test_condor_token.py`'s `_FakeHTTPClient` / existing voms client tests do (check `test_x509_service_mode.py` for the fake-client pattern already used against `VomsTokenServiceClient` and copy its shape).

**Step 1: Write the failing tests**

```python
"""Unit tests for Krb5TokenServiceClient against a stubbed HTTP transport."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from af_mcp_broker.credentials.krb5_service import (
    Krb5TokenAccountError,
    Krb5TokenBadCredentialError,
    Krb5TokenInvalidRequestError,
    Krb5TokenMintError,
    Krb5TokenRateLimitedError,
    Krb5TokenServiceClient,
)

SERVICE_URL = "http://krb5-token-service.test"


class _FakeResponse:
    def __init__(self, status_code, json_body=None, headers=None):
        self.status_code = status_code
        self._json = json_body or {}
        self.headers = headers or {}

    def json(self):
        return self._json


class _FakeHTTPClient:
    def __init__(self, response):
        self._response = response
        self.last_request = None

    async def post(self, url, *, headers, json, timeout):
        self.last_request = {"url": url, "headers": headers, "json": json, "timeout": timeout}
        return self._response


class _FakeIssuer:
    def mint(self, subject, audience, **kwargs):
        return f"fake-broker-token-for-{subject}-{audience}", 9999999999


@pytest.mark.asyncio
async def test_mint_success_parses_response():
    resp = _FakeResponse(
        200,
        {
            "ccache_b64": "ZmFrZQ==",
            "principal": "alice@CERN.CH",
            "realm": "CERN.CH",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "renew_until": "2099-01-08T00:00:00+00:00",
        },
    )
    client = Krb5TokenServiceClient(
        issuer=_FakeIssuer(), service_url=SERVICE_URL, http_client=_FakeHTTPClient(resp)
    )
    ticket = await client.mint(subject="user1", username="alice", password=SecretStr("hunter2"))
    assert ticket.ccache_b64 == "ZmFrZQ=="
    assert ticket.principal == "alice@CERN.CH"
    assert ticket.realm == "CERN.CH"
    assert ticket.renew_until is not None


@pytest.mark.asyncio
async def test_mint_renew_until_null_stays_none():
    resp = _FakeResponse(
        200,
        {
            "ccache_b64": "ZmFrZQ==",
            "principal": "alice@CERN.CH",
            "realm": "CERN.CH",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "renew_until": None,
        },
    )
    client = Krb5TokenServiceClient(
        issuer=_FakeIssuer(), service_url=SERVICE_URL, http_client=_FakeHTTPClient(resp)
    )
    ticket = await client.mint(subject="user1", username="alice", password=SecretStr("hunter2"))
    assert ticket.renew_until is None


@pytest.mark.asyncio
async def test_mint_400_raises_bad_credential_error():
    client = Krb5TokenServiceClient(
        issuer=_FakeIssuer(),
        service_url=SERVICE_URL,
        http_client=_FakeHTTPClient(_FakeResponse(400, {"detail": "bad password"})),
    )
    with pytest.raises(Krb5TokenBadCredentialError):
        await client.mint(subject="user1", username="alice", password=SecretStr("wrong"))


@pytest.mark.asyncio
async def test_mint_403_raises_account_error():
    client = Krb5TokenServiceClient(
        issuer=_FakeIssuer(),
        service_url=SERVICE_URL,
        http_client=_FakeHTTPClient(_FakeResponse(403, {"detail": "account revoked"})),
    )
    with pytest.raises(Krb5TokenAccountError):
        await client.mint(subject="user1", username="alice", password=SecretStr("hunter2"))


@pytest.mark.asyncio
async def test_mint_422_raises_invalid_request_error():
    client = Krb5TokenServiceClient(
        issuer=_FakeIssuer(),
        service_url=SERVICE_URL,
        http_client=_FakeHTTPClient(_FakeResponse(422, {"detail": "invalid lifetime"})),
    )
    with pytest.raises(Krb5TokenInvalidRequestError):
        await client.mint(subject="user1", username="alice", password=SecretStr("hunter2"))


@pytest.mark.asyncio
async def test_mint_429_raises_rate_limited_error_with_retry_after():
    client = Krb5TokenServiceClient(
        issuer=_FakeIssuer(),
        service_url=SERVICE_URL,
        http_client=_FakeHTTPClient(_FakeResponse(429, headers={"Retry-After": "30"})),
    )
    with pytest.raises(Krb5TokenRateLimitedError) as exc_info:
        await client.mint(subject="user1", username="alice", password=SecretStr("hunter2"))
    assert exc_info.value.retry_after == "30"


@pytest.mark.asyncio
async def test_mint_401_raises_generic_mint_error():
    """401 means the BROKER's own identity token was rejected -- a broker<->service
    contract failure the end user cannot act on, so it must NOT read as a bad
    CERN password (unlike condor-token's doctrine, krb5 has genuine
    client-actionable 400/403 cases, so 401 must stay clearly distinct)."""
    client = Krb5TokenServiceClient(
        issuer=_FakeIssuer(),
        service_url=SERVICE_URL,
        http_client=_FakeHTTPClient(_FakeResponse(401)),
    )
    with pytest.raises(Krb5TokenMintError):
        await client.mint(subject="user1", username="alice", password=SecretStr("hunter2"))


@pytest.mark.asyncio
async def test_mint_502_raises_generic_mint_error():
    client = Krb5TokenServiceClient(
        issuer=_FakeIssuer(),
        service_url=SERVICE_URL,
        http_client=_FakeHTTPClient(_FakeResponse(502)),
    )
    with pytest.raises(Krb5TokenMintError):
        await client.mint(subject="user1", username="alice", password=SecretStr("hunter2"))


@pytest.mark.asyncio
async def test_mint_sends_broker_token_and_credentials_in_body():
    resp = _FakeResponse(
        200,
        {
            "ccache_b64": "ZmFrZQ==",
            "principal": "alice@CERN.CH",
            "realm": "CERN.CH",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "renew_until": None,
        },
    )
    fake_client = _FakeHTTPClient(resp)
    client = Krb5TokenServiceClient(
        issuer=_FakeIssuer(), service_url=SERVICE_URL, http_client=fake_client
    )
    await client.mint(
        subject="user1",
        username="alice",
        password=SecretStr("hunter2"),
        lifetime="8:00",
        renewable_lifetime="7d",
    )
    assert fake_client.last_request["url"] == f"{SERVICE_URL}/v1/mint"
    assert fake_client.last_request["headers"]["Authorization"].startswith("Bearer ")
    body = fake_client.last_request["json"]
    assert body["username"] == "alice"
    assert body["password"] == "hunter2"
    assert body["lifetime"] == "8:00"
    assert body["renewable_lifetime"] == "7d"
```

**Step 2: Run to verify failure**

Run: `pixi run -e dev pytest broker/tests/test_krb5_service_client.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'af_mcp_broker.credentials.krb5_service'`)

**Step 3: Write the implementation**

```python
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
        renew_until = (
            _parse_iso_utc(data["renew_until"])
            if data.get("renew_until") is not None
            else None
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
```

**Step 4: Run to verify pass**

Run: `pixi run -e dev pytest broker/tests/test_krb5_service_client.py -v`
Expected: PASS (all 9 tests)

**Step 5: Lint and commit**

```bash
pixi run lint
git add broker/src/af_mcp_broker/credentials/krb5_service.py broker/tests/test_krb5_service_client.py
git commit -m "feat(broker): add Krb5TokenServiceClient for krb5-token-service /v1/mint"
```

---

### Task 3: `KrbTokenProviderConfig`

**Files:**
- Modify: `broker/src/af_mcp_broker/config.py`
- Test: `broker/tests/test_config.py`

**Step 1: Write the failing test**

Find the existing `condor-token` config test block (search `test_config.py` for `"type": "condor-token"`, around line 411-419) and add a sibling block immediately after it, following the exact same shape:

```python
# krb5-token identity providers (issue #274) -- KrbTokenProvider's config.
def test_krb5_token_provider_config_parses():
    settings = Settings(
        identity_providers=[
            {
                "type": "krb5-token",
                "alias": "krb5",
                "display_name": "CERN Kerberos ticket",
                "enables": "Kerberos-authenticated access",
                "targets": ["some-service"],
                "service_url": "http://krb5-token-service.invalid",
            }
        ]
    )
    (cfg,) = settings.identity_providers
    assert cfg.type == "krb5-token"
    assert cfg.alias == "krb5"
    assert cfg.targets == ["some-service"]
    assert str(cfg.service_url) == "http://krb5-token-service.invalid/"
    assert cfg.audience == "krb5-token-service"  # default


def test_krb5_token_provider_config_requires_service_url():
    with pytest.raises(ValidationError):
        Settings(
            identity_providers=[
                {"type": "krb5-token", "alias": "krb5", "targets": ["some-service"]}
            ]
        )
```

Check the top of `test_config.py` for how `Settings`/`ValidationError`/`pytest` are already imported and match that (don't add duplicate imports).

**Step 2: Run to verify failure**

Run: `pixi run -e dev pytest broker/tests/test_config.py -k krb5_token -v`
Expected: FAIL (`pydantic_core._pydantic_core.ValidationError` — unknown discriminator value `'krb5-token'`, or `ImportError` if `KrbTokenProviderConfig` doesn't exist yet)

**Step 3: Write the implementation**

In `config.py`, add immediately after `CondorTokenProviderConfig` (before `X509ProviderConfig`, around line 118-120):

```python
class KrbTokenProviderConfig(BaseModel):
    """An AF-native credential source for CERN Kerberos tickets (``KrbTokenProvider``, issue #274): the broker mints an AF Broker Identity Token with ``aud=audience`` and exchanges it, together with a caller-supplied CERN username/password, at krb5-token-service's ``POST /v1/mint`` — see docs/auth.md's "KrbTokenProvider" section.

    Unlike ``CondorTokenProviderConfig``, the broker holds no standing
    secret for this exchange: the CERN password is a live, non-recoverable
    secret supplied per-call via ``POST /v1/krb5/ticket`` (mirroring x509's
    passphrase-unlock flow) and is never persisted.

    ``service_url`` is the base URL of the krb5-token-service deployment
    (no path — the provider appends ``/v1/mint``). ``audience`` is the
    exact ``aud`` claim the service verifies; the default matches the
    service's own default and should only change if a deployment renames
    itself.
    """

    type: Literal["krb5-token"] = "krb5-token"
    alias: str
    targets: list[str] = Field(default_factory=list)
    service_url: AnyHttpUrl
    audience: str = "krb5-token-service"

    # Portal-facing metadata for GET /v1/identities. Optional so a minimal
    # provider config still parses; an operator who leaves these blank just
    # gets an empty label/description on the Identities page until they fill
    # them in.
    display_name: str = ""
    enables: str = ""
```

Add it to the `IdentityProviderConfig` discriminated union:

```python
IdentityProviderConfig = Annotated[
    KeycloakBrokeredProviderConfig
    | OAuth21DirectProviderConfig
    | BrokerIssuedProviderConfig
    | CondorTokenProviderConfig
    | KrbTokenProviderConfig
    | X509ProviderConfig,
    Field(discriminator="type"),
]
```

**Step 4: Run to verify pass**

Run: `pixi run -e dev pytest broker/tests/test_config.py -k krb5_token -v`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/config.py broker/tests/test_config.py
git commit -m "feat(broker): add KrbTokenProviderConfig"
```

---

### Task 4: `KrbTokenProvider`

**Files:**
- Create: `broker/src/af_mcp_broker/credentials/krb5.py`
- Test: Create `broker/tests/test_krb5_token.py`

Mirror `test_condor_token.py`'s structure (a `provider_factory` fixture), but the mint mechanics are stubbed at the `Krb5TokenServiceClient` level (already unit-tested in Task 2) via `monkeypatch` or a fake client, not raw httpx — check whether `test_condor_token.py` patches `get_http_client` directly or the provider takes an injectable client; since `KrbTokenProvider` takes a `Krb5TokenServiceClient` instance (not a raw URL), just construct it with a fake client double directly (simpler than `test_condor_token.py`'s httpx-level fake, since that plumbing already lives in Task 2's tests).

**Step 1: Write the failing tests**

```python
"""Unit tests for KrbTokenProvider (issue #274).

Covers caching, is_linked() reflecting live cache state (no persisted
linkage exists otherwise), and NeedsUnlock when no fresh username/password
is supplied. The krb5-token-service HTTP exchange itself is covered by
test_krb5_service_client.py -- here the client is a fake double.
"""

from __future__ import annotations

import time

import pytest
from pydantic import SecretBytes

from af_mcp_broker.credentials.base import CredentialKind, NeedsUnlock
from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.credentials.krb5 import KrbTokenProvider
from af_mcp_broker.credentials.krb5_service import MintedTicket
from af_mcp_broker.identity import Principal


def make_principal(subject: str = "user1") -> Principal:
    return Principal(
        subject=subject,
        email="user1@example.org",
        groups=[],
        unixname=None,
        uid=None,
        gid=None,
    )


class _FakeClient:
    def __init__(self, ticket: MintedTicket | None = None, error: Exception | None = None):
        self._ticket = ticket
        self._error = error
        self.calls: list[dict] = []

    async def mint(self, *, subject, username, password, lifetime=None, renewable_lifetime=None):
        self.calls.append(
            {
                "subject": subject,
                "username": username,
                "password": password.get_secret_value(),
                "lifetime": lifetime,
                "renewable_lifetime": renewable_lifetime,
            }
        )
        if self._error is not None:
            raise self._error
        assert self._ticket is not None
        return self._ticket


def provider_factory(client, targets=("krb5-target",)):
    cache = CredentialCache()
    provider = KrbTokenProvider(
        client=client, cache=cache, alias="krb5", targets=frozenset(targets)
    )
    return provider, cache


def _ticket(not_after=None) -> MintedTicket:
    return MintedTicket(
        ccache_b64="ZmFrZQ==",
        principal="alice@CERN.CH",
        realm="CERN.CH",
        not_after=not_after if not_after is not None else time.time() + 3600,
        renew_until=None,
    )


@pytest.mark.asyncio
async def test_issue_without_credentials_raises_needs_unlock():
    provider, _ = provider_factory(_FakeClient())
    with pytest.raises(NeedsUnlock) as exc_info:
        await provider.issue(make_principal(), "krb5-target")
    assert exc_info.value.unlock_endpoint == "/v1/krb5/ticket"


@pytest.mark.asyncio
async def test_issue_with_credentials_mints_and_caches():
    client = _FakeClient(ticket=_ticket())
    provider, cache = provider_factory(client)
    principal = make_principal()
    cred = await provider.issue(
        principal,
        "krb5-target",
        passphrase=SecretBytes(b"hunter2"),
        username="alice",
    )
    assert cred.cred_class == "krb5_ticket"
    assert cred.kind == CredentialKind.KRB5_CCACHE
    assert cred.payload["ccache_b64"] == "ZmFrZQ=="
    assert cred.payload["principal"] == "alice@CERN.CH"
    assert client.calls[0]["username"] == "alice"
    assert client.calls[0]["password"] == "hunter2"

    cached = await cache.get(principal.subject, "krb5-target", min_remaining=0)
    assert cached is not None


@pytest.mark.asyncio
async def test_issue_returns_cached_credential_without_recontacting_service():
    client = _FakeClient(ticket=_ticket())
    provider, _ = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )
    # Second call within validity, no credentials supplied -- must hit cache.
    cred = await provider.issue(principal, "krb5-target")
    assert cred.payload["ccache_b64"] == "ZmFrZQ=="
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_is_linked_false_with_no_cached_ticket():
    provider, _ = provider_factory(_FakeClient())
    assert await provider.is_linked(make_principal()) is False


@pytest.mark.asyncio
async def test_is_linked_true_after_mint():
    client = _FakeClient(ticket=_ticket())
    provider, _ = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )
    assert await provider.is_linked(principal) is True


@pytest.mark.asyncio
async def test_revoke_drops_cached_ticket():
    client = _FakeClient(ticket=_ticket())
    provider, cache = provider_factory(client)
    principal = make_principal()
    await provider.issue(
        principal, "krb5-target", passphrase=SecretBytes(b"hunter2"), username="alice"
    )
    await provider.revoke(principal, "krb5-target")
    assert await cache.get(principal.subject, "krb5-target", min_remaining=0) is None
```

Check `Principal`'s exact constructor kwargs (`broker/src/af_mcp_broker/identity.py`) and `CredentialCache()`'s constructor before finalizing — copy the exact pattern `test_condor_token.py` already uses for both rather than guessing field names.

**Step 2: Run to verify failure**

Run: `pixi run -e dev pytest broker/tests/test_krb5_token.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'af_mcp_broker.credentials.krb5'`)

**Step 3: Write the implementation**

```python
"""Kerberos tickets via krb5-token-service (issue #274).

Unlike ``CondorTokenProvider`` (broker-authoritative, no external secret),
krb5-token-service needs a live CERN username+password on every mint --
there is no standing linkage the broker can redeem on its own. This
provider therefore raises ``NeedsUnlock`` (pointing at ``POST
/v1/krb5/ticket``, the credentials API's new endpoint) whenever no fresh
username/password was supplied and nothing valid is cached, mirroring
``X509Provider``'s passphrase-unlock doctrine rather than
``CondorTokenProvider``'s unconditional ``is_linked() -> True``.

Nothing is persisted at rest: no Vault record, no "remember" option. The
CERN password is a live, non-recoverable secret (not a passphrase that
merely unlocks an already-stored credential the way x509's Globus
passphrase does), so ``is_linked()`` reports whether a still-valid ticket
happens to be cached for one of this entry's targets -- not a durable
linkage state.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

import structlog
from pydantic import SecretStr

from af_mcp_broker import metrics
from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
    NeedsUnlock,
    _new_audit_id,
)

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.credentials.cache import CredentialCache
    from af_mcp_broker.credentials.krb5_service import Krb5TokenServiceClient
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)


class KrbTokenProvider(CredentialProvider):
    """Issues per-user Kerberos tickets by exchanging a caller-supplied CERN username/password at krb5-token-service.

    ``is_linked()`` reflects live cache state (True iff any of this entry's
    targets has an unexpired cached ticket) rather than a durable linkage --
    see the module docstring.
    """

    cred_class: ClassVar[str] = "krb5_ticket"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED

    def __init__(
        self,
        client: Krb5TokenServiceClient,
        cache: CredentialCache,
        alias: str,
        targets: frozenset[str],
    ) -> None:
        self._client = client
        self._cache = cache
        self._alias = alias
        self._targets = targets
        self._log = structlog.get_logger(__name__).bind(
            provider="KrbTokenProvider", alias=alias
        )

    async def is_linked(self, principal: Principal) -> bool:
        """True iff a still-valid ticket happens to be cached for one of this entry's targets — see the module docstring."""
        for target in self._targets:
            if await self._cache.get(principal.subject, target, min_remaining=0) is not None:
                return True
        return False

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,
        *,
        username: str | None = None,
        lifetime: str | None = None,
        renewable_lifetime: str | None = None,
    ) -> IssuedCredential:
        """Return a cached ticket, or mint a fresh one when *username*/*passphrase* (the CERN password) are supplied.

        Raises:
            NeedsUnlock: nothing valid is cached and no fresh
                username/password was supplied — the caller should POST
                both to ``/v1/krb5/ticket``.
            Krb5TokenBadCredentialError / Krb5TokenAccountError /
                Krb5TokenInvalidRequestError / Krb5TokenRateLimitedError /
                Krb5TokenMintError: see ``Krb5TokenServiceClient.mint``.

        """
        cached = await self._cache.get(
            principal.subject, target, min_remaining=min_remaining_seconds
        )
        if cached is not None:
            self._log.debug(
                "krb5_token.issue.cache_hit", subject=principal.subject, target=target
            )
            return cached

        if passphrase is None or username is None:
            raise NeedsUnlock(
                target,
                "Kerberos ticket not yet minted or expired",
                unlock_endpoint="/v1/krb5/ticket",
            )

        async def _do_mint() -> IssuedCredential:
            ticket = await self._client.mint(
                subject=principal.subject,
                username=username,
                password=SecretStr(passphrase.get_secret_value().decode()),
                lifetime=lifetime,
                renewable_lifetime=renewable_lifetime,
            )
            audit_id = _new_audit_id()
            cred = IssuedCredential(
                cred_class=self.cred_class,
                target=target,
                kind=CredentialKind.KRB5_CCACHE,
                expires_at=ticket.not_after,
                payload={
                    "ccache_b64": ticket.ccache_b64,
                    "principal": ticket.principal,
                    "realm": ticket.realm,
                    "renew_until": ticket.renew_until,
                },
                audit_id=audit_id,
                source="krb5_token_service",
                execution_model=self.execution_model,
            )
            await self._cache.put(
                principal.subject, target, cred, expires_at=ticket.not_after
            )
            metrics.krb5_tickets_issued_total.labels(target=target).inc()
            # Never log ccache/password material -- subject/target/audit only.
            self._log.info(
                "krb5_token.issue.success",
                subject=principal.subject,
                target=target,
                audit_id=audit_id,
                expires_at=ticket.not_after,
            )
            return cred

        # Single-flighted like every other provider (issue #94's pattern).
        return await self._cache.get_or_mint(
            principal.subject, target, min_remaining_seconds, _do_mint
        )

    async def revoke(self, principal: Principal, target: str) -> None:
        """Drop the cached ticket; ccaches are not server-side revocable, so the short lifetime is the actual revocation bound."""
        await self._cache.revoke(principal.subject, target)
```

Check whether `_new_audit_id` is actually importable from `credentials.base` (it's a module-level function there per `base.py`'s reading earlier) — if it's name-mangled/private-by-convention only, either import it as shown (it has no leading-underscore-enforced privacy at the module level, `condor.py` uses its own local `uuid.uuid4().hex` instead of importing it) or just do what `condor.py` does and generate the id inline with `uuid.uuid4().hex` for consistency with the sibling provider. **Prefer matching `condor.py`'s own approach** (inline `uuid.uuid4().hex`, importing `uuid` at the top) rather than importing `_new_audit_id`, since that's what the file you're mirroring actually does.

**Step 4: Run to verify pass**

Run: `pixi run -e dev pytest broker/tests/test_krb5_token.py -v`
Expected: PASS (6 tests)

**Step 5: Lint and commit**

```bash
pixi run lint
git add broker/src/af_mcp_broker/credentials/krb5.py broker/tests/test_krb5_token.py
git commit -m "feat(broker): add KrbTokenProvider"
```

---

### Task 5: `metrics.krb5_tickets_issued_total`

**Files:**
- Modify: `broker/src/af_mcp_broker/metrics.py`

**Step 1: Add the counter**

Find `condor_tokens_issued_total` (line ~152) and add a sibling immediately after it:

```python
krb5_tickets_issued_total = Counter(
    "af_mcp_krb5_tickets_issued_total",
    "Kerberos tickets actually obtained from krb5-token-service (issue "
    "#274; cache hits not counted).",
    ["target"],
)
```

Match whatever registry/namespace kwargs `condor_tokens_issued_total`'s `Counter(...)` call actually uses (read the full call before copying — don't guess at extra kwargs).

**Step 2: Commit**

```bash
git add broker/src/af_mcp_broker/metrics.py
git commit -m "feat(broker): add krb5_tickets_issued_total metric"
```

(Covered indirectly by Task 4's `test_issue_with_credentials_mints_and_caches` once wired — no dedicated metrics test needed, matching how `condor_tokens_issued_total` itself has no dedicated test.)

---

### Task 6: `credentials/__init__.py` exports

**Files:**
- Modify: `broker/src/af_mcp_broker/credentials/__init__.py`

**Step 1: Add imports and `__all__` entries**

```python
from af_mcp_broker.credentials.krb5 import KrbTokenProvider
from af_mcp_broker.credentials.krb5_service import (
    Krb5TokenAccountError,
    Krb5TokenBadCredentialError,
    Krb5TokenInvalidRequestError,
    Krb5TokenMintError,
    Krb5TokenRateLimitedError,
    Krb5TokenServiceClient,
)
```

placed alphabetically among the existing `from af_mcp_broker.credentials.*` block (after `condor`, before `oauth21` — check exact alphabetical placement against the existing lines). Add the matching names to `__all__` in the same alphabetical style already used there.

**Step 2: Verify nothing else broke**

Run: `pixi run -e dev pytest broker/ -v -k "not slow"` (or just `pixi run test` if fast enough) to confirm the import graph is still sound.

**Step 3: Commit**

```bash
git add broker/src/af_mcp_broker/credentials/__init__.py
git commit -m "feat(broker): export KrbTokenProvider and krb5_service errors"
```

---

### Task 7: App wiring — provider registration + fail-closed signing-key check

**Files:**
- Modify: `broker/src/af_mcp_broker/app.py`
- Test: Create `broker/tests/test_krb5_token_app.py` (mirror `test_condor_token_app.py` closely, including its `_make_rsa_key`/`_private_pem` import from `test_broker_issued`)

**Step 1: Write the failing tests**

Copy `test_condor_token_app.py` to `test_krb5_token_app.py` and adapt:

```python
"""App-level wiring for KrbTokenProvider (issue #274).

Covers: provider registration from an ``identity_providers`` krb5-token
entry, the startup fail-closed check (a krb5-token entry with no broker
signing key must refuse to boot -- the provider composes the same
``BrokerTokenIssuer`` as broker-issued/condor-token), and /v1/identities
listing the provider's is_linked() state. The provider unit tests (HTTP
boundary stubbed) live in test_krb5_token.py.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest
from test_broker_issued import _make_rsa_key, _private_pem

from af_mcp_broker.credentials import KrbTokenProvider

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_KRB5_TOKEN_PROVIDERS = [
    {
        "type": "krb5-token",
        "alias": "krb5",
        "display_name": "CERN Kerberos ticket",
        "targets": ["krb5-target"],
        "service_url": "http://krb5-token-service.invalid",
    }
]
```

Then port over each of `test_condor_token_app.py`'s three tests (`test_condor_token_provider_registered_from_config`, `test_condor_token_entry_without_signing_key_refuses_to_start`, `test_identities_lists_condor_token_provider_as_linked`), renaming to krb5 equivalents and its fixture (`condor_token_env` → `krb5_token_env`). Read the full existing file first (not just the header already shown) since the fixture body (services.yaml content, env building) needs a `krb5-target` service entry instead of `condor-mcp`, and copy that shape exactly rather than re-deriving it.

For the third test (identities listing), note `KrbTokenProvider.is_linked()` is cache-state-based (Task 4), not unconditionally `True` like `CondorTokenProvider` — so assert `linked is False` for a freshly-started app with nothing minted yet (adjust the ported assertion accordingly; don't copy `assert provider["linked"] is True` verbatim).

**Step 2: Run to verify failure**

Run: `pixi run -e dev pytest broker/tests/test_krb5_token_app.py -v`
Expected: FAIL (`ImportError: cannot import name 'KrbTokenProvider'` from `af_mcp_broker.credentials`, since Task 6 exports it but `app.py` doesn't construct it yet — or a config/registration mismatch)

**Step 3: Write the implementation**

In `app.py`:

1. Import `KrbTokenProvider` and `Krb5TokenServiceClient` alongside the existing `CondorTokenProvider` import (line ~38).
2. Extend the fail-closed signing-key check (line ~438-451) to include `krb5-token`:

```python
    if broker_token_issuer is None and any(
        cfg.type in ("broker-issued", "condor-token", "krb5-token")
        for cfg in settings.identity_providers
    ):
        msg = (
            "identity_providers contains a broker-issued, condor-token, or "
            "krb5-token entry but BROKER_SIGNING_KEY_FILE is not set, so "
            "the broker cannot sign AF Broker Identity Tokens for its "
            "targets. Mount the RS256 signing key (chart: broker."
            "identityToken.existingSigningKeySecret) or remove the entry "
            "-- see docs/auth.md's 'AF Broker Identity Token' section."
        )
        raise RuntimeError(msg)
```

3. Add a branch in the provider-registration loop (line ~546, immediately after the `condor-token` `elif`):

```python
        elif cfg.type == "krb5-token":
            assert broker_token_issuer is not None  # guaranteed by the check above
            provider = KrbTokenProvider(
                client=Krb5TokenServiceClient(
                    issuer=broker_token_issuer,
                    service_url=str(cfg.service_url),
                    audience=cfg.audience,
                ),
                cache=credential_cache,
                alias=cfg.alias,
                targets=frozenset(cfg.targets),
            )
```

**Step 4: Run to verify pass**

Run: `pixi run -e dev pytest broker/tests/test_krb5_token_app.py -v`
Expected: PASS (3 tests)

**Step 5: Run the full suite and commit**

```bash
pixi run test
git add broker/src/af_mcp_broker/app.py broker/tests/test_krb5_token_app.py
git commit -m "feat(broker): wire KrbTokenProvider into app startup"
```

---

### Task 8: `POST /v1/krb5/ticket` endpoint

**Files:**
- Modify: `broker/src/af_mcp_broker/api/credentials.py`
- Test: Create `broker/tests/test_krb5_ticket_endpoint.py` — first check which existing test file exercises `POST /v1/x509/proxy` at the API/HTTP level (`test_x509_identity_provider.py` or `test_x509_service_mode.py` — grep for `"/v1/x509/proxy"` and read whichever file actually POSTs to it end-to-end through the FastAPI test client) and mirror THAT file's app-construction/client fixtures, not `test_krb5_token_app.py`'s.

This task also needs `app.state.krb5_targets`, mirroring `app.state.x509_targets` (app.py line ~322, ~338, ~838) — a `krb5_targets` builder mirroring the x509 one (there's no analogous `_validate_x509_provider_targets`-style requirement for krb5 since `services.yaml`'s `auth_type` doesn't have a krb5 variant — skip that validation step, just collect `cfg.targets` for every `krb5-token` entry into `application.state.krb5_targets`).

**Step 1: Write the failing tests**

Read the actual x509-proxy-endpoint test file found above in full first, then write krb5 equivalents of at least:
- Happy path: `POST /v1/krb5/ticket` with `{"username": ..., "password": ...}` against a stubbed krb5-token-service returns 201 with `KrbTicketMetadata` (principal/realm/expires_at/remaining_seconds/renew_until), no `ccache_b64` field in the body.
- A 400 from the stubbed service surfaces as the endpoint's own 400.
- A 403 from the stubbed service surfaces as 403.
- A 422 from the stubbed service surfaces as 422.
- A 429 from the stubbed service surfaces as 429 with `Retry-After` forwarded.
- `GET /v1/credential?target=<krb5-target>` before any ticket is minted returns a 409 `proxy_unlock_required`-shaped conflict naming `/v1/krb5/ticket` (mirrors the existing `NeedsUnlock` → 409 mapping already in `issue_credential`, exercised today by x509 — check `test_x509_identity_provider.py` for that exact assertion shape and mirror it, since `create_credential`/`issue_credential`'s existing `except NeedsUnlock` handler needs no krb5-specific code — it already maps any `NeedsUnlock` generically).

**Step 2: Run to verify failure**

Run: `pixi run -e dev pytest broker/tests/test_krb5_ticket_endpoint.py -v`
Expected: FAIL (404 — no such route yet)

**Step 3: Write the implementation**

In `api/credentials.py`:

1. Add imports: `KrbTokenProvider`, `Krb5TokenAccountError`, `Krb5TokenBadCredentialError`, `Krb5TokenInvalidRequestError`, `Krb5TokenRateLimitedError` from `af_mcp_broker.credentials`.

2. Add request/response models near `ProxyRequest`/`ProxyMetadata`:

```python
class KrbTicketRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    username: str
    # SecretStr prevents the CERN password from appearing in repr/logs.
    password: SecretStr
    # Which krb5-token target to mint for; defaults to the first configured
    # krb5-token target.
    target: str | None = None
    lifetime: str | None = None
    renewable_lifetime: str | None = None


class KrbTicketMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    principal: str
    realm: str
    expires_at: str  # ISO-8601
    remaining_seconds: int
    renew_until: str | None = None  # ISO-8601, null if not renewable
    # ccache_b64 is intentionally absent -- the ticket is cached server-side
    # (same "credentials never transit to the client" rule as x509's PEM).
```

3. Add resolution helpers mirroring `_resolve_x509_target`/`_x509_provider`:

```python
async def _krb5_provider(request: Request, target: str) -> KrbTokenProvider:
    registry = _registry(request)
    try:
        provider = await registry.resolve(target)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No krb5-token credential provider is configured for '{target}'",
        ) from exc
    if not isinstance(provider, KrbTokenProvider):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target '{target}' is not a krb5-token target",
        )
    return provider


def _resolve_krb5_target(request: Request, target: str | None) -> str:
    if target is not None:
        return target
    targets: list[str] = getattr(request.app.state, "krb5_targets", [])
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No krb5-token target is configured",
        )
    return targets[0]
```

4. Add the route (near `create_proxy`):

```python
@router.post(
    "/krb5/ticket",
    response_model=KrbTicketMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Mint and cache a Kerberos ticket",
)
async def create_krb5_ticket(
    body: KrbTicketRequest,
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> KrbTicketMetadata:
    target = _resolve_krb5_target(request, body.target)
    provider = await _krb5_provider(request, target)
    passphrase = SecretBytes(body.password.get_secret_value().encode())
    try:
        cred = await provider.issue(
            principal,
            target,
            passphrase=passphrase,
            username=body.username,
            lifetime=body.lifetime,
            renewable_lifetime=body.renewable_lifetime,
        )
    except Krb5TokenBadCredentialError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Krb5TokenAccountError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    except Krb5TokenInvalidRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except Krb5TokenRateLimitedError as exc:
        headers = {"Retry-After": exc.retry_after} if exc.retry_after else None
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers=headers,
        ) from exc
    # Krb5TokenMintError (infra/contract failure) is deliberately left to the
    # generic exception handler -> 500, matching how a bare ValueError/
    # RuntimeError from the legacy x509 path is handled today (there is no
    # existing "generic 502" catch-all convention to reuse here without
    # inventing new middleware -- confirm this against how VomsServiceMintError
    # is actually surfaced in the real create_proxy route before finalizing;
    # if that route DOES catch VomsServiceMintError -> 502 explicitly, add the
    # same explicit catch here instead of relying on the generic handler).

    payload = cred.payload
    renew_until = payload.get("renew_until")
    return KrbTicketMetadata(
        target=target,
        principal=payload["principal"],
        realm=payload["realm"],
        expires_at=_iso(cred.expires_at),
        remaining_seconds=max(0, int(cred.expires_at - time.time())),
        renew_until=_iso(renew_until) if renew_until is not None else None,
    )
```

Before finalizing, re-check the real `create_proxy` route body (already read this session — it DOES catch `VomsServiceMintError` explicitly and maps it to 502) — mirror that precedent exactly: add `except Krb5TokenMintError as exc: raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail="Kerberos ticket issuance is temporarily unavailable — retry later.") from exc` rather than leaving it to a generic handler. Update the plan snippet above accordingly during implementation — the comment above flags this as a spot to verify, not a final decision.

5. Populate `app.state.krb5_targets` in `app.py`'s lifespan, mirroring `x509_targets` (search for all three `x509_targets` write/read sites found earlier — lines ~322, ~338 (validation — skip, no krb5 equivalent needed), ~838, ~869):

```python
    krb5_targets: list[str] = [
        target
        for cfg in settings.identity_providers
        if cfg.type == "krb5-token"
        for target in cfg.targets
    ]
```

and `application.state.krb5_targets = krb5_targets` alongside `application.state.x509_targets = x509_targets`.

**Step 4: Run to verify pass**

Run: `pixi run -e dev pytest broker/tests/test_krb5_ticket_endpoint.py -v`
Expected: PASS

**Step 5: Run the full broker suite, lint, typecheck, and commit**

```bash
pixi run test
pixi run lint
pixi run typecheck
git add broker/src/af_mcp_broker/api/credentials.py broker/src/af_mcp_broker/app.py broker/tests/test_krb5_ticket_endpoint.py
git commit -m "feat(broker): add POST /v1/krb5/ticket unlock endpoint"
```

---

### Task 9: `/v1/identities` — `ProviderType`/`LinkMechanism`

**Files:**
- Modify: `broker/src/af_mcp_broker/api/identities.py`
- Test: `broker/tests/test_identities.py` (check whether it already parametrizes over provider types the way `test_condor_token_app.py` covers condor's row instead — if `condor-token`/`broker-issued` aren't separately tested there, no new test is needed here beyond what Task 7's `test_krb5_token_app.py` already covers for the identities listing; only add a dedicated test if `test_identities.py` already has a per-provider-type table you'd be leaving incomplete)

**Step 1: Extend the literals**

```python
ProviderType = Literal[
    "keycloak-brokered",
    "oauth21-direct",
    "broker-issued",
    "condor-token",
    "krb5-token",
    "x509",
]
```

Add a new `LinkMechanism` value distinct from x509's single-field `"passphrase"`, since krb5 needs two fields (username + password) and conflating them would misdescribe the eventual portal form:

```python
LinkMechanism = Literal["redirect", "passphrase", "credential", "none"]

_LINK_MECHANISM_BY_TYPE: dict[str, LinkMechanism] = {
    "keycloak-brokered": "redirect",
    "oauth21-direct": "redirect",
    "broker-issued": "none",
    "condor-token": "none",
    "krb5-token": "credential",
    "x509": "passphrase",
}
```

Update the two comment blocks just above `ProviderType` and `LinkMechanism` (lines ~28-50) to mention `krb5-token`/`"credential"` alongside the existing entries, following the exact prose style already there (don't leave the old comments describing only 5 types once there are 6).

**Step 2: Run the identities test file to confirm nothing broke**

Run: `pixi run -e dev pytest broker/tests/test_identities.py -v`
Expected: PASS (no regressions — this task doesn't change existing providers' output)

**Step 3: Commit**

```bash
git add broker/src/af_mcp_broker/api/identities.py
git commit -m "feat(broker): list krb5-token in /v1/identities"
```

---

### Task 10: Docs — `docs/auth.md`, `docs/ecosystem.md`, `docs/observability.md`, `README.md`

**Files:**
- Modify: `docs/auth.md`, `docs/ecosystem.md`, `docs/observability.md`, `README.md`

**Step 1: `docs/auth.md`**

Add a new `### KrbTokenProvider: CERN Kerberos tickets (issue #274)` section immediately after the existing `### CondorTokenProvider: HTCondor IDTOKENs (issue #169)` section (ends right before the `---` at the line after "...condor-mcp, and the registry wiring are untouched."). Model it on that section's structure but describe:
- Why this provider differs from `condor-token` (no standing secret — live CERN username/password required per call).
- The `POST /v1/krb5/ticket` unlock endpoint and its request/response shape.
- `is_linked()`'s cache-based semantics (not a durable link).
- The status-code mapping (400/403/422/429/401→502/other→502) and that response bodies are never relayed.
- The explicit "no downstream aggregator.services consumer yet" caveat, linking back to issue #274 the same way the flux_apps helmrelease.yaml comment already does.
- Example config snippet matching the one already validated in Task 3's config test.

**Step 2: `docs/ecosystem.md`**

Add a bullet mirroring the `condor-token-service` one (line ~29-32):

```markdown
- **[krb5-token-service](https://github.com/maniaclab/krb5-token-service)**
  mints CERN Kerberos tickets (ccaches) for CERN-authenticated identities
  via the `krb5-token` identity-provider type (see
  [Authentication](auth.md#krbtokenprovider-cern-kerberos-tickets-issue-274)).
```

**Step 3: `docs/observability.md`**

Add a row to the metrics table (near `af_mcp_condor_tokens_issued_total`, line ~239):

```markdown
| `af_mcp_krb5_tickets_issued_total` | counter | `target` | Kerberos tickets actually obtained from krb5-token-service (cache hits not counted). |
```

**Step 4: `README.md`**

Add `krb5-token-service` to the "Credential-minting services" bullet (line ~67):

```markdown
- **Credential-minting services:** [condor-token-service](https://github.com/maniaclab/condor-token-service), [krb5-token-service](https://github.com/maniaclab/krb5-token-service), [voms-token-service](https://github.com/maniaclab/voms-token-service), [af-credentials](https://github.com/maniaclab/af-credentials)
```

**Step 5: Commit**

```bash
git add docs/auth.md docs/ecosystem.md docs/observability.md README.md
git commit -m "docs: document KrbTokenProvider"
```

---

### Task 11: Helm chart — commented example entry

**Files:**
- Modify: `charts/af-mcp-platform/values.yaml`

**Step 1: Add a commented example**

Add a new commented block immediately after the existing `# - type: condor-token` example (ends at the `serviceUrl` line, before `# - type: x509`), following the exact same comment-block style:

```yaml
  # - type: krb5-token
  #   alias: krb5
  #   displayName: "CERN Kerberos ticket"
  #   enables: "Kerberos-authenticated access via <some-downstream-service>"
  #   # No downstream aggregator.services consumer is defined yet (issue
  #   # #274) -- leave targets empty until one is chosen.
  #   targets: []
  #   # Base URL of the krb5-token-service deployment (the broker appends
  #   # /v1/mint). audience defaults to "krb5-token-service".
  #   serviceUrl: "http://krb5-token-service.krb5-token.svc.cluster.local:8080"
```

**Step 2: Lint the chart**

Run: `helm lint charts/af-mcp-platform`
Expected: no new errors (a commented-out block can't break lint, but confirm the file still parses)

**Step 3: Commit**

```bash
git add charts/af-mcp-platform/values.yaml
git commit -m "chore(chart): document krb5-token identityProviders example"
```

---

### Task 12: Full verification pass

**Step 1: Run everything**

```bash
pixi run -e dev lint-all
pixi run test
helm lint charts/af-mcp-platform
```

Expected: all green.

**Step 2: Bump chart version**

Check how the last few feature PRs bumped `charts/af-mcp-platform/Chart.yaml`'s `version` (the repo's commit history shows a "chore: bump version" commit after each feature — e.g. `0a00904`, `f243292`). Follow the same pattern: bump the patch or minor version per whatever convention those prior bump commits actually used (read `Chart.yaml`'s current value and the last bump commit's diff before deciding which segment to increment).

**Step 3: Final commit and open the PR**

```bash
git add charts/af-mcp-platform/Chart.yaml
git commit -m "chore: bump version"
gh pr create --title "feat: add KrbTokenProvider identity-provider type" --body "$(cat <<'EOF'
## Summary
- Adds `KrbTokenProviderConfig`/`KrbTokenProvider`, mirroring the broker-mints-token/exchanges-at-service shape of `CondorTokenProviderConfig`/`CondorTokenProvider`, for krb5-token-service's `POST /v1/mint`.
- Unlike `condor-token`, krb5-token-service needs a live CERN username/password on every mint (no standing secret to redeem), so this also adds a `POST /v1/krb5/ticket` unlock endpoint (mirrors `POST /v1/x509/proxy`) and a `NeedsUnlock`-based flow rather than treating the provider as unconditionally linked.
- Explicitly out of scope (per issue #274 and follow-up discussion): choosing the downstream `aggregator.services` consumer for the minted ccache, and the portal UI for the new two-field unlock form.

Closes maniaclab/af-mcp-platform#274.

## Test plan
- [ ] `pixi run test` — full broker suite green, including new `test_krb5_service_client.py`, `test_krb5_token.py`, `test_krb5_token_app.py`, `test_krb5_ticket_endpoint.py`
- [ ] `pixi run -e dev lint-all`
- [ ] `helm lint charts/af-mcp-platform`
EOF
)"
```

---

## Execution notes for whoever runs this plan

- Several code snippets above are explicitly flagged as "verify against the real file before finalizing" (the `create_proxy` 502-mapping precedent in Task 8, `_new_audit_id` import vs. inline `uuid.uuid4().hex` in Task 4, `Principal`/`CredentialCache` constructor kwargs in Task 4, the `Counter(...)` call's exact kwargs in Task 5, and which test file actually exercises `POST /v1/x509/proxy` at the HTTP level in Task 8). Do not skip those checks — the surrounding prose explains why each one is a judgment call rather than a settled fact.
- Tasks 1-7 have no interdependencies beyond straightforward import ordering and can be done in the order listed. Task 8 depends on Tasks 3, 4, 6, 7. Tasks 9-11 are independent of each other and of Task 8's internals (they only need Task 3's config type to exist). Task 12 is last.

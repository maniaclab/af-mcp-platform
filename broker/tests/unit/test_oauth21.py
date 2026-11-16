"""Tests for OAuth 2.1 credential brokering (issue #66 PR1).

Covers the ``TokenStore`` ABC + ``InMemoryTokenStore`` CAS semantics,
the Fernet-encrypted state token, ``OAuth21Provider.is_linked``/``issue``,
and the ``/v1/oauth/authorize`` + ``/v1/oauth/callback`` routes end-to-end
against an in-process fake backend authorization server.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
import structlog
from cryptography.fernet import Fernet
from oauth21_support import (  # noqa: F401
    ALIAS,
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID,
    CONFIDENTIAL_CLIENT_ID,
    CONFIDENTIAL_CLIENT_SECRET,
    EXPECTED_STATE_ISSUER,
    PROVIDER_ISSUER,
    SUBJECT,
    TOKEN_ENDPOINT,
    _FakeTokenClient,
    _make_cred,
    _make_provider,
    x509_service_env_fixture,
)
from pydantic import SecretStr

from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.credentials.errors import (
    CredentialNotFoundError,
    CredentialReauthRequiredError,
    VersionConflictError,
)
from af_mcp_broker.credentials.oauth21 import (
    InMemoryTokenStore,
    OAuth21Provider,
    StoredOAuthCredential,
    normalize_token_response,
)
from af_mcp_broker.oauth_state import (
    StateTokenError,
    append_linked_error_params,
    append_linked_query_param,
    build_state_token,
    decrypt_state_token,
    sanitize_return_url,
)
from af_mcp_broker.principal import Principal
from af_mcp_broker.service_registry import ServiceRegistry, ServiceSpec
from af_mcp_broker.service_status import service_status

REVOCATION_ENDPOINT = "https://backend-as.example/revoke"


def _principal(subject: str = SUBJECT) -> Principal:
    return Principal(
        subject=subject,
        email="tuser@example.org",
        uid=1000,
        gid=1000,
        unixname="tuser",
        groups=[],
        raw_token=SecretStr("fake-token"),
    )


# ---------------------------------------------------------------------------
# TokenStore / InMemoryTokenStore CAS semantics
# ---------------------------------------------------------------------------


async def test_get_returns_none_on_missing() -> None:
    store = InMemoryTokenStore()
    assert await store.get(SUBJECT, ALIAS) is None


async def test_write_cas_creates_when_missing_returns_version_1() -> None:
    store = InMemoryTokenStore()
    version = await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    assert version == 1
    got = await store.get(SUBJECT, ALIAS)
    assert got is not None
    got_cred, got_version = got
    assert got_version == 1
    assert got_cred.access_token.get_secret_value() == "access-token-1"


async def test_write_cas_none_raises_when_existing() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    with pytest.raises(VersionConflictError):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)


async def test_write_cas_succeeds_when_version_matches() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    version = await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(access_token=SecretStr("access-token-2")),
        expected_version=1,
    )

    assert version == 2


async def test_write_cas_raises_when_version_stale() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)  # v1
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=1)  # v2

    with pytest.raises(VersionConflictError):
        await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=1)


async def test_delete_is_idempotent() -> None:
    store = InMemoryTokenStore()
    await store.delete(SUBJECT, ALIAS)  # no entry yet -- must not raise

    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    await store.delete(SUBJECT, ALIAS)
    assert await store.get(SUBJECT, ALIAS) is None

    await store.delete(SUBJECT, ALIAS)  # already gone -- still must not raise


# ---------------------------------------------------------------------------
# State token
# ---------------------------------------------------------------------------


def _build_state(cipher: Fernet, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "iss": EXPECTED_STATE_ISSUER,
        "sub": SUBJECT,
        "alias": ALIAS,
        "pkce_verifier": "verifier-abc",
        "return_url": "/identities",
        "nonce": "nonce-xyz",
    }
    kwargs.update(overrides)
    return build_state_token(cipher, **kwargs)


def test_state_token_round_trip() -> None:
    cipher = Fernet(Fernet.generate_key())
    token = _build_state(cipher)

    payload = decrypt_state_token(cipher, token, expected_iss=EXPECTED_STATE_ISSUER)

    assert payload.sub == SUBJECT
    assert payload.alias == ALIAS
    assert payload.pkce_verifier == "verifier-abc"
    assert payload.return_url == "/identities"
    assert payload.nonce == "nonce-xyz"


def test_state_token_expired_raises() -> None:
    cipher = Fernet(Fernet.generate_key())
    now = int(time.time())
    payload = {
        "iss": EXPECTED_STATE_ISSUER,
        "aud": EXPECTED_STATE_ISSUER,
        "sub": SUBJECT,
        "alias": ALIAS,
        "pkce_verifier": "v",
        "return_url": "/",
        "nonce": "n",
        "iat": now - 400,
        "exp": now - 100,
    }
    # Fernet's own `encrypt_at` mints the token as if created 400s ago, so its
    # `ttl=` check rejects it without needing to sleep in the test.
    token = cipher.encrypt_at_time(json.dumps(payload).encode(), now - 400).decode()

    with pytest.raises(StateTokenError):
        decrypt_state_token(cipher, token, expected_iss=EXPECTED_STATE_ISSUER)


def test_state_token_wrong_key_raises() -> None:
    cipher_a = Fernet(Fernet.generate_key())
    cipher_b = Fernet(Fernet.generate_key())
    token = _build_state(cipher_a)

    with pytest.raises(StateTokenError):
        decrypt_state_token(cipher_b, token, expected_iss=EXPECTED_STATE_ISSUER)


def test_state_token_mismatched_iss_aud_raises() -> None:
    cipher = Fernet(Fernet.generate_key())
    now = int(time.time())
    payload = {
        "iss": EXPECTED_STATE_ISSUER,
        "aud": "https://other-deployment.example/realms/connect",
        "sub": SUBJECT,
        "alias": ALIAS,
        "pkce_verifier": "v",
        "return_url": "/",
        "nonce": "n",
        "iat": now,
        "exp": now + 300,
    }
    token = cipher.encrypt(json.dumps(payload).encode()).decode()

    with pytest.raises(StateTokenError):
        decrypt_state_token(cipher, token, expected_iss=EXPECTED_STATE_ISSUER)


def test_state_token_malformed_raises() -> None:
    cipher = Fernet(Fernet.generate_key())

    with pytest.raises(StateTokenError):
        decrypt_state_token(
            cipher, "not-a-fernet-token", expected_iss=EXPECTED_STATE_ISSUER
        )


def test_sanitize_return_url_defaults_to_root_when_none() -> None:
    assert sanitize_return_url(None) == "/"


def test_sanitize_return_url_accepts_relative_path() -> None:
    assert sanitize_return_url("/identities") == "/identities"


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://evil.example/x",
        "//evil.example",
        "/a/../b",
        "no-leading-slash",
    ],
)
def test_sanitize_return_url_rejects_unsafe(bad_url: str) -> None:
    with pytest.raises(ValueError, match="return_url"):
        sanitize_return_url(bad_url)


def test_append_linked_query_param_no_existing_query() -> None:
    assert append_linked_query_param("/identities", "rucio-mcp-atlas") == (
        "/identities?linked=rucio-mcp-atlas"
    )


def test_append_linked_query_param_preserves_existing_query() -> None:
    assert append_linked_query_param("/identities?foo=bar", "rucio-mcp-atlas") == (
        "/identities?foo=bar&linked=rucio-mcp-atlas"
    )


def test_append_linked_error_params_no_existing_query() -> None:
    assert append_linked_error_params(
        "/identities", "rucio-mcp-atlas", "server_error"
    ) == ("/identities?linked_error_alias=rucio-mcp-atlas&linked_error=server_error")


def test_append_linked_error_params_preserves_existing_query() -> None:
    assert append_linked_error_params(
        "/identities?foo=bar", "rucio-mcp-atlas", "server_error"
    ) == (
        "/identities?foo=bar&linked_error_alias=rucio-mcp-atlas&linked_error=server_error"
    )


def test_append_linked_error_params_includes_description_and_uri_when_present() -> None:
    url = append_linked_error_params(
        "/identities",
        "rucio-mcp-atlas",
        "server_error",
        error_description="An unexpected error occurred",
        error_uri="https://backend-as.example/errors/server_error",
    )
    query = parse_qs(urlparse(url).query)
    assert query["linked_error_alias"] == ["rucio-mcp-atlas"]
    assert query["linked_error"] == ["server_error"]
    assert query["linked_error_description"] == ["An unexpected error occurred"]
    assert query["linked_error_uri"] == [
        "https://backend-as.example/errors/server_error"
    ]


def test_append_linked_error_params_omits_absent_description_and_uri() -> None:
    url = append_linked_error_params("/identities", "rucio-mcp-atlas", "server_error")
    assert "linked_error_description" not in url
    assert "linked_error_uri" not in url


# ---------------------------------------------------------------------------
# OAuth21Provider.is_linked
# ---------------------------------------------------------------------------


async def test_is_linked_false_when_missing() -> None:
    provider = _make_provider(InMemoryTokenStore())
    assert await provider.is_linked(_principal()) is False


async def test_is_linked_false_when_expired() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) - timedelta(seconds=10)),
        expected_version=None,
    )
    provider = _make_provider(store)

    assert await provider.is_linked(_principal()) is False


async def test_is_linked_true_when_future() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(hours=1)),
        expected_version=None,
    )
    provider = _make_provider(store)

    assert await provider.is_linked(_principal()) is True


async def test_is_linked_false_when_no_refresh_token_and_within_skew() -> None:
    """A token with no refresh_token that is about to expire can never be
    refreshed, so it must already read as unlinked -- consistent with
    ``issue()`` refusing it -- rather than as linked-but-unusable."""
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(
            refresh_token=None, expires_at=datetime.now(UTC) + timedelta(seconds=10)
        ),
        expected_version=None,
    )
    provider = _make_provider(store)

    assert await provider.is_linked(_principal()) is False


async def test_is_linked_true_when_no_refresh_token_inside_refresh_window() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(
            refresh_token=None, expires_at=datetime.now(UTC) + timedelta(seconds=120)
        ),
        expected_version=None,
    )
    provider = _make_provider(store)

    assert await provider.is_linked(_principal()) is True


async def test_is_linked_true_when_no_expiry_and_no_refresh_token() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(refresh_token=None, expires_at=None, refresh_expires_at=None),
        expected_version=None,
    )
    provider = _make_provider(store)

    assert await provider.is_linked(_principal()) is True


# ---------------------------------------------------------------------------
# normalize_token_response
# ---------------------------------------------------------------------------


def _normalize(data: dict[str, Any]) -> StoredOAuthCredential:
    return normalize_token_response(
        data,
        alias=ALIAS,
        subject=SUBJECT,
        issuer=PROVIDER_ISSUER,
        token_endpoint=TOKEN_ENDPOINT,
    )


def test_normalize_token_response_without_expires_in_has_no_expiry() -> None:
    """RFC 6749 §5.1 makes ``expires_in`` only RECOMMENDED; Indico and GitHub
    OAuth Apps omit it because their tokens do not expire -- issue #344."""
    cred = _normalize(
        {"access_token": "tok", "token_type": "Bearer", "scope": "read:user"}
    )

    assert cred.expires_at is None


def test_normalize_token_response_with_expires_in_sets_expiry() -> None:
    before = datetime.now(UTC)

    cred = _normalize({"access_token": "tok", "expires_in": 3600})

    assert cred.expires_at is not None
    assert (cred.expires_at - before).total_seconds() == pytest.approx(3600, abs=5)


# ---------------------------------------------------------------------------
# OAuth21Provider.issue
# ---------------------------------------------------------------------------


async def test_issue_returns_bearer_when_plenty_of_life() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(hours=1)),
        expected_version=None,
    )
    provider = _make_provider(store)

    issued = await provider.issue(_principal(), ALIAS)

    assert issued.payload["access_token"] == "access-token-1"
    assert issued.kind.value == "bearer"


async def test_issue_refreshes_when_within_window() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(seconds=60)),
        expected_version=None,
    )
    fake_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "access-token-2", "expires_in": 3600},
    )
    provider = _make_provider(store, http_client=fake_client)

    issued = await provider.issue(_principal(), ALIAS)

    assert issued.payload["access_token"] == "access-token-2"
    assert len(fake_client.calls) == 1
    assert fake_client.calls[0]["data"]["grant_type"] == "refresh_token"
    assert fake_client.calls[0]["data"]["refresh_token"] == "refresh-token-1"
    # Per OAuth 2.1 (RFC 6749 §6 + §3.2.1), a public client (CIMD
    # `token_endpoint_auth_method: "none"`) MUST send client_id on every
    # token request, including the refresh_token grant -- see issue #68.
    assert fake_client.calls[0]["data"]["client_id"] == CLIENT_ID

    stored = await store.get(SUBJECT, ALIAS)
    assert stored is not None
    new_cred, new_version = stored
    assert new_version == 2
    assert new_cred.access_token.get_secret_value() == "access-token-2"
    # The fake response omitted refresh_token -- must fall back to the existing one.
    assert new_cred.refresh_token is not None
    assert new_cred.refresh_token.get_secret_value() == "refresh-token-1"


async def test_issue_raises_404_when_missing() -> None:
    provider = _make_provider(InMemoryTokenStore())

    with pytest.raises(CredentialNotFoundError):
        await provider.issue(_principal(), ALIAS)


async def test_issue_raises_401_when_refresh_fails() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(seconds=10)),
        expected_version=None,
    )
    fake_client = _FakeTokenClient(
        status_code=400, json_body={"error": "invalid_grant"}
    )
    provider = _make_provider(store, http_client=fake_client)

    with pytest.raises(CredentialReauthRequiredError):
        await provider.issue(_principal(), ALIAS)


async def test_issue_raises_401_when_no_refresh_token() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(
            refresh_token=None, expires_at=datetime.now(UTC) + timedelta(seconds=10)
        ),
        expected_version=None,
    )
    provider = _make_provider(store)

    with pytest.raises(CredentialReauthRequiredError):
        await provider.issue(_principal(), ALIAS)


async def test_issue_returns_token_without_refresh_token_inside_refresh_window() -> (
    None
):
    """An AS that never issues refresh tokens (e.g. JupyterHub) must not have
    its token 401 five minutes early: with nothing to refresh, the stored token
    stays usable right up to its expiry minus a small skew."""
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(
            refresh_token=None, expires_at=datetime.now(UTC) + timedelta(seconds=120)
        ),
        expected_version=None,
    )
    provider = _make_provider(store)

    issued = await provider.issue(_principal(), ALIAS, min_remaining_seconds=600)

    assert issued.payload["access_token"] == "access-token-1"


async def test_issue_serves_token_without_expiry_and_reports_no_expiry() -> None:
    """An AS that issues non-expiring tokens (Indico, GitHub OAuth Apps) gives
    no expiry to report: the issued credential must say so rather than
    invent one -- issue #344."""
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(refresh_token=None, expires_at=None, refresh_expires_at=None),
        expected_version=None,
    )
    provider = _make_provider(store)

    issued = await provider.issue(_principal(), ALIAS, min_remaining_seconds=600)

    assert issued.payload["access_token"] == "access-token-1"
    assert issued.expires_at is None


async def test_issue_never_refreshes_token_without_expiry() -> None:
    """A token with no known expiry is never inside the refresh window, even
    when a refresh token happens to be stored alongside it."""
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT, ALIAS, _make_cred(expires_at=None), expected_version=None
    )
    fake_client = _FakeTokenClient(
        status_code=200, json_body={"access_token": "access-token-2"}
    )
    provider = _make_provider(store, http_client=fake_client)

    issued = await provider.issue(_principal(), ALIAS)

    assert issued.payload["access_token"] == "access-token-1"
    assert fake_client.calls == []


# ---------------------------------------------------------------------------
# OAuth21Provider.mark_rejected
# ---------------------------------------------------------------------------


async def test_mark_rejected_unlinks_but_keeps_the_token() -> None:
    """A backend rejecting a stored token that cannot be refreshed marks it
    rejected rather than deleting it: the user re-links (and re-consents)
    themselves -- issue #344."""
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT, ALIAS, _make_cred(refresh_token=None), expected_version=None
    )
    provider = _make_provider(store)

    await provider.mark_rejected(_principal(), "access-token-1")

    assert await provider.is_linked(_principal()) is False
    stored = await store.get(SUBJECT, ALIAS)
    assert stored is not None
    assert stored[0].rejected_at is not None
    assert stored[0].access_token.get_secret_value() == "access-token-1"


async def test_issue_raises_401_with_relink_hint_when_rejected() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(rejected_at=datetime.now(UTC)),
        expected_version=None,
    )
    provider = _make_provider(store)

    with pytest.raises(CredentialReauthRequiredError) as exc_info:
        await provider.issue(_principal(), ALIAS)

    assert "rejected" in exc_info.value.detail
    assert "re-link" in exc_info.value.detail


async def test_mark_rejected_ignores_a_token_that_was_since_replaced() -> None:
    """A late 401 for an old token must not reject the token a re-link or
    refresh has stored since."""
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(access_token=SecretStr("access-token-2")),
        expected_version=None,
    )
    provider = _make_provider(store)

    await provider.mark_rejected(_principal(), "access-token-1")

    assert await provider.is_linked(_principal()) is True


async def test_mark_rejected_when_nothing_stored_is_a_noop() -> None:
    store = InMemoryTokenStore()
    provider = _make_provider(store)

    await provider.mark_rejected(_principal(), "access-token-1")

    assert await store.get(SUBJECT, ALIAS) is None


async def test_mark_rejected_loses_a_write_race_quietly() -> None:
    """A concurrent write (another replica's refresh, or a re-link) wins: the
    stored entry is newer than the token that was rejected."""

    class _RacingStore(InMemoryTokenStore):
        async def write_cas(self, *args: Any, **kwargs: Any) -> int:
            raise VersionConflictError

    store = _RacingStore()
    await InMemoryTokenStore.write_cas(
        store, SUBJECT, ALIAS, _make_cred(refresh_token=None), expected_version=None
    )
    provider = _make_provider(store)

    await provider.mark_rejected(_principal(), "access-token-1")

    assert await provider.is_linked(_principal()) is True


async def test_mark_rejected_refreshes_once_instead_of_rejecting() -> None:
    """With a refresh token, a 401 first earns one refresh: the AS may still
    honor the refresh token, so the user need not re-link."""
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    fake_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "access-token-2", "expires_in": 3600},
    )
    provider = _make_provider(store, http_client=fake_client)

    await provider.mark_rejected(_principal(), "access-token-1")

    assert [c["data"]["grant_type"] for c in fake_client.calls] == ["refresh_token"]
    assert await provider.is_linked(_principal()) is True
    stored = await store.get(SUBJECT, ALIAS)
    assert stored is not None
    assert stored[0].access_token.get_secret_value() == "access-token-2"
    assert stored[0].rejected_at is None
    assert stored[0].refreshed_after_rejection is True


async def test_mark_rejected_rejects_a_token_already_refreshed_after_a_401() -> None:
    """A second 401, for the token that refresh produced, rejects it: one
    refresh per rejection, never a refresh loop against a backend that
    rejects everything."""
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(refreshed_after_rejection=True),
        expected_version=None,
    )
    fake_client = _FakeTokenClient(
        status_code=200, json_body={"access_token": "access-token-2"}
    )
    provider = _make_provider(store, http_client=fake_client)

    await provider.mark_rejected(_principal(), "access-token-1")

    assert fake_client.calls == []
    assert await provider.is_linked(_principal()) is False


async def test_mark_rejected_rejects_when_the_as_refuses_the_refresh() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    fake_client = _FakeTokenClient(
        status_code=400, json_body={"error": "invalid_grant"}
    )
    provider = _make_provider(store, http_client=fake_client)

    await provider.mark_rejected(_principal(), "access-token-1")

    assert await provider.is_linked(_principal()) is False
    stored = await store.get(SUBJECT, ALIAS)
    assert stored is not None
    assert stored[0].access_token.get_secret_value() == "access-token-1"


async def test_mark_rejected_leaves_the_token_alone_when_the_as_is_unreachable() -> (
    None
):
    """A 5xx from the AS says nothing about the refresh token: leave the
    credential as it was, so the next 401 tries again, rather than forcing a
    re-link over an AS outage."""
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    fake_client = _FakeTokenClient(status_code=503, json_body={})
    provider = _make_provider(store, http_client=fake_client)

    with structlog.testing.capture_logs() as logs:
        await provider.mark_rejected(_principal(), "access-token-1")

    assert await provider.is_linked(_principal()) is True
    stored = await store.get(SUBJECT, ALIAS)
    assert stored is not None
    assert stored[0].access_token.get_secret_value() == "access-token-1"
    assert stored[0].refreshed_after_rejection is False
    assert [e["event"] for e in logs] == ["oauth21.mark_rejected.refresh_failed"]
    assert logs[0]["log_level"] == "warning"


async def test_issue_refresh_clears_refreshed_after_rejection() -> None:
    """A routine refresh starts a fresh token lifetime, so a later 401 earns
    its own refresh again."""
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(
            expires_at=datetime.now(UTC) + timedelta(seconds=60),
            refreshed_after_rejection=True,
        ),
        expected_version=None,
    )
    fake_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "access-token-2", "expires_in": 3600},
    )
    provider = _make_provider(store, http_client=fake_client)

    await provider.issue(_principal(), ALIAS)

    stored = await store.get(SUBJECT, ALIAS)
    assert stored is not None
    assert stored[0].access_token.get_secret_value() == "access-token-2"
    assert stored[0].refreshed_after_rejection is False


# ---------------------------------------------------------------------------
# A rejected credential in the catalog (service_status.py::service_status)
# ---------------------------------------------------------------------------


async def _catalog_state(
    provider: OAuth21Provider, service_registry: ServiceRegistry | None = None
) -> tuple[str, str, str | None]:
    """(status, status_detail, link_state) the catalog reports for SUBJECT's view of ALIAS."""
    spec = ServiceSpec(
        name=ALIAS,
        prefix="rucio",
        url="http://backend.invalid/mcp",
        transport="http",
        required_permission="__none__",
        auth_type="bearer",
    )
    credentials = CredentialRegistry()
    credentials.register(ALIAS, provider)
    status, detail, _request_id, link_state = await service_status(
        spec, _principal(), set(), credentials, service_registry or ServiceRegistry()
    )
    return status, detail, link_state


async def test_is_rejected_is_false_without_a_stored_credential() -> None:
    provider = _make_provider(InMemoryTokenStore())

    assert await provider.is_rejected(_principal()) is False


async def test_is_rejected_is_false_for_a_usable_credential() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    assert await _make_provider(store).is_rejected(_principal()) is False


async def test_is_rejected_is_true_for_a_stored_rejected_credential() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT, ALIAS, _make_cred(rejected_at=datetime.now(UTC)), expected_version=None
    )
    provider = _make_provider(store)

    assert await provider.is_rejected(_principal()) is True
    assert await provider.is_linked(_principal()) is False


async def test_catalog_says_not_linked_when_nothing_is_stored() -> None:
    status, detail, link_state = await _catalog_state(
        _make_provider(InMemoryTokenStore())
    )

    assert (status, link_state) == ("link_required", "not_linked")
    assert detail.startswith("Link your identity")


async def test_catalog_says_rejected_for_a_stored_rejected_credential() -> None:
    """A user who linked, whose token the backend rejected, is told so --
    never asked to link as if they never had."""
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT, ALIAS, _make_cred(rejected_at=datetime.now(UTC)), expected_version=None
    )

    status, detail, link_state = await _catalog_state(_make_provider(store))

    assert (status, link_state) == ("link_required", "rejected")
    assert detail.startswith("Your linked credential was rejected")


async def test_catalog_ignores_an_unauthorized_listing_record_the_provider_resolved() -> (
    None
):
    """The provider, not the per-caller "unauthorized" listing record, decides
    whether an oauth21 credential is rejected. A 401 that a refresh resolved
    leaves the credential usable, so the record it also left behind must not
    keep the catalog on "rejected"."""
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    provider = _make_provider(
        store,
        http_client=_FakeTokenClient(
            status_code=200,
            json_body={"access_token": "access-token-2", "expires_in": 3600},
        ),
    )
    service_registry = ServiceRegistry()

    await provider.mark_rejected(_principal(), "access-token-1")
    service_registry.record_list_failure(ALIAS, "unauthorized", SUBJECT)

    status, _detail, link_state = await _catalog_state(provider, service_registry)
    assert (status, link_state) == ("available", None)


async def test_catalog_does_not_claim_rejected_when_the_as_is_unreachable() -> None:
    """An authorization-server outage leaves the credential as it was, so
    the catalog must not call it rejected."""
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    provider = _make_provider(store, http_client=_FakeTokenClient(status_code=503))
    service_registry = ServiceRegistry()

    await provider.mark_rejected(_principal(), "access-token-1")
    service_registry.record_list_failure(ALIAS, "unauthorized", SUBJECT)

    status, _detail, link_state = await _catalog_state(provider, service_registry)
    assert (status, link_state) == ("available", None)


async def test_catalog_clears_rejected_when_the_user_relinks() -> None:
    """Re-linking replaces the stored entry, which drops ``rejected_at``; a
    leftover "unauthorized" listing record must not hold the catalog on
    "rejected" until the caller's next successful listing."""
    store = InMemoryTokenStore()
    version = await store.write_cas(
        SUBJECT, ALIAS, _make_cred(rejected_at=datetime.now(UTC)), expected_version=None
    )
    provider = _make_provider(store)
    service_registry = ServiceRegistry()
    service_registry.record_list_failure(ALIAS, "unauthorized", SUBJECT)
    assert (await _catalog_state(provider, service_registry))[2] == "rejected"

    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(access_token=SecretStr("access-token-2")),
        expected_version=version,
    )

    status, _detail, link_state = await _catalog_state(provider, service_registry)
    assert (status, link_state) == ("available", None)


async def test_issue_handles_version_conflict_during_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Another replica refreshing concurrently must not be clobbered -- the
    caller gets back whichever credential won the race.
    """
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(seconds=10)),
        expected_version=None,
    )  # version 1
    fake_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "our-refresh-token", "expires_in": 3600},
    )
    provider = _make_provider(store, http_client=fake_client)

    real_write_cas = store.write_cas
    call_count = 0

    async def _racing_write_cas(
        subject: str,
        alias: str,
        cred: StoredOAuthCredential,
        expected_version: int | None,
    ) -> int:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # Simulate a concurrent replica winning the race just before our
            # own write lands.
            racer_cred = _make_cred(access_token=SecretStr("winning-racer-token"))
            await real_write_cas(subject, alias, racer_cred, expected_version=1)
        return await real_write_cas(subject, alias, cred, expected_version)

    monkeypatch.setattr(store, "write_cas", _racing_write_cas)

    issued = await provider.issue(_principal(), ALIAS)

    assert issued.payload["access_token"] == "winning-racer-token"


def test_provider_exposes_client_id() -> None:
    provider = _make_provider(InMemoryTokenStore(), client_id=CONFIDENTIAL_CLIENT_ID)

    assert provider.client_id == CONFIDENTIAL_CLIENT_ID


async def test_issue_refresh_sends_client_secret_when_confidential() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(seconds=60)),
        expected_version=None,
    )
    fake_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "access-token-2", "expires_in": 3600},
    )
    provider = _make_provider(
        store,
        client_id=CONFIDENTIAL_CLIENT_ID,
        client_secret=SecretStr(CONFIDENTIAL_CLIENT_SECRET),
        http_client=fake_client,
    )

    await provider.issue(_principal(), ALIAS)

    assert len(fake_client.calls) == 1
    sent = fake_client.calls[0]["data"]
    assert sent["client_id"] == CONFIDENTIAL_CLIENT_ID
    assert sent["client_secret"] == CONFIDENTIAL_CLIENT_SECRET


async def test_issue_refresh_omits_client_secret_when_public() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT,
        ALIAS,
        _make_cred(expires_at=datetime.now(UTC) + timedelta(seconds=60)),
        expected_version=None,
    )
    fake_client = _FakeTokenClient(
        status_code=200,
        json_body={"access_token": "access-token-2", "expires_in": 3600},
    )
    provider = _make_provider(store, http_client=fake_client)

    await provider.issue(_principal(), ALIAS)

    assert "client_secret" not in fake_client.calls[0]["data"]


# ---------------------------------------------------------------------------
# OAuth21Provider.revoke
# ---------------------------------------------------------------------------


async def test_revoke_without_revocation_endpoint_only_deletes_locally() -> None:
    """No revocation_endpoint configured -- best-effort upstream call is
    skipped entirely, but the stored token is still deleted."""
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    fake_client = _FakeTokenClient()
    provider = _make_provider(store, http_client=fake_client)

    await provider.revoke(_principal(), ALIAS)

    assert fake_client.calls == []
    assert await store.get(SUBJECT, ALIAS) is None


async def test_revoke_with_revocation_endpoint_posts_token_and_deletes() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    fake_client = _FakeTokenClient(status_code=200)
    provider = _make_provider(
        store, revocation_endpoint=REVOCATION_ENDPOINT, http_client=fake_client
    )

    await provider.revoke(_principal(), ALIAS)

    assert len(fake_client.calls) == 1
    call = fake_client.calls[0]
    assert call["url"] == REVOCATION_ENDPOINT
    assert call["data"]["token"] == "refresh-token-1"
    assert call["data"]["token_type_hint"] == "refresh_token"
    assert call["data"]["client_id"] == CLIENT_ID
    assert await store.get(SUBJECT, ALIAS) is None


async def test_revoke_sends_client_secret_when_confidential() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    fake_client = _FakeTokenClient(status_code=200)
    provider = _make_provider(
        store,
        revocation_endpoint=REVOCATION_ENDPOINT,
        client_id=CONFIDENTIAL_CLIENT_ID,
        client_secret=SecretStr(CONFIDENTIAL_CLIENT_SECRET),
        http_client=fake_client,
    )

    await provider.revoke(_principal(), ALIAS)

    assert len(fake_client.calls) == 1
    sent = fake_client.calls[0]["data"]
    assert sent["client_id"] == CONFIDENTIAL_CLIENT_ID
    assert sent["client_secret"] == CONFIDENTIAL_CLIENT_SECRET


async def test_revoke_falls_back_to_access_token_when_no_refresh_token() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(
        SUBJECT, ALIAS, _make_cred(refresh_token=None), expected_version=None
    )
    fake_client = _FakeTokenClient(status_code=200)
    provider = _make_provider(
        store, revocation_endpoint=REVOCATION_ENDPOINT, http_client=fake_client
    )

    await provider.revoke(_principal(), ALIAS)

    assert len(fake_client.calls) == 1
    call = fake_client.calls[0]
    assert call["data"]["token"] == "access-token-1"
    assert call["data"]["token_type_hint"] == "access_token"


async def test_revoke_upstream_failure_still_deletes_locally() -> None:
    """The revocation-endpoint call is best-effort -- an unreachable or
    rejecting backend AS must never block the local unlink."""
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)
    fake_client = _FakeTokenClient(status_code=500)
    provider = _make_provider(
        store, revocation_endpoint=REVOCATION_ENDPOINT, http_client=fake_client
    )

    await provider.revoke(_principal(), ALIAS)

    assert len(fake_client.calls) == 1
    assert await store.get(SUBJECT, ALIAS) is None


async def test_revoke_upstream_unreachable_still_deletes_locally() -> None:
    store = InMemoryTokenStore()
    await store.write_cas(SUBJECT, ALIAS, _make_cred(), expected_version=None)

    class _RaisingClient:
        async def post(self, *args: Any, **kwargs: Any) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused")

    provider = _make_provider(
        store, revocation_endpoint=REVOCATION_ENDPOINT, http_client=_RaisingClient()
    )

    await provider.revoke(_principal(), ALIAS)

    assert await store.get(SUBJECT, ALIAS) is None


async def test_revoke_when_nothing_stored_is_a_noop() -> None:
    """Unlinking an alias with no stored token must not attempt an upstream
    call -- there is no token to revoke -- and must not raise."""
    store = InMemoryTokenStore()
    fake_client = _FakeTokenClient()
    provider = _make_provider(
        store, revocation_endpoint=REVOCATION_ENDPOINT, http_client=fake_client
    )

    await provider.revoke(_principal(), ALIAS)

    assert fake_client.calls == []

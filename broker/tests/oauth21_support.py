"""Fixtures and helpers shared by the unit and integration tests of ``test_oauth21``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx2
import pytest
from conftest import configure_x509_service_env
from pydantic import SecretStr

from af_mcp_broker.credentials.oauth21 import (
    InMemoryTokenStore,
    OAuth21Provider,
    StoredOAuthCredential,
)

if TYPE_CHECKING:
    from pathlib import Path


ALIAS = "rucio-mcp-atlas"
SUBJECT = "kc-subject-123"

# Matches the fixed OIDC_ISSUER `app_client_factory` (conftest.py) sets before
# every test — `settings.oauth21_effective_state_issuer` falls back to it
# whenever OAUTH21_STATE_ISSUER is unset, which none of these tests set.
EXPECTED_STATE_ISSUER = "https://keycloak.invalid/realms/connect"

AUTHORIZATION_ENDPOINT = "https://backend-as.example/authorize"
TOKEN_ENDPOINT = "https://backend-as.example/token"
PROVIDER_ISSUER = "https://backend-as.example"
CLIENT_ID = "https://mcp.example.org/.well-known/cimd"

# A statically-registered confidential client (e.g. a JupyterHub service),
# as opposed to the broker's shared CIMD client_id above.
CONFIDENTIAL_CLIENT_ID = "service-af-mcp-platform"
CONFIDENTIAL_CLIENT_SECRET = "confidential-s3cret"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_cred(**overrides: Any) -> StoredOAuthCredential:
    now = datetime.now(UTC)
    defaults: dict[str, Any] = {
        "alias": ALIAS,
        "subject": SUBJECT,
        "access_token": SecretStr("access-token-1"),
        "refresh_token": SecretStr("refresh-token-1"),
        "expires_at": now + timedelta(hours=1),
        "refresh_expires_at": now + timedelta(days=30),
        "scope": ["openid", "profile"],
        "issuer": PROVIDER_ISSUER,
        "token_endpoint": TOKEN_ENDPOINT,
    }
    defaults.update(overrides)
    return StoredOAuthCredential(**defaults)


class _FakeTokenClient:
    """Fake httpx2 client capturing token-endpoint POSTs, injected as the
    provider's client (refresh) or as the app's shared client (exchange).
    """

    def __init__(self, status_code: int = 200, json_body: dict[str, Any] | None = None):
        self.status_code = status_code
        self.json_body = json_body or {}
        self.calls: list[dict[str, Any]] = []

    async def post(
        self, url: str, data: dict[str, Any], **kwargs: Any
    ) -> httpx2.Response:
        self.calls.append({"url": url, "data": data})
        # `request=` must be set -- `Response.raise_for_status()` (called by
        # the production code on success too) requires it even for 2xx.
        return httpx2.Response(
            self.status_code, json=self.json_body, request=httpx2.Request("POST", url)
        )


@pytest.fixture(name="_x509_service_env", autouse=True)
def x509_service_env_fixture(
    monkeypatch: pytest.MonkeyPatch, broker_signing_key_file: Path
) -> None:
    """The shipped "ami" service (covered by every IDENTITY_PROVIDERS override here) needs the signing key and Vault connection to boot."""
    configure_x509_service_env(monkeypatch, broker_signing_key_file)


def _make_provider(
    store: InMemoryTokenStore,
    revocation_endpoint: str | None = None,
    client_id: str = CLIENT_ID,
    client_secret: SecretStr | None = None,
    http_client: Any = None,
) -> OAuth21Provider:
    return OAuth21Provider(
        alias=ALIAS,
        targets=frozenset({ALIAS}),
        authorization_endpoint=AUTHORIZATION_ENDPOINT,
        token_endpoint=TOKEN_ENDPOINT,
        issuer=PROVIDER_ISSUER,
        scope="openid profile",
        store=store,
        client_id=client_id,
        client_secret=client_secret,
        revocation_endpoint=revocation_endpoint,
        http_client=http_client or httpx2.AsyncClient(),
    )

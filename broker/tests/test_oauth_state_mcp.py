"""Tests for the MCP OAuth discovery bootstrap state token (issue #140).

Sibling to test_oauth21.py's ``StatePayload``/``build_state_token``/
``decrypt_state_token`` tests, covering the new ``McpAuthorizePayload``/
``build_mcp_authorize_state``/``decrypt_mcp_authorize_state`` added to
oauth_state.py for the broker's own authorize->Keycloak leg of the MCP OAuth
bootstrap flow (api/mcp_oauth.py). Exercises the same tamper/replay defences
the ground rules require: a tampered or expired state token must be rejected.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from cryptography.fernet import Fernet

from af_mcp_broker.oauth_state import (
    StateTokenError,
    build_mcp_authorize_state,
    decrypt_mcp_authorize_state,
)

EXPECTED_ISS = "https://mcp.af.uchicago.edu"


def _build(cipher: Fernet, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "iss": EXPECTED_ISS,
        "pkce_verifier": "broker-verifier-abc",
        "mcp_client_id": "https://client.example/.well-known/cimd",
        "mcp_redirect_uri": "http://localhost:12345/callback",
        "mcp_state": "client-state-xyz",
        "mcp_code_challenge": "client-challenge-abc",
        "mcp_client_name": "Test MCP Client",
        "nonce": "nonce-123",
    }
    kwargs.update(overrides)
    return build_mcp_authorize_state(cipher, **kwargs)


def test_mcp_authorize_state_round_trip() -> None:
    cipher = Fernet(Fernet.generate_key())
    token = _build(cipher)

    payload = decrypt_mcp_authorize_state(cipher, token, expected_iss=EXPECTED_ISS)

    assert payload.pkce_verifier == "broker-verifier-abc"
    assert payload.mcp_client_id == "https://client.example/.well-known/cimd"
    assert payload.mcp_redirect_uri == "http://localhost:12345/callback"
    assert payload.mcp_state == "client-state-xyz"
    assert payload.mcp_code_challenge == "client-challenge-abc"
    assert payload.mcp_client_name == "Test MCP Client"
    assert payload.nonce == "nonce-123"


def test_mcp_authorize_state_expired_raises() -> None:
    cipher = Fernet(Fernet.generate_key())
    now = int(time.time())
    payload = {
        "iss": EXPECTED_ISS,
        "aud": EXPECTED_ISS,
        "pkce_verifier": "v",
        "mcp_client_id": "https://client.example/.well-known/cimd",
        "mcp_redirect_uri": "http://localhost/callback",
        "mcp_state": "s",
        "mcp_code_challenge": "c",
        "mcp_client_name": "",
        "nonce": "n",
        "iat": now - 400,
        "exp": now - 100,
    }
    token = cipher.encrypt_at_time(json.dumps(payload).encode(), now - 400).decode()

    with pytest.raises(StateTokenError):
        decrypt_mcp_authorize_state(cipher, token, expected_iss=EXPECTED_ISS)


def test_mcp_authorize_state_wrong_key_raises() -> None:
    """A tampered/replayed-under-a-different-key state token must be rejected."""
    cipher_a = Fernet(Fernet.generate_key())
    cipher_b = Fernet(Fernet.generate_key())
    token = _build(cipher_a)

    with pytest.raises(StateTokenError):
        decrypt_mcp_authorize_state(cipher_b, token, expected_iss=EXPECTED_ISS)


def test_mcp_authorize_state_mismatched_iss_raises() -> None:
    cipher = Fernet(Fernet.generate_key())
    token = _build(cipher, iss="https://other-deployment.example")

    with pytest.raises(StateTokenError):
        decrypt_mcp_authorize_state(cipher, token, expected_iss=EXPECTED_ISS)


def test_mcp_authorize_state_missing_field_raises() -> None:
    cipher = Fernet(Fernet.generate_key())
    now = int(time.time())
    payload = {
        "iss": EXPECTED_ISS,
        "aud": EXPECTED_ISS,
        "pkce_verifier": "v",
        # mcp_client_id deliberately omitted
        "mcp_redirect_uri": "http://localhost/callback",
        "mcp_state": "s",
        "mcp_code_challenge": "c",
        "mcp_client_name": "",
        "nonce": "n",
        "iat": now,
        "exp": now + 300,
    }
    token = cipher.encrypt(json.dumps(payload).encode()).decode()

    with pytest.raises(StateTokenError):
        decrypt_mcp_authorize_state(cipher, token, expected_iss=EXPECTED_ISS)

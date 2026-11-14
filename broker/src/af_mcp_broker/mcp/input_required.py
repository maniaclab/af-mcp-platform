"""Deliver "go to the portal" prompts as MCP multi-round-trip results (SEP-2322).

A tool call that needs the user to link an identity or unlock a credential
fails today with a plain-text ``ToolError`` naming a portal link. A client
that negotiated the 2026-07-28 protocol and can elicit input gets something
better: an ``InputRequiredResult`` whose single embedded form request shows the
link and asks only for a confirmation. When the user confirms, the client
retries the original call with the echoed ``request_state``; the broker
verifies that state and runs the call again, re-checking linkage and unlock
state from scratch.

The prompt never asks for a secret: its form schema has no fields. The portal
remains the only place a passphrase or credential is entered.

``request_state`` is sealed twice, for different reasons:

- the MCP transport seals every outgoing value (``request_state_security``
  below supplies a key every replica shares, so a retry may land on any pod);
- ``InputRequiredState`` is the broker's own claim set inside it, binding the
  principal, tool and service the prompt was issued for. The transport binds
  the tool name and arguments but not the broker's service, and its principal
  binding depends on an access token the broker does not use, so the broker
  checks these itself.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import hmac
import time
from typing import TYPE_CHECKING, Any

import mcp_types
from cryptography.fernet import Fernet, InvalidToken
from fastmcp.server.dependencies import fastmcp_request_ctx
from fastmcp.tools.base import InputRequiredToolResult
from mcp.server.request_state import RequestStateSecurity
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from af_mcp_broker.errors import BrokerError
from af_mcp_broker.oauth_state import StateTokenError, decrypt_claims, encrypt_claims

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from fastmcp.server.context import Context

    from af_mcp_broker.config import Settings

# How long a prompt stays answerable: long enough to link an identity or
# enter a passphrase in the portal, short enough that a leaked state is
# worthless soon after. Matches the transport's own request_state ttl.
INPUT_REQUIRED_TTL_SECONDS = 600

# Key of the one embedded request in the InputRequiredResult.
INPUT_REQUEST_KEY = "portal_action"

# The form asks for a confirmation only: no properties, so nothing to type.
_CONFIRM_ONLY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}

_STATE_TYPE = "mcp_input_required"
_STATE_FIELDS = ("iss", "aud", "iat", "exp", "typ", "sub", "tool", "svc")

# Domain separation: the transport's AES key is derived from the broker's
# state key under this label, so it never equals the key the Fernet tokens use.
_TRANSPORT_KEY_LABEL = b"af-mcp-broker/mcp-request-state/v1"


class InvalidInputRequiredStateError(BrokerError):
    """A ``request_state`` failed verification: forged, expired, or issued for a different principal, tool or service."""


class InputRequiredState:
    """Seals and verifies the broker's claims inside ``request_state``.

    *cipher* is the Fernet cipher every replica shares (``broker_state_key``);
    *issuer* binds a state to this deployment; *clock* returns seconds since
    the epoch and is injectable so expiry can be tested without sleeping.
    """

    def __init__(
        self,
        cipher: Fernet,
        *,
        issuer: str,
        ttl_seconds: int = INPUT_REQUIRED_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._cipher = cipher
        self._issuer = issuer
        self._ttl_seconds = ttl_seconds
        self._clock = clock

    def owns(self, token: str) -> bool:
        """Whether *token* was sealed by this deployment's key, expired or not.

        Tells a state this broker issued apart from one a backend minted for
        its own multi-round-trip ask, which the aggregator relays untouched.
        """
        try:
            self._cipher.decrypt(token.encode())
        except (InvalidToken, UnicodeEncodeError):
            return False
        return True

    def seal(self, *, subject: str, tool: str, service: str) -> str:
        """Return an opaque token binding *subject*, *tool* and *service*."""
        return encrypt_claims(
            self._cipher,
            {"typ": _STATE_TYPE, "sub": subject, "tool": tool, "svc": service},
            iss=self._issuer,
            ttl_seconds=self._ttl_seconds,
            now=int(self._clock()),
        )

    def verify(self, token: str, *, subject: str, tool: str, service: str) -> None:
        """Raise ``InvalidInputRequiredStateError`` unless *token* was sealed by this deployment, unexpired, for exactly this *subject*, *tool* and *service*."""
        try:
            claims = decrypt_claims(
                self._cipher,
                token,
                fields=_STATE_FIELDS,
                expected_iss=self._issuer,
                ttl_seconds=self._ttl_seconds,
                now=int(self._clock()),
            )
        except StateTokenError as exc:
            raise InvalidInputRequiredStateError(str(exc)) from exc
        expected = {
            "typ": _STATE_TYPE,
            "sub": subject,
            "tool": tool,
            "svc": service,
        }
        # Constant-time per claim; every mismatch is the same refusal.
        mismatched = [
            name
            for name, value in expected.items()
            if not hmac.compare_digest(str(claims[name]), value)
        ]
        if mismatched:
            raise InvalidInputRequiredStateError(
                f"request_state was issued for a different {', '.join(mismatched)}"
            )


def build_input_required_state(settings: Settings) -> InputRequiredState | None:
    """Return the state codec for *settings*, or None without ``broker_state_key`` (the broker then answers with the plain error, since it cannot seal a state)."""
    key = settings.broker_state_key.get_secret_value()
    if not key:
        return None
    return InputRequiredState(
        Fernet(key.encode()), issuer=settings.oauth21_effective_state_issuer
    )


def request_state_security(settings: Settings) -> RequestStateSecurity | None:
    """Return the MCP transport's request_state policy keyed from ``broker_state_key``, or None to keep the SDK's per-process key.

    A per-process key would reject a retry that lands on another replica, so
    every replica derives the same key from the shared secret. ``ttl`` matches
    ``INPUT_REQUIRED_TTL_SECONDS``.
    """
    key = settings.broker_state_key.get_secret_value()
    if not key:
        return None
    transport_key = hmac.new(
        key.encode(), _TRANSPORT_KEY_LABEL, hashlib.sha256
    ).hexdigest()
    return RequestStateSecurity(keys=[transport_key], ttl=INPUT_REQUIRED_TTL_SECONDS)


def client_supports_input_required(ctx: Context) -> bool:
    """Whether *ctx*'s client can answer an ``InputRequiredResult`` carrying a form prompt.

    Two conditions, both read from the negotiated connection rather than
    guessed: the protocol era is one that has multi-round-trip results
    (2026-07-28 and later; earlier eras have no such result type), and the
    client declared form-mode elicitation (a URL-only declaration cannot
    render the form). A client without the second would auto-retry a state-only
    result in a loop with no user in it.
    """
    request_context = ctx.request_context
    if request_context is None:
        return False
    if request_context.protocol_version not in MODERN_PROTOCOL_VERSIONS:
        return False
    capabilities = ctx.session.client_capabilities
    if capabilities is None or capabilities.elicitation is None:
        return False
    elicitation = capabilities.elicitation
    # An empty `elicitation: {}` is form mode by the spec's backward-compat rule.
    return elicitation.form is not None or elicitation.url is None


def input_required_result(prompt: str, request_state: str) -> InputRequiredToolResult:
    """Return the tool result asking the user to act in the portal, then confirm."""
    return InputRequiredToolResult(
        mcp_types.InputRequiredResult(
            input_requests={
                INPUT_REQUEST_KEY: mcp_types.ElicitRequest(
                    params=mcp_types.ElicitRequestFormParams(
                        message=prompt,
                        requested_schema=_CONFIRM_ONLY_SCHEMA,
                    )
                )
            },
            request_state=request_state,
        )
    )


# The wire names of the continuation fields on a tools/call request.
_CONTINUATION_PARAMS = ("inputResponses", "requestState")


@contextlib.contextmanager
def without_continuation() -> Iterator[None]:
    """Hide this request's ``inputResponses``/``requestState`` from everything downstream.

    The proxy relays both to a modern backend so a backend's own multi-round-trip
    ask can be answered. On the retry of the broker's own prompt they are
    the broker's: a sealed state naming the principal, and the user's answer to
    a question the backend never asked. The backend would reject the state, and
    must not see it. Rebinds the request context for the duration of the block
    with those two params removed; the SDK documents ``dataclasses.replace`` of
    the request context as how to alter what a handler sees.
    """
    request_context = fastmcp_request_ctx.get()
    params = request_context._srctx.params if request_context is not None else None
    if request_context is None or not isinstance(params, dict):
        yield
        return
    stripped = {k: v for k, v in params.items() if k not in _CONTINUATION_PARAMS}
    token = fastmcp_request_ctx.set(
        dataclasses.replace(
            request_context,
            _srctx=dataclasses.replace(request_context._srctx, params=stripped),
        )
    )
    try:
        yield
    finally:
        fastmcp_request_ctx.reset(token)

"""Deliver "go to the portal" prompts as MCP multi-round-trip results (SEP-2322).

A tool call that needs the user to link an identity or unlock a credential
fails today with a plain-text ``ToolError`` naming a portal link. A client
that negotiated the 2026-07-28 protocol and can elicit input gets something
better: an ``InputRequiredResult`` whose single embedded form request shows the
link and asks only for a confirmation. When the user confirms, the client
retries the original call with the echoed ``request_state``; the broker
verifies that state and runs the call again, re-checking linkage and unlock
state from scratch.

A handshake-era client that can elicit is asked the same thing as a
server-initiated form-mode elicitation within the request (``elicit_portal_action``),
and a client that can do neither gets the plain error. ``prompt_route`` is the
one place that chooses.

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
import enum
import hashlib
import hmac
import time
from typing import TYPE_CHECKING, Any

import mcp_types
import structlog
from cryptography.fernet import Fernet, InvalidToken
from fastmcp.server.dependencies import fastmcp_request_ctx
from fastmcp.server.elicitation import AcceptedElicitation
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

logger = structlog.get_logger(__name__)

# The two answers a handshake-era elicitation offers.
ELICIT_RETRY_OPTION = "I've linked it \u2014 try again"
ELICIT_CANCEL_OPTION = "Cancel"

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

    The policy is fixed when ``build_aggregator`` constructs the ``FastMCP``;
    ``populate_aggregator`` cannot swap it afterwards (the SDK builds its
    request-state boundary at construction). ``app.py`` builds the aggregator
    from ``Settings()`` read from the environment, the same source the
    lifespan's settings come from, so the two agree in a deployment.
    """
    key = settings.broker_state_key.get_secret_value()
    if not key:
        return None
    transport_key = hmac.new(
        key.encode(), _TRANSPORT_KEY_LABEL, hashlib.sha256
    ).hexdigest()
    return RequestStateSecurity(keys=[transport_key], ttl=INPUT_REQUIRED_TTL_SECONDS)


class PromptRoute(enum.Enum):
    """How a blocked call asks the user to act in the portal, decided by what the client negotiated."""

    # 2026-07-28+ protocol and form elicitation: an InputRequiredResult.
    INPUT_REQUIRED = "input_required"
    # Handshake-era protocol and form elicitation: a server-initiated
    # form-mode elicitation, answered within the same request.
    ELICIT = "elicit"
    # Anything else: the plain error text.
    PLAIN = "plain"


def prompt_route(ctx: Context, *, can_seal_state: bool) -> PromptRoute:
    """Decide how to prompt *ctx*'s client; the one place that branches on era and capability.

    Read from the negotiated connection, not guessed from a client name.
    Both prompting routes need the client to have declared form-mode
    elicitation (a URL-only declaration cannot render the form; an empty
    ``elicitation: {}`` is form mode by the spec's backward-compat rule). A
    modern client without it would auto-retry a state-only result in a loop
    with no user in it, so it gets the plain error.

    The input-required route additionally needs *can_seal_state*: without a
    ``broker_state_key`` there is nothing to seal ``request_state`` with. The
    handshake-era route is a synchronous round trip and needs no state.
    """
    request_context = ctx.request_context
    if request_context is None:
        return PromptRoute.PLAIN
    capabilities = ctx.session.client_capabilities
    if capabilities is None or capabilities.elicitation is None:
        return PromptRoute.PLAIN
    elicitation = capabilities.elicitation
    if elicitation.form is None and elicitation.url is not None:
        return PromptRoute.PLAIN
    if request_context.protocol_version in MODERN_PROTOCOL_VERSIONS:
        return PromptRoute.INPUT_REQUIRED if can_seal_state else PromptRoute.PLAIN
    return PromptRoute.ELICIT


async def elicit_portal_action(ctx: Context, prompt: str) -> bool:
    """Ask a handshake-era client to confirm it has acted in the portal; return True only if the user chose to retry.

    A decline, a cancel and a failure of the round trip all return False, so
    the caller falls back to the plain error. A failure is logged at warning
    level with its type rather than swallowed: it is a client or transport
    fault worth seeing, not an expected outcome.
    """
    try:
        result = await ctx.elicit(prompt, [ELICIT_RETRY_OPTION, ELICIT_CANCEL_OPTION])  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 -- falls back to the plain error, logged
        logger.warning(
            "mcp.portal_prompt_elicit_failed",
            exc_type=type(exc).__name__,
            error=str(exc),
        )
        return False
    return (
        isinstance(result, AcceptedElicitation) and result.data == ELICIT_RETRY_OPTION
    )


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

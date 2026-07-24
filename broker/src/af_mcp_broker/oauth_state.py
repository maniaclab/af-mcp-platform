"""Stateless, AEAD-encrypted OAuth 2.1 flow state.

See issue #66's "State token design" section for the full rationale. The
``state`` parameter round-tripped between ``/v1/oauth/authorize/{alias}`` and
``/v1/oauth/callback/{alias}`` carries everything the callback needs to
resume the flow (PKCE verifier, return URL, initiating subject) without any
server-side session storage — broker replicas share no session store.

Because the PKCE verifier travels inside it, the token uses authenticated
*encryption* (Fernet — AES-128-CBC + HMAC-SHA256), not just a signature: a
signed-only token would leak the verifier to anyone with access to logs,
browser history, or a reverse proxy.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cryptography.fernet import InvalidToken

if TYPE_CHECKING:
    from cryptography.fernet import Fernet

# TTL for the encrypted state token, in seconds — also embedded as `exp`
# inside the payload so validation is belt-and-braces even though Fernet's
# own `ttl=` argument already rejects tokens minted more than this long ago.
STATE_TOKEN_TTL_SECONDS = 300

# Raw byte length of the nonce embedded in the state token and mirrored in
# the browser cookie (128 bits, per issue #66's state token design).
_NONCE_BYTES = 16

# Cookie carrying the nonce back to the callback; scoped narrowly to the
# callback path so it is never sent on unrelated /v1 requests.
NONCE_COOKIE_NAME = "oauth_state_nonce"
NONCE_COOKIE_PATH = "/v1/oauth/callback/"

_STATE_PAYLOAD_FIELDS = (
    "iss",
    "aud",
    "sub",
    "alias",
    "pkce_verifier",
    "return_url",
    "nonce",
    "iat",
    "exp",
)


class StateTokenError(Exception):
    """Raised for any invalid, expired, malformed, or mis-audienced state token."""


@dataclass(frozen=True)
class StatePayload:
    iss: str
    aud: str
    sub: str
    alias: str
    pkce_verifier: str
    return_url: str
    nonce: str
    iat: int
    exp: int


def generate_nonce() -> str:
    """Return a fresh 128-bit random nonce, base64url-encoded (no padding).

    Padding is stripped so the value is safe to use unquoted as a cookie
    value -- ``=`` is technically legal in a cookie-octet, but some cookie
    codecs (including Python's stdlib ``http.cookies``) quote values that
    contain it, and quoting round-trips inconsistently across HTTP clients.
    """
    return (
        base64.urlsafe_b64encode(secrets.token_bytes(_NONCE_BYTES)).decode().rstrip("=")
    )


def generate_pkce_pair() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for PKCE S256 (RFC 7636).

    ``code_verifier`` is 32 random bytes, base64url-encoded without padding
    (43 characters — the RFC's recommended length, within the 43-128 char
    range of unreserved characters it requires).
    """
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


# A relative path starting with exactly one '/' (rejects absolute URLs,
# scheme-relative '//host' URLs, and anything not starting with '/').
_RETURN_URL_RE = re.compile(r"^/(?!/)[^\r\n]*$")


def sanitize_return_url(return_url: str | None) -> str:
    """Validate *return_url* is a safe same-origin relative path.

    Only relative paths starting with a single ``/`` are allowed — no
    scheme, no host, no leading ``//`` (which browsers treat as
    protocol-relative and would silently redirect off-site), and no ``..``
    path-traversal segments. Returns ``"/"`` when *return_url* is None.
    Raises ``ValueError`` for anything else, so callers can turn it into a
    400.
    """
    if return_url is None:
        return "/"
    if not _RETURN_URL_RE.match(return_url):
        msg = f"return_url must be a relative path starting with '/': {return_url!r}"
        raise ValueError(msg)
    path_only = return_url.split("?", 1)[0].split("#", 1)[0]
    if ".." in path_only.split("/"):
        msg = f"return_url must not contain '..' path segments: {return_url!r}"
        raise ValueError(msg)
    return return_url


def append_linked_query_param(return_url: str, alias: str) -> str:
    """Append ``linked=<alias>`` to *return_url*'s query string.

    Lets the OAuth 2.1 callback tell the portal which provider was just
    linked, so the Identities page can show a confirmation banner without an
    extra round trip. Preserves any existing query string rather than
    clobbering it — a plain ``f"{return_url}?linked={alias}"`` would double
    up on ``?`` if *return_url* already has query parameters.
    """
    parsed = urlparse(return_url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("linked", alias))
    return urlunparse(parsed._replace(query=urlencode(query)))


def build_state_token(
    cipher: Fernet,
    *,
    iss: str,
    sub: str,
    alias: str,
    pkce_verifier: str,
    return_url: str,
    nonce: str,
) -> str:
    """Encrypt an OAuth flow's in-flight state into an opaque token."""
    now = int(datetime.now(UTC).timestamp())
    payload = {
        "iss": iss,
        "aud": iss,
        "sub": sub,
        "alias": alias,
        "pkce_verifier": pkce_verifier,
        "return_url": return_url,
        "nonce": nonce,
        "iat": now,
        "exp": now + STATE_TOKEN_TTL_SECONDS,
    }
    return cipher.encrypt(json.dumps(payload).encode()).decode()


def decrypt_state_token(
    cipher: Fernet, token: str, *, expected_iss: str
) -> StatePayload:
    """Decrypt and validate a state token minted by ``build_state_token``.

    Raises ``StateTokenError`` on any failure: Fernet TTL/HMAC failure,
    malformed JSON, missing fields, an ``iss``/``aud`` that does not match
    *expected_iss* (rejects tokens minted for another deployment), or an
    already-past ``exp`` (belt-and-braces on top of Fernet's own ``ttl=``
    enforcement).
    """
    try:
        raw = cipher.decrypt(token.encode(), ttl=STATE_TOKEN_TTL_SECONDS)
    except InvalidToken as exc:
        raise StateTokenError("state token is invalid or expired") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StateTokenError("state token payload is not valid JSON") from exc

    if not isinstance(data, dict):
        raise StateTokenError("state token payload is not a JSON object")

    missing = [k for k in _STATE_PAYLOAD_FIELDS if k not in data]
    if missing:
        raise StateTokenError(f"state token missing fields: {', '.join(missing)}")

    if data["iss"] != expected_iss or data["aud"] != expected_iss:
        raise StateTokenError("state token iss/aud does not match this deployment")

    now = int(datetime.now(UTC).timestamp())
    if data["exp"] < now:
        raise StateTokenError("state token has expired")

    return StatePayload(**{k: data[k] for k in _STATE_PAYLOAD_FIELDS})

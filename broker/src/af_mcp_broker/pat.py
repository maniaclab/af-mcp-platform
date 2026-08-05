"""Broker-issued identity PAT (Personal Access Token) format and hashing (issue #144 step 2a).

Replaces the RFC 8693 token-exchange bootstrap `POST /v1/tokens` used to
mint (see ``api/tokens.py``): instead of exchanging the caller's Keycloak JWT
for another JWT, the broker mints its own opaque, static credential.

Format, GitHub/Stripe/OpenAI-style::

    mcp_pat_<lookup_id>_<secret>

* ``mcp_pat_`` is a stable prefix -- makes tokens greppable by secret
  scanners and recognizable in logs/error messages without decoding anything.
* ``lookup_id`` is non-secret (128-bit random, hex-encoded -- hex rather than
  base64/base64url specifically so it never contains ``_``, which matters
  for parsing below). It lets validation be a direct fetch by lookup_id
  against the PAT store (token_registry.py) rather than a scan over every
  stored hash.
* ``secret`` is the actual credential (256-bit random, urlsafe-base64).
  Only its SHA-256 hash is ever persisted (see ``hash_secret``) -- the
  plaintext returned by ``mint_pat()`` is the only time it exists outside
  this process's stack.

Parsing splits on the FIRST ``_`` after the prefix: since ``lookup_id`` is
hex-only (no underscores can appear in it), this unambiguously separates
``lookup_id`` from ``secret`` even though ``secret``'s own alphabet
(urlsafe-base64) can itself contain underscores.

Hashing: plain SHA-256, deliberately not bcrypt/argon2. Those exist to slow
down brute-forcing a *low-entropy* human-chosen password; a 256-bit random
secret is not brute-forcible by any means a slow KDF would meaningfully
defend against, and paying a deliberately-slow hash on every single ``/mcp``
request would be a self-inflicted latency bug for zero security benefit. Do
not "harden" this later without re-reading this paragraph.

Comparison is constant-time (``hmac.compare_digest``) so response timing
cannot be used to narrow down a correct hash byte-by-byte.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

# Stable, greppable prefix -- see the module docstring.
PAT_PREFIX = "mcp_pat_"

# 128-bit lookup id, hex-encoded (32 hex chars) -- see the module docstring
# for why hex specifically (no '_' in the alphabet).
_LOOKUP_ID_BYTES = 16

# 256-bit secret, urlsafe-base64-encoded.
_SECRET_BYTES = 32


def hash_secret(secret: str) -> str:
    """Return the hex-encoded SHA-256 digest of *secret* -- see the module docstring for why plain SHA-256 is correct here."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_secret(secret: str, secret_hash: str) -> bool:
    """Constant-time comparison of *secret* against a previously stored ``hash_secret()`` digest."""
    return hmac.compare_digest(hash_secret(secret), secret_hash)


def mint_pat() -> tuple[str, str, str]:
    """Generate a new PAT.

    Returns ``(plaintext, lookup_id, secret_hash)``. *plaintext* is the full
    ``mcp_pat_<lookup_id>_<secret>`` string -- the caller must return it to
    the user exactly once and persist only *lookup_id*/*secret_hash* (see
    token_registry.py's ``TokenRecord``).
    """
    lookup_id = secrets.token_hex(_LOOKUP_ID_BYTES)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    plaintext = f"{PAT_PREFIX}{lookup_id}_{secret}"
    return plaintext, lookup_id, hash_secret(secret)


def parse_pat(token: str) -> tuple[str, str] | None:
    """Split a ``mcp_pat_<lookup_id>_<secret>`` string into ``(lookup_id, secret)``.

    Returns None for anything that doesn't match the shape (wrong prefix, or
    missing lookup_id/secret after it) -- deliberately not distinguishing
    *which* part is malformed, since the caller (pat_auth.py) treats every
    parse failure the same as an unknown/wrong credential.
    """
    if not token.startswith(PAT_PREFIX):
        return None
    remainder = token[len(PAT_PREFIX) :]
    lookup_id, sep, secret = remainder.partition("_")
    if not sep or not lookup_id or not secret:
        return None
    return lookup_id, secret

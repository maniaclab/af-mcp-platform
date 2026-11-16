"""Helpers shared by the tests of ``test_broker_issued`` and the app-level tests in ``test_broker_issued_app``."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import TYPE_CHECKING, Any

import jwt
from jwt.algorithms import RSAAlgorithm

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import rsa


ISSUER_URL = "https://mcp.example.com"


# The documented claim set (issue #162) -- identity assertion, nothing more.
# Tests assert EXACT equality against these: any extra claim (a permission,
# a group, anything) is a design failure, not an additive change.
_BASE_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "jti"})


def _rfc7638_thumbprint(key: rsa.RSAPrivateKey) -> str:
    """Independently compute the RFC 7638 JWK thumbprint an issuer's kid must equal."""
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    canonical = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_against_jwks(
    token: str, jwks: dict[str, Any], *, audience: str, issuer: str = ISSUER_URL
) -> dict[str, Any]:
    """Validate *token* exactly the way an AF-native consumer would.

    Select the JWK by the token header's ``kid``, then verify signature,
    ``aud``, ``iss``, and ``exp`` with a standard library -- no
    broker-internal shortcuts.
    """
    kid = jwt.get_unverified_header(token)["kid"]
    matches = [k for k in jwks["keys"] if k["kid"] == kid]
    assert matches, f"no JWKS key matches kid={kid!r}"
    public_key = RSAAlgorithm.from_jwk(json.dumps(matches[0]))
    return jwt.decode(
        token,
        public_key,  # type: ignore[arg-type]  # JWKS only has public keys
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
        options={"verify_exp": True},
    )


def _find_service_provider(state: Any, service_name: str) -> Any:
    """Return one backend's ``_ObservableProxyProvider`` from the app's recorded providers."""
    return state.broker.mcp_aggregator.backend_providers.get(service_name)

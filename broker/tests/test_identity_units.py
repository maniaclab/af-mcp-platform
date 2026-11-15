"""Direct unit tests for pure helpers in ``af_mcp_broker.identity``."""

from __future__ import annotations

import pytest

from af_mcp_broker.identity import _extract_principal, _select_jwk, issuer_is_local

_KEY_A = {"kid": "a", "kty": "RSA", "n": "AA"}
_KEY_B = {"kid": "b", "kty": "RSA", "n": "BB"}


class TestIssuerIsLocal:
    @pytest.mark.parametrize(
        "issuer",
        [
            "http://localhost:8080/realms/af",
            "http://127.0.0.1/realms/af",
            "http://[::1]:8080/realms/af",
            "http://LOCALHOST/realms/af",
            "http://kc.localhost/realms/af",
            "http://kc.local/realms/af",
            "http://kc.test/realms/af",
        ],
    )
    def test_local_hosts(self, issuer: str) -> None:
        assert issuer_is_local(issuer) is True

    @pytest.mark.parametrize(
        "issuer",
        [
            "https://keycloak.example.org/realms/af",
            "https://evil-localhost.com/realms/af",
            "https://localhost.example.org/realms/af",
            "https://notlocal/realms/af",
            "https://example.test.org/realms/af",
        ],
    )
    def test_remote_hosts(self, issuer: str) -> None:
        assert issuer_is_local(issuer) is False

    def test_unparseable_issuer_fails_closed(self) -> None:
        # urlparse raises ValueError("Invalid IPv6 URL") for an unclosed bracket.
        assert issuer_is_local("http://[::1/realms/af") is False

    @pytest.mark.parametrize(
        "issuer", ["", "not-a-url", "/realms/af", "http:///realms/af"]
    )
    def test_missing_hostname_fails_closed(self, issuer: str) -> None:
        assert issuer_is_local(issuer) is False


class TestSelectJwk:
    def test_kid_match_returns_matching_key(self) -> None:
        assert _select_jwk([_KEY_A, _KEY_B], "b") is _KEY_B

    def test_kid_without_match_returns_none_even_with_single_key(self) -> None:
        assert _select_jwk([_KEY_A], "other") is None

    def test_no_kid_single_key_falls_back_to_it(self) -> None:
        assert _select_jwk([_KEY_A], None) is _KEY_A

    @pytest.mark.parametrize("keys", [[], [_KEY_A, _KEY_B], [_KEY_A, _KEY_B, _KEY_A]])
    def test_no_kid_without_exactly_one_key_returns_none(
        self, keys: list[dict[str, str]]
    ) -> None:
        assert _select_jwk(keys, None) is None


class TestExtractPrincipal:
    def test_maps_subject_email_and_raw_token(self) -> None:
        principal = _extract_principal({"sub": "u1", "email": "u1@example.org"}, "tok")
        assert principal.subject == "u1"
        assert principal.email == "u1@example.org"
        assert principal.raw_token is not None
        assert principal.raw_token.get_secret_value() == "tok"

    def test_missing_claims_default_to_empty_strings(self) -> None:
        principal = _extract_principal({}, "tok")
        assert principal.subject == ""
        assert principal.email == ""

    def test_groups_and_posix_claims_are_ignored(self) -> None:
        principal = _extract_principal(
            {
                "sub": "u1",
                "groups": ["admins"],
                "posix": {"uid": 1, "gid": 2, "unixname": "x"},
            },
            "tok",
        )
        assert principal.groups == []
        assert principal.uid is None
        assert principal.gid is None
        assert principal.unixname is None

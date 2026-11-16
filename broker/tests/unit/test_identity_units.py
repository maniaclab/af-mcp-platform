"""Direct unit tests for pure helpers in ``af_mcp_broker.identity``."""

from __future__ import annotations

import json

import pytest

from af_mcp_broker.identity import (
    _extract_principal,
    _select_jwk,
    build_dev_principal,
    issuer_is_local,
)

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
            "https://evillocalhost/realms/af",
            "https://corp.mytest/realms/af",
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


def _dev_payload(**overrides: object) -> str:
    payload: dict[str, object] = {"uid": 1000, "gid": 1001, "unixname": "devuser"}
    payload.update(overrides)
    return json.dumps(payload)


class TestBuildDevPrincipal:
    def test_minimal_payload_defaults_email_and_groups_to_empty(self) -> None:
        principal = build_dev_principal(_dev_payload())

        assert principal.uid == 1000
        assert principal.gid == 1001
        assert principal.unixname == "devuser"
        assert principal.email == ""
        assert principal.groups == []

    def test_subject_marks_the_principal_as_bypassed_traffic(self) -> None:
        assert build_dev_principal(_dev_payload()).subject == "dev-insecure:devuser"

    def test_forwards_no_credential(self) -> None:
        principal = build_dev_principal(_dev_payload())

        assert principal.raw_token is not None
        assert principal.raw_token.get_secret_value() == ""

    def test_groups_and_email_are_carried_through(self) -> None:
        principal = build_dev_principal(
            _dev_payload(groups=["af-users", "admins"], email="d@localhost")
        )

        assert principal.groups == ["af-users", "admins"]
        assert principal.email == "d@localhost"

    def test_numeric_strings_are_accepted_for_uid_and_gid(self) -> None:
        principal = build_dev_principal(_dev_payload(uid="7", gid="8"))

        assert (principal.uid, principal.gid) == (7, 8)

    def test_malformed_json_is_a_runtime_error_naming_the_position(self) -> None:
        with pytest.raises(RuntimeError, match=r"not valid JSON.*line 1, column"):
            build_dev_principal("{not json")

    @pytest.mark.parametrize("payload", ["[]", '"x"', "7", "null"])
    def test_non_object_json_is_rejected(self, payload: str) -> None:
        with pytest.raises(RuntimeError, match="must be a JSON object"):
            build_dev_principal(payload)

    @pytest.mark.parametrize(
        ("missing", "expected"),
        [
            (["uid"], "uid"),
            (["gid", "unixname"], "gid, unixname"),
            (["uid", "gid", "unixname"], "gid, uid, unixname"),
        ],
    )
    def test_missing_required_keys_are_named_in_sorted_order(
        self, missing: list[str], expected: str
    ) -> None:
        payload = json.loads(_dev_payload())
        for key in missing:
            del payload[key]

        with pytest.raises(RuntimeError, match=f"missing required keys: {expected}$"):
            build_dev_principal(json.dumps(payload))

    @pytest.mark.parametrize(
        "overrides",
        [{"uid": "root"}, {"gid": None}, {"uid": [1]}, {"gid": "1.5"}],
    )
    def test_non_integer_uid_or_gid_is_rejected(
        self, overrides: dict[str, object]
    ) -> None:
        with pytest.raises(RuntimeError, match="uid/gid must be integers"):
            build_dev_principal(_dev_payload(**overrides))

    @pytest.mark.parametrize(
        "groups",
        ["af-users", {"a": 1}, None, ["ok", 1], [1, 2], [["nested"]]],
    )
    def test_groups_must_be_a_list_of_strings(self, groups: object) -> None:
        with pytest.raises(RuntimeError, match="'groups' must be a list of strings"):
            build_dev_principal(_dev_payload(groups=groups))

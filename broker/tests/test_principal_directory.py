"""Tests for KeycloakPrincipalDirectory (issue #144 step 2a).

Fakes the Keycloak Admin REST API + token endpoint via monkeypatching
``principal_directory.get_http_client`` -- never a real Keycloak.
"""

from __future__ import annotations

from typing import Any

import pytest

from af_mcp_broker import principal_directory as principal_directory_module
from af_mcp_broker.config import Settings
from af_mcp_broker.principal_directory import (
    KeycloakPrincipalDirectory,
    PrincipalNotFoundError,
    _admin_base_url,
)

ISSUER = "https://keycloak.test/realms/connect"


class _FakeResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeKeycloakAdmin:
    def __init__(self) -> None:
        self.token_calls: list[dict[str, Any]] = []
        self.token_urls: list[str] = []
        self.get_calls: list[str] = []
        self.token_expires_in = 3600
        self.users: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, list[dict[str, Any]]] = {}

    async def post(self, url: str, *, data: dict[str, Any], **kwargs: Any):
        assert data["grant_type"] == "client_credentials"
        self.token_calls.append(data)
        self.token_urls.append(url)
        return _FakeResponse(
            200,
            {"access_token": "fake-admin-token", "expires_in": self.token_expires_in},
        )

    async def get(self, url: str, *, headers: dict[str, str], **kwargs: Any):
        self.get_calls.append(url)
        assert headers["Authorization"] == "Bearer fake-admin-token"
        if url.endswith("/groups"):
            principal_id = url.split("/users/", maxsplit=1)[1].split(
                "/groups", maxsplit=1
            )[0]
            return _FakeResponse(200, self.groups.get(principal_id, []))
        principal_id = url.split("/users/", maxsplit=1)[1]
        user = self.users.get(principal_id)
        if user is None:
            return _FakeResponse(404, {})
        return _FakeResponse(200, user)


@pytest.fixture
def fake_admin(monkeypatch: pytest.MonkeyPatch) -> _FakeKeycloakAdmin:
    fake = _FakeKeycloakAdmin()
    monkeypatch.setattr(principal_directory_module, "get_http_client", lambda: fake)
    return fake


@pytest.fixture
def settings() -> Settings:
    return Settings(oidc_issuer=ISSUER)


def _directory(settings: Settings) -> KeycloakPrincipalDirectory:
    return KeycloakPrincipalDirectory(settings, "admin-client", "admin-secret")


def test_admin_base_url_derivation() -> None:
    assert (
        _admin_base_url("https://kc.example.com/realms/connect")
        == "https://kc.example.com/admin/realms/connect"
    )


def test_admin_base_url_rejects_issuer_without_realms_segment() -> None:
    with pytest.raises(ValueError, match="realms"):
        _admin_base_url("https://kc.example.com/not-a-realm-path")


async def test_backchannel_calls_use_internal_url_when_set(
    fake_admin: _FakeKeycloakAdmin,
) -> None:
    """oidc_internal_url must redirect BOTH the admin-token grant and the
    Admin REST API queries; oidc_issuer stays the external identity only."""
    internal = "http://keycloak.svc.test:8080/realms/connect"
    fake_admin.users["user-123"] = {
        "attributes": {"uid": ["1"], "gid": ["1"], "unixname": ["u"]},
    }
    fake_admin.groups["user-123"] = []

    directory = _directory(Settings(oidc_issuer=ISSUER, oidc_internal_url=internal))
    await directory.resolve("user-123")

    assert fake_admin.token_urls == [f"{internal}/protocol/openid-connect/token"]
    admin_base = "http://keycloak.svc.test:8080/admin/realms/connect"
    assert fake_admin.get_calls
    for url in fake_admin.get_calls:
        assert url.startswith(f"{admin_base}/users/")


async def test_resolve_returns_attributes_and_groups(
    settings: Settings, fake_admin: _FakeKeycloakAdmin
) -> None:
    fake_admin.users["user-123"] = {
        "id": "user-123",
        "email": "user@example.org",
        "attributes": {"uid": ["50123"], "gid": ["5000"], "unixname": ["auser"]},
    }
    fake_admin.groups["user-123"] = [
        {"id": "g1", "name": "atlas", "path": "/atlas"},
        {"id": "g2", "name": "af-admins", "path": "/af-admins"},
    ]

    directory = _directory(settings)
    attrs = await directory.resolve("user-123")

    assert attrs.uid == 50123
    assert attrs.gid == 5000
    assert attrs.unixname == "auser"
    assert attrs.email == "user@example.org"
    assert attrs.groups == ["atlas", "af-admins"]


async def test_resolve_uses_group_name_not_path(
    settings: Settings, fake_admin: _FakeKeycloakAdmin
) -> None:
    """AF Keycloak's Group Membership mapper is configured with 'Full group
    path: OFF' (docs/auth.md), so JWTs carry bare group names -- this
    directory must match that shape exactly, or policy.yaml's
    group_permissions lookups would silently never match for PAT callers."""
    fake_admin.users["user-123"] = {
        "attributes": {"uid": ["1"], "gid": ["1"], "unixname": ["u"]},
    }
    fake_admin.groups["user-123"] = [{"name": "atlas", "path": "/some/nested/atlas"}]

    directory = _directory(settings)
    attrs = await directory.resolve("user-123")

    assert attrs.groups == ["atlas"]


async def test_resolve_unknown_user_raises_principal_not_found(
    settings: Settings, fake_admin: _FakeKeycloakAdmin
) -> None:
    directory = _directory(settings)
    with pytest.raises(PrincipalNotFoundError):
        await directory.resolve("no-such-user")


async def test_resolve_leaves_missing_posix_attributes_none(
    settings: Settings, fake_admin: _FakeKeycloakAdmin
) -> None:
    """Issue #148: a Keycloak user with no POSIX profile attributes must
    resolve successfully -- not raise -- with the missing fields left None.
    This is what lets a PAT for such a user authenticate at all."""
    fake_admin.users["user-123"] = {
        "attributes": {"uid": ["1"]}
    }  # gid/unixname missing
    fake_admin.groups["user-123"] = []

    directory = _directory(settings)
    attrs = await directory.resolve("user-123")

    assert attrs.uid == 1
    assert attrs.gid is None
    assert attrs.unixname is None


async def test_resolve_all_posix_attributes_absent(
    settings: Settings, fake_admin: _FakeKeycloakAdmin
) -> None:
    """A Keycloak user with no POSIX attributes at all (not even a partial
    set) resolves successfully with every POSIX field None."""
    fake_admin.users["user-123"] = {"attributes": {}}
    fake_admin.groups["user-123"] = []

    directory = _directory(settings)
    attrs = await directory.resolve("user-123")

    assert attrs.uid is None
    assert attrs.gid is None
    assert attrs.unixname is None


async def test_resolve_uses_configured_attribute_names(
    fake_admin: _FakeKeycloakAdmin,
) -> None:
    """Issue #148: a facility whose POSIX identity is LDAP-federated under
    different profile attribute names (the common spelling is
    uidNumber/gidNumber) must be able to point the directory at those
    instead of AF's own uid/gid/unixname convention."""
    settings = Settings(
        oidc_issuer=ISSUER,
        posix_uid_attribute="uidNumber",
        posix_gid_attribute="gidNumber",
        posix_unixname_attribute="cn",
    )
    fake_admin.users["user-123"] = {
        "attributes": {
            "uidNumber": ["50123"],
            "gidNumber": ["5000"],
            "cn": ["auser"],
            # AF's own default-named attributes are present too, to prove
            # the configured names -- not the defaults -- are what's read.
            "uid": ["1"],
            "gid": ["1"],
            "unixname": ["someone-else"],
        }
    }
    fake_admin.groups["user-123"] = []

    directory = _directory(settings)
    attrs = await directory.resolve("user-123")

    assert attrs.uid == 50123
    assert attrs.gid == 5000
    assert attrs.unixname == "auser"


async def test_resolve_defaults_to_af_attribute_names(
    settings: Settings, fake_admin: _FakeKeycloakAdmin
) -> None:
    """Settings() without overrides reproduces the old hardcoded uid/gid/unixname behavior."""
    assert settings.posix_uid_attribute == "uid"
    assert settings.posix_gid_attribute == "gid"
    assert settings.posix_unixname_attribute == "unixname"


async def test_resolve_respects_group_full_path_setting(
    fake_admin: _FakeKeycloakAdmin,
) -> None:
    """A site whose Group Membership mapper has 'Full group path' ON must be
    able to make this directory match `path` instead of `name` -- otherwise
    every PAT-authenticated permission lookup silently returns nothing even
    though the equivalent JWT path works fine (issue #148)."""
    settings = Settings(oidc_issuer=ISSUER, principal_directory_group_full_path=True)
    fake_admin.users["user-123"] = {
        "attributes": {"uid": ["1"], "gid": ["1"], "unixname": ["u"]},
    }
    fake_admin.groups["user-123"] = [{"name": "atlas", "path": "/atlas/users"}]

    directory = _directory(settings)
    attrs = await directory.resolve("user-123")

    assert attrs.groups == ["/atlas/users"]


async def test_group_full_path_defaults_to_false(settings: Settings) -> None:
    assert settings.principal_directory_group_full_path is False


async def test_resolve_defaults_email_to_empty_string_when_absent(
    settings: Settings, fake_admin: _FakeKeycloakAdmin
) -> None:
    fake_admin.users["user-123"] = {
        "attributes": {"uid": ["1"], "gid": ["1"], "unixname": ["u"]},
    }
    fake_admin.groups["user-123"] = []

    directory = _directory(settings)
    attrs = await directory.resolve("user-123")

    assert attrs.email == ""


async def test_admin_token_is_cached_across_calls(
    settings: Settings, fake_admin: _FakeKeycloakAdmin
) -> None:
    fake_admin.users["user-123"] = {
        "attributes": {"uid": ["1"], "gid": ["1"], "unixname": ["u"]},
    }
    fake_admin.groups["user-123"] = []

    directory = _directory(settings)
    await directory.resolve("user-123")
    await directory.resolve("user-123")

    assert len(fake_admin.token_calls) == 1


async def test_admin_token_refreshes_once_expired(
    settings: Settings, fake_admin: _FakeKeycloakAdmin
) -> None:
    fake_admin.users["user-123"] = {
        "attributes": {"uid": ["1"], "gid": ["1"], "unixname": ["u"]},
    }
    fake_admin.groups["user-123"] = []
    fake_admin.token_expires_in = 30  # inside the refresh buffer immediately

    directory = _directory(settings)
    await directory.resolve("user-123")
    await directory.resolve("user-123")

    assert len(fake_admin.token_calls) == 2

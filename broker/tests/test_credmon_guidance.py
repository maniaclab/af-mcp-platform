"""Tests for what agents are told about credentials in HTCondor jobs (docs/credmon.md).

Agents learn the *pattern* from the session instructions and the per-kind
detail (file format, environment variable) from af_list_identities -- both
built from ``JobCredentialGuide``. Kinds are a closed set fixed by the broker's
redeem endpoints, so their usage lives in code; the coverage test below makes
adding a kind without describing it fail CI.
"""

from __future__ import annotations

from typing import get_args

import pytest

from af_mcp_broker.config import CredmonKindName, Settings
from af_mcp_broker.credmon.guidance import (
    KIND_USAGE,
    JobCredentialGuide,
    wired_kinds,
)


def test_every_credmon_kind_has_usage() -> None:
    assert set(KIND_USAGE) == set(get_args(CredmonKindName))


def _guide(kinds: set[str], prefix: str = "af_") -> JobCredentialGuide:
    return JobCredentialGuide(service_prefix=prefix, kinds=frozenset(kinds))


@pytest.mark.parametrize(
    ("provider_type", "service", "env"),
    [
        ("krb5-token", "af_krb5", "KRB5CCNAME=FILE:$_CONDOR_CREDS/af_krb5.use"),
        ("x509", "af_x509", "X509_USER_PROXY=$_CONDOR_CREDS/af_x509.use"),
    ],
)
def test_job_credential_for_wired_provider_type(
    provider_type: str, service: str, env: str
) -> None:
    cred = _guide({"krb5", "x509"}).for_provider_type(provider_type)

    assert cred is not None
    assert cred.service == service
    assert cred.path == f"$_CONDOR_CREDS/{service}.use"
    assert cred.env == env
    assert cred.format


def test_servicex_has_a_format_but_no_env_variable() -> None:
    cred = _guide({"servicex"}).for_provider_type("servicex-token")

    assert cred is not None
    assert cred.service == "af_servicex"
    assert "access_token" in cred.format
    assert cred.env is None


def test_configured_prefix_is_used() -> None:
    cred = _guide({"krb5"}, prefix="site_").for_provider_type("krb5-token")

    assert cred is not None
    assert cred.service == "site_krb5"
    assert cred.path == "$_CONDOR_CREDS/site_krb5.use"


def test_kind_not_wired_at_this_site_gets_no_job_credential() -> None:
    assert _guide({"x509"}).for_provider_type("krb5-token") is None


@pytest.mark.parametrize(
    "provider_type", ["keycloak-brokered", "oauth21-direct", "condor-token"]
)
def test_provider_types_that_are_not_credmon_kinds_get_none(provider_type: str) -> None:
    assert _guide({"x509", "krb5", "servicex"}).for_provider_type(provider_type) is None


def test_instructions_describe_the_pattern_and_point_to_list_identities() -> None:
    text = _guide({"krb5", "x509"}).instructions()

    assert "use_oauth_services = af_<kind>" in text
    assert "$_CONDOR_CREDS/af_<kind>.use" in text
    assert "af_list_identities" in text
    assert "af_link_identity" in text
    assert "never" in text.lower()
    # The pattern is kind-agnostic: no kind is named, so adding one never
    # requires editing this text.
    assert "krb5" not in text
    assert "x509" not in text


def test_wired_kinds_keeps_requested_kinds_that_have_targets(tmp_path) -> None:
    token = tmp_path / "t"
    token.write_text("x")
    settings = Settings(
        credmon_enabled=True,
        credmon_htcondor_api_url="https://htcondor-api.example",
        credmon_htcondor_api_token_file=str(token),
        credmon_user_domain="af.example.org",
        credmon_kinds=["x509", "krb5"],
    )

    kinds = wired_kinds(
        settings, {"x509": ["ami_service"], "krb5": [], "servicex": ["sx"]}
    )

    # krb5 has no target here; servicex has one but was not requested.
    assert kinds == ["x509"]

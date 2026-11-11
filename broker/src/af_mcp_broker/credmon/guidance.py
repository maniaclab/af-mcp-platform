"""What agents are told about using linked credentials in HTCondor jobs (docs/credmon.md).

Two surfaces, one source:

- the session instructions carry only the *pattern* (``use_oauth_services =
  <prefix><kind>`` -> ``$_CONDOR_CREDS/<prefix><kind>.use``, look up the rest
  in af_list_identities, never print the files), so they never name a kind
  and never need editing when one is added;
- af_list_identities carries the per-kind detail for *this* user, as a
  ``job_credential`` on each identity whose provider type is a credmon kind
  wired at this site.

Kinds are a closed set fixed by the broker's ``/v1/credentials/<kind>/redeem``
endpoints and af-credmon's ``.use`` rendering, so their usage lives here in
code, not in deployment config: a custom service plugs into an existing
identity-provider type and inherits that type's usage unchanged. Adding a kind
is a code change in both repositories anyway, and test_credmon_guidance's
coverage test fails until KIND_USAGE describes it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from af_mcp_broker.config import CredmonKindName, Settings


@dataclass(frozen=True)
class KindUsage:
    """How a job uses one kind's ``.use`` file: what is in it, and the environment variable tools read it from (None when tools take the file directly)."""

    format: str
    env_var: str | None
    # How the variable's value refers to the file (krb5 needs a "FILE:" type
    # prefix; most tools take the bare path).
    env_value_prefix: str = ""


# Must match af-credmon's .use rendering (maniaclab/af-credmon redeem.py).
KIND_USAGE: Final[Mapping[CredmonKindName, KindUsage]] = {
    "x509": KindUsage(format="VOMS proxy (PEM)", env_var="X509_USER_PROXY"),
    "krb5": KindUsage(
        format="Kerberos credentials cache",
        env_var="KRB5CCNAME",
        env_value_prefix="FILE:",
    ),
    "servicex": KindUsage(
        format='JSON object {"access_token": "<ServiceX access token>"}',
        env_var=None,
    ),
}

# identity_providers entry ``type`` -> the credmon kind it supplies.
PROVIDER_TYPE_KIND: Final[Mapping[str, CredmonKindName]] = {
    "x509": "x509",
    "krb5-token": "krb5",
    "servicex-token": "servicex",
}


@dataclass(frozen=True)
class JobCredential:
    """One kind as a job sees it: the credd service to request, where the file lands, and how to use it."""

    service: str
    path: str
    format: str | None
    env: str | None


def wired_kinds(
    settings: Settings, targets_by_kind: Mapping[str, Sequence[str]]
) -> list[CredmonKindName]:
    """Return the requested credmon kinds (``settings.credmon_kinds``) that have an identity provider target at this site, in requested order."""
    return [kind for kind in settings.credmon_kinds if targets_by_kind.get(kind)]


@dataclass(frozen=True)
class JobCredentialGuide:
    """The credmon kinds wired at this site and the credd service prefix jobs request them with."""

    service_prefix: str
    kinds: frozenset[str]

    def for_provider_type(self, provider_type: str) -> JobCredential | None:
        """The job credential an identity of *provider_type* yields here, or None when that type is not a wired credmon kind."""
        kind = PROVIDER_TYPE_KIND.get(provider_type)
        if kind is None or kind not in self.kinds:
            return None
        service = f"{self.service_prefix}{kind}"
        path = f"$_CONDOR_CREDS/{service}.use"
        usage = KIND_USAGE.get(kind)
        env = (
            f"{usage.env_var}={usage.env_value_prefix}{path}"
            if usage is not None and usage.env_var is not None
            else None
        )
        return JobCredential(
            service=service,
            path=path,
            format=usage.format if usage is not None else None,
            env=env,
        )

    def instructions(self) -> str:
        """The kind-agnostic session-instructions section describing the pattern."""
        p = self.service_prefix
        return (
            "HTCondor jobs can receive the user's linked credentials on the worker "
            f"node. Request one with `use_oauth_services = {p}<kind>` "
            "(comma-separate several); the job then finds it at "
            f"$_CONDOR_CREDS/{p}<kind>.use. Call af_list_identities to see which "
            "kinds this user has linked and, per kind (its job_credential), the "
            "file format and the environment variable to set. Reference these "
            "files only through those variables -- never cat, echo, or base64 "
            "them: job output is returned to you verbatim. If a kind is not "
            "linked, route the user to af_link_identity."
        )

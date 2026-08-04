"""Tests for app.py's lifespan helpers that don't require booting the full
FastAPI app (see test_dev_bypass.py / test_api.py for full-boot coverage).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from af_mcp_broker.app import _build_target_to_alias
from af_mcp_broker.config import (
    KeycloakBrokeredProviderConfig,
    OAuth21DirectProviderConfig,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def test_build_target_to_alias_covers_all_auth_shapes() -> None:
    """target_to_alias (issue #90) joins backend targets to whichever
    credential provider services them: x509 targets get the synthetic
    "x509" alias, keycloak-brokered/oauth21-direct targets get their
    configured alias, and auth_type "none" targets (e.g. "docs") are simply
    absent — no user credential is needed for them.
    """
    identity_providers_cfgs = [
        KeycloakBrokeredProviderConfig(alias="atlas-oidc", targets=["rucio"]),
        OAuth21DirectProviderConfig(
            alias="rucio-mcp-atlas",
            targets=["rucio-mcp-atlas"],
            authorization_endpoint="https://backend-as.example/authorize",
            token_endpoint="https://backend-as.example/token",
            issuer="https://backend-as.example",
        ),
    ]

    mapping = _build_target_to_alias(
        x509_targets=["ami"],
        identity_providers_cfgs=identity_providers_cfgs,
    )

    assert mapping == {
        "rucio": "atlas-oidc",
        "rucio-mcp-atlas": "rucio-mcp-atlas",
        "ami": "x509",
    }
    assert "docs" not in mapping


# ---------------------------------------------------------------------------
# Fail-closed startup validation (issue #60): a backend that omits
# `required_capability` relies on the credential layer as its sole
# authorization gate. If no credential provider resolves for its target
# either, there is no gate at all -- the broker must refuse to start.
# ---------------------------------------------------------------------------


def _write_backends(tmp_path: Path, text: str) -> str:
    path = tmp_path / "backends.yaml"
    path.write_text(text)
    return str(path)


def test_omitted_capability_with_credential_provider_starts_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """Omitting required_capability is allowed as long as the credential
    layer actually gates the backend. Here that's via ``auth_type: x509``,
    which the lifespan auto-registers into credential_registry for every
    x509 backend regardless of `identity_providers` config -- so this
    backend has a real gate (a mintable credential) even without a declared
    capability.
    """
    monkeypatch.setenv(
        "BACKENDS_FILE",
        _write_backends(
            tmp_path,
            "backends:\n"
            "  - name: ami\n"
            "    prefix: ami\n"
            "    url: http://ami.invalid/mcp\n"
            "    auth_type: x509\n",
        ),
    )

    with app_client_factory() as (client, _):
        resp = client.get("/v1/healthz")

    assert resp.status_code == 200, resp.text


def test_omitted_capability_without_credential_provider_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    """A backend that omits required_capability AND has no credential
    provider resolving for its target (here: `auth_type: bearer`, the
    default, with no `identity_providers` entry naming it) has no
    authorization gate at all -- neither a declared capability nor a
    mintable credential. The broker must refuse to start naming the
    offending backend rather than silently exposing it to any authenticated
    caller.
    """
    monkeypatch.setenv(
        "BACKENDS_FILE",
        _write_backends(
            tmp_path,
            "backends:\n"
            "  - name: mystery\n"
            "    prefix: mystery\n"
            "    url: http://mystery.invalid/mcp\n"
            "    auth_type: bearer\n",
        ),
    )

    with pytest.raises(RuntimeError, match="mystery"):  # noqa: SIM117
        with app_client_factory():
            pass

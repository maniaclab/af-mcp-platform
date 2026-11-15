"""Startup validation that every ``auth_type: krb5``/``servicex`` service is covered by a matching identity_providers entry.

Such a service authenticates with an AF Broker Identity Token, and its
credential comes from the krb5-token/servicex-token entry that targets it.
An uncovered service has no provider to redeem against and, with no such
entry, no reason for the broker to hold a signing key either, so boot must
fail naming the service rather than let the gap surface per request.
(``auth_type: x509`` coverage is validated in
``test_x509_startup_validation.py``.)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def _services_yaml(auth_type: str) -> str:
    return (
        "services:\n"
        f"  - name: {auth_type}-backend\n"
        f"    prefix: {auth_type}be\n"
        f"    url: http://{auth_type}-backend.invalid/mcp\n"
        f"    auth_type: {auth_type}\n"
        "    required_permission: __none__\n"
    )


@pytest.fixture
def boot_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Callable[..., None]:
    """Point the app at a one-service registry and *entries*, with no signing key.

    Applied from inside the test body so it runs after ``app_client_factory``'s
    own default environment.
    """

    def _apply(auth_type: str, entries: list[dict]) -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(_services_yaml(auth_type))
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(entries))
        monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)

    return _apply


@pytest.mark.parametrize("auth_type", ["krb5", "servicex"])
def test_service_with_no_matching_entry_refuses_to_boot_naming_the_service(
    boot_env: Callable[..., None], app_client_factory, auth_type: str
) -> None:
    boot_env(auth_type, [])

    with (
        pytest.raises(RuntimeError, match=f"auth_type: {auth_type}") as excinfo,
        app_client_factory(),
    ):
        pass  # pragma: no cover - boot must fail before yielding

    assert f"{auth_type}-backend" in str(excinfo.value)
    assert f"{auth_type}-token" in str(excinfo.value)

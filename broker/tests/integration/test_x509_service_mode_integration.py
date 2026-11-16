"""Integration tests for the area ``test_x509_service_mode.py`` covers; the unit tests live in ``unit/test_x509_service_mode.py``."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


import json

import pytest
from x509_fakes import FakeX509Store

from af_mcp_broker.credentials.voms_service import VomsTokenServiceClient

# ---------------------------------------------------------------------------
# App wiring (Settings validation for the service-mode Vault coupling lives
# in test_config.py's test_vault_config_required_by_x509_entry_with_service_url)
# ---------------------------------------------------------------------------


class TestAppWiring:
    @pytest.fixture
    def voms_service_env(self, monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
        """Returns a callable that points the app at an explicit x509 entry with a voms-token-service URL.

        A callable, applied from inside the test body -- not a plain
        fixture -- so its ``monkeypatch.setenv("IDENTITY_PROVIDERS", ...)``
        is guaranteed to run after ``app_client_factory``'s own (fixture
        setup order between two same-scoped, non-dependent fixtures is
        unspecified, and app_client_factory sets a default
        IDENTITY_PROVIDERS unconditionally). The shipped services.yaml
        already declares "ami" as ``auth_type: x509``, so this entry
        (targeting "ami") satisfies the broker's coverage check with no
        need to override SERVICES_FILE.
        """

        def _apply() -> None:
            monkeypatch.setenv(
                "IDENTITY_PROVIDERS",
                json.dumps(
                    [
                        {
                            "type": "x509",
                            "voms": "atlas",
                            "alias": "x509",
                            "targets": ["ami"],
                            "service_url": "http://voms-token-service.invalid:8000",
                        }
                    ]
                ),
            )

        return _apply

    def test_boot_fails_without_signing_key(
        self,
        voms_service_env: Callable[[], None],
        monkeypatch: pytest.MonkeyPatch,
        app_client_factory,
    ) -> None:
        """Minting at the service needs broker-signed identity tokens: an
        x509 entry with no signing key is fail-closed at boot (same
        reasoning as the broker-issued provider check)."""
        voms_service_env()
        monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)
        with (
            pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"),
            app_client_factory(),
        ):
            pass  # pragma: no cover - boot must fail before yielding

    def test_boot_wires_voms_client_and_vault_store(
        self,
        voms_service_env: Callable[[], None],
        app_client_factory,
    ) -> None:
        voms_service_env()

        with app_client_factory() as (client, _):
            provider = client.app.state.broker.x509_provider
            assert isinstance(provider.voms_client, VomsTokenServiceClient)
            assert isinstance(provider.vault_store, FakeX509Store)

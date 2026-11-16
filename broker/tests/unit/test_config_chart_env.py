"""The flat environment-variable interface of ``Settings`` is stable.

``data/chart_env/<values>.json`` holds, for each ``charts/af-mcp-platform/ci``
values file, the broker container's env as the chart renders it (secret
references replaced by a ``<secret:name/key>`` placeholder) and either the
``Settings`` parsed from it or the validation error it is refused with.

The chart is rendered live with ``helm`` (a dev-environment dependency) on
every run, so a chart change that alters the broker env fails here until the
fixtures are regenerated on purpose. Regenerate them with
``UPDATE_CHART_ENV_FIXTURES=1 pixi run -e dev pytest
broker/tests/integration/test_config_chart_env_integration.py`` and review the diff.
"""

from __future__ import annotations

from typing import Any

import pytest
from config_chart_env_support import (
    _FIXTURE_DIR,
    _VALUES_FILES,
    _clear_settings_env,
    _fixture_path,
)
from pydantic import ValidationError

from af_mcp_broker.config import Settings


def test_every_fixture_has_a_values_file() -> None:
    expected = {_fixture_path(values).name for values in _VALUES_FILES}
    assert {path.name for path in _FIXTURE_DIR.glob("*.json")} == expected


_VAULT_MESSAGE = (
    "{field} ({env}) must be set when token_store_backend, "
    "token_registry_backend, principal_cache_backend, or "
    "maintenance_mode_backend is 'vault' or an x509, krb5-token, or "
    "servicex-token identity_providers entry is configured (their credential "
    "material persists in Vault, with no in-memory fallback)."
)
_CREDMON_MESSAGE = (
    "{field} ({env}) must be set when credmon_enabled is true -- the storer "
    "needs it to store top tokens in credd through htcondor-api."
)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        pytest.param(
            {"token_store_backend": "vault", "vault_auth_role": "r"},
            "Value error, "
            + _VAULT_MESSAGE.format(field="vault_addr", env="VAULT_ADDR"),
            id="vault-addr",
        ),
        pytest.param(
            {"maintenance_mode_backend": "vault", "vault_addr": "https://v"},
            "Value error, "
            + _VAULT_MESSAGE.format(field="vault_auth_role", env="VAULT_AUTH_ROLE"),
            id="vault-auth-role",
        ),
        pytest.param(
            {"usage_store_backend": "postgres"},
            "Value error, usage_postgres_dsn (USAGE_POSTGRES_DSN) must be set "
            "when usage_store_backend is 'postgres' -- typically the `uri` key "
            "of a Crunchy PGO `<cluster>-pguser-<user>` secret.",
            id="usage-dsn",
        ),
        pytest.param(
            {"maintenance_mode_backend": "postgres"},
            "Value error, maintenance_mode_postgres_dsn "
            "(MAINTENANCE_MODE_POSTGRES_DSN) or usage_postgres_dsn "
            "(USAGE_POSTGRES_DSN) must be set when maintenance_mode_backend is "
            "'postgres'.",
            id="maintenance-dsn",
        ),
        pytest.param(
            {"credmon_enabled": True},
            "Value error, "
            + _CREDMON_MESSAGE.format(
                field="credmon_htcondor_api_url", env="CREDMON_HTCONDOR_API_URL"
            ),
            id="credmon-url",
        ),
        pytest.param(
            {"credmon_enabled": True, "credmon_htcondor_api_url": "http://x"},
            "Value error, "
            + _CREDMON_MESSAGE.format(
                field="credmon_htcondor_api_token_file",
                env="CREDMON_HTCONDOR_API_TOKEN_FILE",
            ),
            id="credmon-token-file",
        ),
        pytest.param(
            {
                "credmon_enabled": True,
                "credmon_htcondor_api_url": "http://x",
                "credmon_htcondor_api_token_file": "/f",
            },
            "Value error, "
            + _CREDMON_MESSAGE.format(
                field="credmon_user_domain", env="CREDMON_USER_DOMAIN"
            ),
            id="credmon-user-domain",
        ),
    ],
)
def test_validation_error_messages_are_pinned(
    kwargs: dict[str, Any], message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_settings_env(monkeypatch, {})
    with pytest.raises(ValidationError) as excinfo:
        Settings(_env_file=None, **kwargs)
    assert excinfo.value.errors()[0]["msg"] == message

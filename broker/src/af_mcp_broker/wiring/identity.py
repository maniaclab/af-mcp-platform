"""Builders for the identity-side subsystems: the dev auth bypass, the principal cache, the token registry and the MCP OAuth bootstrap code store."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from af_mcp_broker.identity import build_dev_principal, issuer_is_local
from af_mcp_broker.mcp_auth_codes import McpAuthCodeStore
from af_mcp_broker.principal_cache import PrincipalCache, build_principal_cache_backend
from af_mcp_broker.principal_directory import KeycloakPrincipalDirectory
from af_mcp_broker.token_registry import TokenRegistry, build_token_registry_backend

if TYPE_CHECKING:
    import httpx2
    from cryptography.fernet import Fernet

    from af_mcp_broker.config import Settings
    from af_mcp_broker.principal import Principal
    from af_mcp_broker.shared_state import SharedState
    from af_mcp_broker.token_registry import TokenRegistryBackend
    from af_mcp_broker.vault_kv import VaultConnections

logger = structlog.get_logger(__name__)


def require_oidc_issuer(settings: Settings) -> None:
    """Refuse to boot without an OIDC issuer: JWTs would otherwise be validated against, and JWKS fetched from, a realm the deployer never chose."""
    if not settings.oidc_issuer:
        msg = (
            "OIDC_ISSUER must be set to the deployment's Keycloak realm URL "
            "(e.g. https://keycloak.example.com/realms/example)."
        )
        raise RuntimeError(msg)


def log_access_groups(settings: Settings) -> None:
    """Log once at boot whether the platform is open to every authenticated principal or restricted to ``Settings.access_groups``."""
    logger.info(
        "identity.access_groups",
        mode="restricted" if settings.access_groups else "open",
        groups=settings.access_groups,
    )


def build_dev_bypass_principal(settings: Settings) -> Principal | None:
    """Return the local-development bypass principal, or None when the bypass is off.

    When BROKER_DEV_INSECURE_PRINCIPAL is set it is parsed into a Principal at
    startup, and the broker refuses to boot unless the configured issuer
    clearly points at a local host -- this is the only line of defence against
    the bypass being enabled in production by mistake, so it must be loud and
    fail-closed.
    """
    if settings.dev_insecure_principal is None:
        return None
    if not issuer_is_local(settings.oidc_issuer):
        msg = (
            "BROKER_DEV_INSECURE_PRINCIPAL is set but OIDC_ISSUER "
            f"({settings.oidc_issuer!r}) does not look like a local "
            "development host. Refusing to start. Local hosts are "
            "'localhost', '127.0.0.1', '::1', or a hostname ending in "
            "'.localhost' / '.local' / '.test'."
        )
        raise RuntimeError(msg)
    # build_dev_principal raises RuntimeError with a clear message on
    # bad JSON or missing required keys — propagate as-is.
    dev_principal = build_dev_principal(settings.dev_insecure_principal)
    logger.warning(
        "dev_bypass.active",
        detail="AUTH BYPASSED — DO NOT USE IN PRODUCTION",
        oidc_issuer=settings.oidc_issuer,
        unixname=dev_principal.unixname,
        uid=dev_principal.uid,
    )
    return dev_principal


def build_principal_cache(
    settings: Settings,
    vaults: VaultConnections,
    http_client: httpx2.AsyncClient,
    *,
    dev_bypass_active: bool,
) -> PrincipalCache | None:
    """Build the principal cache (issue #144 steps 2a/3/3b), or None under the dev bypass with no Keycloak admin account.

    The cache resolves every authenticated request's *current*
    groups/uid/gid/unixname/email from Keycloak. PATs are opaque bearers
    carrying none of that themselves, and the JWT path defers to the cache
    too (groups, then POSIX identity), so the token answers only "who is
    this?" and the directory alone answers "what groups/POSIX identity do
    they have?" -- see identity.py's
    `_resolve_current_attributes` and principal_cache.py/
    principal_directory.py's module docstrings for the mechanism.

    The Keycloak admin service account is therefore load-bearing for ALL
    authentication, not just PATs. The dev bypass
    (BROKER_DEV_INSECURE_PRINCIPAL) is the one exception: it short-circuits
    api.auth.keycloak_dependency/mcp's AsgiAuthMiddleware before either ever
    reaches the directory (see build_dev_principal), so it needs no directory
    at all. Neither configured is otherwise a genuine misconfiguration, not a
    degraded mode -- refuse to start rather than boot a broker that can never
    authenticate anyone. Same reasoning as the unreachable-permissions check
    (issue #125): this is Kubernetes, so a Deployment rollout with a failing
    new pod leaves the previous ReplicaSet serving traffic unaffected -- a
    startup RuntimeError surfaces the misconfiguration as a visible rollout
    failure with zero outage risk, which is strictly better than a broker
    that accepts every request and then 503s all of them.
    """
    admin_client_id = settings.keycloak_admin_client_id
    admin_client_secret = settings.keycloak_admin_client_secret.get_secret_value()
    if not (admin_client_id and admin_client_secret):
        if dev_bypass_active:
            return None
        msg = (
            "KEYCLOAK_ADMIN_CLIENT_ID/KEYCLOAK_ADMIN_CLIENT_SECRET are unset "
            "and BROKER_DEV_INSECURE_PRINCIPAL is not active. Every "
            "authenticated request (JWT or PAT) resolves its current groups "
            "from the PrincipalDirectory, so the broker cannot authenticate "
            "anyone without this service account. "
            "Configure the Keycloak admin service account (see "
            "docs/auth.md's 'Operator setup: the Keycloak admin service "
            "account'), or set BROKER_DEV_INSECURE_PRINCIPAL for local "
            "development (see docs/local-development.md)."
        )
        raise RuntimeError(msg)
    principal_directory = KeycloakPrincipalDirectory(
        settings, admin_client_id, admin_client_secret, http_client
    )
    # Persistence service for the cache (issue #144 step 2b), sharing the
    # process-wide Vault transport instance when Vault-backed.
    return PrincipalCache(
        principal_directory,
        backend=build_principal_cache_backend(settings, vaults),
        refresh_interval_seconds=settings.principal_cache_refresh_seconds,
        max_staleness_seconds=settings.principal_cache_max_staleness_seconds,
        heartbeat_interval_seconds=settings.principal_cache_heartbeat_seconds,
    )


@dataclass(frozen=True)
class TokenRegistries:
    """The token registry facade and the backend it wraps (the aggregator's PAT validation reads the backend directly)."""

    backend: TokenRegistryBackend
    registry: TokenRegistry


def build_token_registry(
    settings: Settings, vaults: VaultConnections, shared_state: SharedState
) -> TokenRegistries:
    """Build the durable registry backing the manual bearer-token bootstrap flow (POST/GET/DELETE /v1/tokens, issue #24).

    Vault/OpenBao-backed for HA-safe list/revoke across replicas (issue #115)
    with an in-memory local-dev fallback.
    """
    backend = build_token_registry_backend(settings, vaults)
    return TokenRegistries(
        backend=backend, registry=TokenRegistry(backend, shared_state)
    )


def build_mcp_auth_code_store(
    settings: Settings, state_cipher: Fernet | None, shared_state: SharedState
) -> McpAuthCodeStore | None:
    """Build the MCP OAuth discovery bootstrap code store (issue #140), or None when there is no state cipher.

    Short-lived, single-use authorization codes minted by the Keycloak-login
    callback and redeemed at /v1/oauth/token. Codes are self-contained under
    the same Fernet cipher as the rest of the flow's state, and single use is
    enforced through the shared store -- see mcp_auth_codes.py's module
    docstring. None whenever the cipher is (api/mcp_oauth.py's routes 503 on
    their own then).
    """
    if state_cipher is None:
        return None
    return McpAuthCodeStore(
        state_cipher,
        shared_state,
        issuer=settings.oauth21_effective_state_issuer,
    )

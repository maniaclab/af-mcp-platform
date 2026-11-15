"""Builders for the credential subsystem: state cipher, signing-key issuer, cache, invalidator and provider registry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, assert_never

from cryptography.fernet import Fernet

from af_mcp_broker.config import (
    BrokerIssuedProviderConfig,
    CondorTokenProviderConfig,
    KeycloakBrokeredProviderConfig,
    KrbTokenProviderConfig,
    OAuth21DirectProviderConfig,
    ServiceXTokenProviderConfig,
    X509ProviderConfig,
)
from af_mcp_broker.credentials import (
    BrokerIssuedProvider,
    BrokerIssuedTokenOptions,
    CondorTokenProvider,
    CredentialCache,
    CredentialRegistry,
    Krb5TokenServiceClient,
    KrbTokenProvider,
    OAuth21Provider,
    OIDCProvider,
    ServiceXProvider,
    ServiceXTokenServiceClient,
    VomsTokenServiceClient,
    X509Provider,
    load_broker_token_issuer,
)
from af_mcp_broker.credentials.stores import build_token_store
from af_mcp_broker.errors import require
from af_mcp_broker.mcp.aggregator import (
    invalidate_all_subject_caches,
    invalidate_subject_cache,
)
from af_mcp_broker.mcp.cache_invalidation import ListCacheInvalidator
from af_mcp_broker.wiring.checks import (
    broker_token_entries,
    describe_broker_token_entries,
)

if TYPE_CHECKING:
    from contextlib import AsyncExitStack

    import httpx2

    from af_mcp_broker.config import IdentityProviderConfig, Settings
    from af_mcp_broker.credentials import (
        BrokerTokenIssuer,
        CredentialProvider,
        InMemoryTokenStore,
        TokenStore,
        VaultTokenStore,
    )
    from af_mcp_broker.credentials.stores import VaultLinkStores
    from af_mcp_broker.mcp.aggregator import BackendProviders
    from af_mcp_broker.service_registry import ServiceRegistry
    from af_mcp_broker.shared_state import SharedState
    from af_mcp_broker.vault_kv import VaultKV


def build_state_cipher(settings: Settings) -> Fernet | None:
    """Return the Fernet cipher for in-flight OAuth 2.1 state, or None when neither flow that needs it is configured.

    The cipher is shared by two independent flows that both encrypt in-flight
    OAuth 2.1 state (oauth_state.py): backend-account-linking
    (oauth21-direct identity_providers) and the MCP OAuth discovery bootstrap
    flow (issue #140, api/mcp_oauth.py). Either configuring this cipher on
    its own -- Settings._validate_oauth21_config/_validate_mcp_oauth_config
    already refused to construct *settings* if either is configured without
    broker_state_key.
    """
    has_oauth21_provider = any(
        cfg.type == "oauth21-direct" for cfg in settings.identity_providers
    )
    if has_oauth21_provider or settings.keycloak_login_client_id:
        return Fernet(settings.broker_state_key.get_secret_value().encode())
    return None


def build_oauth21_token_store(
    settings: Settings, vault_kv: VaultKV | None
) -> InMemoryTokenStore | VaultTokenStore | None:
    """Build the token store the oauth21-direct providers share, or None when no such entry is configured."""
    if not any(cfg.type == "oauth21-direct" for cfg in settings.identity_providers):
        return None
    return build_token_store(settings, vault_kv)


def build_broker_token_issuer(settings: Settings) -> BrokerTokenIssuer | None:
    """Load the AF Broker Identity Token issuer (issue #162), refusing to boot when an entry needs it and no signing key is configured.

    The issuer is the broker's own RS256 signing key for the identity-assertion
    JWTs the native providers (BrokerIssuedProvider, CondorTokenProvider's
    service exchange -- issue #169, KrbTokenProvider, ServiceXProvider, and
    X509Provider's voms-token-service mint calls) mint for AF-native services.
    None only when no BROKER_SIGNING_KEY_FILE is set -- a valid local-dev
    state for a deployment with no such entry; load_broker_token_issuer
    itself raises RuntimeError on an unreadable/invalid key or a missing
    issuer URL. The fail-closed check is the remaining gap: an
    identity_providers entry that needs broker-signed tokens (and therefore
    every service resolving to it) with no signing key configured at all must
    refuse to boot rather than fail at first request -- same
    rollout-failure-over-silent-breakage reasoning as the unreachable
    permissions check. The aggregator also injects a broker-issued identity
    JWT for auth_type: x509 targets and the redeem endpoint verifies it, so
    x509 is covered by the same requirement.
    """
    broker_token_issuer = load_broker_token_issuer(settings)
    if broker_token_issuer is None:
        needing_signing_key = broker_token_entries(settings.identity_providers)
        if needing_signing_key:
            msg = (
                "identity_providers contains entries that need the broker to "
                "sign AF Broker Identity Tokens, but BROKER_SIGNING_KEY_FILE "
                "is not set. Affected services: "
                f"{describe_broker_token_entries(needing_signing_key)}. "
                "Mount the RS256 signing key (chart: broker.identityToken."
                "existingSigningKeySecret) or remove the entries "
                "-- see docs/auth.md's 'AF Broker Identity Token' section."
            )
            raise RuntimeError(msg)
    return broker_token_issuer


def build_list_cache_invalidator(
    shared_state: SharedState,
    backend_providers: BackendProviders,
    stack: AsyncExitStack,
) -> ListCacheInvalidator:
    """Start the cross-replica list-cache invalidator and register its ``stop`` on *stack*.

    The credential cache's link/revoke hooks go through it: it drops this
    replica's cached listings and tells the other replicas to drop theirs
    (mcp/cache_invalidation.py).
    """
    list_cache_invalidator = ListCacheInvalidator(
        shared_state,
        invalidate=lambda subject, target: invalidate_subject_cache(
            backend_providers, subject, target
        ),
        invalidate_all=lambda: invalidate_all_subject_caches(backend_providers),
    )
    list_cache_invalidator.start()
    stack.push_async_callback(list_cache_invalidator.stop)
    return list_cache_invalidator


def build_credential_cache(
    settings: Settings,
    shared_state: SharedState,
    list_cache_invalidator: ListCacheInvalidator,
    stack: AsyncExitStack,
) -> CredentialCache:
    """Build the credential cache, start its janitor and register the janitor's stop on *stack*.

    on_revoke wires issue #320's per-(subject, service) tools/list cache
    invalidation to every revoke() (and, by delegation, revoke_all()) call
    -- covering api/identities.py's unlink_identity (oauth21-direct/
    krb5-token/servicex-token, all three revoke through this cache) and
    api/credentials.py's ``DELETE /v1/credential`` (revoke_all) alike,
    without either module needing its own aggregator-cache-invalidation
    code. The janitor's own expiry sweep does NOT go through revoke() (see
    CredentialCache._expire()), so a credential simply expiring never fires
    this hook -- only an actual identity-affecting revoke does.
    """
    credential_cache = CredentialCache(
        max_failed_unlocks=settings.credential_unlock_max_failures,
        unlock_window_seconds=settings.credential_unlock_window_seconds,
        shared_state=shared_state,
        on_revoke=list_cache_invalidator.invalidate,
        # The mirror of on_revoke for issue #355: the /v1 routes that complete
        # a link call credential_cache.notify_linked(), so a caller who just
        # linked does not wait out a cached "no tools" listing.
        on_link=list_cache_invalidator.invalidate,
    )
    credential_cache.start_janitor()
    stack.push_async_callback(credential_cache.stop_janitor)
    return credential_cache


@dataclass(frozen=True)
class CredentialProviders:
    """The credential registry and the providers (and their configs) it was filled from, keyed by ``identity_providers`` alias."""

    registry: CredentialRegistry
    providers: dict[str, CredentialProvider]
    configs: dict[str, IdentityProviderConfig]


@dataclass(frozen=True)
class _ProviderDeps:
    """What the per-entry provider constructors draw on."""

    settings: Settings
    service_registry: ServiceRegistry
    cache: CredentialCache
    issuer: BrokerTokenIssuer | None
    token_store: TokenStore | None
    link_stores: VaultLinkStores
    http_client: httpx2.AsyncClient


# The invariants below are established by build_broker_token_issuer's
# fail-closed check, build_vault_link_stores (each entry type implies its
# store) and Settings' oauth21 validation.
_ISSUER_INVARIANT = (
    "an entry that signs AF Broker Identity Tokens exists but no signing key "
    "is configured (build_broker_token_issuer's fail-closed check)"
)


def _build_broker_issued_provider(
    cfg: BrokerIssuedProviderConfig, deps: _ProviderDeps
) -> CredentialProvider:
    # The aud and POSIX requirement of each target's token are declared
    # on the *service* (ServiceSpec.audience / requires_posix, issue
    # #257), so resolve them from the registry here rather than from
    # provider config -- keeping every token property of a service on
    # the service entry. A target with no matching service entry (not
    # reachable at call time anyway) falls back to the historical
    # default: aud = target name, no POSIX claims.
    token_options: dict[str, BrokerIssuedTokenOptions] = {}
    for target in cfg.targets:
        tspec = deps.service_registry.get(target)
        token_options[target] = BrokerIssuedTokenOptions(
            audience=tspec.effective_audience if tspec else target,
            requires_posix=tspec.requires_posix if tspec else False,
        )
    return BrokerIssuedProvider(
        issuer=require(deps.issuer, _ISSUER_INVARIANT),
        cache=deps.cache,
        alias=cfg.alias,
        targets=frozenset(cfg.targets),
        token_options=token_options,
    )


def _build_oauth21_provider(
    cfg: OAuth21DirectProviderConfig, deps: _ProviderDeps
) -> CredentialProvider:
    return OAuth21Provider(
        alias=cfg.alias,
        targets=frozenset(cfg.targets),
        authorization_endpoint=str(cfg.authorization_endpoint),
        token_endpoint=str(cfg.token_endpoint),
        issuer=cfg.issuer,
        scope=cfg.scope,
        store=require(
            deps.token_store,
            "an oauth21-direct entry exists but no token store was built",
        ),
        # A provider registered under its own client_id uses it;
        # otherwise the broker identifies itself by its CIMD URL.
        client_id=cfg.client_id or deps.settings.oauth21_client_id,
        client_secret=cfg.client_secret,
        revocation_endpoint=(
            str(cfg.revocation_endpoint) if cfg.revocation_endpoint else None
        ),
        http_client=deps.http_client,
    )


def _build_provider(
    cfg: IdentityProviderConfig, deps: _ProviderDeps
) -> CredentialProvider:
    """Construct the provider for one ``identity_providers`` entry."""
    match cfg:
        case KeycloakBrokeredProviderConfig():
            return OIDCProvider(
                deps.settings,
                deps.cache,
                alias=cfg.alias,
                targets=frozenset(cfg.targets),
                http_client=deps.http_client,
            )
        case OAuth21DirectProviderConfig():
            return _build_oauth21_provider(cfg, deps)
        case BrokerIssuedProviderConfig():
            return _build_broker_issued_provider(cfg, deps)
        case CondorTokenProviderConfig():
            return CondorTokenProvider(
                issuer=require(deps.issuer, _ISSUER_INVARIANT),
                cache=deps.cache,
                alias=cfg.alias,
                targets=frozenset(cfg.targets),
                service_url=str(cfg.service_url),
                audience=cfg.audience,
                http_client=deps.http_client,
            )
        case KrbTokenProviderConfig():
            return KrbTokenProvider(
                client=Krb5TokenServiceClient(
                    issuer=require(deps.issuer, _ISSUER_INVARIANT),
                    service_url=str(cfg.service_url),
                    audience=cfg.audience,
                    http_client=deps.http_client,
                ),
                cache=deps.cache,
                alias=cfg.alias,
                targets=frozenset(cfg.targets),
                vault_store=require(
                    deps.link_stores.krb5,
                    "a krb5-token entry exists but no krb5 Vault store was built",
                ),
            )
        case X509ProviderConfig():
            # Mint at the entry's voms-token-service (the only component that
            # mounts user homes) and persist both the proxy and the link
            # (Globus passphrase for hands-free renewal) in Vault (issue #112
            # follow-up).
            return X509Provider(
                deps.settings,
                deps.cache,
                targets=frozenset(cfg.targets),
                voms_client=VomsTokenServiceClient(
                    issuer=require(deps.issuer, _ISSUER_INVARIANT),
                    service_url=str(cfg.service_url),
                    audience=cfg.audience,
                    voms=cfg.voms,
                    valid=cfg.valid,
                    http_client=deps.http_client,
                ),
                vault_store=require(
                    deps.link_stores.x509,
                    "an x509 entry exists but no x509 Vault store was built",
                ),
            )
        case ServiceXTokenProviderConfig():
            return ServiceXProvider(
                servicex_client=ServiceXTokenServiceClient(
                    issuer=require(deps.issuer, _ISSUER_INVARIANT),
                    service_url=str(cfg.service_url),
                    audience=cfg.audience,
                    http_client=deps.http_client,
                ),
                vault_store=require(
                    deps.link_stores.servicex,
                    "a servicex-token entry exists but no ServiceX Vault store "
                    "was built",
                ),
                cache=deps.cache,
                alias=cfg.alias,
                targets=frozenset(cfg.targets),
            )
        case _:
            # Exhaustive over the IdentityProviderConfig union: mypy fails
            # here when a member is added without a case above.
            assert_never(cfg)


def build_credential_providers(
    settings: Settings,
    *,
    service_registry: ServiceRegistry,
    cache: CredentialCache,
    issuer: BrokerTokenIssuer | None,
    token_store: TokenStore | None,
    link_stores: VaultLinkStores,
    http_client: httpx2.AsyncClient,
) -> CredentialProviders:
    """Build one ``CredentialProvider`` per configured ``identity_providers`` entry, registered for the entry's targets.

    Keyed by alias -- either Keycloak's stored-broker-token pattern
    (``keycloak-brokered``, OIDCProvider) or the broker acting as a direct
    OAuth 2.1 client (``oauth21-direct``, OAuth21Provider), sharing a single
    token store (in-memory or Vault-backed, per
    ``settings.token_store_backend`` -- issue #66 PR3), or one of the native
    broker-token kinds -- x509 included (voms-proxy minted via the entry's
    voms-token-service). `bearer`-auth services' credential provider comes
    from `identity_providers`' per-entry `targets` list, not a blanket
    auth_type match -- this lets different services bind to different
    aliases. `none` requires no user credential, so no provider is
    registered.
    """
    deps = _ProviderDeps(
        settings=settings,
        service_registry=service_registry,
        cache=cache,
        issuer=issuer,
        token_store=token_store,
        link_stores=link_stores,
        http_client=http_client,
    )
    registry = CredentialRegistry()
    providers: dict[str, CredentialProvider] = {}
    configs: dict[str, IdentityProviderConfig] = {}
    for cfg in settings.identity_providers:
        provider = _build_provider(cfg, deps)
        providers[cfg.alias] = provider
        configs[cfg.alias] = cfg
        for target in cfg.targets:
            registry.register(target, provider)
    return CredentialProviders(registry=registry, providers=providers, configs=configs)


async def resolve_x509_provider(
    registry: CredentialRegistry, x509_targets: list[str]
) -> X509Provider | None:
    """Return the default ``X509Provider`` api/credentials.py's ``/v1/x509/*`` routes fall back to when no explicit target is given.

    That is the provider servicing the first x509 service (matching
    ``_resolve_x509_target``'s default), or None when no x509 service exists
    at all.
    """
    if not x509_targets:
        return None
    resolved = await registry.resolve(x509_targets[0])
    if not isinstance(resolved, X509Provider):
        raise TypeError(
            f"x509 target {x509_targets[0]!r} resolved to "
            f"{type(resolved).__name__}, not X509Provider"
        )
    return resolved

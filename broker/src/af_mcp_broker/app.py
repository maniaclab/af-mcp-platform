from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Iterable

    from af_mcp_broker.config import IdentityProviderConfig
    from af_mcp_broker.credentials import CredentialProvider

import structlog
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, Response
from fastmcp.utilities.lifespan import combine_lifespans
from pydantic import ValidationError
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from af_mcp_broker._version import version as __version__
from af_mcp_broker.api.router import router as v1_router
from af_mcp_broker.api.tokens import TokenRegistry
from af_mcp_broker.api.wellknown import router as wellknown_router
from af_mcp_broker.audit.logger import init_audit_logger
from af_mcp_broker.authorization import EntitlementPolicy, load_policy
from af_mcp_broker.config import Settings
from af_mcp_broker.credentials import (
    BrokerIssuedProvider,
    CondorTokenProvider,
    CredentialCache,
    CredentialRegistry,
    InMemoryTokenStore,
    OAuth21Provider,
    OIDCProvider,
    VaultTokenStore,
    VaultX509Store,
    VomsTokenServiceClient,
    X509Provider,
    load_broker_token_issuer,
)
from af_mcp_broker.credentials.cache import RateLimitError
from af_mcp_broker.http import aclose_http_client
from af_mcp_broker.identity import build_dev_principal, get_jwks, issuer_is_local
from af_mcp_broker.logging import configure_logging
from af_mcp_broker.mcp.aggregator import (
    build_aggregator,
    build_asgi_auth_middleware,
    populate_aggregator,
)
from af_mcp_broker.mcp.registry import ServiceRegistry
from af_mcp_broker.mcp_auth_codes import McpAuthCodeStore
from af_mcp_broker.principal_cache import (
    InMemoryPrincipalCacheBackend,
    PrincipalCache,
    PrincipalCacheBackend,
    VaultPrincipalCacheBackend,
)
from af_mcp_broker.principal_directory import KeycloakPrincipalDirectory
from af_mcp_broker.token_registry import (
    InMemoryTokenRegistryBackend,
    RevokedJtiCache,
    TokenRegistryBackend,
    VaultTokenRegistryBackend,
)
from af_mcp_broker.vault_kv import VaultKV

logger = structlog.get_logger(__name__)


def _build_target_to_alias(
    identity_providers_cfgs: Iterable[IdentityProviderConfig],
) -> dict[str, str]:
    """Reverse map from service target name to the credential-provider alias that services it, surfaced on /v1/catalog as ``credential_provider`` (issue #90). Every target gets its entry's configured alias — x509 targets included, since x509 is an ordinary ``identity_providers`` type: every ``auth_type: x509`` service must be covered by an explicit entry (``_validate_x509_provider_targets`` refuses to boot otherwise), so this helper never needs a hardcoded synthetic alias. Targets with ``auth_type: none`` need no user credential and are simply absent from the mapping."""
    target_to_alias: dict[str, str] = {}
    for cfg in identity_providers_cfgs:
        for target in cfg.targets:
            target_to_alias[target] = cfg.alias
    return target_to_alias


def _validate_x509_provider_targets(
    identity_providers_cfgs: Iterable[IdentityProviderConfig],
    x509_service_names: set[str],
) -> None:
    """Fail-closed drift protection between ``auth_type: x509`` services and explicit x509 ``identity_providers`` entries (both directions) — same reasoning as issue #60's required_capability consolidation: a mismatch is a typo, a stale services.yaml, or a missing entry, and a startup RuntimeError surfaces it as a visible rollout failure with zero outage risk.

    Universal: there is no synthesized-entry escape hatch. Every
    ``auth_type: x509`` service must be named in some explicit entry's
    ``targets``, including deployments with zero x509 entries at all — an
    x509 service with no covering entry refuses to boot naming it, the same
    as one covered by the wrong entry.
    """
    x509_cfgs = [cfg for cfg in identity_providers_cfgs if cfg.type == "x509"]
    covered = {target for cfg in x509_cfgs for target in cfg.targets}
    uncovered = sorted(x509_service_names - covered)
    if uncovered:
        msg = (
            "The following auth_type: x509 services are not targeted by any "
            f"x509 identity_providers entry: {uncovered}. They would have no "
            "credential provider (and no catalog credential_provider alias) "
            "at all. Add an entry covering them, e.g.:\n"
            "  - type: x509\n"
            "    alias: x509\n"
            f"    targets: {uncovered}\n"
            "(add service_url/voms/valid/audience for voms-token-service "
            "mode, or omit service_url for the legacy k8s-Job/local-dev "
            "mint path), or change their auth_type."
        )
        raise RuntimeError(msg)
    not_x509 = sorted(covered - x509_service_names)
    if not_x509:
        msg = (
            "The following x509 identity_providers targets are not "
            f"auth_type: x509 services: {not_x509}. The aggregator only "
            "injects the identity JWT (and the redeem endpoint only accepts "
            "the audience) for auth_type: x509 services, so the entry would "
            "silently do nothing for them. Fix the typo, set the service's "
            "auth_type to x509 in services.yaml, or remove the target."
        )
        raise RuntimeError(msg)


def _open_audit_output(dest: str) -> TextIO:
    """Resolve the AUDIT_LOG_FILE setting to a writable stream.

    "-" means stdout; any other value is opened for appending.
    """
    if dest == "-":
        return sys.stdout
    return Path(dest).open("a")


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    settings = Settings()
    configure_logging(settings.log_level)

    # --- Local-development auth bypass. When BROKER_DEV_INSECURE_PRINCIPAL is
    # set we parse it into a Principal at startup and refuse to boot unless
    # the configured issuer clearly points at a local host — this is the
    # only line of defence against the bypass being enabled in production
    # by mistake, so it must be loud and fail-closed.
    application.state.dev_bypass_active = False
    application.state.dev_bypass_principal = None
    if settings.dev_insecure_principal is not None:
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
        application.state.dev_bypass_active = True
        application.state.dev_bypass_principal = dev_principal
        logger.warning(
            "dev_auth_bypass_active",
            message="AUTH BYPASSED — DO NOT USE IN PRODUCTION",
            oidc_issuer=settings.oidc_issuer,
            unixname=dev_principal.unixname,
            uid=dev_principal.uid,
        )

    # --- /mcp transport mode (issue #128): a stateful aggregator (the
    # fastmcp/mcp SDK default, mcp_stateless_http=False) pins a streamable-
    # HTTP session to the pod that created it -- safe only with an external
    # session-affinity mechanism (e.g. an ingress hashing on client IP) in
    # front of more than one replica. The broker can't see whether that
    # affinity exists, so this can only warn, not refuse to start; it warns
    # whenever mcp_replica_count (chart-supplied) says there's more than one
    # replica to possibly land on.
    if (
        not settings.mcp_stateless_http
        and settings.mcp_replica_count is not None
        and settings.mcp_replica_count > 1
    ):
        logger.warning(
            "mcp_stateful_multi_replica",
            message=(
                "mcp_stateless_http=False with more than one broker replica: "
                "streamable-HTTP sessions are in-process state, so a load "
                "balancer without session affinity will route a session's "
                "later requests to a replica that never created it, which "
                "terminates the session and surfaces as an intermittent "
                "'Session terminated' error to MCP clients. Either leave "
                "mcp_stateless_http at its default (True) or put "
                "client-IP-hash affinity in front of the ingress -- see "
                "docs/architecture.md."
            ),
            replica_count=settings.mcp_replica_count,
        )

    # --- Authorization: the authorization/ engine matches the shipped policy.yaml.
    try:
        entitlement_policy = load_policy(settings.policy_file)
    except FileNotFoundError:
        logger.warning("policy_file_not_found", path=settings.policy_file)
        entitlement_policy = EntitlementPolicy()
    # Observability for issue #125: the effective group -> capability mapping
    # is otherwise implicit (chart default vs. operator override vs. dev-only
    # fallback all merge into the same in-memory EntitlementPolicy), so an
    # operator reading pod logs has no other way to see which policy is
    # actually live. Group/capability names only -- no tokens or secrets ever
    # pass through here.
    logger.info(
        "policy.group_capabilities_loaded",
        group_capabilities={
            group: sorted(caps)
            for group, caps in sorted(entitlement_policy.group_capabilities.items())
        },
    )

    # --- Service registry (config-only; adding a service needs no code change).
    # services_loaded means "services.yaml parsed without error" — an empty
    # `services: []` is a valid, successfully-parsed degraded state (issue #29);
    # it is only False when the file is missing or fails to parse.
    service_registry = ServiceRegistry()
    try:
        service_registry.load(settings.services_file)
        services_loaded = True
    except FileNotFoundError:
        logger.warning("services_file_not_found", path=settings.services_file)
        services_loaded = False
    services = service_registry.all_services()
    if not services:
        logger.warning("no_services_configured")

    # A service's required_capability that no group in group_capabilities
    # grants makes that service unusable by every principal -- e.g. the
    # operator never wrote a policy for it (a chart-rendered policy.yaml
    # with a stale key name the broker doesn't read, issue #59) or typo'd
    # the capability name. This is a hard startup failure, not a log line:
    # this is Kubernetes, so a Deployment rollout with a failing new pod
    # leaves the previous ReplicaSet serving traffic unaffected -- refusing
    # to start surfaces the misconfiguration as a visible rollout failure /
    # CrashLoopBackOff / k8s event with zero outage risk, which is strictly
    # better than a log line an operator has to be watching for. (Distinct
    # from the fail-closed check below, which guards against a service with
    # *no* gate at all -- this one guards against a gate nobody can pass.)
    granted_capabilities = {
        cap for caps in entitlement_policy.group_capabilities.values() for cap in caps
    }
    unreachable_capabilities: list[tuple[str, str]] = []
    for spec in services:
        if spec.required_capability in (None, "__none__"):
            continue
        if spec.required_capability not in granted_capabilities:
            unreachable_capabilities.append((spec.name, spec.required_capability))
    if unreachable_capabilities:
        msg = (
            "The following services require a capability that no group in "
            "group_capabilities grants, so they are unreachable by every "
            "principal (a forgotten policy entry or a typo'd capability "
            f"name): {sorted(unreachable_capabilities)}. Set "
            "entitlements.group_capabilities (chart) / policy.yaml (local "
            "dev) so at least one group grants each missing capability."
        )
        raise RuntimeError(msg)

    # --- x509 services and the identity-provider config list: x509 is an
    # ordinary `identity_providers` type with no synthesized fallback --
    # every `auth_type: x509` service must be covered by an explicit entry,
    # drift-checked both directions, fail-closed (_validate_x509_provider_
    # targets). Every surface downstream — provider registration,
    # /v1/catalog's credential_provider alias, /v1/identities — works from
    # these real, operator-declared entries.
    x509_targets: list[str] = [
        spec.name for spec in services if spec.auth_type == "x509"
    ]
    identity_provider_cfg_list = list(settings.identity_providers)
    _validate_x509_provider_targets(settings.identity_providers, set(x509_targets))
    has_service_mode_x509_cfg = any(
        cfg.type == "x509" and cfg.service_url is not None
        for cfg in identity_provider_cfg_list
    )

    # --- Credential subsystem: cache + janitor + provider registry.
    credential_cache = CredentialCache(
        max_failed_unlocks=settings.credential_unlock_max_failures,
        unlock_window_seconds=settings.credential_unlock_window_seconds,
    )
    credential_cache.start_janitor()

    credential_registry = CredentialRegistry()

    # --- Vault/OpenBao transport: one VaultKV instance (one K8s auth login
    # per process) shared by the oauth21 token store, the token registry,
    # the principal cache, and the x509 link/proxy store below, whichever of
    # the four (or more) is configured to use Vault — see vault_kv.py's
    # module docstring for the transport/domain split.
    # A service-mode x509 entry implies the x509 store: in service mode
    # proxies and passphrases persist in Vault (Settings._validate_vault_config
    # already refused to construct `settings` without the connection
    # settings).
    vault_kv: VaultKV | None = None
    if (
        settings.token_store_backend == "vault"
        or settings.token_registry_backend == "vault"
        or settings.principal_cache_backend == "vault"
        or has_service_mode_x509_cfg
    ):
        vault_kv = VaultKV(
            addr=settings.vault_addr,
            auth_mount=settings.vault_auth_mount,
            auth_role=settings.vault_auth_role,
            kv_mount=settings.vault_kv_mount,
            sa_token_path=settings.vault_sa_token_path,
        )
        # Trial authentication only -- proves the K8s auth flow works (SA JWT
        # readable, Vault reachable, role accepted) without touching any
        # stored credential or token-registry entry. A misconfigured Vault
        # backend is a security-sensitive state; refusing to start is safer
        # than silently degrading to a broker that can't persist state.
        try:
            await vault_kv._authenticate()
        except Exception as exc:
            logger.exception("vault_auth.failed")
            raise RuntimeError(f"Vault K8s auth failed at startup: {exc}") from exc
        logger.info("vault_auth.ok", vault_addr=settings.vault_addr)

    # --- Identity providers (issue #66 PR4): one CredentialProvider instance
    # per configured `identity_providers` entry, keyed by alias — either
    # Keycloak's stored-broker-token pattern (`keycloak-brokered`,
    # OIDCProvider) or the broker acting as a direct OAuth 2.1 client
    # (`oauth21-direct`, OAuth21Provider), sharing a single token store
    # (in-memory or Vault-backed, per `settings.token_store_backend` — issue
    # #66 PR3). `Settings._validate_oauth21_config` already refused to
    # construct `settings` above if an oauth21-direct entry is configured
    # without broker_state_key/oauth21_client_id, so both are guaranteed
    # present here whenever an oauth21-direct entry exists.
    identity_providers: dict[str, CredentialProvider] = {}
    identity_provider_configs: dict[str, IdentityProviderConfig] = {}
    oauth21_token_store: InMemoryTokenStore | VaultTokenStore | None = None
    oauth21_state_cipher = None
    has_oauth21_provider = any(
        cfg.type == "oauth21-direct" for cfg in settings.identity_providers
    )
    if has_oauth21_provider:
        if settings.token_store_backend == "vault":
            assert vault_kv is not None  # guaranteed by the check above
            oauth21_token_store = VaultTokenStore(
                vault_kv=vault_kv,
                kv_path_prefix=settings.vault_kv_path_prefix,
            )
        else:
            oauth21_token_store = InMemoryTokenStore()
    # The Fernet cipher is shared by two independent flows that both encrypt
    # in-flight OAuth 2.1 state (oauth_state.py): backend-account-linking
    # (oauth21-direct identity_providers, above) and the MCP OAuth discovery
    # bootstrap flow (issue #140, api/mcp_oauth.py). Either configuring this
    # cipher on its own -- Settings._validate_oauth21_config/
    # _validate_mcp_oauth_config already refused to construct `settings`
    # above if either is configured without broker_state_key.
    if has_oauth21_provider or settings.keycloak_login_client_id:
        oauth21_state_cipher = Fernet(
            settings.broker_state_key.get_secret_value().encode()
        )

    # --- AF Broker Identity Token issuer (issue #162): the broker's own
    # RS256 signing key for the identity-assertion JWTs the native providers
    # (BrokerIssuedProvider, and CondorTokenProvider's service exchange --
    # issue #169) mint for AF-native services. None when the feature is
    # unconfigured entirely (no BROKER_SIGNING_KEY_FILE -- a valid local-dev
    # state); load_broker_token_issuer itself raises RuntimeError on an
    # unreadable/invalid key or a missing issuer URL. The fail-closed check
    # below is the remaining gap: a native identity_providers entry (and
    # therefore every service resolving to it) with no signing key configured
    # at all must refuse to boot rather than fail at first request -- same
    # rollout-failure-over-silent-breakage reasoning as
    # unreachable_capabilities above.
    broker_token_issuer = load_broker_token_issuer(settings)
    if broker_token_issuer is None and any(
        cfg.type in ("broker-issued", "condor-token")
        for cfg in settings.identity_providers
    ):
        msg = (
            "identity_providers contains a broker-issued or condor-token "
            "entry but BROKER_SIGNING_KEY_FILE is not set, so the broker "
            "cannot sign AF Broker Identity Tokens for its targets. Mount "
            "the RS256 signing key (chart: broker.identityToken."
            "existingSigningKeySecret) or remove the entry -- see "
            "docs/auth.md's 'AF Broker Identity Token' section."
        )
        raise RuntimeError(msg)

    # --- x509 signing-key requirements. The aggregator injects a
    # broker-issued identity JWT for auth_type: x509 targets, the redeem
    # endpoint verifies it, and in service mode every voms-token-service
    # mint call is authenticated the same way — so a service-mode entry
    # (``service_url`` set) needs the signing key and is fail-closed at boot
    # without it — same rollout-failure-over-silent-breakage reasoning as
    # the broker-issued/condor-token check above. A legacy-mode entry
    # (``service_url`` None — every x509 service still needs one covering
    # it, see ``_validate_x509_provider_targets`` above) keeps the
    # pre-existing loud WARNING instead: the shipped services.yaml has
    # always declared an x509 service (ami), so refusing to boot would break
    # existing keyless deployments that never call it; enforcement then
    # stays at the point of use — the aggregator's x509 factory raises an
    # actionable ToolError and the redeem endpoint answers 503.
    if broker_token_issuer is None:
        if has_service_mode_x509_cfg:
            msg = (
                "identity_providers contains an x509 entry with a "
                "service_url but BROKER_SIGNING_KEY_FILE is not set, so the "
                "broker cannot sign the AF Broker Identity Tokens the "
                "aggregator injects for x509 targets, the redeem endpoint "
                "verifies, and voms-token-service authenticates mint calls "
                "with. Mount the RS256 signing key (chart: broker."
                "identityToken.existingSigningKeySecret) or remove "
                "service_url from the entry."
            )
            raise RuntimeError(msg)
        if x509_targets:
            logger.warning(
                "x509_services_without_signing_key",
                x509_targets=x509_targets,
                hint=(
                    "BROKER_SIGNING_KEY_FILE is not set; x509 services cannot "
                    "be called over /mcp until the RS256 signing key is "
                    "mounted (chart: broker.identityToken."
                    "existingSigningKeySecret)."
                ),
            )

    # --- x509 Vault link/proxy store, shared by every service-mode entry:
    # one KV record per subject regardless of how many entries exist (issue
    # #112's custodianship model — the link is per user, not per service).
    x509_vault_store: VaultX509Store | None = None
    if has_service_mode_x509_cfg:
        assert vault_kv is not None  # guaranteed by the vault block above
        x509_vault_store = VaultX509Store(
            vault_kv=vault_kv, kv_path_prefix=settings.x509_kv_path_prefix
        )
        logger.info(
            "x509_voms_service_mode",
            kv_path_prefix=settings.x509_kv_path_prefix,
        )

    # One CredentialProvider per configured entry, registered for the entry's
    # targets below — x509 included (voms-proxy minted from the user's
    # ~/.globus cert in legacy mode, or via the entry's voms-token-service
    # when a service_url is configured). `bearer`-auth services' credential
    # provider comes from `identity_providers`' per-entry `targets` list,
    # not a blanket auth_type match — this lets different services bind to
    # different aliases. `none` requires no user credential, so no provider
    # is registered.
    for cfg in identity_provider_cfg_list:
        provider: CredentialProvider
        if cfg.type == "keycloak-brokered":
            provider = OIDCProvider(
                settings,
                credential_cache,
                alias=cfg.alias,
                targets=frozenset(cfg.targets),
            )
        elif cfg.type == "broker-issued":
            assert broker_token_issuer is not None  # guaranteed by the check above
            provider = BrokerIssuedProvider(
                issuer=broker_token_issuer,
                cache=credential_cache,
                alias=cfg.alias,
                targets=frozenset(cfg.targets),
                target_options=cfg.target_options,
            )
        elif cfg.type == "condor-token":
            assert broker_token_issuer is not None  # guaranteed by the check above
            provider = CondorTokenProvider(
                issuer=broker_token_issuer,
                cache=credential_cache,
                alias=cfg.alias,
                targets=frozenset(cfg.targets),
                service_url=str(cfg.service_url),
                audience=cfg.audience,
            )
        elif cfg.type == "x509":
            if cfg.service_url is not None:
                # voms-token-service mode: mint at the entry's service (the
                # only component that mounts user homes) and persist both the
                # proxy and the link (Globus passphrase for hands-free
                # renewal) in Vault (issue #112 follow-up).
                assert broker_token_issuer is not None  # guaranteed by the check above
                assert x509_vault_store is not None  # built above for service mode
                provider = X509Provider(
                    settings,
                    credential_cache,
                    targets=frozenset(cfg.targets),
                    voms_client=VomsTokenServiceClient(
                        issuer=broker_token_issuer,
                        service_url=str(cfg.service_url),
                        audience=cfg.audience,
                        voms=cfg.voms,
                        valid=cfg.valid,
                    ),
                    vault_store=x509_vault_store,
                )
            else:
                # Legacy k8s-Job/local-dev mint path, exactly as before.
                provider = X509Provider(
                    settings,
                    credential_cache,
                    targets=frozenset(cfg.targets),
                )
        else:
            assert oauth21_token_store is not None  # guaranteed by the check above
            provider = OAuth21Provider(
                alias=cfg.alias,
                targets=frozenset(cfg.targets),
                authorization_endpoint=str(cfg.authorization_endpoint),
                token_endpoint=str(cfg.token_endpoint),
                issuer=cfg.issuer,
                scope=cfg.scope,
                store=oauth21_token_store,
                client_id=settings.oauth21_client_id,
                revocation_endpoint=(
                    str(cfg.revocation_endpoint) if cfg.revocation_endpoint else None
                ),
            )
        identity_providers[cfg.alias] = provider
        identity_provider_configs[cfg.alias] = cfg
        for target in cfg.targets:
            credential_registry.register(target, provider)

    # --- Fail-closed check (issue #60): a service that omits
    # `required_capability` in services.yaml relies on the credential layer
    # as its sole authorization gate -- the user must have a linked identity
    # / mintable credential for that target. If credential_registry can't
    # resolve a provider for it either (e.g. `auth_type: bearer` with no
    # `identity_providers` entry targeting it, or `auth_type: none` with no
    # provider registered at all), there is no gate whatsoever: any
    # authenticated principal could call it. Refuse to start rather than
    # silently exposing an ungated service -- this must be based on whether
    # credential_registry actually resolves the target, not the `auth_type`
    # string, since `auth_type: bearer` alone doesn't guarantee a provider is
    # wired up for this specific target.
    ungated_services: list[str] = []
    for spec in services:
        if spec.required_capability is not None:
            continue
        try:
            await credential_registry.resolve(spec.name)
        except KeyError:
            ungated_services.append(spec.name)
    if ungated_services:
        msg = (
            "The following services omit `required_capability` in "
            "services.yaml and have no credential provider resolving for "
            "their target, so there is no authorization gate at all "
            f"(neither a declared capability nor a mintable credential): "
            f"{sorted(ungated_services)}. Either declare `required_capability` "
            "(or `__none__` to explicitly open it to any authenticated user), "
            "or configure a credential provider (identity_providers / x509) "
            "targeting this service."
        )
        raise RuntimeError(msg)

    # --- Identity<->service join for /v1/catalog's credential_provider field
    # (issue #90): who services each target, from the same effective config
    # list the providers above were wired from — x509 targets get their real
    # entry's alias, no synthetic string.
    target_to_alias = _build_target_to_alias(identity_provider_cfg_list)

    # The default X509Provider api/credentials.py's /v1/x509/* routes fall
    # back to when no explicit target is given: the provider servicing the
    # first x509 service (matching _resolve_x509_target's default), or None
    # when no x509 service exists at all.
    x509_provider: X509Provider | None = None
    if x509_targets:
        resolved = await credential_registry.resolve(x509_targets[0])
        assert isinstance(resolved, X509Provider)  # registered above
        x509_provider = resolved

    # --- MCP OAuth discovery bootstrap (issue #140): short-lived, single-use
    # authorization codes minted by the Keycloak-login callback and redeemed
    # at /v1/oauth/token -- see mcp_auth_codes.py's module docstring for why
    # this is in-process rather than Vault-backed. Built unconditionally
    # (like pat_last_used_tracker in identity_mw.py) since it has no external
    # dependency; api/mcp_oauth.py's routes 503 on their own when
    # keycloak_login_client_id is unset, so an unused store here is harmless.
    mcp_auth_code_store = McpAuthCodeStore()

    # --- Tokens: durable registry backing the manual bearer-token bootstrap
    # flow (POST/GET/DELETE /v1/tokens, issue #24), Vault/OpenBao-backed for
    # HA-safe list/revoke across replicas (issue #115) with the same
    # in-memory local-dev fallback pattern as oauth21_token_store above.
    token_registry_backend: TokenRegistryBackend
    if settings.token_registry_backend == "vault":
        assert vault_kv is not None  # guaranteed by the check above
        token_registry_backend = VaultTokenRegistryBackend(
            vault_kv=vault_kv,
            kv_path_prefix=settings.token_registry_kv_path_prefix,
        )
    else:
        token_registry_backend = InMemoryTokenRegistryBackend()
    token_registry = TokenRegistry(token_registry_backend)

    # --- Revoked-jti cache: bridges the token registry to identity.py's hot
    # JWT-validation path (both /v1's keycloak_dependency and /mcp's
    # IdentityMiddleware call identity.get_principal, the single choke point
    # this enforces revocation at) without a per-request Vault round trip.
    # See token_registry.RevokedJtiCache's docstring for the staleness bound.
    revoked_jti_cache = RevokedJtiCache(
        token_registry_backend,
        refresh_interval_seconds=settings.revoked_jti_cache_refresh_seconds,
    )

    # --- Principal cache (issue #144 steps 2a/3/3b): resolves every
    # authenticated request's *current* groups/uid/gid/unixname/email from
    # Keycloak. Originally built only for PATs (opaque bearers carrying none
    # of that themselves); steps 3 and 3b made the JWT path defer to it too
    # (groups, then POSIX identity), so the token answers only "who is this?"
    # and the directory alone answers "what groups/POSIX identity do they
    # have?" -- see identity.py's `_resolve_current_attributes` and
    # principal_cache.py/principal_directory.py's module docstrings for the
    # mechanism.
    #
    # Both empty used to be a valid, degraded state (PAT-only): the broker
    # still started, and only a `mcp_pat_...` bearer on /mcp was rejected.
    # That is no longer true -- since step 3 removed the JWT path's
    # claims-based fallback, this account is now load-bearing for ALL
    # authentication, not just PATs. The dev bypass (BROKER_DEV_INSECURE_PRINCIPAL)
    # is the one exception: it short-circuits identity.keycloak_dependency/
    # mcp's AsgiAuthMiddleware before either ever reaches the directory (see
    # build_dev_principal), so it needs no directory at all. Neither
    # configured is therefore a genuine misconfiguration, not a degraded
    # mode -- refuse to start rather than boot a broker that can never
    # authenticate anyone. Same reasoning as the unreachable_capabilities
    # check above (issue #125): this is Kubernetes, so a Deployment rollout
    # with a failing new pod leaves the previous ReplicaSet serving traffic
    # unaffected -- a startup RuntimeError surfaces the misconfiguration as
    # a visible rollout failure with zero outage risk, which is strictly
    # better than a broker that accepts every request and then 503s all of
    # them.
    principal_cache: PrincipalCache | None = None
    if (
        settings.keycloak_admin_client_id
        and settings.keycloak_admin_client_secret.get_secret_value()
    ):
        principal_directory = KeycloakPrincipalDirectory(
            settings,
            settings.keycloak_admin_client_id,
            settings.keycloak_admin_client_secret.get_secret_value(),
        )
        # Persistence service for the cache above (issue #144 step 2b) —
        # same in-memory/Vault selection shape as token_registry_backend
        # above, sharing the same vault_kv transport instance.
        principal_cache_backend: PrincipalCacheBackend
        if settings.principal_cache_backend == "vault":
            assert vault_kv is not None  # guaranteed by the check above
            principal_cache_backend = VaultPrincipalCacheBackend(
                vault_kv=vault_kv,
                kv_path_prefix=settings.principal_cache_kv_path_prefix,
            )
        else:
            principal_cache_backend = InMemoryPrincipalCacheBackend()
        principal_cache = PrincipalCache(
            principal_directory,
            backend=principal_cache_backend,
            refresh_interval_seconds=settings.principal_cache_refresh_seconds,
            max_staleness_seconds=settings.principal_cache_max_staleness_seconds,
            heartbeat_interval_seconds=settings.principal_cache_heartbeat_seconds,
        )
    elif not application.state.dev_bypass_active:
        msg = (
            "KEYCLOAK_ADMIN_CLIENT_ID/KEYCLOAK_ADMIN_CLIENT_SECRET are unset "
            "and BROKER_DEV_INSECURE_PRINCIPAL is not active. As of issue "
            "#144 step 3, every authenticated request (JWT or PAT) resolves "
            "its current groups from the PrincipalDirectory, so the broker "
            "cannot authenticate anyone without this service account. "
            "Configure the Keycloak admin service account (see "
            "docs/auth.md's 'Operator setup: the Keycloak admin service "
            "account'), or set BROKER_DEV_INSECURE_PRINCIPAL for local "
            "development (see docs/local-development.md)."
        )
        raise RuntimeError(msg)

    # --- MCP aggregator: the FastMCP instance and its ASGI app already exist
    # (built eagerly at module scope below, since the aggregator must be
    # mountable before Settings()/ServiceRegistry() are known — see the
    # comment above `_mcp_aggregator`). Push the registry/policy/settings/
    # credential_registry/revoked_jti_cache/identity providers just loaded
    # above into it now that they're real -- the last three feed the af_*
    # diagnostic tools (issue #153).
    populate_aggregator(
        _mcp_aggregator,
        service_registry,
        settings,
        entitlement_policy,
        credential_registry,
        revoked_jti_cache,
        pat_backend=token_registry_backend,
        principal_cache=principal_cache,
        identity_providers=identity_providers,
        identity_provider_configs=identity_provider_configs,
        target_to_alias=target_to_alias,
        broker_token_issuer=broker_token_issuer,
    )

    # --- Audit: without init the module drops every record. Honor AUDIT_LOG_FILE.
    audit_output = _open_audit_output(settings.audit_log_file)
    init_audit_logger(audit_output)

    # --- Metrics: /metrics lives on its own port (chart NetworkPolicy allows
    # Prometheus only there), served by prometheus_client's thread so the
    # single uvicorn worker owns the process-wide registry.
    metrics_server = None
    application.state.metrics_port = None
    if settings.metrics_port >= 0:
        try:
            from prometheus_client import start_http_server

            metrics_server, _ = start_http_server(settings.metrics_port)
            application.state.metrics_port = metrics_server.server_port
            logger.info("metrics_server_started", port=metrics_server.server_port)
        except ImportError:
            logger.debug("prometheus_client_not_installed")

    application.state.settings = settings
    application.state.entitlement_policy = entitlement_policy
    application.state.service_registry = service_registry
    application.state.services = services
    application.state.services_loaded = services_loaded
    application.state.credential_cache = credential_cache
    application.state.credential_registry = credential_registry
    application.state.x509_provider = x509_provider
    application.state.x509_targets = x509_targets
    application.state.identity_providers = identity_providers
    application.state.identity_provider_configs = identity_provider_configs
    application.state.target_to_alias = target_to_alias
    application.state.oauth21_token_store = oauth21_token_store
    application.state.oauth21_state_cipher = oauth21_state_cipher
    application.state.token_registry = token_registry
    application.state.revoked_jti_cache = revoked_jti_cache
    application.state.principal_cache = principal_cache
    application.state.mcp_auth_code_store = mcp_auth_code_store
    application.state.broker_token_issuer = broker_token_issuer

    # Prime the JWKS cache at startup so the first request does not pay the
    # latency cost of a remote fetch.
    try:
        keys = await get_jwks(settings)
        logger.info("jwks_cache_primed", key_count=len(keys))
    except Exception as exc:  # noqa: BLE001  # non-fatal prime; broad catch intentional
        # Non-fatal at startup — the cache will be retried on the first request.
        logger.warning("jwks_cache_prime_failed", error=str(exc))

    logger.info(
        "af_mcp_broker_started",
        version=__version__,
        oidc_issuer=settings.oidc_issuer,
        policy_file=settings.policy_file,
        services_file=settings.services_file,
        services_count=len(services),
        x509_targets=x509_targets,
        identity_provider_aliases=list(identity_providers),
    )

    yield

    await credential_cache.stop_janitor()
    await aclose_http_client()
    if metrics_server is not None:
        metrics_server.shutdown()
        metrics_server.server_close()
    if audit_output is not sys.stdout:
        audit_output.close()
    logger.info("af_mcp_broker_stopped")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

# The aggregator's FastMCP instance (and the ASGI app built from it) must
# exist before FastAPI is constructed below: Starlette's Mount needs a
# concrete ASGI app at `app.mount()` time, and combining the aggregator's own
# lifespan (required so its StreamableHTTPSessionManager task group actually
# starts — omitting this makes every /mcp/** request 500) means the ASGI
# app's `.lifespan` must already exist when `lifespan=` is passed to
# FastAPI() below. Settings()/ServiceRegistry() are only loaded inside the
# async `lifespan()` above, which runs later — so this is built with an
# empty registry and placeholder Settings()/EntitlementPolicy()/
# CredentialRegistry(), and `lifespan()` calls `populate_aggregator()` to
# push in the real values before the app starts serving requests.
_mcp_aggregator_placeholder_settings = Settings()
_mcp_aggregator = build_aggregator(
    ServiceRegistry(),
    _mcp_aggregator_placeholder_settings,
    EntitlementPolicy(),
    CredentialRegistry(),
)
# stateless_http (issue #128): unlike policy_file/services_file, Settings()
# reads env vars synchronously at construction, so the placeholder instance
# above already reflects the real MCP_STATELESS_HTTP value -- no need to
# wait for populate_aggregator() to push in a later value.
#
# middleware=[build_asgi_auth_middleware(...)] (issue #138/#144 step 1):
# enforces identity at the ASGI layer, in front of FastMCP's own
# message-processing pipeline, so a missing/invalid/expired bearer token
# produces a genuine HTTP 401 instead of a 200 carrying a JSON-RPC error --
# see mcp/middleware/identity_mw.py's module docstring for the full mechanism
# and why IdentityMiddleware (still registered inside build_aggregator()
# above) survives alongside it as a thin hand-off rather than being removed.
_mcp_aggregator_app = _mcp_aggregator.http_app(
    path="/",
    stateless_http=_mcp_aggregator_placeholder_settings.mcp_stateless_http,
    middleware=[build_asgi_auth_middleware(_mcp_aggregator)],
)

app = FastAPI(
    title="AF MCP Broker",
    version=__version__,
    description=(
        "Credential-brokered MCP gateway for an ATLAS Analysis Facility. "
        "Provides Identity, Authorization, Credentialing, and Audit subsystems."
    ),
    lifespan=combine_lifespans(lifespan, _mcp_aggregator_app.lifespan),
)

# Trust X-Forwarded-{Proto,For,Host} from the fronting proxy so ``request.url``
# reports the client-visible scheme (https) instead of the container-local one
# (http). Load-bearing for /.well-known/cimd, whose self-referential
# ``client_id`` must equal the URL the fetcher used. ``trusted_hosts="*"`` is
# acceptable because the broker pod's HTTP port is only reachable inside the
# cluster via its Service — reaching it already implies cluster-network access.
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# Mount the MCP aggregator at /mcp. Requests to /mcp/** are handled entirely
# by the aggregator sub-application; they do not pass through the broker's
# FastAPI middleware chain after the mount point.
app.mount("/mcp", _mcp_aggregator_app)

app.include_router(v1_router)
app.include_router(wellknown_router)


@app.middleware("http")
async def _dev_bypass_header(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Annotate every response with ``X-Dev-Bypass: true`` when the local-dev auth bypass is active.

    Making bypassed responses visibly different from real ones is the
    client-side half of the defence-in-depth: any curl/browser interaction
    against a "prod" URL that unexpectedly answers with this header is a
    signal the deployment is misconfigured.
    """
    response = await call_next(request)
    if getattr(request.app.state, "dev_bypass_active", False):
        response.headers["X-Dev-Bypass"] = "true"
    return response


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

try:
    from prometheus_fastapi_instrumentator import Instrumentator  # type: ignore[import]

    # instrument() records request metrics into the default prometheus
    # registry; the lifespan serves that registry on METRICS_PORT (9090).
    # No expose() here — the API port must not serve /metrics (issue #11).
    Instrumentator().instrument(app)
except ImportError:
    # prometheus-fastapi-instrumentator is an optional dependency. The broker
    # functions correctly without it; metrics simply won't be available.
    logger.debug("prometheus_instrumentator_not_installed")


# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException) -> Response:
    # Delegate to FastAPI's built-in handler so WWW-Authenticate headers etc.
    # are preserved, then let structlog capture the event.
    logger.info(
        "http_exception",
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path,
    )
    return await http_exception_handler(request, exc)


@app.exception_handler(ValidationError)
async def _validation_error_handler(
    request: Request, exc: ValidationError
) -> JSONResponse:
    # A bare pydantic ValidationError reaching here is an internal bug
    # (e.g. building a response model): report a 500, not a client 422.
    # Bad request bodies raise RequestValidationError, which FastAPI's
    # default handler already turns into a 422.
    logger.error(
        "internal_validation_error",
        path=request.url.path,
        errors=exc.errors(),
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.exception_handler(RateLimitError)
async def _rate_limit_error_handler(
    request: Request, exc: RateLimitError
) -> JSONResponse:
    # RateLimitError is raised by CredentialCache.record_failed_unlock()/
    # check_unlock_rate_limit() on the x509 credential-issuance path (bad
    # passphrase / minting-backend failures against a colocated user's
    # ~/.globus) -- plain cache misses never raise it (see cache.py's get()).
    # Map it to 429 with Retry-After so well-behaved clients — and the portal
    # — back off instead of hammering the endpoint.
    retry_after = exc.retry_after_seconds
    retry_at = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=retry_after)
    logger.info(
        "rate_limit_exceeded",
        path=request.url.path,
        retry_after_seconds=retry_after,
    )
    return JSONResponse(
        status_code=429,
        content={
            "detail": (
                f"Too many failed unlock attempts. Try again in {retry_after} seconds."
            ),
            "retry_after_seconds": retry_after,
            "retry_at": retry_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        headers={"Retry-After": str(retry_after)},
    )

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any, Literal

import structlog
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    SecretStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings

from af_mcp_broker.mcp.registry import BUILTIN_SERVICE_NAME

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Identity provider config (issue #66 PR4) — one entry per identity provider
# the broker can link a user's account to. Unifies the two linking
# mechanisms (Keycloak's stored-broker-token pattern and the broker acting
# as a direct OAuth 2.1 client) into a single discriminated-union list.
# `alias` doubles as the portal-facing id on GET /v1/identities — no
# separate id-to-alias mapping.
# ---------------------------------------------------------------------------


class KeycloakBrokeredProviderConfig(BaseModel):
    """A Keycloak IdP the broker retrieves a stored brokered token from (``OIDCProvider`` — see ``GET /realms/<realm>/broker/<alias>/token``).

    ``alias`` must match the IdP alias configured in the OIDC issuer's realm.
    """

    type: Literal["keycloak-brokered"] = "keycloak-brokered"
    alias: str
    targets: list[str] = Field(default_factory=list)

    # Portal-facing metadata for GET /v1/identities. Optional so a minimal
    # provider config still parses; an operator who leaves these blank just
    # gets an empty label/description on the Identities page until they fill
    # them in.
    display_name: str = ""
    enables: str = ""


class OAuth21DirectProviderConfig(BaseModel):
    """A backend OAuth 2.1 authorization server the broker acts as a direct client to (``OAuth21Provider``) — see docs/auth.md for why this differs from the Keycloak-brokered path above."""

    type: Literal["oauth21-direct"] = "oauth21-direct"
    alias: str
    targets: list[str] = Field(default_factory=list)
    authorization_endpoint: AnyHttpUrl
    token_endpoint: AnyHttpUrl
    issuer: str
    scope: str = "openid profile email"

    # RFC 7009 token revocation endpoint. Optional -- when unset,
    # OAuth21Provider.revoke() skips the upstream call entirely and only
    # deletes the locally-stored token (see docs/auth.md and issue #86).
    revocation_endpoint: AnyHttpUrl | None = None

    # Portal-facing metadata for GET /v1/identities. Optional so a minimal
    # provider config still parses; an operator who leaves these blank just
    # gets an empty label/description on the Identities page until they fill
    # them in.
    display_name: str = ""
    enables: str = ""


class BrokerIssuedProviderConfig(BaseModel):
    """An AF-native credential source: the broker itself signs short-TTL identity-assertion JWTs (``BrokerIssuedProvider``, issue #162) — no linking, no external identity system, the broker is authoritative. See docs/auth.md's "AF Broker Identity Token" section.

    Carries no per-target token options: the ``aud`` and POSIX requirement of
    each target's token are declared on the *service* (``ServiceSpec.audience``
    / ``requires_posix``, issue #257) and resolved from the registry at wiring
    time, so every token property of a service lives in one place -- the
    service entry -- rather than being split between here and the aggregator.
    """

    type: Literal["broker-issued"] = "broker-issued"
    alias: str
    targets: list[str] = Field(default_factory=list)

    # Portal-facing metadata for GET /v1/identities. Optional so a minimal
    # provider config still parses; an operator who leaves these blank just
    # gets an empty label/description on the Identities page until they fill
    # them in.
    display_name: str = ""
    enables: str = ""


class CondorTokenProviderConfig(BaseModel):
    """An AF-native credential source for HTCondor IDTOKENs (``CondorTokenProvider``, issue #169): the broker mints an AF Broker Identity Token with ``aud=audience`` plus POSIX claims and exchanges it at condor-token-service's ``POST /v1/token`` — see docs/auth.md's "CondorTokenProvider" section.

    ``service_url`` is the base URL of the condor-token-service deployment
    (no path — the provider appends ``/v1/token``). ``audience`` is the exact
    ``aud`` claim the service verifies; the default matches the service's own
    default and should only change if a deployment renames itself.
    """

    type: Literal["condor-token"] = "condor-token"
    alias: str
    targets: list[str] = Field(default_factory=list)
    service_url: AnyHttpUrl
    audience: str = "condor-token-service"

    # Portal-facing metadata for GET /v1/identities. Optional so a minimal
    # provider config still parses; an operator who leaves these blank just
    # gets an empty label/description on the Identities page until they fill
    # them in.
    display_name: str = ""
    enables: str = ""


class X509ProviderConfig(BaseModel):
    """A grid-certificate credential source (``X509Provider``): VOMS proxies minted for the entry's targets, delivered by service-side redemption (``POST /v1/credentials/x509/redeem``) rather than header injection — see docs/auth.md.

    ``service_url`` is the base URL of the voms-token-service deployment
    (no path — the client appends ``/v1/mint``); when set, proxies and the
    Globus passphrase persist in Vault (the connection settings are then
    required — see ``_validate_vault_config``). ``None`` selects the legacy
    k8s-Job/local-dev mint path. ``voms``/``valid`` are the VOMS attribute
    set and proxy validity (HH:MM) forwarded on every mint; ``audience`` is
    the ``aud`` claim minted into each mint call's AF Broker Identity Token
    (same shape as ``CondorTokenProviderConfig``). Multiple entries with
    different service URLs/VOs are expressible — every ``auth_type: x509``
    service must be covered by an explicit entry (see
    ``app.py``'s ``_validate_x509_provider_targets``); there is no
    synthesized fallback.
    """

    type: Literal["x509"] = "x509"
    alias: str
    targets: list[str] = Field(default_factory=list)
    service_url: AnyHttpUrl | None = None
    voms: str = "atlas"
    valid: str = "192:00"
    audience: str = "voms-token-service"

    # Portal-facing metadata for GET /v1/identities. Optional so a minimal
    # provider config still parses; an operator who leaves these blank just
    # gets an empty label/description on the Identities page until they fill
    # them in.
    display_name: str = ""
    enables: str = ""


IdentityProviderConfig = Annotated[
    KeycloakBrokeredProviderConfig
    | OAuth21DirectProviderConfig
    | BrokerIssuedProviderConfig
    | CondorTokenProviderConfig
    | X509ProviderConfig,
    Field(discriminator="type"),
]


# pydantic-settings matches env vars to field names case-insensitively, so the
# uppercase env var names (OIDC_ISSUER, ...) map to these fields without
# explicit aliases.


class Settings(BaseSettings):
    # ``keycloak_dependency`` injects Settings via ``Depends(Settings)``. FastAPI
    # builds a request model from the callable's signature, and the pydantic-
    # settings ``BaseSettings.__init__`` exposes private (``_cli_parse_args`` …)
    # parameters that FastAPI cannot turn into fields. Overriding ``__init__``
    # with a plain ``**data`` signature keeps env loading intact while giving
    # FastAPI a clean signature to introspect.
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

    # OIDC configuration. The default below is the reference deployment's
    # (UChicago AF) realm URL, not a canonical value -- every deployment
    # overrides it via OIDC_ISSUER.
    oidc_issuer: str = "https://auth.af.uchicago.edu/realms/connect"
    oidc_audience: str = "mcp-gateway"
    # Optional realm URL for server-to-server (back-channel) Keycloak calls
    # -- JWKS, token endpoint, Admin REST API, brokered-token fetch. Set it
    # when the issuer is only reachable by its externally-advertised hostname
    # (it's embedded in tokens' `iss`) but the broker runs in the same
    # cluster and should reach Keycloak via cluster-local DNS instead of
    # hairpinning back out through the public ingress. Empty (the common
    # case) means back-channel calls use oidc_issuer directly.
    oidc_internal_url: str = ""

    # Filesystem
    home_root: str = "/data/homes"

    # Broker-owned per-uid proxy files live here (tmpfs in the chart, which
    # passes PROXY_DIR when broker.tmpfsProxy is enabled).
    proxy_dir: str = "/run/broker/proxies"

    # Policy and service config files read at startup
    policy_file: str = "/etc/af-mcp/policy.yaml"
    services_file: str = "/etc/af-mcp/services.yaml"

    # Name of the builtin gateway service the registry self-registers for the
    # broker's own af_* methods (issue #240) -- its registry key, catalog
    # identity, and audit/usage `mcp_service` label. Deployment-configurable so
    # a facility can align it with its service-naming convention; the reserved
    # `af` prefix (and the af_* method wire-names) are unaffected. Default is
    # registry.BUILTIN_SERVICE_NAME.
    builtin_service_name: str = BUILTIN_SERVICE_NAME

    # Keycloak group whose members see and can use every admin-only broker
    # surface (require_admin dependency, authorization/base.py's is_admin).
    # Empty means no admin surface is reachable by anyone: fail closed, no
    # magic default group name.
    admin_group: str = ""

    # Audit log destination; "-" means stdout
    audit_log_file: str = "-"

    # tiktoken encoding name used to ESTIMATE how many tokens a tool
    # result's serialized text would occupy if injected into an LLM
    # client's context (AuditRecord.result_tokens_est -- see
    # audit/measure.py). It is an estimate of context-injection cost, not a
    # provider-reported count: different LLMs tokenize differently, and
    # o200k_base is simply a reasonable modern reference tokenizer. Empty
    # string disables token estimation entirely (the field stays None;
    # byte measurement is unaffected).
    token_estimate_encoding: str = "o200k_base"

    # Which MeteringBackend implementation (audit/pipeline.py) carries
    # success/error audit records from the tool-call hot path to the worker
    # that measures and writes them. The single-valued Literal is deliberate:
    # the extension point exists (a future distributed backend, e.g. taskiq,
    # widens this Literal alongside its implementation), but no other backend
    # is implemented yet, and a value must never be accepted before its
    # implementation exists -- fail-closed at Settings construction time.
    metering_backend: Literal["in_process"] = "in_process"

    # Which UsageStore implementation (usage/) accumulates per-user tool-call
    # usage -- the per-(day, service, tool, outcome) aggregates GET /v1/usage
    # serves. "in_memory" is single-replica and lost on restart (fine for dev
    # and small facilities that treat usage as a convenience view; the audit
    # log stays authoritative either way); "postgres" persists events to the
    # af_mcp_usage_events table via asyncpg -- see usage/postgres.py.
    usage_store_backend: Literal["in_memory", "postgres"] = "in_memory"

    # asyncpg-compatible DSN (postgresql://user:pass@host/db) for the
    # postgres usage store. Required when usage_store_backend="postgres" --
    # fail-closed at Settings construction time, see
    # _validate_usage_store_config. With Crunchy PGO this is typically the
    # `uri` key of the operator-generated `<cluster>-pguser-<user>` secret,
    # wired in the chart via broker.usage.postgres.existingSecret.
    usage_postgres_dsn: SecretStr | None = None

    # Model key (a tokencost.TOKEN_COSTS entry) whose *input* token price
    # turns GET /v1/usage's result_tokens_est sums into estimated_cost_usd at
    # read time. Dollars are never stored -- only tokens -- so repricing is a
    # config change, not a migration. Overridable per-request via ?model=.
    cost_reference_model: str = "claude-sonnet-4-20250514"

    # OTLP/HTTP collector base URL (e.g. http://collector:4318) that turns on
    # OpenTelemetry trace EMISSION (tracing.py). Empty (the default) means
    # tracing is off: no SDK tracer provider is installed and every OTel API
    # call -- fastmcp's native spans included -- no-ops. The field name is
    # deliberately the standard OTel env var OTEL_EXPORTER_OTLP_ENDPOINT
    # (pydantic-settings matches it case-insensitively), which the SDK's OTLP
    # exporter also reads natively (appending the /v1/traces signal path) --
    # the broker only uses the value as the on/off gate and lets the exporter
    # do its own env handling. Sampling is likewise configured through the
    # standard OTEL_TRACES_SAMPLER / OTEL_TRACES_SAMPLER_ARG env vars, which
    # the SDK reads natively; the default sampler (parentbased_always_on) is
    # fine at tool-call volumes.
    otel_exporter_otlp_endpoint: str = ""

    # Prometheus /metrics is served on its own port so a NetworkPolicy can
    # firewall scraping separately from API traffic. 0 picks an ephemeral
    # port (tests); a negative value disables the metrics server.
    metrics_port: int = 9090

    # User-facing portal, used in unlock hints and identity-linking redirects.
    # The default below is the reference deployment's (UChicago AF) portal
    # hostname, not a canonical value -- every deployment overrides it via
    # PORTAL_URL.
    portal_url: str = "https://mcp-portal.af.uchicago.edu"

    # /mcp aggregator transport mode (issue #128). Streamable-HTTP sessions
    # are in-process state: a stateful session (the fastmcp/mcp SDK default)
    # created by one pod's `initialize` only exists in that pod's memory, so
    # an un-pinned load balancer routing a later request for the same
    # session to a different replica gets an unknown-session 404 and the
    # client sees "Session terminated" -- intermittently, invisibly in any
    # single-replica test, and roughly as often as replicas outnumber 1.
    # True (every request self-contained, any replica can serve it) is the
    # only mode that is safe without session-affinity infrastructure, so it
    # is the default. Disabling it trades that safety for the standalone GET
    # SSE stream (server-initiated notifications outside an active
    # tools/call, e.g. notifications/tools/list_changed) -- see
    # docs/architecture.md. mcp_replica_count below backs the startup check
    # that warns when this is disabled at replicaCount > 1.
    mcp_stateless_http: bool = True

    # Chart-supplied replica count (from .Values.broker.replicaCount),
    # purely so app.py's startup check can warn about the unsafe
    # mcp_stateless_http=False + replicaCount>1 combination described above.
    # None outside the chart (e.g. local dev) -- the check is skipped rather
    # than guessing.
    mcp_replica_count: int | None = None

    log_level: str = Field(
        default="INFO",
        alias="LOG_LEVEL",
    )

    # Local-development auth bypass. When set to a JSON blob describing a
    # principal, the broker's keycloak_dependency short-circuits and returns
    # that principal *without validating any bearer token*. This exists so
    # `astro dev` can hit `/v1/*` on a locally-running broker without
    # oauth2-proxy in front. The lifespan refuses to start unless
    # ``oidc_issuer`` points at a local host — defence-in-depth against
    # accidental production deployment. Never set this in any chart values,
    # container default, or CI env.
    dev_insecure_principal: str | None = Field(
        default=None,
        alias="BROKER_DEV_INSECURE_PRINCIPAL",
    )

    # CredentialCache.record_failed_unlock()/check_unlock_rate_limit() count
    # actual failed unlock attempts (bad passphrase, or a minting-backend
    # failure) per uid -- not plain cache misses from get(), see cache.py --
    # this many are allowed inside the window below before RateLimitError
    # trips. 5 is generous enough to tolerate a mistyped passphrase but tight
    # enough to slow a brute-force guesser who has read access to a user's
    # ~/.globus.
    credential_unlock_max_failures: int = 5

    # Sliding window, in seconds, over which the failures above are counted.
    # 15 minutes roughly matches how often a browser session's token refresh
    # forces re-authentication anyway, so it rarely inconveniences real users.
    credential_unlock_window_seconds: int = 15 * 60

    # Client ID Metadata Document (CIMD, draft-ietf-oauth-client-id-metadata-
    # document) served at /.well-known/cimd — lets the broker identify itself
    # to backend OAuth 2.1 authorization servers without per-backend Dynamic
    # Client Registration.
    cimd_client_name: str = "AF MCP Broker"

    # Fernet key (urlsafe-base64-encoded 32 bytes) that encrypts the OAuth 2.1
    # flow's `state` token — see oauth_state.py. Required (non-empty) whenever
    # `identity_providers` contains an `oauth21-direct` entry; enforced by
    # `_validate_oauth21_config`.
    broker_state_key: SecretStr = SecretStr("")

    # `iss`/`aud` self-reference embedded in the OAuth 2.1 state token, so a
    # token minted by one deployment is rejected by another. Empty means "use
    # oidc_issuer" — resolved at read time via `oauth21_effective_state_issuer`
    # rather than baked in here, so it always tracks the current oidc_issuer.
    oauth21_state_issuer: str = ""

    # The broker's own CIMD URL (e.g. https://mcp.af.uchicago.edu/.well-known/cimd),
    # used as `client_id` when the broker acts as an OAuth 2.1 client.
    oauth21_client_id: str = ""

    # Canonical origin (scheme + host, no trailing slash) for every
    # externally-visible URL the broker itself constructs in the OAuth 2.1
    # flow: the `redirect_uri` sent to a backend AS at authorize/callback
    # time, and every `redirect_uris` entry in the CIMD document. Both must
    # resolve to the same origin the portal SPA is served from -- the flow's
    # nonce cookie is host-only, so a request-relative callback URL (varying
    # by which ingress host the request arrived on) would drop the cookie on
    # the callback leg. Required (non-empty) whenever `identity_providers`
    # contains an oauth21-direct entry, or the MCP OAuth discovery bootstrap
    # flow (`keycloak_login_client_id` below) is configured; enforced by
    # `_validate_oauth21_config`/`_validate_mcp_oauth_config` respectively.
    # It is also the AS/resource identifier the broker advertises in its own
    # RFC 8414/RFC 9728 discovery metadata (api/wellknown.py, issue #140).
    broker_public_origin: str = ""

    # Confidential Keycloak client the broker authenticates as (authorization_
    # code grant, PKCE, plus this client secret) when it stands in for an MCP
    # client during the OAuth discovery bootstrap flow (issue #140,
    # api/mcp_oauth.py): the broker's own `/v1/oauth/authorize` redirects the
    # browser to Keycloak using this client, then exchanges the resulting code
    # at Keycloak's token endpoint to learn who logged in, before minting a
    # PAT for the MCP client. `TOKEN_MINT_CLIENT_ID`/`TOKEN_MINT_CLIENT_SECRET`
    # is the same "confidential client + sealed secret" env var pair the chart
    # already wires (see charts/af-mcp-platform/values.yaml's
    # `broker.tokenMint`) -- it was left unused when issue #144 step 2a
    # replaced the RFC 8693 token-exchange design that originally needed it;
    # this repurposes the identical shape for a different grant type
    # (authorization_code instead of token-exchange) rather than adding a
    # second confidential-client env var pair.
    keycloak_login_client_id: str = Field(default="", alias="TOKEN_MINT_CLIENT_ID")
    keycloak_login_client_secret: SecretStr = Field(
        default=SecretStr(""), alias="TOKEN_MINT_CLIENT_SECRET"
    )

    # One entry per identity provider the broker can link a user's account
    # to — either Keycloak's stored-broker-token pattern
    # (`keycloak-brokered`, OIDCProvider) or the broker acting as a direct
    # OAuth 2.1 client (`oauth21-direct`, OAuth21Provider). `alias` doubles
    # as the portal-facing id on GET /v1/identities. Parsed from
    # IDENTITY_PROVIDERS as a JSON array. An empty list is a valid, if
    # degraded, config — a broker with no identity providers configured.
    identity_providers: list[IdentityProviderConfig] = Field(default_factory=list)

    # Which TokenStore implementation backs the oauth21-direct providers above.
    # "in_memory" is single-replica and lost on restart (fine for dev/testing);
    # "vault" persists to Vault/OpenBao KV-v2 via the broker's K8s auth
    # identity — see credentials/vault.py.
    token_store_backend: Literal["in_memory", "vault"] = "in_memory"

    # Vault/OpenBao HTTP API base URL, no trailing slash (e.g.
    # https://vault.example.com). Required when token_store_backend="vault".
    vault_addr: str = ""

    # Vault auth mount point for the K8s auth backend (auth/<mount>/login).
    vault_auth_mount: str = "kubernetes"

    # Vault role the broker's ServiceAccount JWT is exchanged against.
    # Required when token_store_backend="vault".
    vault_auth_role: str = ""

    # Vault KV-v2 secrets engine mount point.
    vault_kv_mount: str = "secret"

    # Path prefix under the KV mount where per-subject/alias credentials are
    # stored: {vault_kv_mount}/data/{vault_kv_path_prefix}/{subject}/{alias}.
    vault_kv_path_prefix: str = "mcp/tokens"

    # Filesystem path to the broker's own ServiceAccount JWT, projected by
    # Kubernetes automatically whenever a ServiceAccount is set on the pod —
    # no extra volume mount needed at the chart's default.
    vault_sa_token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"

    # Which TokenRegistryBackend implementation backs the manual bearer-token
    # bootstrap flow (POST/GET/DELETE /v1/tokens, issue #115). "in_memory" is
    # single-replica and lost on restart (fine for dev/testing); "vault"
    # persists to the same Vault/OpenBao instance as token_store_backend
    # above, under a separate kv_path_prefix — see token_registry.py.
    token_registry_backend: Literal["in_memory", "vault"] = "in_memory"

    # KV-v2 path prefix for the token registry, distinct from
    # vault_kv_path_prefix (which is oauth21's TokenStore prefix) so the two
    # Vault-backed stores never collide under the same kv_mount.
    token_registry_kv_path_prefix: str = "mcp/token-registry"

    # How often (seconds) identity.RevokedJtiCache re-reads the token
    # registry's revoked-jti set. Bounds how long a revoked token keeps
    # working after DELETE /v1/tokens/{jti} -- see token_registry.py's
    # RevokedJtiCache docstring.
    revoked_jti_cache_refresh_seconds: float = 30.0

    # Grace window (seconds) token_sweep.py's expired-token janitor keeps a
    # record around after its expires_at passes, before removing it from
    # Vault -- see TokenRegistryBackend.sweep_expired's docstring. Default is
    # 7 days: long enough that a recently-expired token still shows up as
    # "expired" (not simply gone) on the portal's token list for a while.
    token_sweep_grace_seconds: int = 7 * 24 * 60 * 60

    # Default lifetime (days) for a PAT minted via POST /v1/tokens when the
    # caller doesn't request a specific expires_in_days -- issue #144 step
    # 2a. A never-expiring PAT is an explicit opt-in (MintTokenRequest.
    # never_expires), never the default: a long-lived, unrevoked-by-accident
    # credential that reaches a grid-credential broker deserves a deliberate
    # choice, not a config default nobody looked at twice.
    pat_default_expiry_days: int = 90

    # Confidential Keycloak client the broker authenticates as when calling
    # the Admin REST API to resolve any authenticated principal's current
    # groups/uid/gid/unixname (principal_directory.py's
    # KeycloakPrincipalDirectory) -- client_credentials grant, requires the
    # realm-management client roles `view-users` and `query-groups` (the
    # narrowest roles that satisfy GET .../users/{id} and
    # GET .../users/{id}/groups; see docs/auth.md). Issue #144 step 3 unified
    # groups resolution through this account for JWT callers too, not just
    # PATs -- both empty (the default) is therefore no longer a degraded-but-
    # working state. app.py's lifespan refuses to start when both are empty
    # unless the dev bypass (BROKER_DEV_INSECURE_PRINCIPAL) is active, which
    # short-circuits this account entirely -- see that lifespan's own
    # comment for the fail-fast reasoning. Deliberately not validated here at
    # Settings-construction time the way oauth21_client_id etc. are
    # (_validate_oauth21_config) -- unlike those, this check also depends on
    # dev_insecure_principal and issuer_is_local, which app.py's lifespan
    # already needs to evaluate together for the bypass's own startup check,
    # so doing it there once covers both rather than duplicating the logic.
    keycloak_admin_client_id: str = ""
    keycloak_admin_client_secret: SecretStr = SecretStr("")

    # Principal cache (principal_cache.py) staleness bounds -- two SEPARATE
    # numbers, not one, because they answer different questions: how often to
    # *try* refreshing (short -- a group removal should propagate quickly),
    # and how long a value may be served *without* a successful refresh
    # before failing closed (long -- a brief Keycloak outage should not lock
    # out every PAT-authenticated caller; this is research infrastructure,
    # not a bank). Mirrors RevokedJtiCache's single-interval shape, but that
    # cache has only ever needed the one number because its failure mode
    # (serve stale forever) has no analogous "eventually distrust this" bound
    # -- a principal's authority is a stronger thing to get wrong than
    # whether one specific token was revoked.
    principal_cache_refresh_seconds: float = 45.0
    principal_cache_max_staleness_seconds: float = 6 * 60 * 60.0

    # How often (seconds) a successful refresh that merely *confirms*
    # unchanged attributes still writes to the persistence backend below,
    # refreshing the durability of that knowledge -- a pure content-diff
    # (write only when something changed) would otherwise leave a stable
    # principal's persisted record weeks old, already past
    # principal_cache_max_staleness_seconds by the time a restart ever
    # happens, defeating the point of persisting at all. See
    # principal_cache.py's module docstring for the full write-amplification
    # arithmetic. Default (3 hours) is deliberately comfortably below the
    # default max_staleness_seconds (6 hours, i.e. half of it) so a healthy,
    # reachable system always has a persisted record well inside the
    # staleness bound. A *changed* value still persists immediately,
    # regardless of this interval.
    principal_cache_heartbeat_seconds: float = 3 * 60 * 60.0

    # Which PrincipalCacheBackend implementation persists the principal
    # cache above so a cold start doesn't lose every principal's last-known
    # attributes (issue #144 step 2b). "in_memory" is single-replica and
    # lost on restart (fine for dev/testing, and the pre-existing behavior
    # before this setting existed); "vault" persists to the same
    # Vault/OpenBao instance as token_store_backend/token_registry_backend
    # above, under a separate kv_path_prefix — see principal_cache.py.
    principal_cache_backend: Literal["in_memory", "vault"] = "in_memory"

    # KV-v2 path prefix for the persisted principal cache, distinct from
    # vault_kv_path_prefix/token_registry_kv_path_prefix so all three
    # Vault-backed stores never collide under the same kv_mount.
    principal_cache_kv_path_prefix: str = "mcp/principal-cache"

    # Keycloak user-profile attribute keys `principal_directory.py`'s
    # KeycloakPrincipalDirectory reads a PAT-authenticated principal's POSIX
    # identity from (Admin REST API `GET .../users/{id}`'s `attributes` map
    # -- issue #148). Defaults match AF's own profile attribute names; a
    # facility whose POSIX identity is LDAP-federated under different names
    # (the common spelling is `uidNumber`/`gidNumber`) overrides these rather
    # than the broker hardcoding AF's convention -- same reasoning as #125's
    # group_permissions. Unlike these, the JWT path (`identity.py`'s
    # `_extract_principal`) is NOT affected by this setting: a token's
    # `posix.uid`/`posix.gid`/`posix.unixname` claim shape is fixed by
    # convention (Keycloak's User Attribute mappers already normalize
    # whatever the underlying profile attribute is named into that shape),
    # so only the PAT path, which reads the Admin REST API directly with no
    # mapper in between, needs to know the real attribute name.
    posix_uid_attribute: str = "uid"
    posix_gid_attribute: str = "gid"
    posix_unixname_attribute: str = "unixname"

    # Whether `principal_directory.py` matches an authenticated principal's
    # group membership by Keycloak's group ``path`` (e.g. ``/atlas/users``)
    # instead of its bare ``name`` (e.g. ``atlas``). Issue #144 step 3
    # unified groups resolution through this same directory for every
    # credential type, so this setting now governs JWT and PAT callers
    # identically -- there is no longer a separate JWT-side mapper
    # convention it needs to be kept consistent with (see docs/auth.md's
    # "Keycloak: Group Membership mapper" section). Default False (bare
    # name) matches ``policy.yaml``'s ``group_permissions`` keys directly.
    principal_directory_group_full_path: bool = False

    # --- AF Broker Identity Token (issue #162): the broker's own RS256
    # signing key for the short-TTL identity-assertion JWTs
    # BrokerIssuedProvider mints for AF-native backends (identityProviders
    # type "broker-issued"). Filesystem path to the private key PEM,
    # mounted from a Secret in the chart (broker.identityToken.
    # existingSigningKeySecret) -- same "secret material comes from a
    # mounted file, never an inline env value" shape as
    # AF_SERVICE_TOKEN_FILE. Empty means the feature is unconfigured: valid
    # for local dev, but app.py's lifespan refuses to start when a
    # broker-issued identityProviders entry exists without it (fail-closed,
    # like the unreachable_permissions/ungated_services checks).
    broker_signing_key_file: str = ""

    # Directory of ADDITIONAL public key PEMs (files named *.pem) published
    # in /.well-known/jwks.json alongside the active signing key, so a new
    # key can be published before first use and the old one retired after an
    # overlap window -- see docs/auth.md's key-rotation procedure. Public
    # material only; the private half of a retiring key never needs to be
    # here.
    broker_additional_public_keys_dir: str = ""

    # `iss` claim minted into every AF Broker Identity Token. Empty means
    # "use broker_public_origin" -- resolved at read time via
    # `broker_token_effective_issuer` (same shape as
    # `oauth21_effective_state_issuer`), which is the natural default since
    # consumers verify against {origin}/.well-known/jwks.json.
    broker_token_issuer: str = ""

    # Lifetime (seconds) of each minted AF Broker Identity Token. The
    # default is deliberately 2x the credential layer's default
    # min-remaining floor (`issue(min_remaining_seconds=300)`, see
    # credentials/base.py): CredentialCache only serves an entry with at
    # least that many seconds left, so a TTL at or below the floor would
    # make every issue() a cache miss and a fresh mint -- functionally fine
    # but defeating the cache entirely. Keep this comfortably above 300.
    broker_token_ttl_seconds: int = 600

    # KV-v2 path prefix for the per-subject x509 link/proxy records
    # ({prefix}/{subject}/x509 -- see credentials/x509_vault.py), distinct
    # from vault_kv_path_prefix/token_registry_kv_path_prefix/
    # principal_cache_kv_path_prefix so all four Vault-backed stores never
    # collide under the same kv_mount.
    x509_kv_path_prefix: str = "mcp/x509"

    @property
    def broker_token_effective_issuer(self) -> str:
        """``broker_token_issuer`` if set, else ``broker_public_origin``.

        Computed at read time (like ``oauth21_effective_state_issuer``) so it
        always reflects the current value of either field rather than a value
        frozen at construction time.
        """
        return self.broker_token_issuer or self.broker_public_origin

    @property
    def oauth21_effective_state_issuer(self) -> str:
        """``oauth21_state_issuer`` if set, else ``oidc_issuer``.

        Computed at read time (like ``oidc_backchannel_url``) so it always
        reflects the current value of either field rather than a value frozen
        at construction time.
        """
        return self.oauth21_state_issuer or self.oidc_issuer

    @property
    def oidc_backchannel_url(self) -> str:
        """Realm URL for server-to-server Keycloak calls.

        ``oidc_internal_url`` if set, else ``oidc_issuer``. Every back-channel
        call (JWKS, token endpoint, Admin REST API, brokered-token fetch) must
        build its URL from this; ``oidc_issuer`` itself is reserved for token
        identity -- `iss` validation and anything embedded in minted tokens.
        """
        return self.oidc_internal_url or self.oidc_issuer

    @property
    def oidc_jwks_uri(self) -> str:
        """JWKS endpoint at the standard OIDC discovery path."""
        return f"{self.oidc_backchannel_url.rstrip('/')}/protocol/openid-connect/certs"

    @field_validator("broker_token_ttl_seconds")
    @classmethod
    def _validate_broker_token_ttl(cls, value: int, info: ValidationInfo) -> int:
        if value < 1:
            raise ValueError(
                f"{info.field_name} must be >= 1; see the field comment for "
                "why it should also stay comfortably above the credential "
                "layer's 300s min-remaining floor."
            )
        return value

    @field_validator(
        "credential_unlock_max_failures", "credential_unlock_window_seconds"
    )
    @classmethod
    def _validate_positive_rate_limit(cls, value: int, info: ValidationInfo) -> int:
        if value < 1:
            raise ValueError(
                f"{info.field_name} must be >= 1; a zero or negative value "
                "disables the rate limit instead of tuning it, defeating "
                "its purpose as a brute-force defence."
            )
        return value

    @model_validator(mode="after")
    def _validate_oauth21_config(self) -> Settings:
        """Fail startup loudly when an ``oauth21-direct`` identity provider is configured but the settings it depends on are not — a half-configured OAuth21Provider would otherwise fail at first request instead of at boot."""
        if not any(p.type == "oauth21-direct" for p in self.identity_providers):
            return self
        if not self.broker_state_key.get_secret_value():
            log.error(
                "oauth21_config_invalid",
                reason=(
                    "broker_state_key is empty but an oauth21-direct "
                    "identity provider is configured"
                ),
            )
            raise ValueError(
                "broker_state_key (BROKER_STATE_KEY) must be set when "
                "identity_providers contains an oauth21-direct entry — it "
                "protects in-flight OAuth 2.1 linking flows."
            )
        if not self.oauth21_client_id:
            log.error(
                "oauth21_config_invalid",
                reason=(
                    "oauth21_client_id is empty but an oauth21-direct "
                    "identity provider is configured"
                ),
            )
            raise ValueError(
                "oauth21_client_id (OAUTH21_CLIENT_ID) must be set when "
                "identity_providers contains an oauth21-direct entry — it "
                "identifies the broker as an OAuth 2.1 client via its CIMD "
                "document."
            )
        if not self.broker_public_origin:
            log.error(
                "oauth21_config_invalid",
                reason=(
                    "broker_public_origin is empty but an oauth21-direct "
                    "identity provider is configured"
                ),
            )
            raise ValueError(
                "broker_public_origin (BROKER_PUBLIC_ORIGIN) must be set when "
                "identity_providers contains an oauth21-direct entry — it is "
                "the canonical origin for the redirect_uri the broker sends "
                "to a backend AS and for the redirect_uris advertised in the "
                "CIMD document; the two must always agree."
            )
        return self

    @model_validator(mode="after")
    def _validate_broker_public_origin_format(self) -> Settings:
        """Validate ``broker_public_origin``'s shape whenever it is set, regardless of which feature required it (oauth21-direct linking or the MCP OAuth bootstrap flow below) -- split out from `_validate_oauth21_config` so both callers get the same format check instead of only whichever validator historically ran first."""
        if not self.broker_public_origin:
            return self
        if self.broker_public_origin.endswith("/"):
            raise ValueError(
                "broker_public_origin (BROKER_PUBLIC_ORIGIN) must not have a "
                "trailing slash — it is concatenated directly with a "
                "leading-slash path, e.g. f'{broker_public_origin}/v1/oauth/"
                "callback/{alias}'."
            )
        try:
            AnyHttpUrl(self.broker_public_origin)
        except ValidationError as exc:
            raise ValueError(
                "broker_public_origin (BROKER_PUBLIC_ORIGIN) must be a valid "
                f"http(s) URL: {exc}"
            ) from exc
        return self

    @model_validator(mode="after")
    def _validate_mcp_oauth_config(self) -> Settings:
        """Fail startup loudly when the MCP OAuth discovery bootstrap flow is half-configured -- a broker that redirected to Keycloak but couldn't exchange the resulting code (missing secret) or couldn't encrypt its own state (missing broker_state_key) would fail at first request instead of at boot, same rationale as `_validate_oauth21_config`."""
        if not self.keycloak_login_client_id:
            return self
        if not self.keycloak_login_client_secret.get_secret_value():
            log.error(
                "mcp_oauth_config_invalid",
                reason=(
                    "keycloak_login_client_id is set but "
                    "keycloak_login_client_secret is empty"
                ),
            )
            raise ValueError(
                "keycloak_login_client_secret (TOKEN_MINT_CLIENT_SECRET) must "
                "be set when keycloak_login_client_id (TOKEN_MINT_CLIENT_ID) "
                "is -- the broker authenticates as a confidential Keycloak "
                "client to exchange the login code it receives."
            )
        if not self.broker_state_key.get_secret_value():
            log.error(
                "mcp_oauth_config_invalid",
                reason=(
                    "broker_state_key is empty but keycloak_login_client_id "
                    "is configured"
                ),
            )
            raise ValueError(
                "broker_state_key (BROKER_STATE_KEY) must be set when "
                "keycloak_login_client_id is configured -- it protects the "
                "in-flight MCP OAuth bootstrap flow's state, the same way it "
                "protects the oauth21-direct linking flow's state."
            )
        if not self.broker_public_origin:
            log.error(
                "mcp_oauth_config_invalid",
                reason=(
                    "broker_public_origin is empty but keycloak_login_client_id "
                    "is configured"
                ),
            )
            raise ValueError(
                "broker_public_origin (BROKER_PUBLIC_ORIGIN) must be set when "
                "keycloak_login_client_id is configured -- it is the redirect_"
                "uri origin the broker sends to Keycloak and the issuer/"
                "endpoint origin advertised in the broker's own AS metadata."
            )
        return self

    @model_validator(mode="after")
    def _validate_vault_config(self) -> Settings:
        """Fail startup loudly when any Vault-backed store is selected but the settings they depend on are not — a half-configured VaultTokenStore/VaultTokenRegistryBackend/VaultPrincipalCacheBackend/VaultX509Store would otherwise fail at first request instead of at boot (see also app.py's lifespan trial authentication). All four stores share the same Vault connection settings (only their kv_path_prefix differs), so one validator covers any or all being selected. voms-token-service mode — an x509 identity_providers entry with a service_url — implies the x509 store: in service mode proxies and passphrases persist in Vault, there is no in-memory fallback (a legacy-mode x509 entry, no service_url, touches no Vault store and imposes nothing here)."""
        if (
            self.token_store_backend != "vault"
            and self.token_registry_backend != "vault"
            and self.principal_cache_backend != "vault"
            and not any(
                p.type == "x509" and p.service_url is not None
                for p in self.identity_providers
            )
        ):
            return self
        if not self.vault_addr:
            log.error(
                "vault_config_invalid",
                reason=(
                    "vault_addr is empty but token_store_backend, "
                    "token_registry_backend, and/or principal_cache_backend "
                    "is 'vault', or voms-token-service mode is configured "
                    "(an x509 identity_providers entry with a service_url)"
                ),
            )
            raise ValueError(
                "vault_addr (VAULT_ADDR) must be set when token_store_backend, "
                "token_registry_backend, or principal_cache_backend is 'vault' "
                "or voms-token-service mode is configured (an x509 "
                "identity_providers entry with a service_url)."
            )
        if not self.vault_auth_role:
            log.error(
                "vault_config_invalid",
                reason=(
                    "vault_auth_role is empty but token_store_backend, "
                    "token_registry_backend, and/or principal_cache_backend "
                    "is 'vault', or voms-token-service mode is configured "
                    "(an x509 identity_providers entry with a service_url)"
                ),
            )
            raise ValueError(
                "vault_auth_role (VAULT_AUTH_ROLE) must be set when "
                "token_store_backend, token_registry_backend, or "
                "principal_cache_backend is 'vault' or voms-token-service "
                "mode is configured (an x509 identity_providers entry with a "
                "service_url)."
            )
        return self

    @model_validator(mode="after")
    def _validate_usage_store_config(self) -> Settings:
        """Fail startup loudly when the postgres usage store is selected without a DSN — a half-configured PostgresUsageStore would otherwise fail at first request instead of at boot, same rationale as ``_validate_vault_config``."""
        if self.usage_store_backend != "postgres":
            return self
        if self.usage_postgres_dsn is None or not (
            self.usage_postgres_dsn.get_secret_value()
        ):
            log.error(
                "usage_store_config_invalid",
                reason=(
                    "usage_postgres_dsn is empty but usage_store_backend is 'postgres'"
                ),
            )
            raise ValueError(
                "usage_postgres_dsn (USAGE_POSTGRES_DSN) must be set when "
                "usage_store_backend is 'postgres' -- typically the `uri` key "
                "of a Crunchy PGO `<cluster>-pguser-<user>` secret."
            )
        return self

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance.

    Use as a FastAPI dependency (``Depends(get_settings)``) so ``.env`` is read
    once at first access rather than re-instantiated on every request.
    """
    return Settings()

# Admin capabilities design

Four related asks, one design pass: a config-driven admin group with a
reusable gating helper, an investigation of the duplicate-group-name issue,
an admin view of another user's usage, and a broker-wide maintenance mode.

## 1. Duplicate group listing — investigation, no broker code change yet

`af_whoami` showed `atlas` and `uchicago` twice in one caller's group list.
`principal_directory.py`'s docstring and `docs/auth.md` explain why:
`KeycloakPrincipalDirectory.resolve()` reads each group's Keycloak `name`
(bare, no path) rather than `path`, because AF Keycloak's Group Membership
mapper is configured "Full group path: OFF" and the policy engine
(`authorization/base.py`) string-matches those bare names against
`policy.yaml`'s `group_permissions` keys. `Settings
.principal_directory_group_full_path` exists to switch this to `path`
instead. The duplicates are almost certainly two distinct Keycloak groups at
different paths (e.g. `/atlas/foo`, `/other/atlas`) colliding once flattened
to bare names.

Flipping this requires three things to move together, not just the broker
flag:

1. Keycloak's Group Membership mapper → "Full group path: ON" (operator-side,
   Giordon's).
2. `principal_directory_group_full_path: true` (`Settings` / chart value
   `broker.principalDirectoryGroupFullPath` if not already exposed).
3. Every key in `policy.yaml`'s `group_permissions` rewritten from bare names
   to full paths — `get_principal_permissions` does a plain string match
   against `principal.groups`, so stale bare-name keys silently stop granting
   anything the moment full paths are turned on.

No broker code change is scoped here. Once the real group paths are known,
a follow-up rewrites `policy.yaml` (and any deployed overlay) to match.

## 2. Admin gating

**Config.** `Settings.admin_group: str = ""` (env `ADMIN_GROUP`, chart
`broker.adminGroup`). Empty means no admin surface is reachable — fail
closed, no magic default group name.

**Helper.** `is_admin(principal: Principal, settings: Settings) -> bool` in
`authorization/base.py`, next to the permission engine:
`bool(settings.admin_group) and settings.admin_group in principal.groups`.
Deliberately separate from the permission engine's `group_permissions` — an
admin surface answers a different question ("can this principal manage the
platform") than a service permission does, and item 4 (maintenance mode)
needs the same check to bypass an otherwise-universal gate, which doesn't
fit the permission model.

**Enforcement.** A FastAPI dependency `require_admin` (`identity.py` or a
new `admin.py`) that depends on `keycloak_dependency` and 403s with an
actionable detail when `is_admin()` is false. Every admin-only `/v1` route
(usage-for-other-users below, maintenance mode's admin endpoints, and any
future admin action) depends on it — this is the reusable gate the original
ask wanted, so adding a new admin action later is `Depends(require_admin)`
on its route, nothing else.

**Surfacing to the portal.** `IdentitiesResponse` (`api/identities.py`)
gets a new `is_admin: bool` field, computed the same way `require_admin`
computes it. The portal already fetches `/v1/identities` on every
authenticated page load, so no new round trip. `Base.astro` conditionally
renders an "Admin" nav entry; a new `admin.astro` page hosts the admin
views from items 3 and 4.

## 3. Admin usage view for other users

**`UsageStore` gets a listing method.** `usage/store.py`'s `UsageStore(ABC)`
gains `async def list_subjects(self, days: int) -> list[str]` — distinct
principal subjects with recorded usage in the trailing window.
`InMemoryUsageStore` derives it from its in-process counters;
`PostgresUsageStore` runs `SELECT DISTINCT subject FROM
af_mcp_usage_events WHERE ...` bounded by the same window. This only ever
lists people with broker activity, never a full Keycloak user directory.

**Endpoints.**
- `GET /v1/usage` gains an optional `subject` query param. A non-admin
  caller passing it gets 422 (or it's silently ignored — TBD at
  implementation time, 422 is more honest). An admin caller passing it gets
  that subject's usage instead of their own; response shape unchanged.
- `GET /v1/usage/subjects?days=` (new, `require_admin`) returns
  `list_subjects()`'s result, each resolved to `unixname`/`email` via the
  existing `PrincipalCache`/`PrincipalDirectory` (a cache hit for anyone
  already resolved recently; a cold miss triggers a live Keycloak lookup —
  acceptable here since this is an infrequent admin-only read, not a hot
  path). Subjects that fail to resolve (e.g. a deleted Keycloak user) are
  either omitted or shown with the bare subject as a fallback label — TBD at
  implementation time.

**Portal.** A dropdown on the new admin page (item 2's `admin.astro`),
populated from `GET /v1/usage/subjects`, showing `unixname` (or `email` if
unixname is absent) rather than raw subjects. Selecting an entry re-fetches
`GET /v1/usage?subject=...` and renders it through the existing
`UsagePage.vue`/`UsageCard.vue` components — no new usage-rendering code,
just a new data source feeding the same components.

## 4. Maintenance mode

**Store abstraction.** New `maintenance.py`, `MaintenanceModeStore(ABC)`
following the shape `TokenRegistryBackend`/`PrincipalCacheBackend` already
use — a `get()`/`set()` pair over:

```python
@dataclass(frozen=True)
class MaintenanceState:
    enabled: bool
    reason: str | None
    enabled_by: str | None   # admin subject
    enabled_at: float | None # time.time()
```

Selected via `Settings.maintenance_mode_backend: Literal["in_memory",
"vault", "postgres"] = "in_memory"`:

- `InMemoryMaintenanceModeStore` — dev/single-replica default.
- `VaultMaintenanceModeStore` — same `VaultKV` transport as the other
  Vault-backed stores, its own `kv_path_prefix`
  (`maintenance_mode_kv_path_prefix`), one record.
- `PostgresMaintenanceModeStore` — a small table on a DSN. New
  `Settings.maintenance_mode_postgres_dsn: SecretStr | None = None` with an
  `effective_*` property (mirroring `broker_token_effective_issuer`) that
  falls back to `usage_postgres_dsn` when unset — a facility already running
  Postgres for usage reuses it with no new secret, but isn't forced to
  couple the two if they diverge later. `_validate_maintenance_mode_config`
  (new model validator, alongside `_validate_usage_store_config`) fails
  startup when the backend is `postgres` and neither DSN is set.

**Startup warning, not a hard failure.** Mirroring the existing
`mcp_stateless_http` + `mcp_replica_count` check in `app.py`: if
`maintenance_mode_backend == "in_memory"` and `mcp_replica_count is not None
and mcp_replica_count > 1`, log a loud startup warning that maintenance
mode won't propagate across replicas. Never fail closed — a single-replica
or local-dev deployment legitimately wants the in-memory default with no
extra infra.

**Enforcement.** One `check_not_maintenance(principal, settings, store)`
gate, consulted in exactly two places so every caller of both surfaces is
covered uniformly:

- The `/v1` dependency chain, alongside `keycloak_dependency`.
- `AsgiAuthMiddleware` (`mcp/middleware/identity_mw.py`), right after
  `principal` is resolved (JWT or PAT) and before it's stashed on
  `scope["state"]` — this is the "PATs need the same check" requirement
  from the original ask: both credential types resolve a `Principal` at the
  same point in that middleware, so one gate covers both without a second
  code path.

`is_admin(principal, settings)` always bypasses the gate. A blocked caller
gets 503 (platform-level unavailability, not a credential problem — same
status-code reasoning `PrincipalDirectoryUnavailableError` already
established) with the configured `reason` in the detail when set.

**Admin API + portal.**
- `POST /v1/admin/maintenance` (`require_admin`) — body sets
  `enabled`/`reason`; `enabled_by`/`enabled_at` are stamped server-side.
- `GET /v1/admin/maintenance` — no `require_admin`, so the portal can show a
  maintenance banner to every visitor when it's on, not just admins.

Toggle UI lives on the item-2 admin page.

## Testing

Standard unit + integration split (`broker/tests/`), no new pattern needed:

- `is_admin`/`require_admin`: unit tests over `Principal`/`Settings`
  combinations (empty `admin_group`, member, non-member).
- `MaintenanceModeStore`: unit tests per backend (in-memory trivially; Vault
  and Postgres against the same fixtures `token_registry`/`usage/postgres`
  tests already use — real Vault/Postgres in CI, not mocks, matching this
  repo's no-mocks-in-integration-tests rule).
- `check_not_maintenance` enforcement: integration tests hitting `/v1/*` and
  `/mcp` with maintenance on, as an admin and as a non-admin, both JWT and
  PAT credentials.
- `UsageStore.list_subjects`: unit tests per backend, plus the `subject=`
  param on `GET /v1/usage` (admin vs. non-admin).
- Portal: component tests for the new admin page, dropdown, and maintenance
  banner, following the existing `__tests__` pattern next to
  `UsagePage.vue`/`IdentitiesPage.vue`.

## Open items to resolve during implementation

- `GET /v1/usage?subject=` for a non-admin: reject (422) vs. ignore. Leaning
  422 — silently ignoring a parameter a caller explicitly sent is worse than
  telling them why it didn't work.
- Unresolvable subjects in `GET /v1/usage/subjects` (deleted Keycloak user):
  omit vs. show bare subject as fallback label.
- Exact chart values wiring for the three new settings
  (`broker.adminGroup`, `broker.maintenanceMode.*`) — follows the existing
  `broker.principalCache.*`/`broker.usage.postgres.*` nesting conventions.

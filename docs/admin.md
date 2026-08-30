# Admin Capabilities

## Overview

A small set of broker surfaces are gated behind membership in one Keycloak
group rather than the permission model `policy.yaml` drives everything else
through: `is_admin()` (`authorization/base.py`) is a separate axis from
`group_permissions` — "can this principal manage the platform" is a
different question from "can this principal call this tool," and
maintenance mode (below) needs the same check to bypass an otherwise
universal gate, which doesn't fit the permission model.

This page covers what that admin group unlocks and how to configure it, and
the one admin-only feature with real operational weight: maintenance mode.

## Configuring the admin group

Set `broker.adminGroup` in the chart values to the name (or path, if
`broker.groupFullPath`/`PRINCIPAL_DIRECTORY_GROUP_FULL_PATH` is enabled) of
a Keycloak group in your realm, e.g.:

```yaml
broker:
  adminGroup: "af-admins"
```

This renders as the broker's `ADMIN_GROUP` env var (`Settings.admin_group`).
The empty string — the default — means no admin surface is reachable by
anyone: fail closed, with no magic default group name. Membership is
resolved the same way every other group membership is: live, on every
request, from `PrincipalDirectory` via the principal cache — there is no
token claim to configure and no separate mapper. Adding or removing someone
from this Keycloak group takes effect on their next request once the
principal cache refreshes, the same as any other group-derived permission.

## What the admin group gates

Three surfaces check `is_admin()` (directly, or via the `require_admin`
FastAPI dependency):

- **The portal's Admin page** (`/admin/`). The nav item itself is hidden
  client-side until `GET /v1/identities` reports `is_admin: true` for the
  caller — this is a static build with no per-request server auth state, so
  the real enforcement is server-side on the API calls the page makes, not
  the nav visibility. The page hosts both the usage-by-subject view below
  and the maintenance-mode toggle described next.
- **Usage for other subjects.** `GET /v1/usage/subjects` lists the distinct
  subjects with recorded usage in a trailing window (resolved to
  unixname/email where the principal cache can), and is admin-only end to
  end (`require_admin`). `GET /v1/usage` itself is normally scoped to the
  caller's own `principal.subject`; passing `?subject=<other>` is rejected
  with 403 unless the caller is in the admin group, in which case it
  returns that subject's usage instead. Both only ever surface subjects
  with actual broker activity — never a full Keycloak user directory.
- **`POST /v1/admin/maintenance`** — see below.

## Maintenance mode

Maintenance mode is a single broker-wide on/off flag. While enabled, every
non-admin caller is refused on both `/v1` and `/mcp` with a 503 ("The
broker is in maintenance mode." plus the configured reason, if any);
callers in the admin group pass through untouched on both surfaces.
Two routes are deliberately never gated by it regardless of who's calling:
the `/v1` health probes (Kubernetes liveness/readiness must keep passing
during a deliberate maintenance window, or the platform restarts pods
exactly when it shouldn't) and `GET /v1/admin/maintenance` itself (the
portal needs to be able to show a maintenance banner to a visitor who is
currently blocked by it on everything else).

### The fail-open limitation — read this before toggling maintenance mode for an incident

**Maintenance mode fails OPEN for non-admins if the backing store itself is
unreachable.** `check_not_maintenance` (`maintenance.py`) checks whether the
caller is an admin *before* it reads the store, specifically so an admin
can still get through to fix things during a store outage. But that means
if the store itself can't be reached — a Vault or Postgres outage — a
non-admin caller is let straight through too, exactly as if maintenance
mode were disabled, rather than being blocked. The failure is logged (ERROR
level, with a traceback) and counted
(`metrics.maintenance_store_unavailable_total`) so it's visible to
operators, but the caller is never blocked by it.

The practical consequence: **do not rely on maintenance mode as an
incident-containment control** — "lock everyone out right now because
something is actively wrong" — if the maintenance store could plausibly
share that incident's blast radius. The same outage or attack that
motivated locking the platform down could also be what takes out
Vault/Postgres, which would silently defeat the lockdown for exactly the
population it was meant to stop. Maintenance mode is a planned-maintenance
convenience feature — "give me a clean window to run a migration without
users hitting a half-upgraded broker" — not an incident-response kill
switch. If you need the latter, it has to live somewhere upstream of the
broker (an ingress-level block, a network policy, or similar) that doesn't
share fate with the broker's own dependencies.

### Don't combine an empty `admin_group` with maintenance mode

If `broker.adminGroup` is ever unset or misconfigured (empty is the
fail-closed default — see above) *while* maintenance mode is enabled, every
principal is a non-admin, so `is_admin()` is `False` for everyone —
including whoever meant to be the admin. `POST /v1/admin/maintenance` then
403s unconditionally (there is no bypass), so the API alone can't turn
maintenance mode back off. `GET /v1/admin/maintenance` stays reachable (it
requires no auth), so you can at least confirm it's stuck on.

The recovery path is still simple: `admin_group` is a `Settings` field
(`ADMIN_GROUP` env var, `broker.adminGroup` chart value), not something
stored in the maintenance-mode backend — restoring it to a correct group
name and redeploying fixes `is_admin()` for everyone immediately, regardless
of whether the maintenance-mode backend is in-memory, Vault, or Postgres.
Direct manipulation of the maintenance store itself is only needed if chart
or `kubectl` access is *also* unavailable.

### Toggling it

The portal's Admin page has a maintenance-mode section (status, reason,
who/when it was last enabled, and enable/disable controls) for an admin who
just wants to click a button. Every visitor, admin or not, also sees a
banner across the top of the portal whenever maintenance mode is on — it's
fetched from `GET /v1/admin/maintenance` with no authentication at all, so
it renders even for someone whose session has expired or who was never
logged in, which is the population it exists to inform.

To toggle it without the portal, enable or disable it directly against the
API:

```bash
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN

# Enable, with a reason
curl -sS -X POST "https://mcp.af.uchicago.edu/v1/admin/maintenance" \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "reason": "Scheduled Postgres upgrade, back by 14:00 UTC"}'

# Disable
curl -sS -X POST "https://mcp.af.uchicago.edu/v1/admin/maintenance" \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

`POST` requires admin-group membership (403 otherwise); `enabled_by` and
`enabled_at` are always stamped server-side from the caller's own principal
and the current time, never taken from the request body, so an admin can't
misattribute a toggle to someone else. Disabling clears `reason`,
`enabled_by`, and `enabled_at` back to null, rather than leaving a stale
reason sitting around unauthenticated (see below) until the next toggle
happens to overwrite it. On the Vault backend, a concurrent write from
another admin can lose the compare-and-set race; that surfaces as a 409
Conflict, and the caller should re-check `GET /v1/admin/maintenance` and
retry.

**`reason` is broadcast with zero authentication.** `GET
/v1/admin/maintenance` requires no credential of any kind — anyone who can
reach the broker at all gets `reason` (and `enabled_by`, a Keycloak
subject) back verbatim. Whatever you type into `reason` should be treated
like a public status-page message: never put secrets, internal hostnames,
incident details, or anything else you wouldn't post publicly into it.

### Backend choice

`broker.maintenanceMode.backend` selects which `MaintenanceModeStore`
implementation holds the flag, and it must be visible to every broker
replica consistently — a flag flipped on one pod is useless if the others
keep admitting requests:

- **`in-memory`** (the default) is process-local and single-replica: the
  flag is lost on restart, and in a multi-replica deployment only the pod
  that handled the `POST` ever sees the change — the broker warns at
  startup (never fails) when this is selected alongside `replicaCount > 1`.
  This is the same in-memory/single-replica tradeoff the principal cache,
  token registry, and usage store all make with their own backend
  selections; it is fine for local dev or a single-replica deployment, but
  not for a real multi-replica facility.
- **`vault`** persists to the same Vault/OpenBao instance the other
  Vault-backed stores use, under its own `broker.maintenanceMode.kvPathPrefix`
  (default `mcp/maintenance-mode`) so it never collides with them under the
  same KV mount. Concurrent writes are compare-and-set; a lost race
  surfaces as the 409 described above rather than silently applying
  last-writer-wins.
- **`postgres`** persists to a single-row table (`af_mcp_maintenance_mode`)
  via asyncpg. `broker.maintenanceMode.postgres.existingSecret` points at a
  secret carrying the DSN (rendered as `MAINTENANCE_MODE_POSTGRES_DSN`); if
  left unset, it falls back to reusing `broker.usage.postgres`'s DSN (both
  point at the same database by default) rather than forcing a second
  secret — set it explicitly only if maintenance mode should use a
  genuinely different database than the usage store. Postgres writes are
  last-writer-wins, not compare-and-set.

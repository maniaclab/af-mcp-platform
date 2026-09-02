# Ops-platform usability pass

## Background

Bringing up `af-mcp-ops-platform` (a condor-only second front door, see the
`flux_apps` repo's `docs/plans/2026-09-01-mcp-ops-platform-design.md`)
surfaced two categories of friction: the portal is hardcoded to "AF MCP
Platform" / "ATLAS Analysis Facility" branding with no way to identify a
second deployment as distinct, and diagnosing a real audience-mismatch
misconfiguration (`mcp-ops-gateway` scope missing its Audience mapper) took
longer than it should have because nothing in the UI or logs pointed
directly at the cause.

## 1–3: Configurable branding

The portal is a static build (`astro.config.mjs` `output: 'static'`), so
per-deployment text can't be baked in at build time — it has to come from
`/config.json` (the existing runtime-config mechanism for OIDC settings and
`brokerOrigin`) and get patched into the DOM after mount, same as those.

- `portal/src/lib/branding.ts`: `BrandingConfig` (`shortName`, `fullName`,
  `facilityName`), `DEFAULT_BRANDING` (today's hardcoded strings, unchanged),
  and `applyBranding(config, doc)` — patches every `[data-af-brand]`
  element's `textContent` (or `aria-label` when
  `data-af-brand-target="aria-label"` is set), falling back to
  `DEFAULT_BRANDING` per-field for anything left empty.
- `auth.ts`'s `getBranding()` loads `/config.json` and merges
  `branding.*` over the defaults, mirroring `getBrokerOrigin()`'s
  fallback-never-throws convention exactly.
- Wired in: `Base.astro`'s mount script (sidebar + topbar logo — handled
  directly rather than via the generic data-attribute pass, since the logo
  needs `"<fullName> home"` as its aria-label, not a bare field value; and
  the overview hero eyebrow, tagged `data-af-brand="facilityName"`, covered
  by the same generic sweep). `Footer.astro` gets its own tiny
  self-contained script, since it also renders under `PublicBase.astro`
  (the unauthenticated landing page), which never runs Base's mount script.
- Chart: `portal.branding.{shortName,fullName,facilityName}` (all default
  `""`), rendered into `config.json` by `configmap-portal-config.yaml`. A
  deployment that sets nothing renders byte-identical `config.json`
  branding fields to before this existed.

## 4: Entitlements visibility

Two API additions, both already-authenticated (`keycloak_dependency`, same
as every other `/v1` route — no special-cased public route):

- `GET /v1/permissions` now also returns the caller's raw
  `principal.groups` alongside the resolved `grants` it already returned —
  the internal data existed already, it just wasn't surfaced.
- `GET /v1/entitlements` (new): the static `EntitlementPolicy.group_permissions`
  table verbatim, the same for every caller.

Portal: new `/entitlements/` page (`EntitlementsPage.vue`), added to the
existing **Platform** sidebar section (previously just "Admin") —
deliberately *not* admin-gated, since the point is helping an
under-provisioned user see why, not an admin tool. Shows "you're in
{groups} → {grants}" next to the full reference table, with the caller's
own row(s) marked. Added to `ingress-portal-authenticated.yaml`'s
ForwardAuth path list like every other authenticated route (verified by the
existing `check-protected-routes.mjs` build check).

## 5: Diagnosability

The audience-mismatch path (`TokenAudienceError`, `"insufficient_scope"`,
correlation_id) was already well-designed end to end — see
`docs/plans/2026-08-24-audience-mismatch-error-ui-design.md` — and the
portal-side error code is intentionally NOT changed here, since the portal
already pattern-matches on it (`api.ts`'s `AccessDeniedError`). The actual
gap: the `jwt_audience_mismatch` log line carried only `subject` and
`correlation_id`, not the token's actual vs. expected audience, so
confirming *which* mismatch this was still meant decoding the token
separately. `identity.py` now logs `actual_audience` (peeked unverified,
same pattern as the existing `_peek_sub`) and `expected_audience`
(`settings.oidc_audience`) directly on that line.

## Testing

- Broker: `test_identity.py`'s new audience test patches
  `identity.logger.warning` directly (`monkeypatch.setattr`) rather than
  `structlog.testing.capture_logs()` — the app's structlog config sets
  `cache_logger_on_first_use=True`, so a logger already resolved by an
  earlier test's real app boot (any test using `app_client_factory`) is
  cached before `capture_logs()`'s processor swap can reach it; this bit
  running the full suite (passes in isolation, flakes in the full run).
  `monkeypatch.setattr` on the module's own logger object sidesteps the
  caching entirely — same pattern already used in `test_app.py`/
  `test_health.py`/`test_mcp_list_time_credentials.py`.
- `test_permissions_api.py` (new): `GET /v1/permissions`'s `groups` field
  and `GET /v1/entitlements`, via the `app_client`/`app_client_factory`
  fixtures (real app, `keycloak_dependency` overridden).
- Portal: `branding.test.ts` (pure `applyBranding` DOM patching, jsdom),
  `auth.test.ts` additions mirroring `getBrokerOrigin`'s three existing
  cases (dev-bypass, unreachable, configured), `api.test.ts` additions for
  the extended `PermissionsResponse` and new `fetchEntitlements`. No Vue
  component-mount tests for `EntitlementsPage.vue`, consistent with this
  repo's existing convention (see `backendStatus.ts`'s docstring).

/**
 * maintenanceBanner.ts — display/error logic behind maintenance mode's two
 * portal surfaces: the every-visitor banner (Base.astro's mount script) and
 * AdminPage.vue's toggle section.
 *
 * Kept as plain functions (no DOM access, no Vue) following x509Identity.ts's
 * pattern, so both are unit testable without a component harness.
 */
import { APIError, SessionExpiredError } from './api';
import type { MaintenanceStatus } from './api';

/**
 * Text to show in the maintenance banner, or null when it should stay
 * hidden. Pure mapping so Base.astro's shell script stays trivial, mirroring
 * navSummary.ts's `navBadges` — it fetches GET /v1/admin/maintenance
 * (best-effort, no auth) and pins the returned text onto the banner
 * element. A `null` status (fetch failed) or a disabled one yields nothing
 * to reveal, so the banner degrades to staying hidden rather than showing
 * misleading or stale content.
 */
export function maintenanceBannerText(status: MaintenanceStatus | null): string | null {
  if (!status || !status.enabled) return null;
  return status.reason
    ? `Maintenance mode is enabled: ${status.reason}`
    : 'Maintenance mode is enabled.';
}

/**
 * Extracts FastAPI's `{"detail": "..."}` from an APIError body, or null when
 * the body isn't that shape (e.g. an HTML error page from a proxy hop). Same
 * helper as x509Identity.ts's own apiErrorDetail() — duplicated rather than
 * shared since each lives beside its own single call site and neither module
 * imports from the other.
 */
function apiErrorDetail(err: APIError): string | null {
  try {
    const parsed = JSON.parse(err.body) as { detail?: unknown };
    return typeof parsed.detail === 'string' ? parsed.detail : null;
  } catch {
    return null;
  }
}

/**
 * User-facing message for a failed POST /v1/admin/maintenance (AdminPage.vue's
 * toggle). The broker's own `detail` is preferred when present, same as
 * x509Identity.ts's x509LinkErrorMessage/x509PreflightErrorMessage — for both
 * 403 (identity.py::require_admin's "This action requires membership in the
 * admin group.") and 409 (api/admin.py::set_maintenance_status's re-check-
 * and-retry sentence) the broker's detail text is already the exact message
 * an admin needs, so the canned fallbacks below are reached only if the
 * response body isn't the expected `{"detail": ...}` shape.
 *
 * AdminPage.vue does NOT route a SessionExpiredError through this function —
 * that gets its own dedicated "Reload" button UI, the same as the Usage
 * section's identical condition — but it's handled here too so this function
 * has one complete, independently testable contract for every error this
 * POST can throw, matching x509LinkErrorMessage/x509PreflightErrorMessage's
 * own shape.
 */
export function maintenanceErrorMessage(err: unknown): string {
  if (err instanceof SessionExpiredError) {
    return 'Session expired — reload the page to re-authenticate.';
  }
  if (err instanceof APIError) {
    const detail = apiErrorDetail(err);
    if (detail) return detail;
    if (err.status === 403) {
      return 'Access not yet granted — your admin membership may not have refreshed yet.';
    }
    if (err.status === 409) {
      return 'Someone else just changed maintenance mode. Reload and retry.';
    }
  }
  if (err instanceof Error && err.message) return err.message;
  return 'Could not update maintenance mode.';
}

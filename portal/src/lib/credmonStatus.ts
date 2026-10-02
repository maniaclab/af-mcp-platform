/**
 * credmonStatus.ts — display logic behind AdminPage.vue's HTCondor credmon
 * panel (GET /v1/admin/credmon, POST /v1/admin/credmon/sync; see
 * docs/credmon.md).
 *
 * Kept as plain functions (no DOM access, no Vue) following
 * maintenanceBanner.ts's pattern, so the health rules are unit testable
 * without a component harness.
 */
import { APIError, SessionExpiredError } from './api';
import type { CredmonStatus } from './api';
import { apiErrorDetail } from './x509Identity';

export type CredmonHealth = 'disabled' | 'pending' | 'healthy' | 'warning' | 'error';

/**
 * Overall state of the sync loop at *nowSeconds* (unix seconds).
 *
 * Mirrors the chart's stale-sync alert: a last success older than twice the
 * interval is a warning. A 'partial' cycle (some users failed) still
 * advanced last_success_at broker-side, so it is a warning rather than an
 * error; 'failed' (the cycle itself raised) or no success ever is an error.
 */
export function credmonHealth(status: CredmonStatus, nowSeconds: number): CredmonHealth {
  if (!status.enabled) return 'disabled';
  const run = status.last_run;
  if (!run) return 'pending';
  if (run.outcome === 'failed' || run.last_success_at === null) return 'error';
  if (run.outcome === 'partial') return 'warning';
  if (
    status.interval_seconds !== null &&
    nowSeconds - run.last_success_at > 2 * status.interval_seconds
  ) {
    return 'warning';
  }
  return 'healthy';
}

export interface CredmonKindRow {
  kind: string;
  /** credd service name jobs put in use_oauth_services. */
  service: string;
  stored: number;
  notLinked: number;
  noPosix: number;
  failed: number;
}

/** One row per synced kind with the last cycle's counts; kinds absent from a count map (nothing to report) read as 0. */
export function credmonKindRows(status: CredmonStatus): CredmonKindRow[] {
  const run = status.last_run;
  return status.kinds.map((kind) => ({
    kind,
    service: `${status.service_prefix}${kind}`,
    stored: run?.stored[kind] ?? 0,
    notLinked: run?.not_linked[kind] ?? 0,
    noPosix: run?.skipped_no_posix[kind] ?? 0,
    failed: run?.failed[kind] ?? 0,
  }));
}

/** When the broker's own timer next makes a cycle due (unix seconds), or null when there is no last run yet or an external scheduler drives cycles. */
export function credmonNextRunAt(status: CredmonStatus): number | null {
  if (!status.internal_timer || !status.last_run || status.interval_seconds === null) {
    return null;
  }
  return status.last_run.finished_at + status.interval_seconds;
}

/**
 * User-facing message for a failed POST /v1/admin/credmon/sync. The broker's
 * own `detail` (with its correlation reference) is preferred; the canned
 * sentences cover a response body that isn't `{"detail": ...}` (e.g. an
 * HTML error page from a proxy hop).
 */
export function credmonSyncErrorMessage(err: unknown): string {
  if (err instanceof SessionExpiredError) {
    return 'Your session has expired. Reload the page to sign in again.';
  }
  if (err instanceof APIError) {
    const detail = apiErrorDetail(err);
    if (detail) return detail;
    if (err.status === 404)
      return 'The HTCondor credmon integration is not enabled on this broker.';
    if (err.status === 409)
      return 'A sync is already running on another broker replica. Try again shortly.';
    if (err.status === 403) return 'Running a sync requires admin access.';
  }
  return err instanceof Error ? err.message : 'The sync could not be started.';
}

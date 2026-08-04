/**
 * backendStatus.ts — pure mapping from a catalog server's `status` (issue
 * #123, see broker/src/af_mcp_broker/api/capabilities.py's _backend_status)
 * to how BackendCard.vue should render it: a label, severity, and the right
 * call to action. Kept as plain data-in/data-out functions (no DOM/fetch
 * access) so it's trivially unit-testable, same pattern as lib/catalog.ts
 * and lib/linkedBanner.ts -- the repo deliberately avoids component-mount
 * harnesses, so component logic stays thin and this module carries the
 * actual decisions.
 */
import type { BackendStatus, CatalogServer } from './api';

export type StatusSeverity = 'ok' | 'info' | 'warning' | 'error';

export interface StatusCta {
  label: string;
  href: string;
}

export interface BackendStatusView {
  label: string;
  /** The broker's own status_detail sentence -- already internals-free. */
  detail: string;
  severity: StatusSeverity;
  /** Null when there's nothing actionable to link to (capability_required/
   * misconfigured are admin-actionable, not user-actionable; unavailable is
   * "wait and retry", not a link). */
  cta: StatusCta | null;
  /** Carried straight through from CatalogServer.correlation_id -- set only
   * for capability_required/misconfigured, so the card can show it for the
   * user to quote in a ticket. */
  correlationId: string | null;
}

const LABELS: Record<BackendStatus, string> = {
  available: 'Available',
  link_required: 'Link required',
  capability_required: 'Access required',
  unavailable: 'Unavailable',
  misconfigured: 'Misconfigured',
};

const SEVERITIES: Record<BackendStatus, StatusSeverity> = {
  available: 'ok',
  link_required: 'info',
  capability_required: 'warning',
  unavailable: 'warning',
  misconfigured: 'error',
};

/**
 * Resolves how a card should present its server's status. Only
 * "link_required" gets a real CTA link (to /identities/, where the user can
 * actually fix it themselves) -- capability_required/misconfigured are
 * admin-actionable (the detail sentence already says to contact admins, and
 * correlationId carries the id to quote), and unavailable is a
 * wait-and-retry state with nothing to link to.
 */
export function resolveBackendStatus(
  server: Pick<CatalogServer, 'status' | 'status_detail' | 'correlation_id'>,
): BackendStatusView {
  return {
    label: LABELS[server.status],
    detail: server.status_detail,
    severity: SEVERITIES[server.status],
    cta:
      server.status === 'link_required' ? { label: 'Link identity', href: '/identities/' } : null,
    correlationId: server.correlation_id,
  };
}

/**
 * Reconciles the "Powered by" affordance's linked/unlinked badge
 * (lib/catalog.ts's resolvePoweredBy, sourced from GET /v1/identities) with
 * the catalog's own `status` (sourced from GET /v1/catalog) so the two
 * fetches -- which can race or land slightly out of sync -- never disagree
 * on-screen: a "link_required" status is authoritative that the identity
 * isn't usable for this backend yet, even if the identities response still
 * says `linked: true` for a moment. Returns `poweredByLinked` unchanged for
 * every other status, and for the "no linked/unlinked concept" case (null).
 */
export function resolvePoweredByLinked(
  status: BackendStatus,
  poweredByLinked: boolean | null,
): boolean | null {
  if (poweredByLinked === null) return null;
  if (status === 'link_required') return false;
  return poweredByLinked;
}

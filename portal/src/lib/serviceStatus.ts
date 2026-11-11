/**
 * serviceStatus.ts — pure mapping from a catalog server's `status` (issue
 * #123, see broker/src/af_mcp_broker/api/permissions.py's _service_status)
 * to how ServiceCard.vue should render it: a label, severity, and the right
 * call to action. Kept as plain data-in/data-out functions (no DOM/fetch
 * access) so it's trivially unit-testable, same pattern as lib/catalog.ts
 * and lib/linkedBanner.ts -- the repo deliberately avoids component-mount
 * harnesses, so component logic stays thin and this module carries the
 * actual decisions.
 */
import type { ServiceStatus, CatalogServer } from './api';

export type StatusSeverity = 'ok' | 'off' | 'info' | 'warning' | 'error';

export interface StatusCta {
  label: string;
  href: string;
}

export interface ServiceStatusView {
  label: string;
  /** The broker's own status_detail sentence -- already internals-free. */
  detail: string;
  severity: StatusSeverity;
  /** Null when there's nothing actionable to link to (permission_required/
   * misconfigured are admin-actionable, not user-actionable; unavailable is
   * "wait and retry", not a link). */
  cta: StatusCta | null;
  /** Carried straight through from CatalogServer.correlation_id -- set only
   * for permission_required/misconfigured, so the card can show it for the
   * user to quote in a ticket. */
  correlationId: string | null;
}

const LABELS: Record<ServiceStatus, string> = {
  available: 'Available',
  link_required: 'Not linked',
  permission_required: 'Access required',
  unavailable: 'Unavailable',
  misconfigured: 'Misconfigured',
};

const SEVERITIES: Record<ServiceStatus, StatusSeverity> = {
  available: 'ok',
  // Not linking an account is the user's choice, not a fault: it only keeps
  // that service's tools from being used.
  link_required: 'off',
  permission_required: 'warning',
  unavailable: 'warning',
  misconfigured: 'error',
};

/**
 * Resolves how a card should present its server's status. Only
 * "link_required" gets a real CTA link (to /identities/, where the user can
 * actually fix it themselves) -- permission_required/misconfigured are
 * admin-actionable (the detail sentence already says to contact admins, and
 * correlationId carries the id to quote), and unavailable is a
 * wait-and-retry state with nothing to link to.
 */
export function resolveServiceStatus(
  server: Pick<CatalogServer, 'status' | 'status_detail' | 'correlation_id'>,
): ServiceStatusView {
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
  status: ServiceStatus,
  poweredByLinked: boolean | null,
): boolean | null {
  if (poweredByLinked === null) return null;
  if (status === 'link_required') return false;
  return poweredByLinked;
}

export interface ServiceCounts {
  total: number;
  /** Services that are available. */
  reachable: number;
  /** Services that only need the user to link an account. */
  needsLink: number;
  /** Services that are temporarily unreachable. */
  unavailable: number;
  /** Services an operator must fix. */
  misconfigured: number;
}

/** Counts services the way the Services page presents them. */
export function summarizeServices(servers: Pick<CatalogServer, 'status'>[]): ServiceCounts {
  const statuses = servers.map((s) => s.status);
  return {
    total: servers.length,
    reachable: statuses.filter((s) => SEVERITIES[s] === 'ok').length,
    needsLink: statuses.filter((s) => s === 'link_required').length,
    unavailable: statuses.filter((s) => s === 'unavailable').length,
    misconfigured: statuses.filter((s) => s === 'misconfigured').length,
  };
}

export interface ServicesBanner {
  tone: 'bad' | 'warn';
  title: string;
  body: string;
}

function countOf(n: number, singular: string, plural: string): string {
  return `${n} ${n === 1 ? singular : plural}`;
}

/**
 * Words the failing services for a banner. Misconfigured (an operator must
 * fix it) and unavailable (temporarily unreachable) stay separate: they ask
 * the user to do different things. Null when nothing is failing.
 */
export function failureSummary(misconfigured: number, unavailable: number): string | null {
  if (misconfigured > 0 && unavailable > 0) {
    return `${countOf(misconfigured, 'service is', 'services are')} misconfigured and ${countOf(unavailable, 'is', 'are')} unavailable`;
  }
  if (misconfigured > 0)
    return `${countOf(misconfigured, 'service is', 'services are')} misconfigured`;
  if (unavailable > 0) return `${countOf(unavailable, 'service is', 'services are')} unavailable`;
  return null;
}

/**
 * The Services page's single banner, raised only for a misconfigured service
 * (a problem) or an unavailable one (a warning: nothing to do but wait). A
 * service that needs a linked account is the user's choice and "Access
 * required" needs an administrator, so neither raises one.
 */
export function resolveServicesBanner(
  servers: Pick<CatalogServer, 'status'>[],
): ServicesBanner | null {
  const { misconfigured, unavailable } = summarizeServices(servers);
  const title = failureSummary(misconfigured, unavailable);
  if (title === null) return null;
  if (misconfigured > 0 && unavailable > 0) {
    return {
      tone: 'bad',
      title,
      body: 'Try again later for the unavailable ones. An administrator needs to fix the misconfigured ones.',
    };
  }
  if (misconfigured > 0) {
    return { tone: 'bad', title, body: 'An administrator needs to fix the configuration.' };
  }
  return { tone: 'warn', title, body: 'The backend is not responding. Try again later.' };
}

// What can I use, and what is actually wrong: problems first, then what works,
// then what the user cannot use yet (access, then an unlinked account).
const ORDER: Record<ServiceStatus, number> = {
  unavailable: 0,
  misconfigured: 0,
  available: 1,
  permission_required: 2,
  link_required: 3,
};

/** Orders services by status group, alphabetically by name within a group. */
export function sortServices<T extends Pick<CatalogServer, 'name' | 'status'>>(servers: T[]): T[] {
  return [...servers].sort(
    (a, b) => ORDER[a.status] - ORDER[b.status] || a.name.localeCompare(b.name),
  );
}

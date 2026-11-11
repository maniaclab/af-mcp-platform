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
import type { ServiceStatus, CatalogServer, IdentityProvider } from './api';
import { identityLinkAnchor, identityLinkLabel } from './identityLinkLabel';

export type StatusSeverity = 'ok' | 'info' | 'warning' | 'error';

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
  link_required: 'warning',
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
  /** Services that are unavailable or misconfigured. */
  failing: number;
}

/** Counts services the way the Services page presents them. */
export function summarizeServices(servers: Pick<CatalogServer, 'status'>[]): ServiceCounts {
  const statuses = servers.map((s) => s.status);
  return {
    total: servers.length,
    reachable: statuses.filter((s) => SEVERITIES[s] === 'ok').length,
    needsLink: statuses.filter((s) => s === 'link_required').length,
    failing: statuses.filter((s) => s === 'unavailable' || s === 'misconfigured').length,
  };
}

export interface ServicesBanner {
  tone: 'bad' | 'warn';
  title: string;
  body: string;
  /** One button, only when a single account fixes every service the banner counts. */
  cta: StatusCta | null;
}

function countOf(n: number, singular: string, plural: string): string {
  return `${n} ${n === 1 ? singular : plural}`;
}

/**
 * The Services page's single banner. A failing or misconfigured service is a
 * problem; a service that only needs the user to link an account is a
 * warning, never counted as a failure. "Access required" needs an
 * administrator, so it never raises a banner of its own.
 */
export function resolveServicesBanner(
  servers: Pick<CatalogServer, 'status' | 'credential_provider'>[],
  providers: Pick<IdentityProvider, 'id' | 'display_name' | 'link_mechanism'>[],
): ServicesBanner | null {
  const failing = servers.filter((s) => s.status === 'unavailable' || s.status === 'misconfigured');
  if (failing.length > 0) {
    const misconfigured = failing.some((s) => s.status === 'misconfigured');
    const unavailable = failing.some((s) => s.status === 'unavailable');
    return {
      tone: 'bad',
      title: `${countOf(failing.length, 'service is', 'services are')} unavailable`,
      body:
        misconfigured && unavailable
          ? 'Some are not responding and some are misconfigured. Try again later, then contact an administrator.'
          : misconfigured
            ? 'An administrator needs to fix the configuration.'
            : 'The backend is not responding. Try again later.',
      cta: null,
    };
  }

  const unlinked = servers.filter((s) => s.status === 'link_required');
  if (unlinked.length === 0) return null;
  const aliases = new Set(unlinked.map((s) => s.credential_provider));
  const [alias] = aliases;
  const provider = providers.find((p) => p.id === alias);
  const cta =
    aliases.size === 1 && alias != null
      ? {
          label: identityLinkLabel(provider ?? { link_mechanism: 'redirect', display_name: alias }),
          href: identityLinkAnchor(alias),
        }
      : null;
  return {
    tone: 'warn',
    title: `${countOf(unlinked.length, 'service needs', 'services need')} a linked account`,
    body: cta
      ? 'Link the account to unlock them.'
      : 'Each one lists the account it needs. Link them on the Identities page.',
    cta,
  };
}

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
  /** Services that only need the user to link an account. A service that
   * needs no credential never counts: there is nothing to link. */
  needsLink: number;
  /** The distinct accounts those services need, in catalog order. */
  needsLinkProviders: string[];
  /** Display names of those services, in catalog order (empty strings never appear). */
  needsLinkNames: string[];
  /** Services that are temporarily unreachable. */
  unavailable: number;
  /** Services an operator must fix. */
  misconfigured: number;
}

/** Counts services the way the Services page presents them. */
export function summarizeServices(
  servers: (Pick<CatalogServer, 'status' | 'credential_provider'> &
    Partial<Pick<CatalogServer, 'display_name'>>)[],
): ServiceCounts {
  const statuses = servers.map((s) => s.status);
  const unlinked = servers.filter(
    (s) => s.status === 'link_required' && s.credential_provider !== null,
  );
  return {
    total: servers.length,
    reachable: statuses.filter((s) => SEVERITIES[s] === 'ok').length,
    needsLink: unlinked.length,
    needsLinkProviders: [...new Set(unlinked.map((s) => s.credential_provider as string))],
    needsLinkNames: unlinked.flatMap((s) => (s.display_name ? [s.display_name] : [])),
    unavailable: statuses.filter((s) => s === 'unavailable').length,
    misconfigured: statuses.filter((s) => s === 'misconfigured').length,
  };
}

/**
 * What a page puts in its banner slot. A banner is a problem or a warning and
 * announces itself as an alert. A hint is quiet information that never alarms
 * (an account left unlinked is the user's choice) and is rendered as an inline
 * note; a banner always outranks it.
 */
export interface BannerMessage {
  kind: 'banner';
  tone: 'bad' | 'warn';
  title: string;
  body: string;
  action: StatusCta | null;
}

export interface HintMessage {
  kind: 'hint';
  title: string;
  body: string;
  action: StatusCta | null;
}

export type PageMessage = BannerMessage | HintMessage;

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
 * The hint for services that are not linked; the same words on every page. One
 * unlinked service is named when its name is known.
 */
export function unlinkedHint(
  count: number,
  action: StatusCta | null,
  serviceName: string | null = null,
): HintMessage {
  return {
    kind: 'hint',
    title:
      count === 1 && serviceName !== null
        ? `${serviceName} is not linked`
        : `${countOf(count, 'service is', 'services are')} not linked`,
    body: `Link an account on the Identities page to use ${count === 1 ? 'it' : 'them'}.`,
    action,
  };
}

/**
 * The one action that links every unlinked service, when they all need the same
 * account; null when they need different accounts (the user picks on the
 * Identities page).
 */
export function unlinkedAction(
  needsLinkProviders: string[],
  providers: Pick<IdentityProvider, 'id' | 'display_name' | 'link_mechanism'>[] = [],
): StatusCta | null {
  const [only, ...others] = needsLinkProviders;
  if (only === undefined || others.length > 0) return null;
  const provider = providers.find((p) => p.id === only);
  return {
    label: provider ? identityLinkLabel(provider) : 'Link identity',
    href: identityLinkAnchor(only),
  };
}

/**
 * The Services page's single message. A misconfigured service (a problem) or
 * an unavailable one (a warning: nothing to do but wait) raises a banner.
 * Otherwise services that only need a linked account raise a hint, with an
 * action only when they all need the same account. "Access required" needs an
 * administrator and raises nothing.
 */
export function resolveServicesMessage(
  servers: (Pick<CatalogServer, 'status' | 'credential_provider'> &
    Partial<Pick<CatalogServer, 'display_name'>>)[],
  providers: Pick<IdentityProvider, 'id' | 'display_name' | 'link_mechanism'>[] = [],
): PageMessage | null {
  const { misconfigured, unavailable, needsLink, needsLinkProviders, needsLinkNames } =
    summarizeServices(servers);
  const title = failureSummary(misconfigured, unavailable);
  if (title === null) {
    if (needsLink === 0) return null;
    const action = unlinkedAction(needsLinkProviders, providers);
    return unlinkedHint(needsLink, action, needsLinkNames.length === 1 ? needsLinkNames[0] : null);
  }
  if (misconfigured > 0 && unavailable > 0) {
    return {
      kind: 'banner',
      tone: 'bad',
      title,
      body: 'Try again later for the unavailable ones. An administrator needs to fix the misconfigured ones.',
      action: null,
    };
  }
  if (misconfigured > 0) {
    return {
      kind: 'banner',
      tone: 'bad',
      title,
      body: 'An administrator needs to fix the configuration.',
      action: null,
    };
  }
  return {
    kind: 'banner',
    tone: 'warn',
    title,
    body: 'The backend is not responding. Try again later.',
    action: null,
  };
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

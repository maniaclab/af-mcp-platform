import { describe, expect, it } from 'vitest';
import {
  resolveServiceStatus,
  resolvePoweredByLinked,
  resolveServicesBanner,
  sortServices,
  summarizeServices,
} from '../serviceStatus';
import type { ServiceStatus, CatalogServer } from '../api';

function statusFields(
  status: ServiceStatus,
  overrides: Partial<Pick<CatalogServer, 'status_detail' | 'correlation_id'>> = {},
): Pick<CatalogServer, 'status' | 'status_detail' | 'correlation_id'> {
  return {
    status,
    status_detail: overrides.status_detail ?? 'detail',
    correlation_id: overrides.correlation_id ?? null,
  };
}

describe('resolveServiceStatus', () => {
  it('reports "available" as ok severity with no CTA and no correlation id', () => {
    const view = resolveServiceStatus(statusFields('available', { status_detail: 'Available.' }));
    expect(view).toEqual({
      label: 'Available',
      detail: 'Available.',
      severity: 'ok',
      cta: null,
      correlationId: null,
    });
  });

  it('reports "link_required" as "Not linked", a quiet off severity, with a link-identity CTA', () => {
    const view = resolveServiceStatus(
      statusFields('link_required', { status_detail: 'Link your identity to use this service.' }),
    );
    expect(view.label).toBe('Not linked');
    expect(view.severity).toBe('off');
    expect(view.cta).toEqual({ label: 'Link identity', href: '/identities/' });
    expect(view.correlationId).toBeNull();
  });

  it('reports "permission_required" as warning severity with no CTA but a correlation id', () => {
    const view = resolveServiceStatus(
      statusFields('permission_required', { correlation_id: 'abc123' }),
    );
    expect(view.severity).toBe('warning');
    expect(view.cta).toBeNull();
    expect(view.correlationId).toBe('abc123');
  });

  it('reports "unavailable" as warning severity with no CTA and no correlation id', () => {
    const view = resolveServiceStatus(statusFields('unavailable'));
    expect(view.severity).toBe('warning');
    expect(view.cta).toBeNull();
    expect(view.correlationId).toBeNull();
  });

  it('reports "misconfigured" as error severity with no CTA but a correlation id', () => {
    const view = resolveServiceStatus(statusFields('misconfigured', { correlation_id: 'def456' }));
    expect(view.severity).toBe('error');
    expect(view.cta).toBeNull();
    expect(view.correlationId).toBe('def456');
  });

  it('always carries the broker-supplied status_detail sentence through verbatim', () => {
    const view = resolveServiceStatus(
      statusFields('permission_required', { status_detail: "Your account doesn't have access." }),
    );
    expect(view.detail).toBe("Your account doesn't have access.");
  });
});

describe('resolvePoweredByLinked', () => {
  it('passes through null (no linked/unlinked concept, e.g. x509/none)', () => {
    expect(resolvePoweredByLinked('available', null)).toBeNull();
    expect(resolvePoweredByLinked('link_required', null)).toBeNull();
  });

  it('forces false when status is "link_required", even if the identities response says linked', () => {
    // Guards against the two fetches (catalog vs identities) racing or
    // landing out of sync -- status is authoritative.
    expect(resolvePoweredByLinked('link_required', true)).toBe(false);
  });

  it('passes the raw linked flag through for every other status', () => {
    expect(resolvePoweredByLinked('available', true)).toBe(true);
    expect(resolvePoweredByLinked('available', false)).toBe(false);
    expect(resolvePoweredByLinked('permission_required', true)).toBe(true);
    expect(resolvePoweredByLinked('unavailable', true)).toBe(true);
    expect(resolvePoweredByLinked('misconfigured', false)).toBe(false);
  });
});

describe('resolveServicesBanner', () => {
  const svc = (status: ServiceStatus) => ({ status });

  it('is absent when every service is available or only needs an administrator', () => {
    expect(resolveServicesBanner([svc('available'), svc('permission_required')])).toBeNull();
  });

  it('never raises a banner for services that only need a linked account', () => {
    expect(
      resolveServicesBanner([svc('available'), svc('link_required'), svc('link_required')]),
    ).toBeNull();
  });

  it('reports failing services as a problem naming how many are unavailable', () => {
    const banner = resolveServicesBanner([
      svc('available'),
      svc('unavailable'),
      svc('misconfigured'),
      svc('link_required'),
    ]);
    expect(banner?.tone).toBe('bad');
    expect(banner?.title).toBe('2 services are unavailable');
  });

  it('uses the singular for one failing service', () => {
    const banner = resolveServicesBanner([svc('misconfigured')]);
    expect(banner?.title).toBe('1 service is unavailable');
  });
});

describe('sortServices', () => {
  const named = (name: string, status: ServiceStatus) => ({ name, status });

  it('puts failing services first, then available, then access required, then not linked', () => {
    const sorted = sortServices([
      named('a-link', 'link_required'),
      named('b-ok', 'available'),
      named('c-perm', 'permission_required'),
      named('d-down', 'unavailable'),
      named('e-bad', 'misconfigured'),
    ]);
    expect(sorted.map((s) => s.name)).toEqual(['d-down', 'e-bad', 'b-ok', 'c-perm', 'a-link']);
  });

  it('keeps alphabetical order within a group', () => {
    const sorted = sortServices([
      named('zeta', 'available'),
      named('alpha', 'available'),
      named('mid', 'link_required'),
      named('beta', 'link_required'),
    ]);
    expect(sorted.map((s) => s.name)).toEqual(['alpha', 'zeta', 'beta', 'mid']);
  });
});

describe('summarizeServices', () => {
  const statuses = (...list: ServiceStatus[]) => list.map((status) => ({ status }));

  it('counts reachable, failing and unlinked services using the Services page statuses', () => {
    expect(
      summarizeServices(
        statuses(
          'available',
          'available',
          'link_required',
          'unavailable',
          'misconfigured',
          'permission_required',
        ),
      ),
    ).toEqual({ total: 6, reachable: 2, needsLink: 1, failing: 2 });
  });

  it('is all zeros for no services', () => {
    expect(summarizeServices([])).toEqual({ total: 0, reachable: 0, needsLink: 0, failing: 0 });
  });
});

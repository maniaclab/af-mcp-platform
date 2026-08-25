import { describe, expect, it } from 'vitest';
import { resolveServiceStatus, resolvePoweredByLinked } from '../serviceStatus';
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

  it('reports "link_required" as info severity with a link-identity CTA', () => {
    const view = resolveServiceStatus(
      statusFields('link_required', { status_detail: 'Link your identity to use this service.' }),
    );
    expect(view.severity).toBe('info');
    expect(view.cta).toEqual({ label: 'Link identity', href: '/identities/' });
    expect(view.correlationId).toBeNull();
  });

  it('reports "capability_required" as warning severity with no CTA but a correlation id', () => {
    const view = resolveServiceStatus(
      statusFields('capability_required', { correlation_id: 'abc123' }),
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
      statusFields('capability_required', { status_detail: "Your account doesn't have access." }),
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
    expect(resolvePoweredByLinked('capability_required', true)).toBe(true);
    expect(resolvePoweredByLinked('unavailable', true)).toBe(true);
    expect(resolvePoweredByLinked('misconfigured', false)).toBe(false);
  });
});

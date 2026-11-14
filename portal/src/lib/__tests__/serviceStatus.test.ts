import { describe, expect, it } from 'vitest';
import {
  resolveServiceStatus,
  resolvePoweredByLinked,
  failureSummary,
  resolveServicesMessage,
  sortServices,
  summarizeServices,
  rejectedBanner,
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
      grantingGroups: [],
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

  describe('"permission_required" with an access URL (issue #395)', () => {
    const denied = (extra: Partial<CatalogServer>) =>
      resolveServiceStatus({
        ...statusFields('permission_required', { correlation_id: 'abc123' }),
        ...extra,
      });

    it('offers "Request access" linking to the access URL', () => {
      const view = denied({ access_url: 'https://groups.example.org/request' });
      expect(view.cta).toEqual({
        label: 'Request access',
        href: 'https://groups.example.org/request',
      });
      // The reference id to quote stays alongside the call to action.
      expect(view.correlationId).toBe('abc123');
    });

    it('carries the groups that grant the permission through', () => {
      const view = denied({ granting_groups: ['/connect/atlas-af', '/connect/escape'] });
      expect(view.grantingGroups).toEqual(['/connect/atlas-af', '/connect/escape']);
      // Naming groups without a URL is information, not a link.
      expect(view.cta).toBeNull();
    });

    it('has no groups when the broker names none, or omits the field', () => {
      expect(denied({ granting_groups: [] }).grantingGroups).toEqual([]);
      expect(denied({}).grantingGroups).toEqual([]);
    });

    it.each(['available', 'unavailable', 'misconfigured'] as const)(
      'never shows "Request access" for a %s service, even with a URL',
      (status) => {
        const view = resolveServiceStatus({
          ...statusFields(status),
          access_url: 'https://groups.example.org/request',
          granting_groups: ['/connect/atlas-af'],
        });
        expect(view.cta).toBeNull();
        expect(view.grantingGroups).toEqual([]);
      },
    );
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

describe('summarizeServices needsLinkNames', () => {
  it('lists the display names of the services that need a link, in catalog order', () => {
    const counts = summarizeServices([
      { status: 'available', credential_provider: 'a', display_name: 'One' },
      { status: 'link_required', credential_provider: 'a', display_name: 'Two' },
      { status: 'link_required', credential_provider: null, display_name: 'Three' },
      { status: 'link_required', credential_provider: 'b', display_name: 'Four' },
    ]);
    expect(counts.needsLinkNames).toEqual(['Two', 'Four']);
  });
});

describe('resolveServicesMessage', () => {
  const svc = (status: ServiceStatus, credential_provider: string | null = 'atlas-oidc') => ({
    status,
    credential_provider,
  });

  it('is absent when every service is available or only needs an administrator', () => {
    expect(resolveServicesMessage([svc('available'), svc('permission_required')])).toBeNull();
  });

  it('says a misconfigured service is misconfigured, as a problem banner', () => {
    const message = resolveServicesMessage([svc('available'), svc('misconfigured')]);
    expect(message?.kind).toBe('banner');
    expect(message).toMatchObject({ tone: 'bad', title: '1 service is misconfigured' });
    expect(message?.body).toContain('administrator');
  });

  it('says unavailable services are unavailable, as a warning that only asks for patience', () => {
    const message = resolveServicesMessage([svc('unavailable'), svc('unavailable')]);
    expect(message?.kind).toBe('banner');
    expect(message).toMatchObject({ tone: 'warn', title: '2 services are unavailable' });
    expect(message?.body).toContain('Try again later');
  });

  it('keeps the two apart when both occur', () => {
    const message = resolveServicesMessage([
      svc('misconfigured'),
      svc('unavailable'),
      svc('unavailable'),
      svc('link_required'),
    ]);
    expect(message).toMatchObject({
      kind: 'banner',
      tone: 'bad',
      title: '1 service is misconfigured and 2 are unavailable',
    });
  });

  it('hints, never alarms, when services only need a linked account', () => {
    const message = resolveServicesMessage([
      svc('available'),
      svc('link_required'),
      svc('link_required', 'x509'),
    ]);
    expect(message).toEqual({
      kind: 'hint',
      title: '2 services are not linked',
      body: 'Link an account on the Identities page to use them.',
      action: null,
    });
  });

  it('uses the singular for one service', () => {
    const message = resolveServicesMessage([svc('link_required')]);
    expect(message).toMatchObject({
      kind: 'hint',
      title: '1 service is not linked',
      body: 'Link an account on the Identities page to use it.',
    });
  });

  it('names the one unlinked service, and its action, when it has a display name', () => {
    const message = resolveServicesMessage(
      [
        { ...svc('available'), display_name: 'AMI' },
        { ...svc('link_required', 'krb5'), display_name: 'ATLAS OpenSearch' },
      ],
      [{ id: 'krb5', display_name: 'CERN Kerberos', link_mechanism: 'passphrase' }],
    );
    expect(message).toMatchObject({
      kind: 'hint',
      title: 'ATLAS OpenSearch is not linked',
      body: 'Link an account on the Identities page to use it.',
    });
    expect(message?.action?.href).toBe('/identities/#identity-card-krb5');
  });

  it('keeps the count when several services are unlinked, even with display names', () => {
    const message = resolveServicesMessage([
      { ...svc('link_required'), display_name: 'A' },
      { ...svc('link_required'), display_name: 'B' },
    ]);
    expect(message).toMatchObject({ title: '2 services are not linked' });
  });

  it('offers one action only when every unlinked service needs the same account', () => {
    const message = resolveServicesMessage(
      [svc('link_required'), svc('link_required'), svc('available')],
      [{ id: 'atlas-oidc', display_name: 'ATLAS IAM', link_mechanism: 'redirect' }],
    );
    expect(message).toMatchObject({
      kind: 'hint',
      action: { label: 'Link ATLAS IAM account', href: '/identities/#identity-card-atlas-oidc' },
    });
  });

  it('puts a failing service ahead of a hint', () => {
    const message = resolveServicesMessage([svc('link_required'), svc('unavailable')]);
    expect(message?.kind).toBe('banner');
  });

  it('does not count a service that needs no credential, such as the gateway itself', () => {
    expect(resolveServicesMessage([svc('available', null), svc('link_required', null)])).toBeNull();
  });
});

describe('failureSummary', () => {
  it('words each failure kind separately', () => {
    expect(failureSummary(1, 0)).toBe('1 service is misconfigured');
    expect(failureSummary(2, 0)).toBe('2 services are misconfigured');
    expect(failureSummary(0, 1)).toBe('1 service is unavailable');
    expect(failureSummary(0, 3)).toBe('3 services are unavailable');
    expect(failureSummary(2, 1)).toBe('2 services are misconfigured and 1 is unavailable');
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
  const services = (...list: [ServiceStatus, (string | null)?][]) =>
    list.map(([status, credential_provider = 'atlas-oidc']) => ({ status, credential_provider }));

  it('counts reachable, unavailable, misconfigured and unlinked services using the Services page statuses', () => {
    expect(
      summarizeServices(
        services(
          ['available'],
          ['available'],
          ['link_required'],
          ['unavailable'],
          ['misconfigured'],
          ['permission_required'],
        ),
      ),
    ).toEqual({
      total: 6,
      reachable: 2,
      needsLink: 1,
      unavailable: 1,
      misconfigured: 1,
      needsLinkProviders: ['atlas-oidc'],
      needsLinkNames: [],
      rejected: 0,
      rejectedProviders: [],
      rejectedNames: [],
    });
  });

  it('never counts a service that needs no credential as unlinked', () => {
    // The gateway's own service has no credential provider: it is available,
    // and even a stray link_required status has nothing a user could link.
    const counts = summarizeServices(services(['available', null], ['link_required', null]));
    expect(counts.needsLink).toBe(0);
    expect(counts.needsLinkProviders).toEqual([]);
  });

  it('lists each account the unlinked services need once', () => {
    const counts = summarizeServices(
      services(['link_required', 'a'], ['link_required', 'b'], ['link_required', 'a']),
    );
    expect(counts.needsLink).toBe(3);
    expect(counts.needsLinkProviders).toEqual(['a', 'b']);
  });

  it('is all zeros for no services', () => {
    expect(summarizeServices([])).toEqual({
      total: 0,
      reachable: 0,
      needsLink: 0,
      unavailable: 0,
      misconfigured: 0,
      needsLinkProviders: [],
      needsLinkNames: [],
      rejected: 0,
      rejectedProviders: [],
      rejectedNames: [],
    });
  });
});

describe('rejected credential', () => {
  const rejected = (
    credential_provider: string | null = 'krb5',
    display_name = 'ATLAS OpenSearch',
  ) => ({
    status: 'link_required' as const,
    link_state: 'rejected' as const,
    credential_provider,
    display_name,
  });
  const notLinked = (credential_provider: string | null = 'krb5') => ({
    status: 'link_required' as const,
    link_state: 'not_linked' as const,
    credential_provider,
    display_name: 'Other',
  });
  const krb5 = {
    id: 'krb5',
    display_name: 'Kerberos ticket',
    link_mechanism: 'credential' as const,
  };
  const iam = { id: 'atlas-oidc', display_name: 'ATLAS IAM', link_mechanism: 'redirect' as const };

  it('resolveServiceStatus words it as a rejected credential, a warning, with a re-link action', () => {
    const view = resolveServiceStatus(
      { ...statusFields('link_required'), link_state: 'rejected' },
      'Kerberos ticket',
    );
    expect(view.label).toBe('Credential rejected');
    expect(view.severity).toBe('warning');
    expect(view.detail).toBe(
      'Your linked Kerberos ticket was rejected. Re-link it to use this service.',
    );
    expect(view.cta).toEqual({ label: 'Re-link identity', href: '/identities/' });
  });

  it('resolveServiceStatus names a credential generically when the identity is unknown', () => {
    const view = resolveServiceStatus({ ...statusFields('link_required'), link_state: 'rejected' });
    expect(view.detail).toBe(
      'Your linked credential was rejected. Re-link it to use this service.',
    );
  });

  it.each(['not_linked', null] as const)(
    'resolveServiceStatus leaves link_state %s as "Not linked", quiet',
    (link_state) => {
      const view = resolveServiceStatus({ ...statusFields('link_required'), link_state });
      expect(view.label).toBe('Not linked');
      expect(view.severity).toBe('off');
    },
  );

  it('resolvePoweredByLinked keeps a rejected credential linked: it is not "Not linked"', () => {
    expect(resolvePoweredByLinked('link_required', true, 'rejected')).toBe(true);
    expect(resolvePoweredByLinked('link_required', true, 'not_linked')).toBe(false);
    expect(resolvePoweredByLinked('link_required', true, null)).toBe(false);
  });

  it('summarizeServices counts it apart from "not linked", and from reachable', () => {
    const counts = summarizeServices([
      { status: 'available', link_state: null, credential_provider: 'a', display_name: 'A' },
      rejected('krb5', 'Search'),
      rejected('krb5', 'Logs'),
      notLinked('atlas-oidc'),
    ]);
    expect(counts.reachable).toBe(1);
    expect(counts.rejected).toBe(2);
    expect(counts.rejectedNames).toEqual(['Search', 'Logs']);
    expect(counts.rejectedProviders).toEqual(['krb5']);
    expect(counts.needsLink).toBe(1);
    expect(counts.needsLinkProviders).toEqual(['atlas-oidc']);
  });

  it('rejectedBanner names the service and identity for one, with the re-link action', () => {
    expect(
      rejectedBanner(1, 'ATLAS OpenSearch', 'Kerberos ticket', {
        label: 'Refresh ticket',
        href: '/identities/#identity-card-krb5',
      }),
    ).toEqual({
      kind: 'banner',
      tone: 'warn',
      title: 'ATLAS OpenSearch rejected your Kerberos ticket',
      body: 'Re-link it to use this service.',
      action: { label: 'Refresh ticket', href: '/identities/#identity-card-krb5' },
    });
  });

  it('rejectedBanner counts several, with an action only when given one', () => {
    expect(rejectedBanner(3, null, null, null)).toEqual({
      kind: 'banner',
      tone: 'warn',
      title: '3 services rejected a linked credential',
      body: 'Re-link the identities they use on the Identities page.',
      action: null,
    });
  });

  it('rejectedBanner falls back to "linked credential" for one service whose identity is unknown', () => {
    expect(rejectedBanner(1, 'Search', null, null)).toMatchObject({
      title: 'Search rejected your linked credential',
    });
  });

  it('resolveServicesMessage raises a warning banner, not a hint, for one rejected service', () => {
    const message = resolveServicesMessage([rejected()], [krb5]);
    expect(message).toEqual({
      kind: 'banner',
      tone: 'warn',
      title: 'ATLAS OpenSearch rejected your Kerberos ticket',
      body: 'Re-link it to use this service.',
      action: { label: 'Refresh ticket', href: '/identities/#identity-card-krb5' },
    });
  });

  it('resolveServicesMessage counts several, with one action only when they share an identity', () => {
    const same = resolveServicesMessage(
      [rejected('krb5', 'A'), rejected('krb5', 'B')],
      [krb5, iam],
    );
    expect(same).toMatchObject({
      kind: 'banner',
      tone: 'warn',
      title: '2 services rejected a linked credential',
      action: { label: 'Refresh ticket', href: '/identities/#identity-card-krb5' },
    });
    const different = resolveServicesMessage(
      [rejected('krb5', 'A'), rejected('atlas-oidc', 'B')],
      [krb5, iam],
    );
    expect(different).toMatchObject({
      title: '2 services rejected a linked credential',
      action: null,
    });
  });

  it('resolveServicesMessage ranks failing services over rejected, and rejected over a not-linked hint', () => {
    expect(
      resolveServicesMessage(
        [rejected(), { ...notLinked(), status: 'unavailable' as const }],
        [krb5],
      ),
    ).toMatchObject({
      title: '1 service is unavailable',
    });
    expect(
      resolveServicesMessage([rejected(), notLinked('atlas-oidc')], [krb5, iam]),
    ).toMatchObject({
      kind: 'banner',
      title: 'ATLAS OpenSearch rejected your Kerberos ticket',
    });
  });

  it('resolveServicesMessage still hints, as before, for a not-linked service', () => {
    expect(resolveServicesMessage([notLinked()], [krb5])).toMatchObject({
      kind: 'hint',
      title: 'Other is not linked',
    });
  });

  it('sortServices puts rejected after failing and before available; not linked stays last', () => {
    const named = (
      name: string,
      status: ServiceStatus,
      link_state: 'rejected' | 'not_linked' | null = null,
    ) => ({ name, status, link_state });
    const sorted = sortServices([
      named('a-link', 'link_required', 'not_linked'),
      named('b-ok', 'available'),
      named('c-rej', 'link_required', 'rejected'),
      named('d-down', 'unavailable'),
      named('e-bad', 'misconfigured'),
    ]);
    expect(sorted.map((s) => s.name)).toEqual(['d-down', 'e-bad', 'c-rej', 'b-ok', 'a-link']);
  });
});

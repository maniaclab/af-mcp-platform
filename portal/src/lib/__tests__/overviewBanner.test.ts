/**
 * overviewMessage() picks the single most urgent message for the Overview
 * page from the dashboard summary: problem beats warning beats information,
 * and nothing is shown when nothing is wrong.
 */
import { describe, expect, it } from 'vitest';
import type { DashboardSummary } from '../api';
import { overviewMessage } from '../overviewBanner';

const HOUR = 3600;
const NOW = Date.UTC(2026, 10, 11, 12, 0, 0);

function summary(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    linkedCount: 3,
    serverCount: 8,
    activeTokenCount: 1,
    reachableCount: 8,
    needsLinkCount: 0,
    needsLinkService: null,
    needsLinkAction: null,
    unavailableCount: 0,
    misconfiguredCount: 0,
    proxyAutoRenews: false,
    soonestExpiringToken: null,
    proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 48 * HOUR },
    ...overrides,
  };
}

describe('overviewMessage', () => {
  it('returns null when nothing is wrong', () => {
    expect(overviewMessage(summary(), NOW)).toBeNull();
  });

  it('reports an expired grid proxy as a problem with a renew action', () => {
    const banner = overviewMessage(
      summary({ proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 0 } }),
      NOW,
    );
    expect(banner).toEqual({
      kind: 'banner',
      tone: 'bad',
      title: 'Your grid proxy has expired',
      body: 'Renew it to keep grid services working.',
      action: { label: 'Renew proxy', href: '/identities/' },
    });
  });

  it('reports a proxy close to expiry as a warning with the time left', () => {
    const banner = overviewMessage(
      summary({
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 40 * 60 },
      }),
      NOW,
    );
    expect(banner).toMatchObject({ kind: 'banner', tone: 'warn' });
    expect(banner?.title).toBe('Your grid proxy expires in 40 minutes');
    expect(banner?.action).toEqual({ label: 'Renew proxy', href: '/identities/' });
  });

  it('stays quiet at the warning threshold boundary', () => {
    const banner = overviewMessage(
      summary({
        proxyStatus: {
          cached: true,
          voms_attributes: [],
          remaining_seconds: HOUR,
        },
      }),
      NOW,
    );
    expect(banner).toBeNull();
  });

  it('stays quiet about a proxy under an hour from expiry when it renews itself', () => {
    expect(
      overviewMessage(
        summary({
          proxyAutoRenews: true,
          proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 600 },
        }),
        NOW,
      ),
    ).toBeNull();
  });

  it('still reports an expired proxy that renews itself, since renewal has failed', () => {
    const banner = overviewMessage(
      summary({
        proxyAutoRenews: true,
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 0 },
      }),
      NOW,
    );
    expect(banner?.title).toBe('Your grid proxy has expired');
  });

  it('ignores a proxy that was never minted', () => {
    expect(
      overviewMessage(summary({ proxyStatus: { cached: false, voms_attributes: [] } }), NOW),
    ).toBeNull();
  });

  it('ignores a cached proxy that reports no remaining time', () => {
    expect(
      overviewMessage(summary({ proxyStatus: { cached: true, voms_attributes: [] } }), NOW),
    ).toBeNull();
  });

  it('hints at linking an account when none is linked', () => {
    const message = overviewMessage(
      summary({ linkedCount: 0, proxyStatus: { cached: false, voms_attributes: [] } }),
      NOW,
    );
    expect(message).toEqual({
      kind: 'hint',
      title: 'No accounts are linked yet',
      body: 'Link an account to use the services that need one.',
      action: { label: 'Link an account', href: '/identities/' },
    });
  });

  it('keeps the first-time hint even when services need a linked account', () => {
    expect(overviewMessage(summary({ linkedCount: 0, needsLinkCount: 3 }), NOW)).toMatchObject({
      kind: 'hint',
      title: 'No accounts are linked yet',
    });
  });

  it('hints that services are not linked when some accounts are linked', () => {
    expect(overviewMessage(summary({ needsLinkCount: 4 }), NOW)).toEqual({
      kind: 'hint',
      title: '4 services are not linked',
      body: 'Link an account on the Identities page to use them.',
      action: { label: 'Link an account', href: '/identities/' },
    });
  });

  it('uses the singular for one unlinked service', () => {
    expect(overviewMessage(summary({ needsLinkCount: 1 }), NOW)).toMatchObject({
      title: '1 service is not linked',
      body: 'Link an account on the Identities page to use it.',
    });
  });

  it('names the one unlinked service and offers its specific action', () => {
    const action = { label: 'Get Kerberos ticket', href: '/identities/#identity-card-krb5' };
    expect(
      overviewMessage(
        summary({
          needsLinkCount: 1,
          needsLinkService: 'ATLAS OpenSearch',
          needsLinkAction: action,
        }),
        NOW,
      ),
    ).toEqual({
      kind: 'hint',
      title: 'ATLAS OpenSearch is not linked',
      body: 'Link an account on the Identities page to use it.',
      action,
    });
  });

  it('keeps the generic action when the unlinked services need different accounts', () => {
    expect(overviewMessage(summary({ needsLinkCount: 2 }), NOW)).toMatchObject({
      title: '2 services are not linked',
      action: { label: 'Link an account', href: '/identities/' },
    });
  });

  it('puts a failing service ahead of the unlinked hint', () => {
    expect(overviewMessage(summary({ needsLinkCount: 2, unavailableCount: 1 }), NOW)?.kind).toBe(
      'banner',
    );
  });

  it('puts an expired proxy ahead of an unlinked account', () => {
    const banner = overviewMessage(
      summary({
        linkedCount: 0,
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 0 },
      }),
      NOW,
    );
    expect(banner).toMatchObject({ kind: 'banner', tone: 'bad' });
  });

  it('puts an expiring proxy ahead of an unlinked account', () => {
    const banner = overviewMessage(
      summary({
        linkedCount: 0,
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: HOUR / 2 },
      }),
      NOW,
    );
    expect(banner).toMatchObject({ kind: 'banner', tone: 'warn' });
  });

  const IN_3_DAYS = new Date(NOW + 3 * 24 * 3600 * 1000).toISOString();
  const IN_30_DAYS = new Date(NOW + 30 * 24 * 3600 * 1000).toISOString();

  it('reports misconfigured services as a problem, apart from unavailable ones', () => {
    const banner = overviewMessage(summary({ misconfiguredCount: 1 }), NOW);
    expect(banner).toMatchObject({ kind: 'banner', tone: 'bad' });
    expect(banner?.title).toBe('1 service is misconfigured');
    expect(banner?.action).toEqual({ label: 'View services', href: '/catalog/' });
  });

  it('reports unavailable services as a warning naming how many', () => {
    const banner = overviewMessage(summary({ unavailableCount: 2 }), NOW);
    expect(banner).toMatchObject({ kind: 'banner', tone: 'warn' });
    expect(banner?.title).toBe('2 services are unavailable');
  });

  it('keeps misconfigured and unavailable apart when both occur', () => {
    const banner = overviewMessage(summary({ misconfiguredCount: 1, unavailableCount: 2 }), NOW);
    expect(banner).toMatchObject({ kind: 'banner', tone: 'bad' });
    expect(banner?.title).toBe('1 service is misconfigured and 2 are unavailable');
  });

  it('puts an expired proxy ahead of failing services', () => {
    const banner = overviewMessage(
      summary({
        misconfiguredCount: 1,
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 0 },
      }),
      NOW,
    );
    expect(banner?.title).toBe('Your grid proxy has expired');
  });

  it('puts failing services ahead of an expiring proxy', () => {
    const banner = overviewMessage(
      summary({
        misconfiguredCount: 1,
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: HOUR / 2 },
      }),
      NOW,
    );
    expect(banner).toMatchObject({ kind: 'banner', tone: 'bad' });
  });

  it('warns when a token expires within 7 days, naming it', () => {
    const banner = overviewMessage(
      summary({ soonestExpiringToken: { name: 'ci-pipeline', expires_at: IN_3_DAYS } }),
      NOW,
    );
    expect(banner).toMatchObject({ kind: 'banner', tone: 'warn' });
    expect(banner?.title).toBe('ci-pipeline expires in 3 days');
    expect(banner?.action).toEqual({ label: 'New token', href: '/tokens/' });
  });

  it('ignores a token that expires after 7 days', () => {
    expect(
      overviewMessage(
        summary({ soonestExpiringToken: { name: 'ci', expires_at: IN_30_DAYS } }),
        NOW,
      ),
    ).toBeNull();
  });

  it('puts an expiring proxy ahead of an expiring token', () => {
    const banner = overviewMessage(
      summary({
        soonestExpiringToken: { name: 'ci', expires_at: IN_3_DAYS },
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: HOUR / 2 },
      }),
      NOW,
    );
    expect(banner?.title).toContain('grid proxy');
  });

  it('never raises a banner for services that need a linked account', () => {
    expect(overviewMessage(summary({ needsLinkCount: 2 }), NOW)?.kind).toBe('hint');
  });
});

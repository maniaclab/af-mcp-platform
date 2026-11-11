/**
 * overviewBanner() picks the single most urgent message for the Overview
 * page from the dashboard summary: problem beats warning beats information,
 * and nothing is shown when nothing is wrong.
 */
import { describe, expect, it } from 'vitest';
import type { DashboardSummary } from '../api';
import { EXPIRY_WARNING_SECONDS, overviewBanner } from '../overviewBanner';

const HOUR = 3600;
const NOW = Date.UTC(2026, 10, 11, 12, 0, 0);

function summary(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    linkedCount: 3,
    serverCount: 8,
    activeTokenCount: 1,
    reachableCount: 8,
    needsLinkCount: 0,
    failingCount: 0,
    soonestExpiringToken: null,
    proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 48 * HOUR },
    ...overrides,
  };
}

describe('overviewBanner', () => {
  it('returns null when nothing is wrong', () => {
    expect(overviewBanner(summary(), NOW)).toBeNull();
  });

  it('reports an expired grid proxy as a problem with a renew action', () => {
    const banner = overviewBanner(
      summary({ proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 0 } }),
      NOW,
    );
    expect(banner).toEqual({
      tone: 'bad',
      title: 'Your grid proxy has expired',
      body: 'Renew it to keep grid services working.',
      action: { label: 'Renew proxy', href: '/identities/' },
    });
  });

  it('reports a proxy close to expiry as a warning with the time left', () => {
    const banner = overviewBanner(
      summary({
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 3 * HOUR },
      }),
      NOW,
    );
    expect(banner?.tone).toBe('warn');
    expect(banner?.title).toBe('Your grid proxy expires in 3 hours');
    expect(banner?.action).toEqual({ label: 'Renew proxy', href: '/identities/' });
  });

  it('stays quiet at the warning threshold boundary', () => {
    const banner = overviewBanner(
      summary({
        proxyStatus: {
          cached: true,
          voms_attributes: [],
          remaining_seconds: EXPIRY_WARNING_SECONDS,
        },
      }),
      NOW,
    );
    expect(banner).toBeNull();
  });

  it('ignores a proxy that was never minted', () => {
    expect(
      overviewBanner(summary({ proxyStatus: { cached: false, voms_attributes: [] } }), NOW),
    ).toBeNull();
  });

  it('ignores a cached proxy that reports no remaining time', () => {
    expect(
      overviewBanner(summary({ proxyStatus: { cached: true, voms_attributes: [] } }), NOW),
    ).toBeNull();
  });

  it('gently suggests linking an account when none is linked', () => {
    const banner = overviewBanner(
      summary({ linkedCount: 0, proxyStatus: { cached: false, voms_attributes: [] } }),
      NOW,
    );
    expect(banner).toEqual({
      tone: 'info',
      title: 'No accounts are linked yet',
      body: 'Link an account to use the services that need one.',
      action: { label: 'Link an account', href: '/identities/' },
    });
  });

  it('keeps the first-time hint even when services need a linked account', () => {
    expect(overviewBanner(summary({ linkedCount: 0, needsLinkCount: 3 }), NOW)?.tone).toBe('info');
  });

  it('puts an expired proxy ahead of an unlinked account', () => {
    const banner = overviewBanner(
      summary({
        linkedCount: 0,
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 0 },
      }),
      NOW,
    );
    expect(banner?.tone).toBe('bad');
  });

  it('puts an expiring proxy ahead of an unlinked account', () => {
    const banner = overviewBanner(
      summary({
        linkedCount: 0,
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: HOUR },
      }),
      NOW,
    );
    expect(banner?.tone).toBe('warn');
  });

  const IN_3_DAYS = new Date(NOW + 3 * 24 * 3600 * 1000).toISOString();
  const IN_30_DAYS = new Date(NOW + 30 * 24 * 3600 * 1000).toISOString();

  it('reports failing services as a problem naming how many', () => {
    const banner = overviewBanner(summary({ failingCount: 2 }), NOW);
    expect(banner?.tone).toBe('bad');
    expect(banner?.title).toBe('2 services are unavailable');
    expect(banner?.action).toEqual({ label: 'View services', href: '/catalog/' });
  });

  it('uses the singular for one failing service', () => {
    expect(overviewBanner(summary({ failingCount: 1 }), NOW)?.title).toBe(
      '1 service is unavailable',
    );
  });

  it('puts an expired proxy ahead of failing services', () => {
    const banner = overviewBanner(
      summary({
        failingCount: 1,
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: 0 },
      }),
      NOW,
    );
    expect(banner?.title).toBe('Your grid proxy has expired');
  });

  it('puts failing services ahead of an expiring proxy', () => {
    const banner = overviewBanner(
      summary({
        failingCount: 1,
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: HOUR },
      }),
      NOW,
    );
    expect(banner?.tone).toBe('bad');
  });

  it('warns when a token expires within 7 days, naming it', () => {
    const banner = overviewBanner(
      summary({ soonestExpiringToken: { name: 'ci-pipeline', expires_at: IN_3_DAYS } }),
      NOW,
    );
    expect(banner?.tone).toBe('warn');
    expect(banner?.title).toBe('ci-pipeline expires in 3 days');
    expect(banner?.action).toEqual({ label: 'New token', href: '/tokens/' });
  });

  it('ignores a token that expires after 7 days', () => {
    expect(
      overviewBanner(
        summary({ soonestExpiringToken: { name: 'ci', expires_at: IN_30_DAYS } }),
        NOW,
      ),
    ).toBeNull();
  });

  it('puts an expiring proxy ahead of an expiring token', () => {
    const banner = overviewBanner(
      summary({
        soonestExpiringToken: { name: 'ci', expires_at: IN_3_DAYS },
        proxyStatus: { cached: true, voms_attributes: [], remaining_seconds: HOUR },
      }),
      NOW,
    );
    expect(banner?.title).toContain('grid proxy');
  });

  it('raises no banner for services that need a linked account', () => {
    expect(overviewBanner(summary({ needsLinkCount: 2 }), NOW)).toBeNull();
  });
});

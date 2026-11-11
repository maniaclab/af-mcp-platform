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

  it('suggests linking an account when none is linked', () => {
    const banner = overviewBanner(
      summary({ linkedCount: 0, proxyStatus: { cached: false, voms_attributes: [] } }),
      NOW,
    );
    expect(banner?.tone).toBe('info');
    expect(banner?.action).toEqual({ label: 'Link an account', href: '/identities/' });
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
});

import { describe, expect, it } from 'vitest';

import { navBadges } from '../navSummary';
import type { DashboardSummary } from '../api';

const healthy: DashboardSummary = {
  linkedCount: 2,
  serverCount: 3,
  proxyStatus: {
    cached: true,
    dn: 'CN=user',
    voms_attributes: ['/atlas/Role=NULL'],
    expires_at: '2026-08-06T00:00:00Z',
  },
  activeTokenCount: 4,
  reachableCount: 3,
  needsLinkCount: 0,
  needsLinkService: null,
  needsLinkAction: null,
  unavailableCount: 0,
  misconfiguredCount: 0,
  rejectedCount: 0,
  rejectedService: null,
  rejectedIdentity: null,
  rejectedAction: null,
  proxyAutoRenews: false,
  soonestExpiringToken: null,
};

const empty: DashboardSummary = {
  linkedCount: 0,
  serverCount: 0,
  proxyStatus: { cached: false, voms_attributes: [] },
  activeTokenCount: 0,
  reachableCount: 0,
  needsLinkCount: 0,
  needsLinkService: null,
  needsLinkAction: null,
  unavailableCount: 0,
  misconfiguredCount: 0,
  rejectedCount: 0,
  rejectedService: null,
  rejectedIdentity: null,
  rejectedAction: null,
  proxyAutoRenews: false,
  soonestExpiringToken: null,
};

describe('navBadges', () => {
  it('returns no badges when the summary fetch failed', () => {
    expect(navBadges(null)).toEqual([]);
  });

  it('maps a healthy summary to count badges', () => {
    const badges = navBadges(healthy);
    expect(badges).toContainEqual({ href: '/catalog/', text: '3', tone: 'ok' });
    expect(badges).toContainEqual({ href: '/identities/', text: '2', tone: 'ok' });
    expect(badges).toContainEqual({ href: '/tokens/', text: '4', tone: 'ok' });
  });

  it('renders zero counts as neutral', () => {
    const badges = navBadges(empty);
    expect(badges).toContainEqual({ href: '/catalog/', text: '0', tone: 'neutral' });
    expect(badges).toContainEqual({ href: '/identities/', text: '0', tone: 'neutral' });
    expect(badges).toContainEqual({ href: '/tokens/', text: '0', tone: 'neutral' });
  });

  it('never emits a /status/ badge -- the page was retired into Identities', () => {
    for (const summary of [healthy, empty]) {
      expect(navBadges(summary).find((b) => b.href === '/status/')).toBeUndefined();
    }
  });

  it('produces one badge per nav item at most', () => {
    const hrefs = navBadges(healthy).map((b) => b.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
  });
});

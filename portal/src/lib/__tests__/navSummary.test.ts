import { describe, expect, it } from 'vitest';

import { navBadges } from '../navSummary';
import type { DashboardSummary } from '../api';

const healthy: DashboardSummary = {
  linkedCount: 2,
  serverCount: 3,
  proxyStatus: {
    cached: true,
    subject: 'CN=user',
    voms_attributes: ['/atlas/Role=NULL'],
    not_after: '2026-08-06T00:00:00Z',
  },
  activeTokenCount: 4,
};

const empty: DashboardSummary = {
  linkedCount: 0,
  serverCount: 0,
  proxyStatus: { cached: false, voms_attributes: [] },
  activeTokenCount: 0,
};

describe('navBadges', () => {
  it('returns no badges when the summary fetch failed', () => {
    expect(navBadges(null)).toEqual([]);
  });

  it('maps a healthy summary to count badges plus an active proxy badge', () => {
    const badges = navBadges(healthy);
    expect(badges).toContainEqual({ href: '/catalog/', text: '3', tone: 'ok' });
    expect(badges).toContainEqual({ href: '/identities/', text: '2', tone: 'ok' });
    expect(badges).toContainEqual({ href: '/tokens/', text: '4', tone: 'ok' });
    expect(badges).toContainEqual({ href: '/status/', text: 'active', tone: 'ok' });
  });

  it('renders zero counts as neutral and omits the proxy badge when no proxy is cached', () => {
    const badges = navBadges(empty);
    expect(badges).toContainEqual({ href: '/catalog/', text: '0', tone: 'neutral' });
    expect(badges).toContainEqual({ href: '/identities/', text: '0', tone: 'neutral' });
    expect(badges).toContainEqual({ href: '/tokens/', text: '0', tone: 'neutral' });
    expect(badges.find((b) => b.href === '/status/')).toBeUndefined();
  });

  it('produces one badge per nav item at most', () => {
    const hrefs = navBadges(healthy).map((b) => b.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
  });
});

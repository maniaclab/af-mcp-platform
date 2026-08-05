/**
 * navSummary.ts — maps the dashboard summary onto sidebar nav badges.
 *
 * Pure mapping so Base.astro's shell script stays trivial: it fetches the
 * summary (best-effort) and pins each returned badge onto the nav item whose
 * href matches. A `null` summary (fetch failed / unauthenticated) yields no
 * badges at all — the nav degrades to plain labels rather than showing
 * misleading zeros.
 */
import type { DashboardSummary } from './api';

export interface NavBadge {
  /** href of the nav item this badge attaches to (matches Base.astro's navGroups) */
  href: string;
  /** short text rendered inside the badge pill */
  text: string;
  /** visual tone — maps to an `af-sidebar__badge--*` modifier class */
  tone: 'ok' | 'neutral';
}

export function navBadges(summary: DashboardSummary | null): NavBadge[] {
  if (!summary) return [];

  const count = (href: string, n: number): NavBadge => ({
    href,
    text: String(n),
    tone: n > 0 ? 'ok' : 'neutral',
  });

  const badges = [
    count('/catalog/', summary.serverCount),
    count('/identities/', summary.linkedCount),
    count('/tokens/', summary.activeTokenCount),
  ];

  // The proxy has no meaningful count — badge it only when one is active.
  if (summary.proxyStatus.cached) {
    badges.push({ href: '/status/', text: 'active', tone: 'ok' });
  }

  return badges;
}

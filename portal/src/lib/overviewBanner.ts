/**
 * overviewBanner.ts — picks the single most urgent message for the Overview
 * page's banner slot from the dashboard summary. Problem beats warning beats
 * information; null means nothing is wrong and the slot stays empty.
 *
 * The summary carries the grid proxy's remaining lifetime and the linked
 * account count. It does not say which services are blocked or when a token
 * expires, so those cases are not decided here.
 */
import type { DashboardSummary } from './api';
import { formatRelative } from './relativeTime';

/** A proxy with less than this left is worth a warning: it will not last a working day. */
export const EXPIRY_WARNING_SECONDS = 6 * 3600;

export interface OverviewBanner {
  tone: 'bad' | 'warn' | 'info';
  title: string;
  body: string;
  action: { label: string; href: string };
}

const IDENTITIES_HREF = '/identities/';

export function overviewBanner(
  summary: DashboardSummary,
  now: number = Date.now(),
): OverviewBanner | null {
  const { proxyStatus, linkedCount } = summary;
  const remaining = proxyStatus.cached ? proxyStatus.remaining_seconds : null;

  if (remaining != null && remaining <= 0) {
    return {
      tone: 'bad',
      title: 'Your grid proxy has expired',
      body: 'Renew it to keep grid services working.',
      action: { label: 'Renew proxy', href: IDENTITIES_HREF },
    };
  }
  if (remaining != null && remaining < EXPIRY_WARNING_SECONDS) {
    return {
      tone: 'warn',
      title: `Your grid proxy expires ${formatRelative(now + remaining * 1000, now)}`,
      body: 'Renew it to keep grid services working.',
      action: { label: 'Renew proxy', href: IDENTITIES_HREF },
    };
  }
  if (linkedCount === 0) {
    return {
      tone: 'info',
      title: 'No accounts are linked yet',
      body: 'Link an account to use the services that need one.',
      action: { label: 'Link an account', href: IDENTITIES_HREF },
    };
  }
  return null;
}

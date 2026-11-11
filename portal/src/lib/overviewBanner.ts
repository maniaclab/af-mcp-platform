/**
 * overviewBanner.ts — picks the single most urgent message for the Overview
 * page's banner slot from the dashboard summary. Problem beats warning beats
 * information; null means nothing is wrong and the slot stays empty.
 *
 * Priority: expired proxy, failing services, proxy expiring, token expiring,
 * no linked accounts. Services that need a linked account never raise a
 * banner: leaving an account unlinked is the user's choice.
 */
import type { DashboardSummary } from './api';
import { failureSummary } from './serviceStatus';
import { formatRelative } from './relativeTime';
import { expiresIn, expiresSoon } from './tokenDisplay';
import { proxyExpiryState } from './x509Identity';

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
  const { proxyStatus, proxyAutoRenews, linkedCount, soonestExpiringToken } = summary;
  const remaining = proxyStatus.cached ? proxyStatus.remaining_seconds : null;
  const proxy = remaining != null ? proxyExpiryState(remaining, proxyAutoRenews) : 'ok';

  if (remaining != null && proxy === 'expired') {
    return {
      tone: 'bad',
      title: 'Your grid proxy has expired',
      body: 'Renew it to keep grid services working.',
      action: { label: 'Renew proxy', href: IDENTITIES_HREF },
    };
  }
  const failures = failureSummary(summary.misconfiguredCount, summary.unavailableCount);
  if (failures !== null) {
    return {
      tone: summary.misconfiguredCount > 0 ? 'bad' : 'warn',
      title: failures,
      body: 'Open Services to see which ones and why.',
      action: { label: 'View services', href: '/catalog/' },
    };
  }
  if (remaining != null && proxy === 'expiring') {
    return {
      tone: 'warn',
      title: `Your grid proxy expires ${formatRelative(now + remaining * 1000, now)}`,
      body: 'Renew it to keep grid services working.',
      action: { label: 'Renew proxy', href: IDENTITIES_HREF },
    };
  }
  if (soonestExpiringToken && expiresSoon({ revoked_at: null, ...soonestExpiringToken }, now)) {
    return {
      tone: 'warn',
      title: `${soonestExpiringToken.name} expires ${expiresIn(soonestExpiringToken.expires_at, now)}`,
      body: 'Create a replacement and update the client.',
      action: { label: 'New token', href: '/tokens/' },
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

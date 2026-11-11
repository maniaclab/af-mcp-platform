/**
 * overviewBanner.ts — picks the single most urgent message for the Overview
 * page's banner slot from the dashboard summary. A problem or warning banner
 * beats a hint; null means nothing is wrong and the slot stays empty.
 *
 * Priority: expired proxy, failing services, proxy expiring, token expiring,
 * then the hints: no linked accounts, services not linked. An account left
 * unlinked is the user's choice, so it only ever hints.
 */
import type { DashboardSummary } from './api';
import { failureSummary, unlinkedHint } from './serviceStatus';
import type { PageMessage } from './serviceStatus';
import { formatRelative } from './relativeTime';
import { expiresIn, expiresSoon } from './tokenDisplay';
import { proxyExpiryState } from './x509Identity';

const IDENTITIES_HREF = '/identities/';

export function overviewMessage(
  summary: DashboardSummary,
  now: number = Date.now(),
): PageMessage | null {
  const { proxyStatus, proxyAutoRenews, linkedCount, soonestExpiringToken } = summary;
  const remaining = proxyStatus.cached ? proxyStatus.remaining_seconds : null;
  const proxy = remaining != null ? proxyExpiryState(remaining, proxyAutoRenews) : 'ok';

  if (remaining != null && proxy === 'expired') {
    return {
      kind: 'banner',
      tone: 'bad',
      title: 'Your grid proxy has expired',
      body: 'Renew it to keep grid services working.',
      action: { label: 'Renew proxy', href: IDENTITIES_HREF },
    };
  }
  const failures = failureSummary(summary.misconfiguredCount, summary.unavailableCount);
  if (failures !== null) {
    return {
      kind: 'banner',
      tone: summary.misconfiguredCount > 0 ? 'bad' : 'warn',
      title: failures,
      body: 'Open Services to see which ones and why.',
      action: { label: 'View services', href: '/catalog/' },
    };
  }
  if (remaining != null && proxy === 'expiring') {
    return {
      kind: 'banner',
      tone: 'warn',
      title: `Your grid proxy expires ${formatRelative(now + remaining * 1000, now)}`,
      body: 'Renew it to keep grid services working.',
      action: { label: 'Renew proxy', href: IDENTITIES_HREF },
    };
  }
  if (soonestExpiringToken && expiresSoon({ revoked_at: null, ...soonestExpiringToken }, now)) {
    return {
      kind: 'banner',
      tone: 'warn',
      title: `${soonestExpiringToken.name} expires ${expiresIn(soonestExpiringToken.expires_at, now)}`,
      body: 'Create a replacement and update the client.',
      action: { label: 'New token', href: '/tokens/' },
    };
  }
  if (linkedCount === 0) {
    return {
      kind: 'hint',
      title: 'No accounts are linked yet',
      body: 'Link an account to use the services that need one.',
      action: { label: 'Link an account', href: IDENTITIES_HREF },
    };
  }
  if (summary.needsLinkCount > 0) {
    return unlinkedHint(summary.needsLinkCount, {
      label: 'Link an account',
      href: IDENTITIES_HREF,
    });
  }
  return null;
}

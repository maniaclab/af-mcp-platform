/**
 * relativeTime.ts — "3 hours ago" / "in 4 hours" formatting shared by the
 * portal pages that show timestamps (TokensPage.vue's expiry/last-used
 * columns, AdminPage.vue's credmon panel).
 */

const relativeFormatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

/** Format *targetMs* (epoch milliseconds) relative to *nowMs*, picking the largest unit under a day's granularity. */
export function formatRelative(targetMs: number, nowMs: number = Date.now()): string {
  const deltaSeconds = Math.round((targetMs - nowMs) / 1000);
  const abs = Math.abs(deltaSeconds);
  if (abs < 60) return relativeFormatter.format(deltaSeconds, 'second');
  if (abs < 3600) return relativeFormatter.format(Math.round(deltaSeconds / 60), 'minute');
  if (abs < 86400) return relativeFormatter.format(Math.round(deltaSeconds / 3600), 'hour');
  return relativeFormatter.format(Math.round(deltaSeconds / 86400), 'day');
}

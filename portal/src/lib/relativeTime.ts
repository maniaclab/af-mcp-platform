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

/**
 * Absolute timestamp in the short form the tables use, e.g. "Oct 2, 12:00 PM
 * UTC". The year is opt-in because most call sites show recent times where
 * it is noise; credential expiries can be far out and need it.
 */
export function formatDateTime(date: Date, { year = false }: { year?: boolean } = {}): string {
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    ...(year ? { year: 'numeric' } : {}),
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

/** Time left until *date* as "3h 25m remaining" / "45m remaining", or "expired" once it has passed. */
export function formatRemaining(date: Date, now: Date = new Date()): string {
  const seconds = Math.floor((date.getTime() - now.getTime()) / 1000);
  if (seconds <= 0) return 'expired';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return h > 0 ? `${h}h ${m}m remaining` : `${m}m remaining`;
}

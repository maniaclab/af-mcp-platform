/**
 * usageFormat.ts — shared display formatting for GET /v1/usage numbers,
 * used by both the overview's UsageCard and the /usage page so the same
 * figure never renders two different ways.
 */

export function formatTokens(n: number): string {
  return n.toLocaleString('en-US');
}

export function formatCost(n: number): string {
  // Tool-result costs are typically fractions of a cent -- keep enough
  // precision that a nonzero estimate never rounds to a misleading $0.00.
  return `$${n.toLocaleString('en-US', { maximumSignificantDigits: 3 })}`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toLocaleString('en-US', { maximumFractionDigits: 1 })} ${units[unit]}`;
}

/**
 * usageContent.ts — display rows for GET /v1/usage's `by_content_type`.
 *
 * Calls recorded without a breakdown (measured before the breakdown existed,
 * or by an older replica) are in `totals` but in no by_content_type entry, so
 * the entries can sum to less than the totals. That remainder is shown as an
 * explicit "Unattributed" row rather than dropped.
 */
import type { UsageByContentType, UsageTotals } from './api';

export const UNATTRIBUTED = 'unattributed';

export interface ContentTypeRow {
  /** The MCP content type, or UNATTRIBUTED for the remainder row. */
  contentType: string;
  label: string;
  /** null for the remainder: block counts are not recoverable. */
  blocks: number | null;
  bytes: number;
  tokens: number;
  /** Fraction (0..1) of the window's estimated tokens. */
  share: number;
}

const LABELS: Record<string, string> = {
  text: 'Text',
  image: 'Images',
  structured: 'Structured',
  audio: 'Audio',
  resource: 'Resources',
  resource_link: 'Resource links',
};

/** The content type is an open set; an unlisted one is shown under its own name. */
export function contentTypeLabel(contentType: string): string {
  return LABELS[contentType] ?? contentType;
}

export function contentTypeRows(
  totals: Pick<UsageTotals, 'result_bytes' | 'result_tokens_est'>,
  byContentType: UsageByContentType[],
): ContentTypeRow[] {
  const share = (tokens: number): number =>
    totals.result_tokens_est > 0 ? tokens / totals.result_tokens_est : 0;

  const rows: ContentTypeRow[] = byContentType
    .map((c) => ({
      contentType: c.content_type,
      label: contentTypeLabel(c.content_type),
      blocks: c.blocks,
      bytes: c.bytes,
      tokens: c.tokens_est,
      share: share(c.tokens_est),
    }))
    .sort(
      (a, b) =>
        b.tokens - a.tokens || b.bytes - a.bytes || a.contentType.localeCompare(b.contentType),
    );

  const bytes = totals.result_bytes - rows.reduce((sum, r) => sum + r.bytes, 0);
  const tokens = totals.result_tokens_est - rows.reduce((sum, r) => sum + r.tokens, 0);
  if (bytes > 0 || tokens > 0) {
    rows.push({
      contentType: UNATTRIBUTED,
      label: 'Unattributed',
      blocks: null,
      bytes: Math.max(bytes, 0),
      tokens: Math.max(tokens, 0),
      share: share(Math.max(tokens, 0)),
    });
  }
  return rows;
}

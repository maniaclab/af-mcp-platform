/**
 * serverTools.ts — pure mapping from a GET /v1/catalog/{service}/tools
 * response (see broker/src/af_mcp_broker/api/catalog_tools.py) to what
 * ServiceCard.vue's Tools accordion should render. Kept as plain
 * data-in/data-out functions (no DOM/fetch access) so it's trivially
 * unit-testable, same pattern as lib/serviceStatus.ts -- component logic
 * stays thin and this module carries the actual decisions.
 */
import type { CatalogTool, ServerToolsResponse } from './api';
import type { StatusCta } from './serviceStatus';

export type ToolListingView =
  /** Status "ok" with at least one tool — render the tool table. */
  | { kind: 'tools'; tools: CatalogTool[] }
  /** Status "ok" but the backend registers no tools — say so rather than
   *  rendering an empty table. */
  | { kind: 'empty'; message: string }
  /** Any non-"ok" status — the broker's own status_detail sentence, plus a
   *  CTA to the Identities page only when linking/re-linking is the
   *  user-actionable fix (not_linked/unauthorized). unavailable is
   *  wait-and-retry and capability_required is admin-actionable — no link. */
  | { kind: 'blocked'; message: string; cta: StatusCta | null };

const CTA_BY_STATUS: Partial<Record<ServerToolsResponse['status'], StatusCta>> = {
  not_linked: { label: 'Link identity', href: '/identities/' },
  unauthorized: { label: 'Re-link identity', href: '/identities/' },
};

export function resolveToolListing(listing: ServerToolsResponse): ToolListingView {
  if (listing.status === 'ok') {
    if (listing.tools.length > 0) {
      return { kind: 'tools', tools: listing.tools };
    }
    return { kind: 'empty', message: 'This service currently registers no methods.' };
  }
  return {
    kind: 'blocked',
    message: listing.status_detail,
    cta: CTA_BY_STATUS[listing.status] ?? null,
  };
}

/** "1 method" / "7 methods" — the accordion toggle's count chip. */
export function toolCountLabel(count: number): string {
  return `${count} ${count === 1 ? 'method' : 'methods'}`;
}

/**
 * Unit tests for lib/serverTools.ts — the pure mapping from a
 * GET /v1/catalog/{service}/tools response to what ServiceCard.vue's Tools
 * accordion should render. Same data-in/data-out pattern as
 * lib/serviceStatus.ts.
 */
import { describe, expect, it } from 'vitest';
import type { ServerToolsResponse } from '../api';
import { resolveToolListing, toolCountLabel } from '../serverTools';

function listing(overrides: Partial<ServerToolsResponse>): ServerToolsResponse {
  return {
    name: 'rucio',
    display_name: 'Rucio',
    description: 'ATLAS data management',
    status: 'ok',
    status_detail: 'Methods listed.',
    tools: [],
    ...overrides,
  };
}

describe('resolveToolListing', () => {
  it('returns the tools for a populated ok listing', () => {
    const tools = [
      {
        name: 'rucio_list_dids',
        description: 'List DIDs.',
        action_type: 'read' as const,
        permission: 'read_data',
      },
    ];
    expect(resolveToolListing(listing({ tools }))).toEqual({ kind: 'tools', tools });
  });

  it('explains an ok listing with zero tools rather than rendering an empty table', () => {
    const view = resolveToolListing(listing({}));
    expect(view.kind).toBe('empty');
    if (view.kind === 'empty') {
      expect(view.message).toBeTruthy();
    }
  });

  it('points not_linked at the Identities page (where the identity linking card lives)', () => {
    const view = resolveToolListing(
      listing({
        status: 'not_linked',
        status_detail: "Link your identity to see this service's methods.",
      }),
    );
    expect(view).toEqual({
      kind: 'blocked',
      message: "Link your identity to see this service's methods.",
      cta: { label: 'Link identity', href: '/identities/' },
    });
  });

  it('points unauthorized (rejected stored credential) at the Identities page too', () => {
    const view = resolveToolListing(
      listing({
        status: 'unauthorized',
        status_detail: 'Your linked credential was rejected. Re-link your identity.',
      }),
    );
    expect(view).toEqual({
      kind: 'blocked',
      message: 'Your linked credential was rejected. Re-link your identity.',
      cta: { label: 'Re-link identity', href: '/identities/' },
    });
  });

  it('renders unavailable as a plain message with no call to action', () => {
    const view = resolveToolListing(
      listing({ status: 'unavailable', status_detail: 'Temporarily unavailable.' }),
    );
    expect(view).toEqual({
      kind: 'blocked',
      message: 'Temporarily unavailable.',
      cta: null,
    });
  });

  it('renders permission_required as a plain message with no call to action', () => {
    const view = resolveToolListing(
      listing({ status: 'permission_required', status_detail: 'Contact the AF admins.' }),
    );
    expect(view).toEqual({
      kind: 'blocked',
      message: 'Contact the AF admins.',
      cta: null,
    });
  });
});

describe('toolCountLabel', () => {
  it('pluralizes', () => {
    expect(toolCountLabel(1)).toBe('1 method');
    expect(toolCountLabel(0)).toBe('0 methods');
    expect(toolCountLabel(12)).toBe('12 methods');
  });
});

import { describe, expect, it } from 'vitest';
import { groupServersByAlias, resolvePoweredBy } from '../catalog';
import type { CatalogServer, IdentityProvider } from '../api';

function makeServer(overrides: Partial<CatalogServer> = {}): CatalogServer {
  return {
    name: 'rucio',
    display_name: 'Rucio',
    description: 'ATLAS distributed data management',
    capability: 'read_data',
    auth_type: 'bearer',
    action_type: 'read',
    credential_provider: 'atlas-oidc',
    status: 'available',
    status_detail: 'Available.',
    correlation_id: null,
    ...overrides,
  };
}

function makeProvider(overrides: Partial<IdentityProvider> = {}): IdentityProvider {
  return {
    id: 'atlas-oidc',
    type: 'keycloak-brokered',
    display_name: 'ATLAS IAM',
    enables: 'VOMS proxy generation and grid certificate credential brokering',
    linked: true,
    link_url: null,
    link_mechanism: 'redirect',
    ...overrides,
  };
}

describe('resolvePoweredBy', () => {
  it('reports "none" with no link target when credential_provider is null', () => {
    expect(resolvePoweredBy(null, [])).toEqual({
      kind: 'none',
      label: 'No credential required',
      linked: null,
      linkHref: null,
    });
  });

  it('resolves an x509 entry through the providers list like any other alias', () => {
    // Since #182 x509 is an ordinary identity_providers entry — its alias
    // resolves against the providers list, linkage tracked, pointing at the
    // Identities page (the single home for x509 credential UX).
    const providers = [
      makeProvider({
        id: 'x509',
        type: 'x509',
        display_name: 'Grid certificate (x509)',
        link_mechanism: 'passphrase',
        linked: true,
      }),
    ];
    expect(resolvePoweredBy('x509', providers)).toEqual({
      kind: 'identity',
      label: 'Grid certificate (x509)',
      linked: true,
      linkHref: '/identities/',
    });
  });

  it('resolves a linked identity provider by alias', () => {
    const providers = [makeProvider({ id: 'atlas-oidc', display_name: 'ATLAS IAM', linked: true })];
    expect(resolvePoweredBy('atlas-oidc', providers)).toEqual({
      kind: 'identity',
      label: 'ATLAS IAM',
      linked: true,
      linkHref: '/identities/',
    });
  });

  it('resolves an unlinked identity provider by alias', () => {
    const providers = [
      makeProvider({ id: 'rucio-mcp-atlas', display_name: 'Rucio (ATLAS)', linked: false }),
    ];
    expect(resolvePoweredBy('rucio-mcp-atlas', providers)).toEqual({
      kind: 'identity',
      label: 'Rucio (ATLAS)',
      linked: false,
      linkHref: '/identities/',
    });
  });

  it('falls back to the alias itself and unlinked when no matching provider is found', () => {
    expect(resolvePoweredBy('unknown-alias', [])).toEqual({
      kind: 'identity',
      label: 'unknown-alias',
      linked: false,
      linkHref: '/identities/',
    });
  });
});

describe('groupServersByAlias', () => {
  it('groups servers under their credential_provider alias', () => {
    const servers = [
      makeServer({ name: 'rucio', credential_provider: 'atlas-oidc' }),
      makeServer({ name: 'panda', credential_provider: 'atlas-oidc' }),
      makeServer({ name: 'gitlab', credential_provider: 'rucio-mcp-atlas' }),
    ];
    const grouped = groupServersByAlias(servers);
    expect([...grouped.keys()]).toEqual(['atlas-oidc', 'rucio-mcp-atlas']);
    expect(grouped.get('atlas-oidc')?.map((s) => s.name)).toEqual(['rucio', 'panda']);
    expect(grouped.get('rucio-mcp-atlas')?.map((s) => s.name)).toEqual(['gitlab']);
  });

  it('groups x509-serviced servers too -- x509 is an ordinary identity_providers row', () => {
    const servers = [
      makeServer({ name: 'ami', credential_provider: 'x509' }),
      makeServer({ name: 'rucio', credential_provider: 'atlas-oidc' }),
    ];
    const grouped = groupServersByAlias(servers);
    expect([...grouped.keys()]).toEqual(['x509', 'atlas-oidc']);
    expect(grouped.get('x509')?.map((s) => s.name)).toEqual(['ami']);
  });

  it('omits credential-less servers -- no identity_providers row to attach to', () => {
    const servers = [
      makeServer({ name: 'docs', credential_provider: null }),
      makeServer({ name: 'rucio', credential_provider: 'atlas-oidc' }),
    ];
    const grouped = groupServersByAlias(servers);
    expect([...grouped.keys()]).toEqual(['atlas-oidc']);
  });
});

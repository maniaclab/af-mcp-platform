import { describe, expect, it } from 'vitest';
import {
  classifyPageLayout,
  diffProtectedRoutes,
  extractIngressProtectedPaths,
  routeForPageFile,
} from '../check-protected-routes.mjs';

describe('classifyPageLayout', () => {
  it('classifies a page importing Base.astro as protected', () => {
    const source = `---\nimport Base from '../layouts/Base.astro';\n---\n<Base></Base>`;
    expect(classifyPageLayout(source)).toBe('protected');
  });

  it('classifies a page importing PublicBase.astro as public', () => {
    const source = `---\nimport PublicBase from '../layouts/PublicBase.astro';\n---\n<PublicBase></PublicBase>`;
    expect(classifyPageLayout(source)).toBe('public');
  });

  it('returns null for a page importing neither layout', () => {
    const source = `---\nconst x = 1;\n---\n<div>{x}</div>`;
    expect(classifyPageLayout(source)).toBeNull();
  });
});

describe('routeForPageFile', () => {
  it('maps index.astro to the root route', () => {
    expect(routeForPageFile('index.astro')).toBe('/');
  });

  it('maps a named page file to its /name route', () => {
    expect(routeForPageFile('overview.astro')).toBe('/overview');
    expect(routeForPageFile('callback.astro')).toBe('/callback');
  });
});

describe('extractIngressProtectedPaths', () => {
  it('parses the quoted paths out of the range list line', () => {
    const template = [
      '        paths:',
      '          {{- range list "/overview" "/catalog" "/identities" "/tokens" "/callback" }}',
      '          - path: {{ . }}',
    ].join('\n');
    expect(extractIngressProtectedPaths(template)).toEqual([
      '/overview',
      '/catalog',
      '/identities',
      '/tokens',
      '/callback',
    ]);
  });

  it('throws when no range list line is found', () => {
    expect(() => extractIngressProtectedPaths('paths:\n  - path: /\n')).toThrow(
      /no `range list` line/,
    );
  });
});

describe('diffProtectedRoutes', () => {
  it('reports no diff when the sets match', () => {
    const astroRoutes = ['/overview', '/catalog'];
    const ingressPaths = ['/catalog', '/overview'];
    expect(diffProtectedRoutes(astroRoutes, ingressPaths)).toEqual({
      missingFromIngress: [],
      staleInIngress: [],
    });
  });

  it('reports a route present in Astro but missing from the Ingress', () => {
    const astroRoutes = ['/overview', '/settings'];
    const ingressPaths = ['/overview'];
    expect(diffProtectedRoutes(astroRoutes, ingressPaths)).toEqual({
      missingFromIngress: ['/settings'],
      staleInIngress: [],
    });
  });

  it('reports a stale path in the Ingress with no matching Astro page', () => {
    const astroRoutes = ['/overview'];
    const ingressPaths = ['/overview', '/old-page'];
    expect(diffProtectedRoutes(astroRoutes, ingressPaths)).toEqual({
      missingFromIngress: [],
      staleInIngress: ['/old-page'],
    });
  });
});

// @vitest-environment node
import { renderToString } from '@vue/server-renderer';
import { describe, expect, it } from 'vitest';
import { createSSRApp, type Component } from 'vue';

import AdminPage from '../AdminPage.vue';
import CatalogPage from '../CatalogPage.vue';
import ConnectClient from '../ConnectClient.vue';
import EntitlementsPage from '../EntitlementsPage.vue';
import IdentitiesPage from '../IdentitiesPage.vue';
import OverviewSummary from '../OverviewSummary.vue';
import TokensPage from '../TokensPage.vue';
import UsagePage from '../UsagePage.vue';

// Astro renders every `client:load` island on the server first (at build time
// and on each `astro dev` request), where there is no window or document. A
// component that touches a browser global during setup makes the whole page
// fail there, while passing every jsdom test. This runs in a plain Node
// environment for that reason.
const islands: [string, Component][] = [
  ['AdminPage', AdminPage],
  ['CatalogPage', CatalogPage],
  ['ConnectClient', ConnectClient],
  ['EntitlementsPage', EntitlementsPage],
  ['IdentitiesPage', IdentitiesPage],
  ['OverviewSummary', OverviewSummary],
  ['TokensPage', TokensPage],
  ['UsagePage', UsagePage],
];

describe('page islands render on the server', () => {
  it.each(islands)('%s renders without a browser', async (_name, component) => {
    expect(typeof window).toBe('undefined');
    const html = await renderToString(createSSRApp(component));
    expect(html.length).toBeGreaterThan(0);
  });
});

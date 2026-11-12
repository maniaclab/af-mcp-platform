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
import AccentSwitcher from '../design/AccentSwitcher.vue';
import DisclosureDemo from '../design/DisclosureDemo.vue';
import OverlayDemo from '../design/OverlayDemo.vue';
import SegmentedDemo from '../design/SegmentedDemo.vue';
import TokenTable from '../design/TokenTable.vue';
import BarChart from '../ui/BarChart.vue';
import CopyField from '../ui/CopyField.vue';

// Astro renders every `client:load` island on the server first (at build time
// and on each `astro dev` request), where there is no window or document. A
// component that touches a browser global during setup makes the whole page
// fail there, while passing every jsdom test. This runs in a plain Node
// environment for that reason.
const islands: [string, Component, Record<string, unknown>?][] = [
  ['AdminPage', AdminPage],
  ['CatalogPage', CatalogPage],
  ['ConnectClient', ConnectClient],
  ['EntitlementsPage', EntitlementsPage],
  ['IdentitiesPage', IdentitiesPage],
  ['OverviewSummary', OverviewSummary],
  ['TokensPage', TokensPage],
  ['UsagePage', UsagePage],
  // The /design/ page's islands.
  ['AccentSwitcher', AccentSwitcher],
  ['DisclosureDemo', DisclosureDemo],
  ['OverlayDemo', OverlayDemo],
  ['SegmentedDemo', SegmentedDemo],
  [
    'TokenTable',
    TokenTable,
    { tokens: [{ name: '--space-8', use: 'Icon to label.' }], specimen: 'space', caption: 'Space' },
  ],
  [
    'BarChart',
    BarChart,
    { labels: ['1 Nov'], series: [{ label: 'Calls', values: [1] }], ariaLabel: 'Calls' },
  ],
  ['CopyField', CopyField, { value: 'https://example.org/mcp' }],
];

describe('page islands render on the server', () => {
  it.each(islands)('%s renders without a browser', async (_name, component, props) => {
    expect(typeof window).toBe('undefined');
    const html = await renderToString(createSSRApp(component, props));
    expect(html.length).toBeGreaterThan(0);
  });
});

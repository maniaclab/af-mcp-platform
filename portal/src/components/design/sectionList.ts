/**
 * sectionList.ts — the design reference page's sections, in page order. The
 * in-page navigation (SectionNav.astro) is generated from it and every
 * section is rendered by `<DesignSection id="...">`, which takes its heading
 * and eyebrow from here, so a section cannot exist without a navigation entry.
 * designSections.test.ts checks the list and the rendered sections agree.
 */

export const SECTION_GROUPS = [
  'Start',
  'Visual styles',
  'Expression',
  'Content',
  'Components',
  'Pages',
] as const;

export type SectionGroup = (typeof SECTION_GROUPS)[number];

export interface SectionInfo {
  id: string;
  title: string;
  group: SectionGroup;
}

export const SECTIONS: SectionInfo[] = [
  { id: 'intro', title: 'Overview', group: 'Start' },
  { id: 'basecoat', title: 'Built on Basecoat', group: 'Start' },
  { id: 'tokens', title: 'Design tokens', group: 'Start' },
  { id: 'colour', title: 'Colour', group: 'Visual styles' },
  { id: 'type', title: 'Typography', group: 'Visual styles' },
  { id: 'dimensions', title: 'Dimensions', group: 'Visual styles' },
  { id: 'grid', title: 'Layout grid', group: 'Visual styles' },
  { id: 'border', title: 'Border and corner radius', group: 'Visual styles' },
  { id: 'elevation', title: 'Elevation', group: 'Visual styles' },
  { id: 'motion', title: 'Motion', group: 'Expression' },
  { id: 'icons', title: 'Icons', group: 'Expression' },
  { id: 'writing', title: 'Writing', group: 'Content' },
  { id: 'status', title: 'Status mark', group: 'Components' },
  { id: 'button', title: 'Button', group: 'Components' },
  { id: 'banner', title: 'Banner, note and hint', group: 'Components' },
  { id: 'table', title: 'Table', group: 'Components' },
  { id: 'field', title: 'Form field', group: 'Components' },
  { id: 'copy', title: 'Copy field', group: 'Components' },
  { id: 'kv', title: 'Key-value list and stat', group: 'Components' },
  { id: 'nav', title: 'Navigation and controls', group: 'Components' },
  { id: 'chart', title: 'Chart', group: 'Components' },
  { id: 'dialog', title: 'Dialog and tooltip', group: 'Components' },
  { id: 'empty', title: 'Empty state', group: 'Components' },
  { id: 'pattern', title: 'Page pattern', group: 'Pages' },
  { id: 'pages', title: 'Per-page specs', group: 'Pages' },
];

/** The listed section with *id*; throws for an id with no navigation entry. */
export function sectionInfo(id: string): SectionInfo {
  const info = SECTIONS.find((s) => s.id === id);
  if (!info) throw new Error(`design section "${id}" is not in sectionList.ts`);
  return info;
}

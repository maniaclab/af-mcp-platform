// @vitest-environment node
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { SECTIONS, SECTION_GROUPS } from '../design/sectionList';

// The page's in-page navigation is generated from SECTIONS, and every section
// is rendered by a `<DesignSection id="...">`, which looks its title up in the
// same list. These tests read the sources to check the two stay the same set,
// in the same order, so a section cannot be added without a navigation entry
// or listed without being rendered.
const DESIGN_DIR = resolve(process.cwd(), 'src/components/design');
const SECTION_FILES_DIR = join(DESIGN_DIR, 'sections');
const PAGE = readFileSync(resolve(process.cwd(), 'src/pages/design.astro'), 'utf8');

const sectionFiles = readdirSync(SECTION_FILES_DIR).filter((f) => f.endsWith('.astro'));

function idsIn(file: string): string[] {
  const source = readFileSync(join(SECTION_FILES_DIR, file), 'utf8');
  return [...source.matchAll(/<DesignSection\s+id="([^"]+)"/g)].map((m) => m[1]);
}

/** Section files in the order the page renders them. */
function renderedFiles(): string[] {
  return [...PAGE.matchAll(/<(\w+)\s*\/>/g)]
    .map((m) => `${m[1]}.astro`)
    .filter((f) => sectionFiles.includes(f));
}

describe('design page sections', () => {
  it('lists each section once, in a known group', () => {
    const ids = SECTIONS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const s of SECTIONS) expect(SECTION_GROUPS).toContain(s.group);
  });

  it('renders every section file from the page', () => {
    expect(renderedFiles().sort()).toEqual([...sectionFiles].sort());
  });

  it('renders exactly the listed sections, in the listed order', () => {
    const rendered = renderedFiles().flatMap(idsIn);
    expect(rendered).toEqual(SECTIONS.map((s) => s.id));
  });

  it('generates the navigation from the list', () => {
    const nav = readFileSync(join(DESIGN_DIR, 'SectionNav.astro'), 'utf8');
    expect(nav).toContain("from './sectionList'");
    expect(nav).toContain('<nav');
    expect(nav).toMatch(/aria-label="[^"]+"/);
  });

  it('has one h1, on the page, and no other', () => {
    expect(PAGE.match(/<h1\b/g)).toHaveLength(1);
    for (const f of sectionFiles) {
      expect(readFileSync(join(SECTION_FILES_DIR, f), 'utf8')).not.toMatch(/<h1\b/);
    }
  });
});

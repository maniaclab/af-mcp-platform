/**
 * Dialog titles are titles. Basecoat's `.dialog > * > header > h2` is body
 * size, so `.dialog.af-modal` (the class every portal dialog carries) sets the
 * contract's dialog title step. Both dialog components must use Basecoat's
 * header/h2 structure and the `af-modal` class for the rule to reach them.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8');

describe('dialog title', () => {
  it('is set to the 20px, weight 600 title step on every af-modal dialog', () => {
    const css = read('src/styles/components.css');
    const rule = css.match(/\.dialog\.af-modal > \* > header > h2\s*\{([^}]*)\}/);
    expect(rule, 'rule for .dialog.af-modal > * > header > h2').not.toBeNull();
    expect(rule![1]).toMatch(/font:\s*600 var\(--text-20\) \/ var\(--text-20--line-height\)/);
  });

  it('leaves a --space-8 gap between the title and the description', () => {
    const css = read('src/styles/components.css');
    const rule = css.match(/\.dialog\.af-modal > \* > header\s*\{([^}]*)\}/);
    expect(rule, 'rule for .dialog.af-modal > * > header').not.toBeNull();
    expect(rule![1]).toMatch(/gap:\s*var\(--space-8\)/);
  });

  it.each(['src/components/ui/ConfirmDialog.vue', 'src/components/TokensPage.vue'])(
    '%s marks its dialog af-modal and titles it with a header h2',
    (file) => {
      const source = read(file);
      expect(source).toMatch(/<dialog[^>]*class="dialog af-modal"/);
      expect(source).toMatch(/<header>\s*<h2 :?id=/);
    },
  );
});

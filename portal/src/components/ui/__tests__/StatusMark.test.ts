import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import StatusMark from '../StatusMark.vue';

describe('StatusMark', () => {
  it.each(['ok', 'warn', 'bad', 'info', 'busy', 'off'] as const)(
    'renders the %s mark, hidden from assistive tech, beside the word',
    (tone) => {
      const w = mount(StatusMark, { props: { tone, label: 'Linked' } });
      expect(w.classes()).toContain('af-st');
      const mark = w.find('.af-mark');
      expect(mark.classes()).toContain(tone);
      expect(mark.attributes('aria-hidden')).toBe('true');
      expect(w.text()).toBe('Linked');
    },
  );

  it('prefers the default slot over the label prop', () => {
    const w = mount(StatusMark, {
      props: { tone: 'ok', label: 'ignored' },
      slots: { default: 'Healthy' },
    });
    expect(w.text()).toBe('Healthy');
  });
});

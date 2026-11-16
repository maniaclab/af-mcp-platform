/**
 * Contract tests for TokenEstimateTip.vue: an InfoTip whose description is the
 * token-counting rules, reachable by keyboard and screen reader.
 */
import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import { TOKEN_ESTIMATE_RULES } from '../../lib/tokenExplainer';
import TokenEstimateTip from '../TokenEstimateTip.vue';

describe('TokenEstimateTip', () => {
  it('is a focusable button named for what it explains and described by the rules', () => {
    const w = mount(TokenEstimateTip, { props: { id: 'tok-tip' } });
    const btn = w.find('button');
    expect(btn.attributes('type')).toBe('button');
    expect(btn.attributes('aria-label')).toBe('How token counts are estimated');
    expect(btn.attributes('aria-describedby')).toBe('tok-tip');
  });

  it('describes every rule in the always-present screen-reader description', () => {
    const text = mount(TokenEstimateTip, { props: { id: 'tok-tip' } })
      .find('#tok-tip')
      .text();
    for (const rule of Object.values(TOKEN_ESTIMATE_RULES)) {
      expect(text).toContain(rule);
    }
    expect(text.toLowerCase()).toContain('estimate');
  });
});

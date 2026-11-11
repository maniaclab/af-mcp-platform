/**
 * Component tests for CopyField.vue and its use of lib/clipboard.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import CopyField from '../CopyField.vue';

function stubClipboard(writeText: (t: string) => Promise<void>) {
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  // @ts-expect-error -- removing test-only stub
  delete navigator.clipboard;
  // @ts-expect-error -- removing test-only stub
  delete document.execCommand;
});

describe('CopyField', () => {
  it('renders the value in mono inside .af-copy with a Copy button', () => {
    const w = mount(CopyField, { props: { value: 'https://mcp.example.org/mcp' } });
    expect(w.classes()).toContain('af-copy');
    expect(w.find('code').text()).toBe('https://mcp.example.org/mcp');
    const btn = w.find('button');
    expect(btn.attributes('type')).toBe('button');
    expect(btn.text()).toBe('Copy');
    expect(btn.classes()).toEqual(expect.arrayContaining(['af-btn', 'secondary', 's']));
    expect(w.find('svg').attributes('aria-hidden')).toBe('true');
  });

  it('uses label as the accessible name of the button', () => {
    const w = mount(CopyField, { props: { value: 'v', label: 'Copy endpoint URL' } });
    expect(w.find('button').attributes('aria-label')).toBe('Copy endpoint URL');
  });

  it('renders a wrapping block for multiline values', () => {
    const w = mount(CopyField, { props: { value: 'line one\nline two', multiline: true } });
    expect(w.find('pre').exists()).toBe(true);
    expect(w.find('pre').text()).toBe('line one\nline two');
  });

  it('copies the value, reads Copied for 2000 ms, then reverts', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    stubClipboard(writeText);
    const w = mount(CopyField, { props: { value: 'secret' } });

    await w.find('button').trigger('click');
    await flushPromises();
    expect(writeText).toHaveBeenCalledWith('secret');
    expect(w.find('button').text()).toBe('Copied');
    expect(w.find('[role="status"]').text()).toBe('Copied to clipboard');

    vi.advanceTimersByTime(1999);
    await w.vm.$nextTick();
    expect(w.find('button').text()).toBe('Copied');

    vi.advanceTimersByTime(1);
    await w.vm.$nextTick();
    expect(w.find('button').text()).toBe('Copy');
    expect(w.find('[role="status"]').text()).toBe('');
  });

  it('shows the manual-copy message on failure without throwing', async () => {
    stubClipboard(vi.fn().mockRejectedValue(new Error('denied')));
    const w = mount(CopyField, { props: { value: 'secret' } });

    await w.find('button').trigger('click');
    await flushPromises();
    expect(w.find('[role="status"]').text()).toBe('Copy failed — select and copy manually');
    expect(w.find('button').text()).toBe('Copy');
  });

  it('does not leave a pending timer behind after unmount', async () => {
    stubClipboard(vi.fn().mockResolvedValue(undefined));
    const w = mount(CopyField, { props: { value: 'secret' } });
    await w.find('button').trigger('click');
    await flushPromises();
    w.unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});

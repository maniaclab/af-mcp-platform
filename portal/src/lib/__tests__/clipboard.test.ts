import { afterEach, describe, expect, it, vi } from 'vitest';

import { copyText } from '../clipboard';

function stubClipboard(writeText: ((text: string) => Promise<void>) | undefined) {
  Object.defineProperty(navigator, 'clipboard', {
    value: writeText ? { writeText } : undefined,
    configurable: true,
  });
}

function stubExecCommand(impl: (cmd: string) => boolean) {
  const fn = vi.fn(impl);
  Object.defineProperty(document, 'execCommand', { value: fn, configurable: true });
  return fn;
}

afterEach(() => {
  // @ts-expect-error -- removing test-only stubs
  delete navigator.clipboard;
  // @ts-expect-error -- removing test-only stubs
  delete document.execCommand;
  document.body.innerHTML = '';
});

describe('copyText', () => {
  it('writes through the async clipboard API and reports success', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    stubClipboard(writeText);

    await expect(copyText('secret')).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith('secret');
  });

  it('falls back to execCommand when the async clipboard API rejects', async () => {
    stubClipboard(vi.fn().mockRejectedValue(new Error('denied')));
    let selected = '';
    const exec = stubExecCommand(() => {
      selected = (document.activeElement as HTMLTextAreaElement).value;
      return true;
    });

    await expect(copyText('fallback text')).resolves.toBe(true);
    expect(exec).toHaveBeenCalledWith('copy');
    expect(selected).toBe('fallback text');
    // The temporary textarea is removed afterwards.
    expect(document.querySelector('textarea')).toBeNull();
  });

  it('falls back to execCommand when the async clipboard API is absent', async () => {
    stubClipboard(undefined);
    const exec = stubExecCommand(() => true);

    await expect(copyText('x')).resolves.toBe(true);
    expect(exec).toHaveBeenCalledWith('copy');
  });

  it('reports failure without throwing when both paths fail', async () => {
    stubClipboard(vi.fn().mockRejectedValue(new Error('denied')));
    stubExecCommand(() => false);

    await expect(copyText('x')).resolves.toBe(false);
    expect(document.querySelector('textarea')).toBeNull();
  });

  it('reports failure when execCommand throws or is unavailable', async () => {
    stubClipboard(undefined);
    await expect(copyText('x')).resolves.toBe(false);

    stubExecCommand(() => {
      throw new Error('boom');
    });
    await expect(copyText('x')).resolves.toBe(false);
  });
});

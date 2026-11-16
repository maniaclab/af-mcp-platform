import { describe, expect, it } from 'vitest';

import { useAsyncAction } from '../useAsyncAction';

const toMessage = (err: unknown) => `failed: ${(err as Error).message}`;

describe('useAsyncAction', () => {
  it('starts idle with no error', () => {
    const a = useAsyncAction(toMessage);
    expect(a.busy.value).toBe(false);
    expect(a.error.value).toBeNull();
  });

  it('is busy while fn is pending and resolves true on success', async () => {
    const a = useAsyncAction(toMessage);
    let resolve!: () => void;
    const pending = a.run(() => new Promise<void>((r) => (resolve = r)));
    expect(a.busy.value).toBe(true);
    resolve();
    expect(await pending).toBe(true);
    expect(a.busy.value).toBe(false);
    expect(a.error.value).toBeNull();
  });

  it('maps a failure through toMessage, clears busy and resolves false', async () => {
    const a = useAsyncAction(toMessage);
    const ok = await a.run(async () => {
      throw new Error('boom');
    });
    expect(ok).toBe(false);
    expect(a.error.value).toBe('failed: boom');
    expect(a.busy.value).toBe(false);
  });

  it('clears the previous error when run again', async () => {
    const a = useAsyncAction(toMessage);
    await a.run(async () => {
      throw new Error('boom');
    });
    let resolve!: () => void;
    const pending = a.run(() => new Promise<void>((r) => (resolve = r)));
    expect(a.error.value).toBeNull();
    resolve();
    await pending;
    expect(a.error.value).toBeNull();
  });
});

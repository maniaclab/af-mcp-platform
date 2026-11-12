import { describe, expect, it, vi } from 'vitest';

import { useFetchOnExpand } from '../useFetchOnExpand';

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('useFetchOnExpand', () => {
  it('starts closed and idle', () => {
    const f = useFetchOnExpand(vi.fn());
    expect(f.open.value).toBe(false);
    expect(f.data.value).toBeNull();
    expect(f.loading.value).toBe(false);
    expect(f.error.value).toBeNull();
  });

  it('fetches on expand and exposes the data', async () => {
    const fetcher = vi.fn().mockResolvedValue({ ok: true });
    const f = useFetchOnExpand(fetcher);

    const p = f.toggle();
    expect(f.open.value).toBe(true);
    expect(f.loading.value).toBe(true);
    await p;

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(f.data.value).toEqual({ ok: true });
    expect(f.loading.value).toBe(false);
  });

  it('does not fetch on collapse', async () => {
    const fetcher = vi.fn().mockResolvedValue(1);
    const f = useFetchOnExpand(fetcher);
    await f.toggle();
    await f.toggle();
    expect(f.open.value).toBe(false);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('refetches on every expand', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce('a').mockResolvedValueOnce('b');
    const f = useFetchOnExpand(fetcher);
    await f.toggle();
    await f.toggle();
    await f.toggle();
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(f.data.value).toBe('b');
  });

  it('surfaces the error message and clears data on failure', async () => {
    const f = useFetchOnExpand(vi.fn().mockRejectedValue(new Error('down')), 'Could not load.');
    await f.toggle();
    expect(f.error.value).toBe('down');
    expect(f.data.value).toBeNull();
    expect(f.loading.value).toBe(false);
  });

  it('uses the fallback message for a non-Error rejection', async () => {
    const f = useFetchOnExpand(vi.fn().mockRejectedValue('x'), 'Could not load.');
    await f.toggle();
    expect(f.error.value).toBe('Could not load.');
  });

  it('discards a response that lands after collapse', async () => {
    const d = deferred<string>();
    const f = useFetchOnExpand(() => d.promise);
    const p = f.toggle();
    await f.toggle(); // collapse
    d.resolve('late');
    await p;
    expect(f.data.value).toBeNull();
    expect(f.loading.value).toBe(false);
  });

  it('never lets a slower earlier response overwrite a newer one', async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    const fetcher = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const f = useFetchOnExpand<string>(fetcher);

    const p1 = f.toggle(); // expand
    await f.toggle(); // collapse
    const p3 = f.toggle(); // expand again -> second fetch

    second.resolve('new');
    await p3;
    first.resolve('stale');
    await p1;

    expect(f.data.value).toBe('new');
    expect(f.loading.value).toBe(false);
  });

  it('ignores a stale rejection too', async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    const fetcher = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const f = useFetchOnExpand<string>(fetcher);

    const p1 = f.toggle();
    await f.toggle();
    const p3 = f.toggle();

    second.resolve('new');
    await p3;
    first.reject(new Error('old failure'));
    await p1;

    expect(f.data.value).toBe('new');
    expect(f.error.value).toBeNull();
  });
});

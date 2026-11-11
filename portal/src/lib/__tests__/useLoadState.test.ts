import { describe, expect, it } from 'vitest';

import { AccessDeniedError, SessionExpiredError } from '../api';
import { useLoadState } from '../useLoadState';

describe('useLoadState', () => {
  it('starts in the loading state with nothing wrong', () => {
    const s = useLoadState();
    expect(s.loading.value).toBe(true);
    expect(s.error.value).toBeNull();
    expect(s.sessionExpired.value).toBe(false);
    expect(s.accessDenied.value).toBeNull();
  });

  it('is loading while fn is pending and clears loading on success', async () => {
    const s = useLoadState();
    let resolve!: () => void;
    const pending = s.run(() => new Promise<void>((r) => (resolve = r)));
    expect(s.loading.value).toBe(true);
    resolve();
    await pending;
    expect(s.loading.value).toBe(false);
    expect(s.error.value).toBeNull();
  });

  it('classifies AccessDeniedError and keeps the error for its message', async () => {
    const s = useLoadState();
    const err = new AccessDeniedError('no audience', 'cid-1');
    await s.run(async () => {
      throw err;
    });
    expect(s.accessDenied.value).toBe(err);
    expect(s.sessionExpired.value).toBe(false);
    expect(s.error.value).toBeNull();
    expect(s.loading.value).toBe(false);
  });

  it('classifies SessionExpiredError', async () => {
    const s = useLoadState();
    await s.run(async () => {
      throw new SessionExpiredError();
    });
    expect(s.sessionExpired.value).toBe(true);
    expect(s.accessDenied.value).toBeNull();
    expect(s.error.value).toBeNull();
    expect(s.loading.value).toBe(false);
  });

  it('uses the message of any other Error', async () => {
    const s = useLoadState();
    await s.run(async () => {
      throw new Error('boom');
    });
    expect(s.error.value).toBe('boom');
    expect(s.loading.value).toBe(false);
  });

  it('uses the fallback message for a non-Error throw', async () => {
    const s = useLoadState();
    await s.run(async () => {
      throw 'nope';
    }, 'Failed to load usage.');
    expect(s.error.value).toBe('Failed to load usage.');
  });

  it('clears a previous failure when run again', async () => {
    const s = useLoadState();
    await s.run(async () => {
      throw new Error('first');
    });
    await s.run(async () => undefined);
    expect(s.error.value).toBeNull();
    expect(s.loading.value).toBe(false);
  });
});

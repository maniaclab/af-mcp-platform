import { describe, expect, it } from 'vitest';

import { APIError, SessionExpiredError } from '../api';
import {
  credmonHealth,
  credmonKindRows,
  credmonNextRunAt,
  credmonSyncErrorMessage,
} from '../credmonStatus';
import type { CredmonRun, CredmonStatus } from '../api';

const INTERVAL = 14400;
const NOW = 2_000_000; // unix seconds

function run(overrides: Partial<CredmonRun> = {}): CredmonRun {
  return {
    outcome: 'success',
    trigger: 'timer',
    holder: 'broker-pod-a:1',
    started_at: NOW - 100,
    finished_at: NOW - 97,
    last_success_at: NOW - 97,
    stored: { krb5: 12 },
    not_linked: { krb5: 3 },
    skipped_no_posix: {},
    failed: {},
    errors: [],
    errors_truncated: 0,
    ...overrides,
  };
}

function status(overrides: Partial<CredmonStatus> = {}): CredmonStatus {
  return {
    enabled: true,
    kinds: ['krb5', 'x509'],
    service_prefix: 'af_',
    interval_seconds: INTERVAL,
    last_run: run(),
    ...overrides,
  };
}

describe('credmonHealth', () => {
  it('is disabled when the integration is off', () => {
    expect(credmonHealth(status({ enabled: false, last_run: null }), NOW)).toBe('disabled');
  });

  it('is pending before the first cycle has run', () => {
    expect(credmonHealth(status({ last_run: null }), NOW)).toBe('pending');
  });

  it('is healthy after a recent successful cycle', () => {
    expect(credmonHealth(status(), NOW)).toBe('healthy');
  });

  it('is a warning after a partial cycle (some users failed)', () => {
    expect(
      credmonHealth(status({ last_run: run({ outcome: 'partial', failed: { krb5: 1 } }) }), NOW),
    ).toBe('warning');
  });

  it('is a warning when the last success is older than twice the interval', () => {
    const stale = run({ finished_at: NOW - 3 * INTERVAL, last_success_at: NOW - 3 * INTERVAL });
    expect(credmonHealth(status({ last_run: stale }), NOW)).toBe('warning');
  });

  it('is an error when the last cycle failed', () => {
    expect(credmonHealth(status({ last_run: run({ outcome: 'failed' }) }), NOW)).toBe('error');
  });

  it('is an error when no cycle has ever succeeded', () => {
    const neverOk = run({ outcome: 'failed', last_success_at: null });
    expect(credmonHealth(status({ last_run: neverOk }), NOW)).toBe('error');
  });
});

describe('credmonKindRows', () => {
  it('lists every synced kind with its credd service name and counts, zero-filled', () => {
    const s = status({
      last_run: run({
        stored: { krb5: 12, x509: 4 },
        not_linked: { krb5: 3 },
        skipped_no_posix: { x509: 1 },
        failed: { krb5: 1 },
      }),
    });

    expect(credmonKindRows(s)).toEqual([
      { kind: 'krb5', service: 'af_krb5', stored: 12, notLinked: 3, noPosix: 0, failed: 1 },
      { kind: 'x509', service: 'af_x509', stored: 4, notLinked: 0, noPosix: 1, failed: 0 },
    ]);
  });

  it('shows zero counts for every kind before the first cycle', () => {
    expect(credmonKindRows(status({ kinds: ['krb5'], last_run: null }))).toEqual([
      { kind: 'krb5', service: 'af_krb5', stored: 0, notLinked: 0, noPosix: 0, failed: 0 },
    ]);
  });
});

describe('credmonNextRunAt', () => {
  it('is the last finish plus the interval', () => {
    expect(credmonNextRunAt(status())).toBe(NOW - 97 + INTERVAL);
  });

  it('is null before the first cycle', () => {
    expect(credmonNextRunAt(status({ last_run: null }))).toBeNull();
  });
});

describe('credmonSyncErrorMessage', () => {
  it("prefers the broker's detail, with its correlation reference", () => {
    const err = new APIError(
      409,
      'Conflict',
      JSON.stringify({
        detail: 'A credmon sync cycle is already running on another replica -- retry shortly.',
      }),
    );
    expect(credmonSyncErrorMessage(err)).toBe(
      'A credmon sync cycle is already running on another replica -- retry shortly.',
    );
  });

  it.each([
    [404, 'The HTCondor credmon integration is not enabled on this broker.'],
    [409, 'A sync is already running on another broker replica. Try again shortly.'],
    [403, 'Running a sync requires admin access.'],
  ])('falls back to a plain message for a %d without a detail body', (code, expected) => {
    expect(credmonSyncErrorMessage(new APIError(code, 'x', '<html></html>'))).toBe(expected);
  });

  it('explains an expired session', () => {
    expect(credmonSyncErrorMessage(new SessionExpiredError())).toBe(
      'Your session has expired. Reload the page to sign in again.',
    );
  });
});

import { describe, expect, it } from 'vitest';

import { APIError, SessionExpiredError } from '../api';
import { maintenanceBannerText, maintenanceErrorMessage } from '../maintenanceBanner';
import type { MaintenanceStatus } from '../api';

describe('maintenanceBannerText', () => {
  it('returns null when the status fetch failed (null)', () => {
    expect(maintenanceBannerText(null)).toBeNull();
  });

  it('returns null when maintenance mode is disabled', () => {
    const disabled: MaintenanceStatus = {
      enabled: false,
      reason: null,
      enabled_by: null,
      enabled_at: null,
    };
    expect(maintenanceBannerText(disabled)).toBeNull();
  });

  it('includes the reason when maintenance mode is enabled with one', () => {
    const enabled: MaintenanceStatus = {
      enabled: true,
      reason: 'Scheduled Postgres upgrade, back by 14:00 UTC',
      enabled_by: 'af92c1d0-...',
      enabled_at: 1756450000,
    };
    expect(maintenanceBannerText(enabled)).toBe(
      'Maintenance mode is enabled: Scheduled Postgres upgrade, back by 14:00 UTC',
    );
  });

  it('falls back to a plain notice when enabled with no reason', () => {
    const enabled: MaintenanceStatus = {
      enabled: true,
      reason: null,
      enabled_by: 'af92c1d0-...',
      enabled_at: 1756450000,
    };
    expect(maintenanceBannerText(enabled)).toBe('Maintenance mode is enabled.');
  });
});

describe('maintenanceErrorMessage', () => {
  it('gives SessionExpiredError the standard reload wording', () => {
    expect(maintenanceErrorMessage(new SessionExpiredError())).toMatch(/reload/i);
  });

  it("surfaces the broker's actual detail text on a 403", () => {
    const err = new APIError(
      403,
      'Forbidden',
      JSON.stringify({ detail: 'This action requires membership in the admin group.' }),
    );
    expect(maintenanceErrorMessage(err)).toBe(
      'This action requires membership in the admin group.',
    );
  });

  it('falls back to a friendly access-denied message when a 403 has no detail', () => {
    const err = new APIError(403, 'Forbidden', 'not-json');
    expect(maintenanceErrorMessage(err)).toMatch(/access/i);
  });

  it("surfaces the broker's actual detail text on a 409", () => {
    const err = new APIError(
      409,
      'Conflict',
      JSON.stringify({
        detail: 'Another admin changed maintenance mode at the same time.',
      }),
    );
    expect(maintenanceErrorMessage(err)).toBe(
      'Another admin changed maintenance mode at the same time.',
    );
  });

  it('falls back to a friendly retry message when a 409 has no detail', () => {
    const err = new APIError(409, 'Conflict', '');
    expect(maintenanceErrorMessage(err)).toMatch(/retry/i);
  });

  it('falls back to the APIError message itself for a status with no special handling', () => {
    // Same as x509LinkErrorMessage/x509PreflightErrorMessage: an APIError is
    // still an Error, so an unhandled status falls through to its own
    // message rather than the fully-generic canned fallback.
    const err = new APIError(500, 'Server Error', 'not-json');
    expect(maintenanceErrorMessage(err)).toBe(err.message);
  });

  it('uses a plain Error message when present', () => {
    expect(maintenanceErrorMessage(new Error('network down'))).toBe('network down');
  });

  it('falls back to a generic message for a non-Error throw', () => {
    expect(maintenanceErrorMessage('boom')).toBe('Could not update maintenance mode.');
  });
});

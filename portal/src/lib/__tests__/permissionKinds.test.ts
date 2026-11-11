import { describe, expect, it } from 'vitest';
import { KNOWN_PERMISSION_ORDER, permissionKind } from '../permissionKinds';

describe('permissionKind', () => {
  it('uses the known classification for a known permission, whatever the action types say', () => {
    expect(permissionKind('read_data', ['read', 'state_change'])).toBe('read');
    expect(permissionKind('manage_jobs', ['read'])).toBe('write');
  });

  it('treats an unknown permission with a state-changing action type as write', () => {
    expect(permissionKind('use_notebooks', ['read', 'state_change'])).toBe('write');
  });

  it('treats an unknown permission with no state-changing action type as read', () => {
    expect(permissionKind('read_search', ['read'])).toBe('read');
    expect(permissionKind('read_search')).toBe('read');
  });

  it('lists every known permission once', () => {
    const names = KNOWN_PERMISSION_ORDER.map((p) => p.name);
    expect(new Set(names).size).toBe(names.length);
  });
});

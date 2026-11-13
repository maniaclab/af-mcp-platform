import { describe, expect, it } from 'vitest';
import { permissionLabel } from '../permissionLabel';

describe('permissionLabel', () => {
  it('replaces underscores with spaces and upper-cases the first letter', () => {
    expect(permissionLabel('read_metadata')).toBe('Read metadata');
  });

  it('upper-cases a single word', () => {
    expect(permissionLabel('admin')).toBe('Admin');
  });

  it('leaves the rest of the name unchanged', () => {
    expect(permissionLabel('read_gitlab')).toBe('Read gitlab');
    expect(permissionLabel('submit_HTCondor_jobs')).toBe('Submit HTCondor jobs');
  });

  it('returns an empty string for an empty name', () => {
    expect(permissionLabel('')).toBe('');
  });
});

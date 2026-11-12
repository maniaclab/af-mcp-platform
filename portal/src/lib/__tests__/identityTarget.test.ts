import { describe, expect, it } from 'vitest';
import { identityTargetFromHash } from '../identityTarget';

const IDS = ['atlas-oidc', 'x509', 'krb5'];

describe('identityTargetFromHash', () => {
  it('returns the id a #identity-card-<id> hash names', () => {
    expect(identityTargetFromHash('#identity-card-krb5', IDS)).toBe('krb5');
    expect(identityTargetFromHash('#identity-card-atlas-oidc', IDS)).toBe('atlas-oidc');
  });

  it.each(['', '#', '#identity-card-', '#identity-card-nope', '#krb5', '#identity-card-krb5x'])(
    'returns null for %j',
    (hash) => {
      expect(identityTargetFromHash(hash, IDS)).toBeNull();
    },
  );
});

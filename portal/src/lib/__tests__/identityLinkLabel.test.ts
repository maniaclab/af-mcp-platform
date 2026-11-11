import { describe, expect, it } from 'vitest';
import { identityLinkAnchor, identityLinkLabel, LINK_ACTION_LABEL } from '../identityLinkLabel';

describe('identityLinkLabel', () => {
  it('names the grid certificate action after the certificate', () => {
    expect(
      identityLinkLabel({ link_mechanism: 'passphrase', display_name: 'Grid certificate' }),
    ).toBe(LINK_ACTION_LABEL.certificate);
  });

  it('names the Kerberos action after the ticket', () => {
    expect(identityLinkLabel({ link_mechanism: 'credential', display_name: 'Kerberos' })).toBe(
      LINK_ACTION_LABEL.kerberos,
    );
  });

  it('names the ServiceX action after the token', () => {
    expect(identityLinkLabel({ link_mechanism: 'servicex-token', display_name: 'ServiceX' })).toBe(
      LINK_ACTION_LABEL.servicex,
    );
  });

  it('names the account for a redirect provider', () => {
    expect(identityLinkLabel({ link_mechanism: 'redirect', display_name: 'CERN' })).toBe(
      'Link CERN account',
    );
  });
});

describe('identityLinkAnchor', () => {
  it('points at the provider card on the Identities page', () => {
    expect(identityLinkAnchor('atlas-oidc')).toBe('/identities/#identity-card-atlas-oidc');
  });
});

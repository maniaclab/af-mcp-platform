import { describe, expect, it } from 'vitest';
import {
  identityLinkAnchor,
  identityLinkLabel,
  identityNoun,
  identityRelinkLabel,
  LINK_ACTION_LABEL,
  RELINK_ACTION_LABEL,
} from '../identityLinkLabel';

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

describe('identityRelinkLabel', () => {
  // The names match what each identity card calls the action while linked.
  it('names the grid certificate action after the certificate', () => {
    expect(
      identityRelinkLabel({ link_mechanism: 'passphrase', display_name: 'Grid certificate' }),
    ).toBe(RELINK_ACTION_LABEL.certificate);
    expect(RELINK_ACTION_LABEL.certificate).toBe('Re-link certificate');
  });

  it('refreshes a Kerberos ticket', () => {
    expect(identityRelinkLabel({ link_mechanism: 'credential', display_name: 'Kerberos' })).toBe(
      'Refresh ticket',
    );
  });

  it('names the ServiceX token', () => {
    expect(
      identityRelinkLabel({ link_mechanism: 'servicex-token', display_name: 'ServiceX' }),
    ).toBe('Re-link ServiceX token');
  });

  it('reconnects the named account for a redirect provider', () => {
    expect(identityRelinkLabel({ link_mechanism: 'redirect', display_name: 'CERN' })).toBe(
      'Reconnect CERN account',
    );
  });
});

describe('identityNoun', () => {
  it('calls a redirect provider an account', () => {
    expect(identityNoun({ link_mechanism: 'redirect', display_name: 'ATLAS IAM' })).toBe(
      'ATLAS IAM account',
    );
  });

  it('uses the display name as is for a credential that is not an account', () => {
    expect(identityNoun({ link_mechanism: 'passphrase', display_name: 'Grid certificate' })).toBe(
      'Grid certificate',
    );
    expect(identityNoun({ link_mechanism: 'credential', display_name: 'Kerberos ticket' })).toBe(
      'Kerberos ticket',
    );
  });
});

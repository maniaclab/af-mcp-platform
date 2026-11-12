/**
 * identityLinkLabel.ts — the names of the "link this identity" actions, shared
 * by the Identities page's cards and the Services page's fix links so both
 * pages name the same action the same way.
 */
import type { IdentityProvider } from './api';

export const LINK_ACTION_LABEL = {
  account: 'Link account',
  certificate: 'Link certificate',
  kerberos: 'Get Kerberos ticket',
  servicex: 'Link ServiceX token',
} as const;

/** The names of the "link this identity again" actions: what each identity card calls its button once the identity is already linked. */
export const RELINK_ACTION_LABEL = {
  certificate: 'Re-link certificate',
  kerberos: 'Refresh ticket',
  servicex: 'Re-link ServiceX token',
} as const;

/**
 * Label for the action that links `provider` when it is read outside its
 * card. A redirect provider's card says "Link account" under the provider's
 * own heading; outside the card the provider is named instead.
 */
export function identityLinkLabel(
  provider: Pick<IdentityProvider, 'link_mechanism' | 'display_name'>,
): string {
  switch (provider.link_mechanism) {
    case 'passphrase':
      return LINK_ACTION_LABEL.certificate;
    case 'credential':
      return LINK_ACTION_LABEL.kerberos;
    case 'servicex-token':
      return LINK_ACTION_LABEL.servicex;
    default:
      return `Link ${provider.display_name} account`;
  }
}

/**
 * Label for the action that links `provider` again, read outside its card
 * (a service whose stored credential was rejected). Each identity card names
 * this action itself while linked; a redirect provider's card says
 * "Reconnect", and outside the card the provider is named instead.
 */
export function identityRelinkLabel(
  provider: Pick<IdentityProvider, 'link_mechanism' | 'display_name'>,
): string {
  switch (provider.link_mechanism) {
    case 'passphrase':
      return RELINK_ACTION_LABEL.certificate;
    case 'credential':
      return RELINK_ACTION_LABEL.kerberos;
    case 'servicex-token':
      return RELINK_ACTION_LABEL.servicex;
    default:
      return `Reconnect ${provider.display_name} account`;
  }
}

/**
 * What to call `provider` in a sentence about its stored credential: a
 * redirect provider is an account ("your ATLAS IAM account"); the others
 * already have a display name that names the credential ("Grid certificate").
 */
export function identityNoun(
  provider: Pick<IdentityProvider, 'link_mechanism' | 'display_name'>,
): string {
  switch (provider.link_mechanism) {
    case 'passphrase':
    case 'credential':
    case 'servicex-token':
      return provider.display_name;
    default:
      return `${provider.display_name} account`;
  }
}

/** Deep link to a provider's card on the Identities page (IdentitiesPage.vue's `identity-card-<id>` anchors). */
export function identityLinkAnchor(providerId: string): string {
  return `/identities/#identity-card-${providerId}`;
}

/**
 * Component tests for IdentityLink.vue's permission-denied rendering.
 *
 * A keycloak-brokered provider's link_permission_denied is true when
 * Keycloak's stored-broker-token endpoint answered 403 (the caller's own
 * access token lacks the `read-token` client role) rather than the
 * ordinary "not linked yet". Without a distinct state here, a user who may
 * have already completed the IdP linking flow sees the same "not linked" +
 * clickable "Link account" button as someone who's never tried — with no
 * indication that the actual blocker is a missing role, not a missing link.
 */
import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import IdentityLink from '../IdentityLink.vue';

function mountLink(linkPermissionDenied: boolean) {
  return mount(IdentityLink, {
    props: {
      id: 'atlas-iam',
      type: 'keycloak-brokered',
      display_name: 'ATLAS IAM',
      enables: 'Rucio/PanDA access',
      linked: false,
      link_url: null,
      link_permission_denied: linkPermissionDenied,
    },
  });
}

describe('IdentityLink permission-denied state', () => {
  it('shows an "access required" status and a notice instead of the plain not-linked state', () => {
    const wrapper = mountLink(true);

    expect(wrapper.find('.il__status--unlinked').exists()).toBe(false);
    expect(wrapper.find('.il__status--permission-denied').exists()).toBe(true);
    expect(wrapper.text()).toContain('access required');
    expect(wrapper.find('.il__notice').exists()).toBe(true);
  });

  it('renders the ordinary not-linked state when permission is not denied', () => {
    const wrapper = mountLink(false);

    expect(wrapper.find('.il__status--unlinked').exists()).toBe(true);
    expect(wrapper.find('.il__status--permission-denied').exists()).toBe(false);
    expect(wrapper.find('.il__notice').exists()).toBe(false);
  });
});

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
import { flushPromises, mount } from '@vue/test-utils';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/api')>()),
  unlinkIdentity: vi.fn().mockResolvedValue(undefined),
}));

import { unlinkIdentity } from '../../lib/api';
import { LINK_ACTION_LABEL, RELINK_ACTION_LABEL } from '../../lib/identityLinkLabel';
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
    expect(wrapper.text()).toContain('Access required');
    expect(wrapper.find('.il__notice').exists()).toBe(true);
  });

  it('renders the ordinary not-linked state when permission is not denied', () => {
    const wrapper = mountLink(false);

    expect(wrapper.find('.il__status--unlinked').exists()).toBe(true);
    expect(wrapper.find('.il__status--permission-denied').exists()).toBe(false);
    expect(wrapper.find('.il__notice').exists()).toBe(false);
  });
});

describe('IdentityLink unlink confirmation', () => {
  function mountLinked() {
    return mount(IdentityLink, {
      props: {
        id: 'example-oauth',
        type: 'oauth21-direct',
        display_name: 'Example Docs Service',
        enables: 'Docs search',
        linked: true,
        link_url: '/v1/oauth/authorize/example-oauth',
      },
      attachTo: document.body,
    });
  }

  it('asks for confirmation naming the identity before unlinking, then emits unlinked', async () => {
    const wrapper = mountLinked();

    await wrapper.find('button.il__btn--unlink').trigger('click');
    expect(unlinkIdentity).not.toHaveBeenCalled();
    const dialog = wrapper.find('dialog');
    expect(dialog.text()).toContain('Unlink Example Docs Service?');

    const confirm = dialog.findAll('button').find((b) => b.text() === 'Unlink account');
    await confirm?.trigger('click');
    await flushPromises();

    expect(unlinkIdentity).toHaveBeenCalledWith('example-oauth');
    expect(wrapper.emitted('unlinked')).toEqual([[]]);
    wrapper.unmount();
  });
});

describe('IdentityLink rejected credential', () => {
  function mountRejected(over: Record<string, unknown> = {}) {
    return mount(IdentityLink, {
      props: {
        id: 'example-oauth',
        type: 'oauth21-direct',
        display_name: 'Example Docs Service',
        enables: 'Docs search',
        linked: false,
        rejected: true,
        link_url: '/v1/oauth/authorize/example-oauth',
        ...over,
      },
    });
  }

  it('shows a warning "Credential rejected" status, not "Not linked"', () => {
    const wrapper = mountRejected();

    expect(wrapper.find('.il__status--rejected').exists()).toBe(true);
    expect(wrapper.find('.il__status--unlinked').exists()).toBe(false);
    expect(wrapper.find('.il__status .af-mark').classes()).toContain('warn');
    expect(wrapper.text()).toContain('Credential rejected');
    expect(wrapper.text()).not.toContain('Not linked');
  });

  it('explains the rejection and what re-linking restores', () => {
    const wrapper = mountRejected();

    expect(wrapper.find('.il__notice').text()).toBe(
      'Example Docs Service rejected the linked credential. Re-link it to restore the services that use it.',
    );
  });

  it('offers the shared re-link action, not "Link account", and still allows unlinking', () => {
    const wrapper = mountRejected();

    expect(wrapper.find('button.il__btn--link').exists()).toBe(false);
    expect(wrapper.find('button.il__btn--reconnect').text()).toBe(RELINK_ACTION_LABEL.account);
    expect(wrapper.find('button.il__btn--unlink').exists()).toBe(true);
  });

  it('reads an absent rejected flag as false', () => {
    const wrapper = mountRejected({ rejected: undefined });

    expect(wrapper.find('.il__status--rejected').exists()).toBe(false);
    expect(wrapper.find('.il__status--unlinked').exists()).toBe(true);
    expect(wrapper.text()).toContain('Not linked');
    expect(wrapper.find('.il__notice').exists()).toBe(false);
    expect(wrapper.find('button.il__btn--link').text()).toBe(LINK_ACTION_LABEL.account);
  });
});

/**
 * Component test for AdminPage.vue -- the placeholder body of the /admin
 * page. Real admin views replace this placeholder; this test just pins
 * the render until then.
 */
import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import AdminPage from '../AdminPage.vue';

describe('AdminPage', () => {
  it('renders the placeholder content', () => {
    const wrapper = mount(AdminPage);
    expect(wrapper.text()).toContain('Platform administration');
  });
});

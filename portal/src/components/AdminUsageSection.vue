<script setup lang="ts">
/**
 * AdminUsageSection.vue -- the admin page's "Usage across users" panel.
 *
 * A UserPicker (a server-side typeahead over the users the platform has seen
 * -- never a user list); selecting one renders that subject's usage via
 * UsagePage.vue's existing rendering (its `subject` prop), rather than
 * duplicating any of that markup here.
 */
import { ref } from 'vue';
import type { AdminUser } from '../lib/api';
import UsagePage from './UsagePage.vue';
import UserPicker from './UserPicker.vue';

const selectedUser = ref<AdminUser | null>(null);
</script>

<template>
  <section class="af-sect" aria-labelledby="ap-usage-title">
    <h2 id="ap-usage-title">Usage across users</h2>
    <UserPicker v-model="selectedUser" label="User" />

    <!-- Keyed on the selection so switching users remounts UsagePage,
           the same way it already reloads when its own window selector
           changes -- no separate refetch wiring needed here. -->
    <UsagePage v-if="selectedUser" :key="selectedUser.subject" :subject="selectedUser.subject" />
  </section>
</template>

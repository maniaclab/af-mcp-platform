<script setup lang="ts">
/**
 * AdminPage.vue -- placeholder body for the /admin page, reachable only
 * once GET /v1/identities reports `is_admin: true` (gated client-side in
 * Base.astro's nav script -- this is a static build with no per-request
 * server auth state). Real admin views replace this placeholder.
 */
</script>

<template>
  <div class="ap">
    <p class="ap__placeholder">Platform administration tools will appear here.</p>
  </div>
</template>

<style scoped>
.ap__placeholder {
  padding: 3rem 1.5rem;
  text-align: center;
  border: 1px dashed var(--color-af-border);
  border-radius: 4px;
  color: var(--color-af-dim);
  font-size: 0.875rem;
  margin: 0;
}
</style>

<script setup lang="ts">
/**
 * OverlayDemo.vue — the real ConfirmDialog opened by a button, the two-step
 * inline confirm, and an InfoTip: the three ways the portal interrupts or
 * explains. Nothing here is faked; confirming only closes the dialog.
 */
import { ref } from 'vue';
import ArmedConfirmButton from '../ui/ArmedConfirmButton.vue';
import ConfirmDialog from '../ui/ConfirmDialog.vue';
import InfoTip from '../ui/InfoTip.vue';

const dialogOpen = ref(false);
const armed = ref(false);
</script>

<template>
  <div class="design-cols">
    <div class="design-stage">
      <h3 class="design-label">Dialog</h3>
      <div class="design-stage__body">
        <div>
          <button
            type="button"
            class="btn af-danger"
            data-variant="outline"
            @click="dialogOpen = true"
          >
            Revoke token…
          </button>
        </div>
        <p class="af-help">
          This dialog is live: it opens a real native dialog on a scrim, traps focus, starts on
          Cancel and closes with Escape.
        </p>
      </div>
      <ConfirmDialog
        v-model:open="dialogOpen"
        title="Revoke claude-desktop-laptop?"
        confirm-label="Revoke token"
        danger
        @confirm="dialogOpen = false"
      >
        <p>Clients using this token stop working immediately. This cannot be undone.</p>
      </ConfirmDialog>
    </div>
    <div class="design-stage">
      <h3 class="design-label">Two-step inline confirm</h3>
      <div class="design-stage__body">
        <div>
          <ArmedConfirmButton
            v-model:armed="armed"
            label="Unlink"
            armed-label="Confirm unlink"
            busy-label="Unlinking…"
            @confirm="armed = false"
          />
        </div>
        <p class="af-help">For a destructive action too small for a dialog.</p>
      </div>
    </div>
    <div class="design-stage">
      <h3 class="design-label">Tooltip</h3>
      <div class="design-stage__body is-row">
        <span>Expires in 2 days</span>
        <InfoTip
          id="design-tip-expiry"
          text="13 November 2026, 09:14 UTC"
          label="Exact expiry time"
        />
      </div>
    </div>
  </div>
</template>

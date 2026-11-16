<script setup lang="ts">
/**
 * UserPicker.vue — a typeahead that finds a platform user by name, username or
 * email, for the admin views that act on one user (usage, tokens).
 *
 * The portal never loads or renders a user list: each pause in typing sends the
 * text to GET /v1/admin/users, which matches server-side among the users the
 * platform has seen and returns a handful of rows. Built on Basecoat's combobox
 * markup and styles (`.combobox`, `[data-popover]`, `[role=option]`) with Vue
 * driving the behaviour, since Basecoat's own combobox script only filters
 * options already in the page.
 *
 * ARIA combobox pattern: the input owns focus, `aria-activedescendant` names
 * the highlighted option, ArrowUp/ArrowDown move it, Enter selects, Escape
 * closes. The status line under the list (type to search, no matches, refine,
 * still loading, failure) is a live region.
 */
import { computed, onBeforeUnmount, ref, useId, watch } from 'vue';
import { searchAdminUsers } from '../lib/api';
import type { AdminUser } from '../lib/api';
import { errorMessage } from '../lib/apiError';

const SEARCH_DEBOUNCE_MS = 250;
const MAX_MATCHES = 20;

const props = defineProps<{
  label: string;
  modelValue: AdminUser | null;
}>();
const emit = defineEmits<{ 'update:modelValue': [user: AdminUser] }>();

const inputId = useId();
const listboxId = useId();

/** What an operator recognises a user by: name · username, falling back to whichever exists. */
function userLabel(u: AdminUser): string {
  const parts = [u.display_name, u.username].filter((p, i, all) => p && all.indexOf(p) === i);
  return parts.join(' · ') || u.subject;
}

const text = ref(props.modelValue ? userLabel(props.modelValue) : '');
const open = ref(false);
const users = ref<AdminUser[]>([]);
const more = ref(false);
const partial = ref(false);
const searching = ref(false);
const searched = ref(false);
const error = ref<string | null>(null);
const activeIndex = ref(-1);

let timer: ReturnType<typeof setTimeout> | undefined;
// Each search takes a number; a response only lands if no later search started.
let latestSearch = 0;
// Set while the input text is being rewritten to the selected user's label,
// so that rewrite is not mistaken for typing.
let programmaticText = false;

function optionId(index: number): string {
  return `${listboxId}-option-${index}`;
}

const activeDescendant = computed(() =>
  activeIndex.value >= 0 ? optionId(activeIndex.value) : undefined,
);

async function runSearch(query: string): Promise<void> {
  const searchNumber = ++latestSearch;
  searching.value = true;
  try {
    const result = await searchAdminUsers(query, MAX_MATCHES);
    if (searchNumber !== latestSearch) return;
    users.value = result.users;
    more.value = result.more;
    partial.value = result.partial;
    error.value = null;
    activeIndex.value = -1;
  } catch (err) {
    if (searchNumber !== latestSearch) return;
    users.value = [];
    more.value = false;
    partial.value = false;
    error.value = errorMessage(err, 'Search failed.');
  } finally {
    if (searchNumber === latestSearch) {
      searching.value = false;
      searched.value = true;
    }
  }
}

watch(text, (value) => {
  clearTimeout(timer);
  if (programmaticText) {
    programmaticText = false;
    return;
  }
  open.value = true;
  if (value.trim() === '') {
    // Nothing to search for: drop any in-flight search and its results.
    latestSearch++;
    users.value = [];
    searching.value = false;
    searched.value = false;
    error.value = null;
    return;
  }
  timer = setTimeout(() => void runSearch(value.trim()), SEARCH_DEBOUNCE_MS);
});

onBeforeUnmount(() => clearTimeout(timer));

function select(user: AdminUser): void {
  clearTimeout(timer);
  programmaticText = true;
  text.value = userLabel(user);
  open.value = false;
  activeIndex.value = -1;
  emit('update:modelValue', user);
}

function move(step: number): void {
  if (!open.value) {
    open.value = true;
    return;
  }
  if (users.value.length === 0) return;
  activeIndex.value = (activeIndex.value + step + users.value.length) % users.value.length;
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'ArrowDown') {
    event.preventDefault();
    move(1);
  } else if (event.key === 'ArrowUp') {
    event.preventDefault();
    move(-1);
  } else if (event.key === 'Enter' && open.value && activeIndex.value >= 0) {
    event.preventDefault();
    select(users.value[activeIndex.value]);
  } else if (event.key === 'Escape' && open.value) {
    event.preventDefault();
    open.value = false;
  }
}

const status = computed(() => {
  if (error.value) return error.value;
  if (text.value.trim() === '') return 'Type to search by name, username or email.';
  if (searching.value || !searched.value) return 'Searching…';
  if (users.value.length === 0) return 'No users found.';
  return '';
});
</script>

<template>
  <div class="field af-narrow">
    <label :for="inputId">{{ label }}</label>
    <div class="combobox w-full">
      <input
        :id="inputId"
        v-model="text"
        class="input w-full"
        type="text"
        role="combobox"
        autocomplete="off"
        spellcheck="false"
        aria-autocomplete="list"
        :aria-expanded="open ? 'true' : 'false'"
        :aria-controls="users.length > 0 ? listboxId : undefined"
        :aria-activedescendant="activeDescendant"
        @focus="open = true"
        @blur="open = false"
        @keydown="onKeydown"
      />
      <div data-popover :aria-hidden="open ? 'false' : 'true'" @mousedown.prevent>
        <!-- Preventing the default of mousedown keeps focus in the input, whose
             blur would otherwise close the popover before a click lands. -->
        <div
          v-if="users.length > 0"
          :id="listboxId"
          class="up__list"
          role="listbox"
          :aria-label="label"
        >
          <div
            v-for="(u, index) in users"
            :id="optionId(index)"
            :key="u.subject"
            role="option"
            :data-value="u.subject"
            :aria-selected="modelValue?.subject === u.subject ? 'true' : 'false'"
            :class="{ active: index === activeIndex }"
            tabindex="-1"
            @click="select(u)"
            @keydown.enter.prevent="select(u)"
          >
            <span class="up__option">
              <span>{{ u.display_name || u.username || u.subject }}</span>
              <span class="up__meta">{{ [u.username, u.email].filter(Boolean).join(' · ') }}</span>
            </span>
          </div>
        </div>
        <p v-if="more && !error" class="up__status">
          {{ users.length }}+ matches, refine your search.
        </p>
        <p v-if="partial && !error" class="up__status">
          User details are still loading, so some matches may be missing. Search again in a moment.
        </p>
        <p v-if="status" class="up__status" role="status" :class="{ up__error: error }">
          {{ status }}
        </p>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* Basecoat caps the list at 18rem, which leaves the sixth row of two-line
   options cut off with nothing to say it scrolls. A little more height shows
   a half-row of the next option, which does. */
.combobox .up__list[role='listbox'] {
  max-height: 21.5rem;
}
.up__option {
  display: flex;
  flex-direction: column;
  min-width: 0;
  line-height: 1.3;
}
.up__meta {
  color: var(--color-af-text-secondary);
  font-size: var(--text-12);
  overflow: hidden;
  text-overflow: ellipsis;
}
.up__status {
  margin: 0;
  padding: 0.5rem 0.75rem;
  font-size: var(--text-13);
  color: var(--color-af-text-secondary);
}
.up__error {
  color: var(--color-af-bad-text);
}
</style>

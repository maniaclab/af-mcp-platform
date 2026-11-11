/**
 * useLoadState.ts — the loading / session-expired / access-denied / error
 * state every data page needs, classified once. Rendered by AsyncState.vue.
 */
import { ref } from 'vue';
import { AccessDeniedError, SessionExpiredError } from './api';

export function useLoadState() {
  // True from the start so the first paint, before onMounted calls run(),
  // shows the loading row rather than a flash of empty content.
  const loading = ref(true);
  const error = ref<string | null>(null);
  const sessionExpired = ref(false);
  const accessDenied = ref<AccessDeniedError | null>(null);

  /** Await *fn*, classifying a failure; *fallbackMessage* covers a throw that is not an Error. */
  async function run(
    fn: () => Promise<unknown>,
    fallbackMessage = 'Failed to load.',
  ): Promise<void> {
    loading.value = true;
    error.value = null;
    sessionExpired.value = false;
    accessDenied.value = null;
    try {
      await fn();
    } catch (err) {
      if (err instanceof AccessDeniedError) {
        accessDenied.value = err;
      } else if (err instanceof SessionExpiredError) {
        sessionExpired.value = true;
      } else {
        error.value = err instanceof Error ? err.message : fallbackMessage;
      }
    } finally {
      loading.value = false;
    }
  }

  return { loading, error, sessionExpired, accessDenied, run };
}

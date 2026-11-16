/**
 * useAsyncAction.ts — the busy / error / try-catch-finally an action button
 * repeats. The action-flavoured sibling of useLoadState.ts, which covers a
 * page's initial load.
 */
import { ref } from 'vue';

/** *toMessage* turns whatever a failed action threw into the text shown in the UI. */
export function useAsyncAction(toMessage: (err: unknown) => string) {
  const busy = ref(false);
  const error = ref<string | null>(null);

  /** Await *fn*; resolves true on success, false once the failure is in `error`. */
  async function run(fn: () => Promise<void>): Promise<boolean> {
    busy.value = true;
    error.value = null;
    try {
      await fn();
      return true;
    } catch (err) {
      error.value = toMessage(err);
      return false;
    } finally {
      busy.value = false;
    }
  }

  return { busy, error, run };
}

/**
 * clipboard.ts — copy text to the clipboard, shared by CopyField.vue and the
 * Astro pages that copy outside a Vue island.
 */

// The async Clipboard API needs a secure context and a permission grant; the
// textarea + execCommand route still works on plain-http dev hosts and in
// embedded webviews that withhold the permission.
function copyViaTextarea(text: string): boolean {
  if (typeof document.execCommand !== 'function') return false;
  const el = document.createElement('textarea');
  el.value = text;
  // Off-screen rather than display:none, which cannot be selected.
  el.style.position = 'fixed';
  el.style.top = '-1000px';
  el.setAttribute('aria-hidden', 'true');
  document.body.appendChild(el);
  try {
    el.focus();
    el.select();
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    el.remove();
  }
}

/** Copy *text*; resolves true on success and false when every route failed. Never rejects. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return copyViaTextarea(text);
  }
}

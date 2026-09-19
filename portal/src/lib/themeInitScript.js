// themeInitScript.js
//
// The literal source of the anti-flash-of-wrong-theme bootstrap that runs in
// <head>, before any stylesheet, on both Base.astro and PublicBase.astro.
//
// Astro's `is:inline` opts a <script>/<style> tag out of Astro's own
// processing and CSP auto-hashing (the same mechanism as Base.astro's
// auth-splash `<style is:inline>`) -- so both this script's *placement*
// (first thing in <head>) and its *hash* (added to
// security.csp.scriptDirective.hashes in astro.config.mjs) have to be done
// by hand. Keeping the source in one importable constant, rather than pasted
// separately into two layouts, is what lets astro.config.mjs hash it
// directly instead of regex-scanning two files for one literal script each.
//
// Deliberately import-free: an ES module <script> is deferred by browsers,
// which would let the browser start painting with the wrong theme before
// this ran. It has to execute synchronously, in its exact document
// position, before the stylesheet <link> Astro injects -- so it duplicates
// the small resolve-and-apply slice of theme.ts's logic rather than
// importing it. theme.ts (and its tests) own that logic in full; this
// string is the only thing allowed to fork it, and it must stay a literal
// subset of resolveTheme()/applyResolvedTheme().
export const THEME_INIT_SCRIPT = `(function () {
  try {
    var KEY = 'themeMode';
    var stored = localStorage.getItem(KEY);
    var mode = stored === 'dark' || stored === 'light' ? stored : 'auto';
    var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    var resolved = mode === 'auto' ? (prefersDark ? 'dark' : 'light') : mode;
    var root = document.documentElement;
    if (resolved === 'dark') root.classList.add('dark');
    root.style.colorScheme = resolved;
  } catch (e) {
    /* localStorage/matchMedia unavailable (private mode, older browser) --
       fall through to the light default already baked into global.css. */
  }
})();`;

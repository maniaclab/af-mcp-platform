/**
 * particleTracks.ts — the ATLAS event-display particle-track canvas shared
 * by the public landing page's hero (pages/index.astro) and the
 * authenticated Overview page's hero (pages/overview.astro). The two pages
 * used to carry byte-identical copies of this script; see DESIGN.md's
 * "Particle-track canvas" entry for what it's meant to look like.
 *
 * A golden-angle-spaced radial event display: quadratic Bezier curves
 * simulate magnetic curvature, teal/amber/ink palette assignment matches
 * Cherenkov/EM-calorimeter physics. One orchestrated moment; the rest of
 * each page is quiet. `prefers-reduced-motion` renders one static frame
 * instead of animating.
 *
 * Canvas 2D's fillStyle/strokeStyle can't resolve CSS custom properties —
 * `readParticleTrackPalette` reads the resolved values once (and again on
 * every theme change, via the MutationObserver in `initParticleTracks`) so
 * the canvas stays in sync with global.css's --af-canvas-* tokens instead of
 * carrying its own hardcoded copy of the palette.
 */

export interface Track {
  angle: number;
  curvature: number;
  length: number;
  paletteKey: 'a' | 'b' | 'c';
  /** In [0, 1) — composed with the live palette's alphaFloor/alphaSpan at draw time, so a theme change can re-tune brightness without rebuilding track geometry. */
  normalizedAlpha: number;
  lineWidth: number;
  phase: number;
}

export const TRACK_COUNT = 18;

/**
 * Builds the track geometry. Golden-angle spacing produces a naturally
 * spread radial distribution that resembles a real ATLAS event-display
 * cross-section. `random` defaults to `Math.random` and is a seam for
 * deterministic tests.
 */
export function buildTracks(count: number = TRACK_COUNT, random: () => number = Math.random): Track[] {
  const tracks: Track[] = [];
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < count; i++) {
    const angle = i * goldenAngle;
    const curvature = (random() - 0.5) * 0.6;
    const length = 0.2 + random() * 0.45;
    // Mostly teal (Cherenkov) with occasional amber (EM calorimeter) / ink.
    const paletteKey = i % 7 === 0 ? 'b' : i % 11 === 0 ? 'c' : 'a';
    const normalizedAlpha = random();
    const lineWidth = 0.5 + random() * 0.8;
    const phase = random() * Math.PI * 2;
    tracks.push({ angle, curvature, length, paletteKey, normalizedAlpha, lineWidth, phase });
  }
  return tracks;
}

export interface ParticleTrackPalette {
  /** "R G B" channel triplets, ready to interpolate into `rgb(${triplet} / alpha)`. */
  a: string;
  b: string;
  c: string;
  grid: string;
  alphaFloor: number;
  alphaSpan: number;
}

// The dark-mode originals — used as fallbacks if a variable is somehow
// unset, so a missing token degrades to today's known-good look rather than
// drawing transparent/invisible tracks.
const DEFAULT_PALETTE: ParticleTrackPalette = {
  a: '0 212 200',
  b: '245 158 11',
  c: '232 236 240',
  grid: '31 41 55',
  alphaFloor: 0.15,
  alphaSpan: 0.45,
};

export function readParticleTrackPalette(root: HTMLElement = document.documentElement): ParticleTrackPalette {
  const style = getComputedStyle(root);
  const triplet = (name: string, fallback: string) => style.getPropertyValue(name).trim() || fallback;
  const num = (name: string, fallback: number) => {
    const parsed = parseFloat(style.getPropertyValue(name));
    return Number.isNaN(parsed) ? fallback : parsed;
  };
  return {
    a: triplet('--af-canvas-track-a', DEFAULT_PALETTE.a),
    b: triplet('--af-canvas-track-b', DEFAULT_PALETTE.b),
    c: triplet('--af-canvas-track-c', DEFAULT_PALETTE.c),
    grid: triplet('--af-canvas-grid', DEFAULT_PALETTE.grid),
    alphaFloor: num('--af-canvas-alpha-floor', DEFAULT_PALETTE.alphaFloor),
    alphaSpan: num('--af-canvas-alpha-span', DEFAULT_PALETTE.alphaSpan),
  };
}

export interface InitParticleTracksOptions {
  root?: HTMLElement;
  win?: Window;
  random?: () => number;
  trackCount?: number;
}

/**
 * Wires up the canvas: resize handling, the draw loop (or single static
 * frame under reduced motion), and a live palette refresh on theme change.
 * Returns a cleanup function that removes the resize listener, cancels any
 * pending frame, and disconnects the theme observer.
 */
export function initParticleTracks(
  canvas: HTMLCanvasElement,
  options: InitParticleTracksOptions = {},
): () => void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};

  const root = options.root ?? document.documentElement;
  const win = options.win ?? window;
  const tracks = buildTracks(options.trackCount, options.random);
  let palette = readParticleTrackPalette(root);
  let W = 0;
  let H = 0;
  let animId = 0;
  let t = 0;

  function resize() {
    W = canvas.offsetWidth;
    H = canvas.offsetHeight;
    canvas.width = W * win.devicePixelRatio;
    canvas.height = H * win.devicePixelRatio;
    ctx!.scale(win.devicePixelRatio, win.devicePixelRatio);
  }

  function draw() {
    ctx!.clearRect(0, 0, W, H);

    const cx = W * 0.5;
    const cy = H * 0.5;
    const R = Math.min(W, H) * 0.44;

    // Faint vertex point.
    ctx!.beginPath();
    ctx!.arc(cx, cy, 3, 0, Math.PI * 2);
    ctx!.fillStyle = `rgb(${palette.a} / 0.35)`;
    ctx!.fill();

    // Concentric barrel rings — pixel-thin, structural not decorative.
    [0.28, 0.55, 0.82, 1.0].forEach((f) => {
      ctx!.beginPath();
      ctx!.arc(cx, cy, R * f, 0, Math.PI * 2);
      ctx!.strokeStyle = `rgb(${palette.grid} / 0.7)`;
      ctx!.lineWidth = 0.5;
      ctx!.stroke();
    });

    tracks.forEach((tr) => {
      // Gentle oscillation — drifting, not bouncing.
      const drift = Math.sin(t * 0.4 + tr.phase) * 0.015;
      const a = tr.angle + drift;
      const maxR = R * tr.length;

      const x1 = cx;
      const y1 = cy;
      const x2 = cx + Math.cos(a) * maxR;
      const y2 = cy + Math.sin(a) * maxR;

      // Perpendicular offset for curvature control point.
      const mx = (x1 + x2) / 2;
      const my = (y1 + y2) / 2;
      const perp = { x: -(y2 - y1), y: x2 - x1 };
      const plen = Math.sqrt(perp.x ** 2 + perp.y ** 2);
      const cpx = mx + (perp.x / plen) * maxR * tr.curvature;
      const cpy = my + (perp.y / plen) * maxR * tr.curvature;

      ctx!.beginPath();
      ctx!.moveTo(x1, y1);
      ctx!.quadraticCurveTo(cpx, cpy, x2, y2);
      const alpha = palette.alphaFloor + tr.normalizedAlpha * palette.alphaSpan;
      ctx!.strokeStyle = `rgb(${palette[tr.paletteKey]} / ${alpha})`;
      ctx!.lineWidth = tr.lineWidth;
      ctx!.stroke();
    });

    t += 1;
    animId = win.requestAnimationFrame(draw);
  }

  // Respect prefers-reduced-motion: render one static frame, no animation.
  const motionOK = win.matchMedia('(prefers-reduced-motion: no-preference)').matches;

  resize();

  if (motionOK) {
    draw();
  } else {
    t = 60;
    draw();
    win.cancelAnimationFrame(animId);
  }

  const onResize = () => {
    resize();
    if (!motionOK) {
      draw();
      win.cancelAnimationFrame(animId);
    }
  };
  win.addEventListener('resize', onResize);

  // The canvas can't react to a CSS media query for theme, and no custom
  // event exists for "the theme changed" — observing the .dark class
  // attribute directly on `root` is the one signal that's true regardless of
  // what changed it (this toggle, a future Basecoat-shipped control, ...).
  const observer = new MutationObserver(() => {
    palette = readParticleTrackPalette(root);
    // A running rAF loop picks up the reassigned `palette` on its own next
    // frame; only the static reduced-motion frame needs an explicit redraw.
    if (!motionOK) draw();
  });
  observer.observe(root, { attributes: true, attributeFilter: ['class'] });

  return function destroy() {
    win.removeEventListener('resize', onResize);
    win.cancelAnimationFrame(animId);
    observer.disconnect();
  };
}

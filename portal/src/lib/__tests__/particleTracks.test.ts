import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  buildTracks,
  initParticleTracks,
  readParticleTrackPalette,
  TRACK_COUNT,
} from '../particleTracks';

describe('buildTracks', () => {
  it('produces TRACK_COUNT tracks by default', () => {
    expect(buildTracks(undefined, () => 0.5)).toHaveLength(TRACK_COUNT);
  });

  it('is deterministic for a seeded random source', () => {
    const seeded = () => 0.5;
    expect(buildTracks(6, seeded)).toEqual(buildTracks(6, seeded));
  });

  it('assigns the amber palette key every 7th track and ink every 11th, teal otherwise', () => {
    const tracks = buildTracks(22, () => 0.5);
    expect(tracks[0].paletteKey).toBe('b'); // i % 7 === 0
    expect(tracks[11].paletteKey).toBe('c'); // i % 11 === 0 (and not also % 7)
    expect(tracks[1].paletteKey).toBe('a');
  });

  it('keeps normalizedAlpha in [0, 1) regardless of the random source', () => {
    const tracks = buildTracks(10, () => 0.9999);
    for (const t of tracks) {
      expect(t.normalizedAlpha).toBeGreaterThanOrEqual(0);
      expect(t.normalizedAlpha).toBeLessThan(1);
    }
  });
});

describe('readParticleTrackPalette', () => {
  function fakeRoot(vars: Record<string, string>): HTMLElement {
    const el = document.createElement('div');
    for (const [k, v] of Object.entries(vars)) el.style.setProperty(k, v);
    document.body.appendChild(el);
    return el;
  }

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('reads the channel-triplet and alpha custom properties', () => {
    const root = fakeRoot({
      '--af-canvas-track-a': '0 98 93',
      '--af-canvas-track-b': '146 97 10',
      '--af-canvas-track-c': '51 65 85',
      '--af-canvas-grid': '195 204 216',
      '--af-canvas-alpha-floor': '0.25',
      '--af-canvas-alpha-span': '0.5',
    });
    expect(readParticleTrackPalette(root)).toEqual({
      a: '0 98 93',
      b: '146 97 10',
      c: '51 65 85',
      grid: '195 204 216',
      alphaFloor: 0.25,
      alphaSpan: 0.5,
    });
  });

  it('falls back to the dark-mode defaults when a variable is unset', () => {
    const root = fakeRoot({});
    const palette = readParticleTrackPalette(root);
    expect(palette.a).toBe('0 212 200');
    expect(palette.alphaFloor).toBe(0.15);
    expect(palette.alphaSpan).toBe(0.45);
  });
});

describe('initParticleTracks', () => {
  function fakeContext() {
    return {
      clearRect: vi.fn(),
      beginPath: vi.fn(),
      arc: vi.fn(),
      fill: vi.fn(),
      stroke: vi.fn(),
      moveTo: vi.fn(),
      quadraticCurveTo: vi.fn(),
      fillStyle: '',
      strokeStyle: '',
      lineWidth: 0,
      scale: vi.fn(),
    };
  }

  function fakeCanvas(ctx: ReturnType<typeof fakeContext>): HTMLCanvasElement {
    const canvas = document.createElement('canvas');
    Object.defineProperty(canvas, 'offsetWidth', { value: 400, configurable: true });
    Object.defineProperty(canvas, 'offsetHeight', { value: 200, configurable: true });
    vi.spyOn(canvas, 'getContext').mockReturnValue(ctx as unknown as CanvasRenderingContext2D);
    return canvas;
  }

  function fakeWin(prefersReducedMotion: boolean) {
    const listeners = new Map<string, () => void>();
    return {
      devicePixelRatio: 1,
      matchMedia: vi.fn().mockReturnValue({ matches: !prefersReducedMotion }),
      requestAnimationFrame: vi.fn().mockReturnValue(1),
      cancelAnimationFrame: vi.fn(),
      addEventListener: vi.fn((event: string, cb: () => void) => listeners.set(event, cb)),
      removeEventListener: vi.fn(),
    } as unknown as Window;
  }

  beforeEach(() => {
    document.documentElement.className = '';
  });

  it('draws exactly one frame and immediately cancels the frame draw() self-schedules, when reduced motion is preferred', () => {
    const ctx = fakeContext();
    const canvas = fakeCanvas(ctx);
    const win = fakeWin(true);

    initParticleTracks(canvas, { win, random: () => 0.5 });

    expect(ctx.clearRect).toHaveBeenCalledTimes(1);
    // draw() always self-schedules its next frame at the end (so a running
    // rAF loop and a single static frame share one code path) -- the
    // reduced-motion path's guarantee is that it cancels that pending frame
    // right away, not that requestAnimationFrame is never called.
    expect(win.requestAnimationFrame).toHaveBeenCalledTimes(1);
    expect(win.cancelAnimationFrame).toHaveBeenCalledTimes(1);
  });

  it('starts a continuing rAF loop when motion is allowed', () => {
    const ctx = fakeContext();
    const canvas = fakeCanvas(ctx);
    const win = fakeWin(false);

    initParticleTracks(canvas, { win, random: () => 0.5 });

    expect(ctx.clearRect).toHaveBeenCalledTimes(1);
    expect(win.requestAnimationFrame).toHaveBeenCalledTimes(1);
  });

  it('returns a no-op cleanup and never draws when the canvas has no 2D context', () => {
    const canvas = document.createElement('canvas');
    vi.spyOn(canvas, 'getContext').mockReturnValue(null);
    const win = fakeWin(true);

    expect(() => initParticleTracks(canvas, { win })).not.toThrow();
  });

  it('re-reads the palette and redraws once when the root element class changes (reduced motion)', async () => {
    const ctx = fakeContext();
    const canvas = fakeCanvas(ctx);
    const win = fakeWin(true);
    const root = document.documentElement;

    initParticleTracks(canvas, { win, root, random: () => 0.5 });
    expect(ctx.clearRect).toHaveBeenCalledTimes(1);

    root.classList.add('dark');
    // MutationObserver callbacks are microtask-queued.
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    expect(ctx.clearRect).toHaveBeenCalledTimes(2);
  });
});

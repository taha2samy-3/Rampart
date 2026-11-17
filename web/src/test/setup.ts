import '@testing-library/jest-dom/vitest';
import { afterEach, expect } from 'vitest';
import { cleanup, configure } from '@testing-library/react';
import * as matchers from 'vitest-axe/matchers';
import '@/lib/i18n';

expect.extend(matchers);

// The suite runs many jsdom workers at once. A findBy that waits 1 s (the default) and a test that is given 5 s failed on a
// busy machine and passed alone, which teaches people to ignore red. Wait for what the screen needs, not for the load.
configure({ asyncUtilTimeout: 4000 });

afterEach(() => {
  cleanup();
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
});

class RO {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= RO as unknown as typeof ResizeObserver;
if (!window.matchMedia) {
  window.matchMedia = (q: string) =>
    ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, onchange: null, dispatchEvent: () => false }) as MediaQueryList;
}
Element.prototype.scrollIntoView ??= () => {};
Element.prototype.hasPointerCapture ??= () => false;
Element.prototype.releasePointerCapture ??= () => {};
// axe probes canvas for icon ligatures; jsdom has none.
HTMLCanvasElement.prototype.getContext = (() => null) as typeof HTMLCanvasElement.prototype.getContext;
// jsdom has no layout: give elements a size so the row virtualizer renders rows.
Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, get: () => 640 });
Object.defineProperty(HTMLElement.prototype, 'clientWidth', { configurable: true, get: () => 800 });
window.scrollTo = (() => {}) as typeof window.scrollTo;

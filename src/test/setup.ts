import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach, vi } from 'vitest';

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

class IntersectionObserverStub {
  readonly root = null;
  readonly rootMargin = '';
  readonly thresholds = [];
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return [];
  }
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  window.adsbygoogle = [];
  document.getElementById('google-adsense-sdk-script')?.remove();
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('{}', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
  );
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

Object.defineProperty(window, 'ResizeObserver', { writable: true, value: ResizeObserverStub });
Object.defineProperty(window, 'IntersectionObserver', { writable: true, value: IntersectionObserverStub });

window.matchMedia = (query: string) => ({
  matches: false,
  media: query,
  onchange: null,
  addListener: () => {},
  removeListener: () => {},
  addEventListener: () => {},
  removeEventListener: () => {},
  dispatchEvent: () => false,
});

window.scrollTo = () => {};
Element.prototype.scrollIntoView = () => {};
Element.prototype.getBoundingClientRect = () => ({
  x: 0,
  y: 0,
  width: 1024,
  height: 768,
  top: 0,
  left: 0,
  right: 1024,
  bottom: 768,
  toJSON() {
    return {};
  },
});

HTMLCanvasElement.prototype.getContext = (() => ({
  canvas: document.createElement('canvas'),
  fillRect() {},
  clearRect() {},
  getImageData: () => ({ data: new Uint8ClampedArray() }),
  putImageData() {},
  createImageData: () => ({ data: new Uint8ClampedArray() }),
  setTransform() {},
  drawImage() {},
  save() {},
  restore() {},
  beginPath() {},
  moveTo() {},
  lineTo() {},
  closePath() {},
  stroke() {},
  translate() {},
  scale() {},
  rotate() {},
  arc() {},
  fill() {},
  measureText: () => ({ width: 0 }),
  transform() {},
  rect() {},
  clip() {},
  fillText() {},
  strokeText() {},
})) as unknown as typeof HTMLCanvasElement.prototype.getContext;

if (!URL.createObjectURL) {
  URL.createObjectURL = () => 'blob:unit-test';
}
URL.revokeObjectURL = () => {};

Object.defineProperty(navigator, 'clipboard', {
  configurable: true,
  value: {
    writeText: vi.fn(async () => {}),
    readText: vi.fn(async () => ''),
  },
});

if (!globalThis.crypto.randomUUID) {
  Object.defineProperty(globalThis.crypto, 'randomUUID', {
    value: () => '00000000-0000-4000-8000-000000000000',
  });
}

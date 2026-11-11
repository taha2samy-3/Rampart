import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath } from 'node:url';
import { mkdirSync, writeFileSync } from 'node:fs';

// The dev server proxies /api and /auth to the mock server (default) or to a
// real backend: RAMPART_BACKEND=http://localhost:8080 pnpm dev
const backend = process.env.RAMPART_BACKEND ?? 'http://127.0.0.1:8099';

// emptyOutDir wipes dist; dist/.keep must survive so Go's //go:embed all:dist compiles before the first build.
const keepDist = {
  name: 'keep-dist',
  closeBundle() {
    mkdirSync('dist', { recursive: true });
    writeFileSync('dist/.keep', '');
  },
};

export default defineConfig({
  base: '/',
  plugins: [react(), tailwindcss(), keepDist],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: backend, changeOrigin: false },
      '/auth': { target: backend, changeOrigin: false },
      '/__mock': { target: backend, changeOrigin: false },
    },
  },
  preview: {
    port: 4173,
    proxy: {
      '/api': { target: backend },
      '/auth': { target: backend },
      '/__mock': { target: backend },
    },
    headers: { 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'" },
  },
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, target: 'es2022', assetsInlineLimit: 0 },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    include: ['src/**/*.test.{ts,tsx}'],
  },
});

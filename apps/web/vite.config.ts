import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';

const src = fileURLToPath(new URL('./src', import.meta.url));
// A private build names its own page list here (see src/extension.ts). Its
// files live outside this folder, so `svelte` is pinned to this one's copy.
const extension = process.env.DEELPE_EXTENSION_UI;

// The build lands in the server crate and is embedded there (rust-embed).
export default defineConfig({
  plugins: [svelte()],
  resolve: {
    alias: { $extension: extension ?? `${src}/extension.ts`, $web: src },
    dedupe: ['svelte'],
  },
  build: { outDir: '../../crates/deelpe-server/ui-dist', emptyOutDir: true },
  server: { proxy: { '/api': { target: 'https://127.0.0.1:18443', secure: false, changeOrigin: true } } },
});

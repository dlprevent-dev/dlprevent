import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// The build lands in the server crate and is embedded there (rust-embed).
export default defineConfig({
  plugins: [svelte()],
  build: { outDir: '../../crates/deelpe-server/ui-dist', emptyOutDir: true },
  server: { proxy: { '/api': { target: 'https://127.0.0.1:18443', secure: false, changeOrigin: true } } },
});

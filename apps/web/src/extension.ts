import type { Component } from 'svelte';

/** A page that another build of the dashboard adds. The open-source build
 *  adds none; `vite.config.ts` swaps this file for the one named in
 *  `DEELPE_EXTENSION_UI`, whose pages import from here through `$web/...`. */
export type ExtraPage = { path: string; label: string; icon: string; admin: boolean; component: Component };

export const pages: ExtraPage[] = [];

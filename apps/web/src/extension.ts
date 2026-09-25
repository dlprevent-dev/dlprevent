import type { Component } from 'svelte';

/** A page that another build of the dashboard adds. The open-source build
 *  adds none; `vite.config.ts` swaps this file for the one named in
 *  `DEELPE_EXTENSION_UI`, whose pages import from here through `$web/...`. */
export type ExtraPage = { path: string; label: string; icon: string; admin: boolean; component: Component };

export const pages: ExtraPage[] = [];

/** A notice above every page, for administrators (e.g. a license running
 *  out). None here. */
export const banner: Component | null = null;

/** More ways to sign in, below the sign-in form (e.g. single sign-on).
 *  None here. */
export const login: Component | null = null;

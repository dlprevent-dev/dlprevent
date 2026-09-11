import type { User } from './types';

export const session = $state({ user: null as User | null, checked: false });

/** One place for the role question: the UI hides things by it, the server
 *  checks again independently (api.rs, extractor `Admin`). */
export function isAdmin(): boolean {
  return session.user?.role === 'admin';
}
export const toast = $state({ text: '', bad: false, until: 0 });

export function notify(text: string, bad = false) {
  toast.text = text;
  toast.bad = bad;
  toast.until = Date.now() + 3500;
  setTimeout(() => { if (Date.now() >= toast.until) toast.text = ''; }, 3600);
}

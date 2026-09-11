import { onMount } from 'svelte';

/** A page's data: load it, hold the error, refresh on a schedule.
 *
 *  The procedure was written out by hand on eight pages, and the versions had
 *  drifted apart: three of the four polling pages had no `catch` at all, so
 *  after an outage of the central server the skeleton stayed up and every
 *  round left an unhandled promise behind. That was fixed in e669246 — in
 *  three places separately. Here it stands once, and a ninth page inherits it
 *  instead of copying it.
 *
 *  Only `Alerts` used to have the guard against races: if a slower, earlier
 *  response arrives after a newer one, it is discarded instead of
 *  overwriting the fresher list.
 *
 *  Deliberately loads in `onMount` and not on creation: when rendering on the
 *  server there is no `fetch`, and the access test renders every page.
 */
export function resource<T>(fetcher: () => Promise<T>, opts: { poll?: number } = {}) {
  let data = $state<T | undefined>(undefined);
  let error = $state('');
  let loading = $state(true);
  /** Serial number of the request; only the youngest may write. */
  let seq = 0;
  let settle: () => void;
  const first = new Promise<void>((r) => (settle = r));

  async function reload(): Promise<void> {
    const mine = ++seq;
    try {
      const v = await fetcher();
      if (mine !== seq) return;
      data = v;
      error = '';
    } catch (e) {
      if (mine === seq) error = (e as Error).message;
    } finally {
      if (mine === seq) loading = false;
      settle();
    }
  }

  onMount(() => {
    reload();
    if (!opts.poll) return;
    const t = setInterval(reload, opts.poll);
    return () => clearInterval(t);
  });

  return {
    get data() {
      return data;
    },
    get error() {
      return error;
    },
    get loading() {
      return loading;
    },
    /** Resolves as soon as the first round is through — in the error case
     *  too. Anyone who still has to do something after loading (the rules
     *  page picks up a draft) hooks in here instead of calling `load()` a
     *  second time. */
    ready: first,
    reload,
  };
}

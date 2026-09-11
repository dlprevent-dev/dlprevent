import type { Alert } from './types';

export const route = $state({ path: location.pathname });

export function go(path: string) {
  if (path === route.path) return;
  history.pushState({}, '', path);
  route.path = path;
}

window.addEventListener('popstate', () => { route.path = location.pathname; });

/** Origin of an alert: exactly one device or exactly one syslog source. */
export interface AlertOrigin { agent?: string; source?: string; name: string }

/** The origin of an alert row as a filter. The row carries `null` where the
 *  filter carries `undefined` — aligned once here so that a comparison
 *  afterwards works without reservations.
 *
 *  Without an id the name remains: if an agent or a source is deleted, the
 *  foreign key sets the alert's `agent_id`/`source_id` to NULL — the row
 *  deliberately stays, and `origin_name` is then all that still identifies its
 *  origin. Not making it clickable for that reason would mean: after the same
 *  device enrolls again, the filter only catches half the list. */
export function originOf(a: Alert): AlertOrigin {
  return { agent: a.agent_id ?? undefined, source: a.source_id ?? undefined, name: a.origin_name };
}

/** What the target page should prefill when it opens: a rule created from a
 *  share on the agents page, or the alert list narrowed to one device. Cleared
 *  when picked up, so that a later switch to the same page does not tear a
 *  form open again or silently filter. */
export const handoff = $state<{ rule?: { path: string; name: string; agent_id: string }; alerts?: AlertOrigin }>({});

export function takeRuleDraft() {
  const r = handoff.rule;
  handoff.rule = undefined;
  return r;
}

/** Switch to the alerts of one origin — from the agents or the sources page.
 *  If the list is already open, `go` turns back and nobody picks the note up;
 *  it would lie around and silently filter the next visit. So do not leave it
 *  behind in the first place. */
export function showAlertsFor(origin: AlertOrigin) {
  if (route.path === '/alerts') return;
  handoff.alerts = origin;
  go('/alerts');
}

/** The alert a link from the alarm mail points at (`/alerts?alert=<id>`), or
 *  `null`.
 *
 *  The id comes out of a mail and therefore from outside. It is checked as
 *  text, not with `Number`: that one lets `9e9`, `0x10`, ` 5 ` and `1.5` all
 *  through, and `Number('')` is 0. Our mail writes nothing but digits.
 *  `isSafeInteger` then holds the top end — server-side the id is an `i64` and
 *  thus larger than a JavaScript number hits exactly.
 *
 *  The counterpart is the list's `id` filter (`api::alerts::AlertQuery`). The
 *  full-text search would **not** do: it runs LIKE over a line that contains
 *  the id as well, and with `1` it catches the 17 too. */
export function deepLinkAlert(search: string): number | null {
  const raw = new URLSearchParams(search).get('alert') ?? '';
  const id = Number(raw);
  return /^[1-9][0-9]*$/.test(raw) && Number.isSafeInteger(id) ? id : null;
}

export function takeAlertOrigin(): AlertOrigin | null {
  const o = handoff.alerts;
  handoff.alerts = undefined;
  return o ?? null;
}

import { session } from './session.svelte';
import type { Alert, Binary } from './types';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}

/** A body that is already bytes (file upload) passes through unchanged;
 *  everything else becomes JSON. This lives here and not at the call site so
 *  there is no reason to call `fetch` by hand: the `401 -> logged out` line
 *  below exists only at this one place, and an upload that slips past it
 *  leaves the UI looking signed in after the session has expired. */
function isBytes(b: unknown): b is Blob | ArrayBuffer | ArrayBufferView {
  return b instanceof Blob || b instanceof ArrayBuffer || ArrayBuffer.isView(b);
}

export async function api<T>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const bytes = isBytes(opts.body);
  const r = await fetch(path, {
    method: opts.method ?? 'GET',
    headers: opts.body === undefined ? {} : { 'content-type': bytes ? 'application/octet-stream' : 'application/json' },
    body: opts.body === undefined ? undefined : bytes ? (opts.body as BodyInit) : JSON.stringify(opts.body),
    credentials: 'same-origin',
  });
  if (r.status === 204) return undefined as T;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401) session.user = null;
    throw new ApiError(r.status, (data as { error?: string }).error ?? r.statusText);
  }
  return data as T;
}

/** Passkeys: the API speaks JSON, the browser wants binary fields. Every
 *  current browser brings the converters for that along itself; an old one
 *  does not have them, and then the button is not offered at all. */
export const passkeysSupported = typeof PublicKeyCredential !== 'undefined' && 'parseCreationOptionsFromJSON' in PublicKeyCredential;

export async function passkeyCreate(options: { publicKey: PublicKeyCredentialCreationOptionsJSON }): Promise<unknown> {
  const cred = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey) });
  if (!cred) throw new Error('No passkey was created.');
  return (cred as PublicKeyCredential).toJSON();
}

export async function passkeyGet(options: { publicKey: PublicKeyCredentialRequestOptionsJSON }): Promise<unknown> {
  const cred = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey) });
  if (!cred) throw new Error('No passkey was used.');
  return (cred as PublicKeyCredential).toJSON();
}

/** The browser reports a cancel as an exception; for the human it is none. */
export function passkeyError(e: unknown): string {
  if (e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError')) return 'No passkey was used.';
  return (e as Error).message;
}

export function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = b / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

/** Time zone of the display. Comes from the server (`/api/me`, setting
 *  `report_timezone`) and applies to everyone looking at the same dashboard.
 *
 *  Until 2026-09-09 the UI silently took the browser's zone. That is right as
 *  long as the viewer's clock is right — and unprovable as soon as two people
 *  see the same alert with different times on it. Empty means: the browser's
 *  zone after all, so that something is there before signing in. */
let displayTz: string | undefined;

export function setDisplayTz(tz: string | undefined | null): void {
  // An unknown name would make every `toLocaleString` throw and leave the
  // page empty. Better the browser's zone than a blank page.
  if (!tz) { displayTz = undefined; return; }
  try { new Date().toLocaleString('en-GB', { timeZone: tz }); displayTz = tz; }
  catch { displayTz = undefined; }
}

export function fmtTime(s: string | null | undefined): string {
  if (!s) return '–';
  const d = new Date(s);
  // Day first and the month as a word: depending on where you are from,
  // 06/09 is 6 September or 9 June, and that must not happen in a record.
  return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: displayTz });
}

/** Short name of the browser's time zone, e.g. "CEST". Sits in the header of
 *  the time columns: a bare clock time does not show whether it means local
 *  time or UTC, and a record that is two hours off is worthless. */
export function tzName(): string {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZoneName: 'short', timeZone: displayTz }).formatToParts(new Date());
  return parts.find((p) => p.type === 'timeZoneName')?.value ?? 'local time';
}

/** The same time in UTC, as evidence in the tooltip next to local time. */
export function fmtUtc(s: string | null | undefined): string {
  if (!s) return '–';
  const d = new Date(s);
  return `${d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' })} UTC`;
}

export function ago(s: string | null | undefined): string {
  if (!s) return 'never';
  const sec = Math.max(0, (Date.now() - new Date(s).getTime()) / 1000);
  if (sec < 60) return `${Math.round(sec)} s ago`;
  if (sec < 3600) return `${Math.round(sec / 60)} min ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)} h ago`;
  return `${Math.round(sec / 86400)} d ago`;
}

/** This many days before expiry an agent renews its certificate on its own
 *  (`deelpe_core::net::RENEW_BEFORE_DAYS`). Inside that window a certificate
 *  that is still the old one is therefore no cause for concern — only a
 *  device that never checks in during that time really does expire. */
export const CERT_RENEW_DAYS = 30;

/** State of an agent certificate. `expired` means: the agent no longer gets
 *  in, not even to renew — only a fresh enrollment helps there. */
export function certState(notAfter: string): 'ok' | 'due' | 'expired' {
  const days = (new Date(notAfter).getTime() - Date.now()) / 86400000;
  if (days <= 0) return 'expired';
  return days <= CERT_RENEW_DAYS ? 'due' : 'ok';
}

/** Which binary belongs to a role. Workstation and file server share the
 *  same EXE on Windows. The same mapping as `binaries::platform_for` on the
 *  server. */
export function platformFor(kind: string | undefined): 'windows' | 'mac' {
  return kind === 'windows_server' || kind === 'windows_client' ? 'windows' : 'mac';
}

/** Roles whose running binary can be compared against the uploaded one. The
 *  same question as `binaries::self_replacing_platform` on the server, and it
 *  has to give the same answer: the macOS service reports the fingerprint of
 *  its executable, but what is staged is the zip around the bundle — the one
 *  checksum can never be the start of the other. Compare them here and every
 *  Mac gets labelled "outdated" forever. */
export function selfReplacing(kind: string | undefined): boolean {
  return kind === 'windows_server' || kind === 'windows_client';
}

/** Is this agent running a different binary from the one staged in the
 *  dashboard?
 *
 *  What gets compared is the file, not the version number: `build` is the
 *  first twelve digits of the SHA-256 of the running file, `sha256` the full
 *  checksum of the uploaded one. The server asks the same question in
 *  `update_due` before it orders an update — here it is merely displayed,
 *  even when rollout is switched off. */
export function agentOutdated(agent: { kind: string; status: { build?: string } | null }, binaries: Binary[]): boolean {
  if (!selfReplacing(agent.kind)) return false;
  const build = agent.status?.build;
  if (!build || build.length < 12) return false;
  const bin = binaries.find((b) => b.platform === platformFor(agent.kind));
  if (!bin?.present || bin.sha256.length !== 64) return false;
  return !bin.sha256.toLowerCase().startsWith(build.toLowerCase());
}

/** This long an order may stay open without meaning anything. A check-in
 *  takes 30 seconds out of the box, plus the time to download the binary. */
export const UPDATE_GRACE_MS = 90_000;

/** An update order the agent has **seen and not carried out**.
 *
 *  The server clears the marker as soon as the agent runs the staged binary.
 *  If it is still there although the agent has long since checked in, then
 *  the order reached it and was left lying there.
 *
 *  The most common reason is the most boring one: the agent runs a build from
 *  **before** self-replacement and does not know the field. That one build
 *  has to go onto the devices by hand — after that it works from here.
 *  Without this indicator it would say "Update sent" forever and nobody
 *  would know what they were waiting for. */
export function updateStuck(agent: { update_requested: string | null; last_seen: string | null }): boolean {
  if (!agent.update_requested || !agent.last_seen) return false;
  return new Date(agent.last_seen).getTime() - new Date(agent.update_requested).getTime() > UPDATE_GRACE_MS;
}

/** Verdicts in the order they should appear in the filter: first what
 *  intervenes, then what stands out, last what merely tags along. */
export const VERDICTS = ['denied', 'hard_limit', 'deviation', 'inbound', 'flagged', 'new', 'no_profile', 'known', 'learning'] as const;

export function isAlarm(verdict: string): boolean {
  return verdict === 'denied' || verdict === 'hard_limit' || verdict === 'deviation';
}

export function verdictClass(v: string): string {
  if (isAlarm(v)) return 'bad';
  switch (v) {
    case 'flagged': case 'new': case 'no_profile': return 'warn';
    case 'learning': return '';
    default: return 'accent';
  }
}

/** What actually happened to the alert — not what its verdict is called.
 *  `Denied` reads like "fended off"; in truth it is the rating of the
 *  destination, and whether anything was done about it is decided separately
 *  by `enforce::action_for`. Whoever looks at the row should see both and not
 *  take the one for the other.
 *
 *  What is read is the note the agent appends after the reason
 *  (`pipeline::note`). It has a fixed, small vocabulary; everything else
 *  means "reported only". The sentences about the stopped process are still
 *  in old rows — the intervention itself has been gone since 6240af9. */
export interface Intervention {
  label: string;
  /** Class of the badge; empty means unremarkable. */
  tone: 'ok' | 'warn' | 'bad' | '';
}

export function interventionOf(a: Alert): Intervention | null {
  // Only where an intervention was on the table at all: the file server's
  // access alerts do not count, they never intervene, and neither does a
  // harmless verdict.
  if (a.kind !== 'endpoint' || !isAlarm(a.verdict)) return null;
  const r = a.reason ?? '';
  if (r.includes('copy deleted')) return { label: 'copy deleted', tone: 'ok' };
  if (r.includes('deletion pending')) return { label: 'deletion pending', tone: 'warn' };
  if (r.includes('copy NOT deleted')) return { label: 'copy not deleted', tone: 'bad' };
  if (r.includes('sender stopped')) return { label: 'sender stopped', tone: 'ok' };
  return { label: 'reported only', tone: '' };
}

export function verdictLabel(v: string): string {
  const m: Record<string, string> = {
    denied: 'Denied', hard_limit: 'Hard limit', deviation: 'Deviation', new: 'New', flagged: 'Flagged', learning: 'Learning',
    known: 'Known', no_profile: 'No profile', ok: 'OK', inbound: 'Arrived',
  };
  return m[v] ?? v;
}

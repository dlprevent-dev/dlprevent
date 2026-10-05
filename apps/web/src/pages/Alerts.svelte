<script lang="ts">
  import { onMount } from 'svelte';
  import { api, fmtBytes, fmtTime, fmtUtc, interventionOf, tzName, verdictClass, verdictLabel, VERDICTS, isAlarm } from '../lib/api';
  import { notify, isAdmin } from '../lib/session.svelte';
  import { createSort } from '../lib/sort.svelte';
  import { chainOf } from '../lib/chain';
  import { deepLinkAlert, originOf, takeAlertOrigin, type AlertOrigin } from '../lib/router.svelte';
  import type { Alert, Insight, Reputation, ReputationView, Settings } from '../lib/types';
  import Icon from '../lib/Icon.svelte';
  import PageHead from '../lib/PageHead.svelte';
  import SearchBox from '../lib/SearchBox.svelte';
  import SortHeader from '../lib/SortHeader.svelte';
  import { ask } from '../lib/confirm.svelte';

  let { onchange }: { onchange: () => void } = $props();
  const PAGE = 100;
  let rows = $state<Alert[]>([]);
  let category = $state<'alerts' | 'notices'>('alerts');
  let loadId = 0;
  const verdicts = $derived(VERDICTS.filter((v) => isAlarm(v) === (category === 'alerts')));
  // From the link in an alarm mail: exactly this one alert. The server
  // filters on it (`id`), not the full-text search — with `1` that one
  // catches the 17 too. When such a link is in effect, the state is "All":
  // whoever opens a mail from yesterday wants to see the alert even if
  // somebody has ticked it off since. Otherwise it would say "Nothing
  // found".
  let only = $state<number | null>(deepLinkAlert(location.search));
  let status = $state<'open' | 'done' | 'all'>(only === null ? 'open' : 'all');
  let q = $state('');
  let verdict = $state('');
  let kind = $state('');
  // Reputation of the destination address. Filtering happens on the server,
  // not in `reps`: the reputation lives in a table of its own, and a filter
  // over the 100 loaded rows would be a different one from what the paging
  // and "close all" mean.
  let rep = $state('');
  // How far back to look, in hours; 0 is "any time". Filtering happens on
  // the server, over the same timestamp the list sorts by — a repeating
  // alert from last month that came back an hour ago belongs in "last 24
  // hours", otherwise the newest rows would drop out of their own window.
  let hours = $state(0);
  const RANGES: [number, string][] = [[0, 'Any time'], [1, 'Last hour'], [24, 'Last 24 hours'], [24 * 7, 'Last 7 days'], [24 * 30, 'Last 30 days']];
  // How many entries the filter matches, not just how many are loaded. The
  // list fetches a page at a time and can only ever say "100+" by itself —
  // and "close all matching" is irreversible, so the number is what makes it
  // a decision instead of a leap. `null` means the count did not arrive.
  let total = $state<number | null>(null);
  /// The server stops counting at a cap: past it "more than ten thousand" is
  /// the same decision, and the count runs on every refresh.
  let capped = $state(false);
  // Narrowed to one origin: set by a click on the source column or when
  // arriving from the agents or sources page.
  let origin = $state<AlertOrigin | null>(takeAlertOrigin());
  let expanded = $state<number | null>(null);
  let more = $state(false);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');
  // Ticked rows. They survive a reload as long as the row is still there:
  // otherwise a refresh would lose the selection.
  let picked = $state<Set<number>>(new Set());
  // For range selection with the shift key.
  let anchor: number | null = null;
  let learnPush = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const admin = $derived(isAdmin());
  // Sorting happens in the database: the table has more rows than the page
  // holds.
  const sort = createSort('id', { asc: false, descFirst: true, onchange: () => load() });
  const filtered = $derived(q.trim() !== '' || verdict !== '' || kind !== '' || rep !== '' || hours !== 0 || origin !== null || only !== null || status !== 'open');

  function params(offset: number) {
    const p = new URLSearchParams({ category, limit: String(PAGE), sort: sort.key, dir: sort.asc ? 'asc' : 'desc' });
    if (status !== 'all') p.set('open', status === 'open' ? 'true' : 'false');
    if (only !== null) p.set('id', String(only));
    if (q.trim()) p.set('q', q.trim());
    if (verdict) p.set('verdict', verdict);
    if (kind) p.set('kind', kind);
    if (rep) p.set('rep', rep);
    if (hours) p.set('hours', String(hours));
    if (origin?.agent) p.set('agent', origin.agent);
    if (origin?.source) p.set('source', origin.source);
    if (origin && !origin.agent && !origin.source) p.set('origin', origin.name);
    if (offset) p.set('offset', String(offset));
    return p;
  }

  async function load(append = false) {
    const requestId = ++loadId;
    busy = true;
    // The old filter's count must not stand while the new one is on its way.
    // The list answers faster than the count, and „close all matching" goes
    // live again the moment it does — with the previous number in the
    // dialog, on an action that cannot be undone. No number is the safe
    // state: the dialog then says „every open one matching", which is true.
    if (!append) total = null;
    try {
      const r = await api<Alert[]>('/api/alerts?' + params(append ? rows.length : 0));
      // A slow response from the previous category must not replace this list.
      if (requestId !== loadId) return;
      // When loading more, the offset counts; if an alert comes in
      // meanwhile, the window slides and a row would appear twice.
      const seen = append ? new Set(rows.map((a) => a.id)) : new Set<number>();
      rows = append ? [...rows, ...r.filter((a) => !seen.has(a.id))] : r;
      // What is no longer there cannot be ticked any more either.
      const here = new Set(rows.filter((a) => !a.acknowledged_at).map((a) => a.id));
      picked = new Set([...picked].filter((id) => here.has(id)));
      more = r.length === PAGE;
      error = '';
      loadReps();
      // Only for the list itself: "load more" does not change what the
      // filter matches, and the count must not be asked for a second time
      // on every page.
      if (!append) countMatching(requestId);
    } catch (e) { if (requestId === loadId) error = (e as Error).message; }
    finally { if (requestId === loadId) { loading = false; busy = false; } }
  }

  /** How many entries the filter matches. A count of its own, and not part
   *  of the list response: it costs a second query, and the list is
   *  refreshed every 20 seconds while nobody is searching. A failed count
   *  leaves the list standing — it is a number, not the evidence. */
  async function countMatching(requestId: number) {
    try {
      const r = await api<{ total: number; capped: boolean }>('/api/alerts/count?' + params(0));
      if (requestId === loadId) { total = r.total; capped = r.capped; }
    } catch { if (requestId === loadId) total = null; }
  }

  // ---------- IP reputation (AbuseIPDB) ----------
  // The alert list does not carry the reputation itself: `remote` is
  // sometimes an address, sometimes a storage device, and a JOIN per row
  // would be more expensive than one query for the 100 rows on screen.
  let reps = $state<Record<string, Reputation>>({});
  let repActive = $state(false);
  /** `1.2.3.4:443` becomes `1.2.3.4`; anything without an address drops out.
   *  The IPv6 form demands a colon, otherwise a word made purely of hex
   *  digits ("cafe") would already pass for an address. */
  function ipOf(remote: string | null): string | null {
    if (!remote) return null;
    const m = remote.match(/^\[([0-9a-fA-F:]+)\](?::\d+)?$/) ?? remote.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/) ?? remote.match(/^([0-9a-fA-F]*:[0-9a-fA-F:]*)$/);
    return m ? m[1] : null;
  }
  async function loadReps() {
    const ips = [...new Set(rows.map((a) => ipOf(a.remote)).filter((x): x is string => !!x))];
    if (!ips.length) return;
    try {
      const r = await api<ReputationView>('/api/reputation?ips=' + encodeURIComponent(ips.join(',')));
      repActive = r.active;
      reps = { ...reps, ...Object.fromEntries(r.items.map((i) => [i.ip, i])) };
    } catch { /* the reputation is a trimming; the list stands without it */ }
  }
  const repOf = (a: Alert) => { const ip = ipOf(a.remote); return ip ? reps[ip] : undefined; };
  /// Where the data went, in plain words. A bare address does not answer the
  /// first question anyone has in front of the list. Domain before operator:
  /// `google.com` says more than `Google LLC`, and both are already in the
  /// reputation lookup — it was just only shown on expanding until now.
  const destOf = (a: Alert) => { const r = repOf(a); return r?.domain || r?.isp || null; };
  /** Thresholds as in the AbuseIPDB docs: from 25 suspicious, from 75 malicious. */
  function repClass(r: Reputation) { return r.is_whitelisted || r.score < 25 ? 'ok' : r.score < 75 ? 'warn' : 'bad'; }

  async function recheck(a: Alert, e: Event) {
    e.stopPropagation();
    const ip = ipOf(a.remote);
    if (!ip) return;
    try { const r = await api<Reputation>(`/api/reputation/${ip}`, { method: 'POST' }); reps = { ...reps, [ip]: r }; notify(`${ip}: ${r.score}%`); }
    catch (err) { notify((err as Error).message, true); }
  }

  // ---------- AI explanation ----------
  // Fetched only on expanding: the fewest of rows have an explanation, and a
  // hundred queries for one page would cost more than they are worth.
  // `undefined` means "not asked yet", `null` "there is none" — otherwise the
  // page would ask afresh on every expand.
  let insights = $state<Record<number, Insight | null>>({});
  let explaining = $state<number | null>(null);
  let assistOn = $state(false);

  async function loadInsight(id: number) {
    // Only an answer is remembered. An error leaves the entry `undefined`,
    // so that the next expand tries again — otherwise one hiccup of the
    // server would leave "no explanation" standing on one that exists, until
    // the page is reloaded.
    try { insights = { ...insights, [id]: await api<Insight | null>(`/api/alerts/${id}/explain`) }; }
    catch { /* try again on the next expand */ }
  }

  function expand(id: number) {
    expanded = expanded === id ? null : id;
    // Administrators only: the dossier carries lines from the agent log, and
    // the central server gives that to nobody else either
    // (`/api/agents/{id}/log`).
    if (admin && expanded !== null && insights[expanded] === undefined) loadInsight(expanded);
  }

  /** Asks the model. With a local model and no graphics card this takes a
   *  good minute — hence the interim text, not just a greyed-out button. */
  async function explain(a: Alert, e: Event) {
    e.stopPropagation();
    explaining = a.id;
    try { insights = { ...insights, [a.id]: await api<Insight>(`/api/alerts/${a.id}/explain`, { method: 'POST' }) }; }
    catch (err) { notify((err as Error).message, true); }
    finally { explaining = null; }
  }

  function changeCategory(next: typeof category) {
    if (category === next) return;
    clearTimeout(timer);
    // Whoever switches the drawer wants the list, not the one row from the
    // mail link any more.
    only = null;
    category = next;
    verdict = '';
    rows = [];
    // The old drawer's count must not stand over the new drawer's empty
    // list for the moment the request takes.
    total = null;
    picked = new Set();
    anchor = null;
    expanded = null;
    more = false;
    loading = true;
    load();
  }

  /** Typing should not send every keystroke to the server. */
  function debounced() { clearTimeout(timer); timer = setTimeout(() => load(), 250); }

  const openRows = $derived(rows.filter((a) => !a.acknowledged_at));
  const allPicked = $derived(openRows.length > 0 && openRows.every((a) => picked.has(a.id)));

  function toggle(a: Alert, e: MouseEvent) {
    const next = new Set(picked);
    const ids = e.shiftKey && anchor !== null ? range(anchor, a.id) : [a.id];
    // The range follows the anchor: ticking or unticking goes by what
    // happens to the clicked row.
    const on = !picked.has(a.id);
    for (const id of ids) (on ? next.add(id) : next.delete(id));
    picked = next;
    anchor = a.id;
  }

  /** All open rows between two ids, in the order of the table. */
  function range(from: number, to: number): number[] {
    const ids = openRows.map((a) => a.id);
    const i = ids.indexOf(from), j = ids.indexOf(to);
    if (i < 0 || j < 0) return [to];
    return ids.slice(Math.min(i, j), Math.max(i, j) + 1);
  }

  function toggleAll() {
    picked = allPicked ? new Set() : new Set(openRows.map((a) => a.id));
    anchor = null;
  }

  async function ackPicked() {
    const ids = [...picked];
    if (!ids.length) return;
    busy = true;
    try {
      const r = await api<{ acked: number }>('/api/alerts/ack', { method: 'POST', body: { ids } });
      notify(`${r.acked} entries marked done`);
      picked = new Set();
      onchange();
      load();
    } catch (err) { notify((err as Error).message, true); } finally { busy = false; }
  }

  /** Close everything that matches the filter — not just what is loaded.
   *  With thousands of open alerts, ticking page by page is not an interface.
   *
   *  The body carries every filter on screen — **except** the id from a mail
   *  link, which the bulk body does not know. That is why the button is not
   *  there at all while the list is narrowed to one row: "all matching" would
   *  otherwise be every open one in the category while a single one is on
   *  screen. That one is closed by its own tick. */
  async function ackAll() {
    if (!(await ask({
      title: 'Close all matching',
      body: total === null
        ? `Every open ${category.slice(0, -1)} that matches the filter in effect is marked done.`
        : `${capped ? 'More than ' : ''}${total} open ${total === 1 && !capped ? category.slice(0, -1) : category} matching the filter in effect ${total === 1 && !capped ? 'is' : 'are'} marked done.`,
      detail: 'Not just the page you can see. This cannot be undone.',
      confirmLabel: 'Close all',
      danger: true,
    }))) return;
    busy = true;
    try {
      const r = await api<{ acked: number }>('/api/alerts/ack', {
        method: 'POST',
        body: { all: true, category, q: q.trim() || null, verdict: verdict || null, kind: kind || null, rep: rep || null, hours: hours || null, agent: origin?.agent ?? null, source: origin?.source ?? null, origin: origin && !origin.agent && !origin.source ? origin.name : null },
      });
      notify(`${r.acked} entries marked done`);
      picked = new Set();
      onchange();
      load();
    } catch (err) { notify((err as Error).message, true); } finally { busy = false; }
  }

  /** "Remember pair": the agent silences this process and destination.
   *  Without it the same unknown pair comes back as a new alert on every
   *  flow. */
  async function learn(a: Alert, action: 'remember' | 'flag', e: Event) {
    e.stopPropagation();
    const what = action === 'remember' ? 'silent from now on' : 'always reported';
    try {
      const r = await api<{ acked: number }>(`/api/alerts/${a.id}/learn`, { method: 'POST', body: { action } });
      notify(`${a.process ?? 'pair'} → ${a.remote ?? '–'}: ${what} (${r.acked} alerts closed)`);
      onchange();
      load();
    } catch (err) { notify((err as Error).message, true); }
  }

  onMount(() => {
    // Arrived from an alarm mail: the alert then sits there expanded,
    // instead of collapsed in a list of one.
    const linked = only;
    load().then(() => { if (linked !== null && rows.some((a) => a.id === linked)) expand(linked); });
    // Take the id out of the address as soon as it has been read: otherwise
    // `?alert=…` would still be there after "clear filters" and a reload
    // would silently bring the filter back.
    if (linked !== null) history.replaceState({}, '', location.pathname);
    // The silencing button hangs on a switch in the settings; without it the
    // server hands out no instructions.
    if (admin) api<Settings>('/api/settings').then((x) => { learnPush = x.learn_push_enabled; assistOn = x.assist_enabled; }).catch(() => {});
    // Refresh only while nobody is searching or paging right now.
    const t = setInterval(() => { if (!q && rows.length <= PAGE) load(); }, 20000);
    return () => { clearInterval(t); clearTimeout(timer); };
  });

  async function ack(a: Alert, e: Event) {
    e.stopPropagation();
    try {
      await api(`/api/alerts/${a.id}/ack`, { method: 'POST' });
      notify(`Alert #${a.id} marked done`);
      onchange();
      load();
    } catch (err) { notify((err as Error).message, true); }
  }

  function reset() { q = ''; verdict = ''; kind = ''; rep = ''; hours = 0; origin = null; only = null; status = 'open'; picked = new Set(); load(); }

  /** Click on the source column: only this device or this source any more.
   *  A second click on the same origin lifts the restriction again. The name
   *  belongs in the comparison: two origins without an id would otherwise be
   *  the same one, and a click on the second would merely lift the first. */
  function filterOrigin(a: Alert, e: Event) {
    e.stopPropagation();
    const o = originOf(a);
    origin = origin?.agent === o.agent && origin?.source === o.source && origin?.name === o.name ? null : o;
    load();
  }

  const cols: [string, string, boolean][] = [
    ['id', '#', false], ['at', `Time (${tzName()})`, false], ['origin', 'Source', false], ['who', 'Who / process', false],
    ['path', 'Folder / target', false], ['files', 'Files', true], ['bytes', 'Volume', true], ['verdict', 'Verdict', false], ['status', 'State', false],
  ];
</script>

<PageHead title="Alerts and notices" />

<div class="toolbar">
  <div class="seg" role="group" aria-label="Category">
    <button class:on={category === 'alerts'} aria-pressed={category === 'alerts'} onclick={() => changeCategory('alerts')}>Alerts</button>
    <button class:on={category === 'notices'} aria-pressed={category === 'notices'} onclick={() => changeCategory('notices')}>Notices</button>
  </div>
  <div class="seg" role="group" aria-label="State">
    {#each [['open', 'Open'], ['done', 'Done'], ['all', 'All']] as [v, l]}
      <button class:on={status === v} onclick={() => { status = v as typeof status; load(); }}>{l}</button>
    {/each}
  </div>
  <SearchBox bind:value={q} placeholder="User, process, folder, target, file name…" oninput={debounced} />
  <select bind:value={verdict} onchange={() => load()} aria-label="Verdict">
    <option value="">Any verdict</option>
    {#each verdicts as v}<option value={v}>{verdictLabel(v)}</option>{/each}
  </select>
  <select bind:value={kind} onchange={() => load()} aria-label="Kind">
    <option value="">Endpoint and access</option>
    <option value="endpoint">Endpoint</option>
    <option value="access">Access</option>
  </select>
  <select bind:value={rep} onchange={() => load()} aria-label="Reputation"
    title="Reputation of the destination address (AbuseIPDB), from the central server's cache">
    <option value="">Any reputation</option>
    <option value="bad">Malicious (75%+)</option>
    <option value="warn">Suspicious (25%+)</option>
    <option value="ok">Clean</option>
    <option value="none">Not checked</option>
  </select>
  <select bind:value={hours} onchange={() => load()} aria-label="Time range"
    title="Counted from when an entry was last seen, so a repeating alert that came back an hour ago stays in the short windows">
    {#each RANGES as [h, l]}<option value={h}>{l}</option>{/each}
  </select>
  {#if origin}
    <span class="badge accent">
      {origin.agent ? 'Agent' : origin.source ? 'Source' : 'Origin'}: {origin.name}
      <button class="iconbtn" onclick={() => { origin = null; load(); }} title="Show every source" aria-label="Remove source filter"><Icon name="x" size={12} /></button>
    </span>
  {/if}
  <!-- The narrowing from a mail link carries the same badge as the origin.
       Without it it would be invisible: the id is taken out of the address on
       arrival, and whoever then types something into the search would get
       "Nothing found" without seeing why. -->
  {#if only !== null}
    <span class="badge accent">
      From email: alert #{only}
      <button class="iconbtn" onclick={() => { only = null; load(); }} title="Show every alert again" aria-label="Remove the filter from the email link"><Icon name="x" size={12} /></button>
    </span>
  {/if}
  {#if filtered}<button class="btn ghost sm" onclick={reset}><Icon name="x" size={14} /> Clear filters</button>{/if}
  <span class="spacer"></span>
  {#if admin && picked.size > 0}
    <span class="badge accent">{picked.size} selected</span>
    <button class="btn sm" onclick={ackPicked} disabled={busy}><Icon name="check" size={14} /> Mark done</button>
    <button class="btn ghost sm" onclick={() => (picked = new Set())}>Clear selection</button>
  {:else if admin && status === 'open' && only === null && rows.length > 0}
    <button class="btn ghost sm" onclick={ackAll} disabled={busy} title="Closes every open entry in this category matching the current filter, not just the loaded page">
      <Icon name="check" size={14} /> Close all {filtered ? 'matching' : 'open'}
    </button>
  {/if}
  <!-- What is loaded, and what the filter matches. Without the second
       number the list could only ever say "100+", and "close all matching"
       would be a leap. -->
  <span class="muted small">{total === null ? `${rows.length}${more ? '+' : ''} entries` : capped || total > rows.length ? `${rows.length} of ${total}${capped ? '+' : ''} entries` : `${total} ${total === 1 ? 'entry' : 'entries'}`}</span>
  <button class="iconbtn" onclick={() => load()} title="Reload" aria-label="Reload" disabled={busy}><Icon name="refresh" /></button>
</div>

{#if error}<p class="error">{error}</p>{/if}

<div class="card">
  {#if loading}
    <div style="padding:16px" class="stack">{#each Array(6) as _}<div class="skel"></div>{/each}</div>
  {:else if rows.length === 0}
    <div class="empty">
      <span class="ico"><Icon name={filtered ? 'search' : 'ok'} size={26} /></span>
      <b>{filtered ? 'Nothing found' : `No open ${category}`}</b>
      <span>{filtered ? 'Try other words or clear the filters.' : category === 'alerts' ? 'No hard limits or deviations. Other observations are listed under Notices.' : 'No open notices. Hard limits and deviations are listed under Alerts.'}</span>
      {#if filtered}<button class="btn sm" onclick={reset}>Clear filters</button>{/if}
    </div>
  {:else}
  <div class="tablewrap">
    <table>
      <thead><tr>
        {#if admin}
          <th class="pick"><input type="checkbox" checked={allPicked} onchange={toggleAll} disabled={openRows.length === 0}
            title="Select every open alert on this page" aria-label="Select every open alert on this page" /></th>
        {/if}
        {#each cols as [key, label, num]}<SortHeader {sort} {key} {label} {num} />{/each}
        <SortHeader {sort} key="reputation" label="Reputation" />
        <th><span class="th"></span></th>
      </tr></thead>
      <tbody>
        {#each rows as a (a.id)}
          <!-- What actually happened stands next to the verdict: "Denied"
               rates the destination, it does not mean that anything was
               fended off. -->
          {@const iv = interventionOf(a)}
          <tr class="click" class:open={expanded === a.id} class:picked={picked.has(a.id)} onclick={() => expand(a.id)}>
            {#if admin}
              <!-- A click on the checkbox does not expand the row. -->
              <td class="pick" onclick={(e) => e.stopPropagation()}>
                {#if !a.acknowledged_at}
                  <input type="checkbox" checked={picked.has(a.id)} onclick={(e) => toggle(a, e)}
                    aria-label="Select alert {a.id}" title="Shift-click selects a range" />
                {/if}
              </td>
            {/if}
            <td class="muted mono">{a.id}</td>
            <td class="nowrap" title={fmtUtc(a.last_at ?? a.at)}>{fmtTime(a.last_at ?? a.at)}{#if a.last_at && a.last_at !== a.at}<div class="cell-2">since {fmtTime(a.at)}</div>{/if}</td>
            <td>
              <button class="linkish" onclick={(e) => filterOrigin(a, e)} title="Show only alerts from {a.origin_name}">{a.origin_name}</button>
              <div class="cell-2">{a.kind === 'access' ? 'Access' : 'Endpoint'}</div>
            </td>
            <td><div class="ellipsis">{a.user_display ?? a.process ?? '–'}</div>{#if a.remote && a.kind === 'access'}<div class="cell-2">from {a.remote}</div>{:else if a.user_display && a.process}<div class="cell-2">{a.process}</div>{/if}</td>
            <td><div class="ellipsis">{a.path ?? '–'}</div>{#if a.remote && a.kind === 'endpoint'}<div class="cell-2">→ {a.remote}{#if destOf(a)}<span class="dest"> {destOf(a)}</span>{/if}</div>{/if}</td>
            <td class="num">{a.file_count}</td>
            <td class="num">{fmtBytes(a.bytes)}</td>
            <td><span class="badge {verdictClass(a.verdict)}">{verdictLabel(a.verdict)}</span>{#if iv}<span class="badge {iv.tone} did" title="What the agent did. The verdict beside it only judges the destination.">{iv.label}</span>{/if}{#if a.reason}<div class="cell-2" style="max-width:240px;white-space:normal">{a.reason}</div>{/if}</td>
            <td class="nowrap">{#if a.acknowledged_at}<span class="badge ok"><Icon name="check" size={12} /> done</span>{:else}<span class="badge warn">open</span>{/if}</td>
            <td class="nowrap">
              {#if repOf(a)}
                {@const r = repOf(a)!}
                <span class="badge {repClass(r)}" title="AbuseIPDB: {r.total_reports} reports{r.is_whitelisted ? ', whitelisted' : ''}">{r.score}%</span>
                {#if r.is_tor}<span class="badge bad" title="Tor exit node">tor</span>{/if}
              {:else if ipOf(a.remote)}
                <span class="muted" title={repActive ? 'not checked yet' : 'IP reputation is off (Settings → Reputation)'}>–</span>
              {:else}
                <span class="muted">–</span>
              {/if}
            </td>
            <td class="nowrap">
              {#if !a.acknowledged_at && admin}<button class="btn sm" onclick={(e) => ack(a, e)}>Mark done</button>{/if}
              {#if admin && learnPush && a.kind === 'endpoint' && a.agent_id}
                <button class="btn ghost sm" onclick={(e) => learn(a, 'remember', e)}
                  title="Tell the agent this process and destination are known: silent from now on, and every open alert for the pair is closed">Remember</button>
              {/if}
            </td>
          </tr>
          {#if expanded === a.id}
            {@const chain = chainOf(a)}
            <tr class="sub"><td colspan={admin ? 12 : 11}>
              <div class="kv" style="margin-bottom:10px">
                <span class="k">Files ({a.file_count})</span><span>{#each a.files as f}<div class="mono">{f}</div>{:else}<span class="muted">no individual files</span>{/each}</span>
                <span class="k">External id</span><span class="mono">{a.external_id}</span>
                <span class="k">Received</span><span>{fmtTime(a.received_at)}</span>
                {#if a.acknowledged_at}<span class="k">Done at</span><span>{fmtTime(a.acknowledged_at)}</span>{/if}
                {#if ipOf(a.remote)}
                  {@const r = repOf(a)}
                  <span class="k">AbuseIPDB</span>
                  <span>
                    {#if r}
                      <strong class="rep-{repClass(r)}">{r.score}% abuse confidence</strong>
                      {#if r.is_whitelisted}· whitelisted{/if}{#if r.is_tor}· <strong class="rep-bad">Tor exit node</strong>{/if}
                      · {r.total_reports} reports in 90 days
                      <div class="cell-2">{[r.country_code, r.isp, r.domain, r.usage_type].filter(Boolean).join(' · ')}</div>
                      <div class="cell-2">
                        checked {fmtTime(r.checked_at)} ·
                        <a href="https://www.abuseipdb.com/check/{r.ip}" target="_blank" rel="noreferrer noopener">Open report</a>
                        {#if admin} · <button class="linkish" onclick={(e) => recheck(a, e)}>Check again</button>{/if}
                      </div>
                    {:else if !repActive}
                      <span class="muted">off — switch it on under Settings → Reputation.</span>
                    {:else}
                      <span class="muted">not checked yet.</span>
                      {#if admin}<button class="linkish" onclick={(e) => recheck(a, e)}>Check now</button>{/if}
                    {/if}
                  </span>
                {/if}
              </div>
              <!-- What the model wrote about it. Sits before the chain: it
                   is the summary, the chain is the evidence. With the
                   assistance switched off and no stored explanation, the box
                   is not there at all. -->
              {#if assistOn || insights[a.id]}
                {@const ins = insights[a.id]}
                <div class="assist">
                  <div class="assist-head">
                    <b>Assistant</b>
                    <span class="muted small">gathers the rule, the destination's reputation, this user's week and the agent log — then summarises. It decides nothing.</span>
                    <span class="spacer"></span>
                    {#if admin && assistOn}
                      <button class="btn ghost sm" onclick={(e) => explain(a, e)} disabled={explaining !== null}>
                        {explaining === a.id ? 'Thinking…' : ins ? 'Explain again' : 'Explain this alert'}
                      </button>
                    {/if}
                  </div>
                  {#if explaining === a.id}
                    <p class="muted small">Collecting the context and asking the model. A local model can take a minute.</p>
                  {:else if ins}
                    <p class="summary">{ins.summary}</p>
                    <div class="cell-2">{ins.model} · {fmtTime(ins.created_at)} · asked by {ins.created_by_name} · {ins.endpoint}</div>
                    <!-- In a tool against data leakage it has to be possible
                         to look up what went out. Word for word. -->
                    <details class="raw"><summary>What was sent to the model</summary><pre class="detail">{ins.prompt}</pre></details>
                  {:else}
                    <p class="muted small">No explanation written yet.</p>
                  {/if}
                </div>
              {/if}
              <!-- The chain from the protected folder to the destination.
                   Until now it was only a sentence in the `via` field, in the
                   middle of the raw data block; anyone who wanted to know why
                   an alert hangs on a process that never read the file had to
                   read JSON. -->
              {#if chain.length}
                <ol class="chain">
                  {#each chain as n}
                    <li class="node">
                      {#if n.edge}<span class="edge">{n.edge}</span>{/if}
                      <div class="box {n.role}">
                        <span class="mono lbl">{n.label}</span>
                        {#if n.sub}<span class="muted small nowrap">{n.sub}</span>{/if}
                      </div>
                    </li>
                  {/each}
                </ol>
              {/if}
              <details class="raw"><summary>Raw data</summary><pre class="detail">{JSON.stringify(a.detail, null, 2)}</pre></details>
              {#if a.first_detail != null}
                <!-- A later report replaced reason and detail; what the alert first said is kept. -->
                <details class="raw"><summary>As first reported{a.first_reason ? `: ${a.first_reason}` : ''}</summary><pre class="detail">{JSON.stringify(a.first_detail, null, 2)}</pre></details>
              {/if}
            </td></tr>
          {/if}
        {/each}
      </tbody>
    </table>
  </div>
  {/if}
</div>
{#if more}<div style="margin-top:12px"><button class="btn" onclick={() => load(true)} disabled={busy}>{busy ? 'Loading…' : 'Load more'}</button></div>{/if}


<style>
  /* The intervention stands next to the verdict, not below it: the two are
     meant to be read together. */
  .did { margin-left: 6px; }
  /* The chain: one box per link, the arrow with the reason in between. */
  .chain { list-style: none; margin: 0 0 12px; padding: 0; max-width: 720px; }
  .chain .edge { display: block; margin-left: 16px; padding: 4px 0 4px 16px; border-left: var(--rule); color: var(--muted); font-size: 11px; }
  .chain .edge::before { content: '\2193'; margin-right: 6px; }
  .chain .box { display: flex; gap: 10px; align-items: baseline; justify-content: space-between; border: var(--rule); border-radius: var(--radius-sm); background: var(--panel); padding: 6px 10px; }
  /* Source and destination are the two ends that matter. */
  .chain .box.source { border-left: 3px solid var(--accent); }
  .chain .box.destination { border-left: 3px solid var(--bad); }
  .chain .lbl { overflow-wrap: anywhere; }
  /* The explanation box: set apart, but not louder than the alert itself —
     it is a contribution, not a finding. */
  .assist { border: var(--rule); border-radius: var(--radius-sm); background: var(--panel); padding: 10px 12px; margin-bottom: 12px; max-width: 720px; }
  .assist-head { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; margin-bottom: 6px; }
  /* The answer arrives with line breaks and bullet dashes; they are kept,
     otherwise three paragraphs turn into one lump. */
  .summary { white-space: pre-wrap; margin: 0 0 6px; }
  .raw > summary { cursor: pointer; color: var(--muted); font-size: 12px; }
  .raw > .detail { margin-top: 8px; }
  /* Narrow and centred: the column should not stand out next to the id. */
  .pick { width: 30px; text-align: center; padding-right: 0 !important; }
  .pick input { accent-color: var(--accent); cursor: pointer; margin: 0; }
  tr.picked > td { background: var(--accent-2); }
  /* The destination's plain name stands next to the address, not instead of
     it: the address stays the fact, the name is the information about it. */
  .dest { color: var(--text-2); }
  /* Traffic light for the IP reputation, same thresholds as the badge in the column. */
  .rep-ok { color: var(--ok); }
  .rep-warn { color: var(--warn); }
  .rep-bad { color: var(--bad); }
</style>

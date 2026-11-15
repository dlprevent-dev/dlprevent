<script lang="ts">
  // Investigation: one look over every alert and notice the filter on screen
  // matches. The findings come from the database and cost nothing; only
  // "AI summary" sends a compact dossier of them to the model.
  import { api, fmtBytes, fmtTime, repClass, verdictClass, verdictLabel, zoneId } from './api';
  import { notify } from './session.svelte';
  import type { Findings, Investigation } from './types';
  import Icon from './Icon.svelte';

  let { filter, assistOn, onpick, onclose }: {
    /** The alert list's query string. Paging, sorting, drawer and state are
     *  dropped: an investigation covers alerts and notices, open and done. So
     *  is the single alert a click on a `#123` narrows the list to: opening
     *  the evidence must not turn the investigation into one about it. */
    filter: () => URLSearchParams;
    assistOn: boolean;
    onpick: (id: number) => void;
    onclose: () => void;
  } = $props();

  function query(): string {
    const p = new URLSearchParams(filter());
    for (const k of ['limit', 'offset', 'sort', 'dir', 'category', 'open', 'id']) p.delete(k);
    p.set('tz', zoneId());
    return p.toString();
  }

  let findings = $state<Findings | null>(null);
  let loadedFor = $state('');
  let loading = $state(false);
  let error = $state('');
  let question = $state('');
  let summary = $state<Investigation | null>(null);
  let asking = $state(false);
  const stale = $derived(findings !== null && query() !== loadedFor);

  async function load() {
    const qs = query();
    loading = true;
    try {
      findings = await api<Findings>('/api/investigate?' + qs);
      loadedFor = qs;
      summary = null;
      error = '';
    } catch (e) { error = (e as Error).message; } finally { loading = false; }
  }
  load();

  /** With a local model and no graphics card this takes a while; an answer
   *  for the very same dossier comes back from the database at once. */
  async function ask(again = false) {
    asking = true;
    try {
      summary = await api<Investigation>('/api/investigate/summary?' + loadedFor, { method: 'POST', body: { question, again } });
      if (summary.cached) notify('Answered before for exactly this data: shown from the database, no tokens spent');
    } catch (e) { notify((e as Error).message, true); } finally { asking = false; }
  }

  /** The answer with every `#123` as a link to the alert — except the ones
   *  the server marked as not in the data: those lead nowhere true. */
  function parts(text: string): (string | number)[] {
    return text.split(/#(\d+)(?!\d| \(not in the data\))/).map((s, i) => (i % 2 ? Number(s) : s));
  }
  const perDay = (now: number, before: number | null) =>
    `${fmtBytes(now)}/day` + (before === null ? ' · no earlier activity' : ` · before ${fmtBytes(before)}/day`);
</script>

<div class="inv card">
  <div class="head">
    <b>Investigation</b>
    <span class="muted small">every alert and notice matching the filter, open and done — {findings?.filter ?? '…'}</span>
    <span class="spacer"></span>
    {#if stale}<span class="badge warn">filter changed</span>{/if}
    <button class="btn ghost sm" onclick={load} disabled={loading}><Icon name="refresh" size={14} /> {stale ? 'Investigate new filter' : 'Refresh'}</button>
    <button class="iconbtn" onclick={onclose} title="Close" aria-label="Close the investigation"><Icon name="x" /></button>
  </div>

  {#if error}<p class="error">{error}</p>{/if}
  {#if loading && !findings}
    <div class="stack">{#each Array(3) as _}<div class="skel"></div>{/each}</div>
  {:else if findings && findings.scope.events === 0}
    <p class="muted">Nothing matches this filter.</p>
  {:else if findings}
    {@const s = findings.scope}
    <p class="small">
      <b>{s.events}</b> events{#if s.first && s.last}, {fmtTime(s.first)} – {fmtTime(s.last)}{/if} ·
      {s.users} user{s.users === 1 ? '' : 's'} · {s.device_count} device{s.device_count === 1 ? '' : 's'}{s.devices.length ? ` (${s.devices.join(', ')}${s.device_count > s.devices.length ? ', …' : ''})` : ''} ·
      sent out <b>{fmtBytes(s.sent_bytes)}</b> in {s.sent_files} files · read on file servers {fmtBytes(s.read_bytes)} in {s.read_files} files
    </p>

    <h4>Findings</h4>
    {#if findings.indicators.length === 0}<p class="muted small">None of the checks matched.</p>{/if}
    <ul class="ind">
      {#each findings.indicators as i}
        <li>
          <span class="badge {i.serious ? 'bad' : 'warn'}">{i.count} {i.unit}</span>
          <span>{i.title}</span>
          {#each i.ids as id}<button class="linkish mono" onclick={() => onpick(id)}>#{id}</button>{/each}
        </li>
      {/each}
    </ul>
    {#if findings.quiet.length}<p class="muted small">Checked, nothing found: {findings.quiet.join(' · ')}</p>{/if}
    {#if findings.skipped.length}<p class="muted small">Not checked: {findings.skipped.join(' · ')}</p>{/if}

    {#if findings.destinations.length}
      <h4>Where data went</h4>
      <div class="tablewrap"><table>
        <thead><tr><th>Target</th><th class="num">Events</th><th class="num">Files</th><th class="num">Volume</th><th>Reputation</th><th>First in fleet</th><th>Alerts</th></tr></thead>
        <tbody>
          {#each findings.destinations as d}
            <tr>
              <td class="mono">{d.target}</td><td class="num">{d.events}</td><td class="num">{d.files}</td><td class="num">{fmtBytes(d.bytes)}</td>
              <td class="nowrap">
                {#if d.score !== null}<span class="badge {repClass({ score: d.score, whitelisted: d.whitelisted })}">{d.score}%</span>{:else if d.public}<span class="muted">unchecked</span>{:else}<span class="muted">–</span>{/if}
                {#if d.tor}<span class="badge bad">tor</span>{/if}
              </td>
              <td class="nowrap">{fmtTime(d.first_in_fleet)}{#if d.new} <span class="badge warn">new</span>{/if}</td>
              <td class="ids">{#each d.ids as id}<button class="linkish mono" onclick={() => onpick(id)}>#{id}</button>{/each}</td>
            </tr>
          {/each}
        </tbody>
      </table></div>
    {/if}

    {#if findings.users.length}
      <h4>Users</h4>
      <div class="tablewrap"><table>
        <thead><tr><th>User</th><th class="num">Events</th><th>Sent out</th><th>Read on file servers</th></tr></thead>
        <tbody>
          {#each findings.users as u}
            <tr>
              <td>{u.user}</td><td class="num">{u.events}</td>
              <td>{fmtBytes(u.sent_bytes)} in {u.sent_files} files<div class="cell-2">{perDay(u.sent_per_day, u.sent_per_day_before)}</div></td>
              <td>{fmtBytes(u.read_bytes)} in {u.read_files} files<div class="cell-2">{perDay(u.read_per_day, u.read_per_day_before)}</div></td>
            </tr>
          {/each}
        </tbody>
      </table></div>
    {/if}

    {#if findings.timeline.length}
      <details class="raw">
        <summary>Timeline — the {findings.timeline.length} most significant of {findings.timeline_groups} groups (same user, process, target and verdict within ten minutes)</summary>
        <div class="tablewrap"><table>
          <thead><tr><th>Time</th><th>User / process</th><th>Folder → target</th><th>Verdict</th><th class="num">Files</th><th class="num">Volume</th><th>Alerts</th></tr></thead>
          <tbody>
            {#each findings.timeline as l}
              <tr>
                <td class="nowrap">{fmtTime(l.at)}</td>
                <td>{l.user ?? '–'}<div class="cell-2">{l.process ?? ''}</div></td>
                <td><div class="ellipsis">{l.path ?? '–'}</div><div class="cell-2">{l.kind === 'access' ? `read from ${l.remote ?? '?'}` : `→ ${l.remote ?? '–'}`}</div></td>
                <td><span class="badge {verdictClass(l.verdict)}">{verdictLabel(l.verdict)}</span></td>
                <td class="num">{l.files}</td><td class="num">{fmtBytes(l.bytes)}</td>
                <td class="ids">{#each l.ids as id}<button class="linkish mono" onclick={() => onpick(id)}>#{id}</button>{/each}{#if l.events > l.ids.length}<span class="muted small">+{l.events - l.ids.length}</span>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table></div>
      </details>
    {/if}

    {#if assistOn}
      <div class="assist">
        <div class="ask">
          <input type="text" bind:value={question} maxlength="500" disabled={asking || stale}
            placeholder="Your suspicion, e.g. “Did this user take contracts out?” — optional"
            onkeydown={(e) => { if (e.key === 'Enter' && !asking && !stale) ask(); }} />
          <button class="btn sm" onclick={() => ask()} disabled={asking || stale}
            title={stale ? 'Investigate the new filter first' : 'Sends the findings above as a compact dossier, never file contents'}>
            {asking ? 'Thinking…' : 'AI summary'}
          </button>
        </div>
        {#if asking}
          <p class="muted small">Asking the model. A local model can take a minute.</p>
        {:else if summary}
          <p class="summary">{#each parts(summary.summary) as p}{#if typeof p === 'number'}<button class="linkish mono" onclick={() => onpick(p)}>#{p}</button>{:else}{p}{/if}{/each}</p>
          <div class="cell-2">
            {summary.model} · {summary.prompt_tokens.toLocaleString()} + {summary.completion_tokens.toLocaleString()} tokens ·
            {fmtTime(summary.created_at)} · asked by {summary.created_by_name}
            {#if summary.cached} · <span class="badge ok">from the database, no tokens spent</span> <button class="linkish" onclick={() => ask(true)}>Ask again</button>{/if}
          </div>
          <details class="raw"><summary>What was sent to the model</summary><pre class="detail">{summary.prompt}</pre></details>
        {/if}
      </div>
    {/if}
  {/if}
</div>

<style>
  .inv { padding: 12px 14px; margin-bottom: 12px; }
  .head { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; margin-bottom: 6px; }
  h4 { margin: 14px 0 6px; font-size: 13px; }
  .ind { list-style: none; margin: 0 0 6px; padding: 0; }
  .ids { display: flex; gap: 6px; flex-wrap: wrap; align-items: baseline; }
  .inv th, .inv td { padding-right: 14px; }
  .ind li { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; padding: 3px 0; }
  .assist { border: var(--rule); border-radius: var(--radius-sm); background: var(--panel); padding: 10px 12px; margin-top: 14px; max-width: 820px; }
  .ask { display: flex; gap: 8px; margin-bottom: 8px; }
  .ask input { flex: 1; min-width: 0; }
  .summary { white-space: pre-wrap; margin: 0 0 6px; }
  .raw > summary { cursor: pointer; color: var(--muted); font-size: 12px; margin-top: 10px; }
  .raw .detail { margin-top: 8px; }
</style>

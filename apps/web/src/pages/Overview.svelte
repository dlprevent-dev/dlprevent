<script lang="ts">
  import { api, fmtBytes, fmtTime, verdictClass, verdictLabel } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import type { Overview, Counts } from '../lib/types';
  import { go, originOf, showAlertsFor } from '../lib/router.svelte';
  import Icon from '../lib/Icon.svelte';
  import PageHead from '../lib/PageHead.svelte';

  let hours = $state(24);
  const res = resource(
    () => Promise.all([api<Overview>('/api/overview'), api<Counts>(`/api/counts?hours=${hours}`)]),
    { poll: 15000 },
  );
  const load = res.reload;
  const o = $derived(res.data?.[0] ?? null);
  const c = $derived(res.data?.[1] ?? null);
  let maxFiles = $derived(Math.max(1, ...(c?.per_hour.map((h) => h.files) ?? [1])));
  // Two digits as on a gauge: the numbers in the status strip then line up
  // in the same place underneath each other. Three-digit ones stay untouched.
  const pad = (n: number) => String(n).padStart(2, '0');
</script>

<PageHead title="Overview" />
{#if res.error}<p class="error">{res.error}</p>{/if}

{#if o}
  <div class="cards">
    <a class="stat" class:is-bad={o.alerts_open > 0} class:is-ok={o.alerts_open === 0} href="/alerts" onclick={(e) => { e.preventDefault(); go('/alerts'); }}>
      <span class="label">Open alerts</span>
      <span class="value">{pad(o.alerts_open)}</span>
      <span class="sub">{o.alerts_24h} in the last 24 h</span>
    </a>
    <div class="stat" class:is-ok={o.agents > 0 && o.agents_online === o.agents} class:is-bad={o.agents > 0 && o.agents_online < o.agents}>
      <span class="label">Agents online</span>
      <span class="value">{pad(o.agents_online)}<span class="muted">/{pad(o.agents)}</span></span>
      <span class="sub">Mac, Windows, Linux</span>
    </div>
    <div class="stat is-accent">
      <span class="label">Syslog sources</span>
      <span class="value">{pad(o.sources)}</span>
      <span class="sub">NAS without an agent</span>
    </div>
    <div class="stat is-accent">
      <span class="label">Active rules</span>
      <span class="value">{pad(o.rules)}</span>
      <span class="sub">protected folders</span>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <div class="card-head">
        <h2>Latest alerts</h2><span class="spacer"></span>
        <button class="btn sm ghost" onclick={() => go('/alerts')}>See all</button>
      </div>
      {#if o.recent.length === 0}
        <div class="empty"><span class="ico"><Icon name="ok" size={24} /></span><b>All quiet</b><span>No hard limits or deviations. Other observations are listed under Alerts → Notices.</span></div>
      {:else}
      <div class="tablewrap">
        <table>
          <thead><tr><th><span class="th">Time</span></th><th><span class="th">Source</span></th><th><span class="th">Who / what</span></th><th><span class="th">Folder</span></th><th class="num"><span class="th">Files</span></th><th class="num"><span class="th">Volume</span></th><th><span class="th">Verdict</span></th></tr></thead>
          <tbody>
            {#each o.recent as a}
              <tr class="click" onclick={() => go('/alerts')}>
                <td class="nowrap">{fmtTime(a.last_at ?? a.at)}</td>
                <td>
                  <button class="linkish" onclick={(e) => { e.stopPropagation(); showAlertsFor(originOf(a)); }} title="Show only alerts from {a.origin_name}">{a.origin_name}</button>
                </td>
                <td><div class="ellipsis">{a.user_display ?? a.process ?? '–'}</div></td>
                <td><div class="ellipsis">{a.path ?? a.remote ?? '–'}</div></td>
                <td class="num">{a.file_count}</td>
                <td class="num">{fmtBytes(a.bytes)}</td>
                <td><span class="badge {verdictClass(a.verdict)}">{verdictLabel(a.verdict)}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {/if}
    </div>

    <div class="stack">
      <div class="card">
        <div class="card-head">
          <h2>Reads</h2><span class="spacer"></span>
          <div class="seg">
            {#each [[24, '24 h'], [24 * 7, '7 d'], [24 * 30, '30 d']] as [h, l]}
              <button class:on={hours === h} onclick={() => { hours = h as number; load(); }}>{l}</button>
            {/each}
          </div>
        </div>
        <div style="padding:16px">
          {#if c && c.per_hour.length}
            <!-- The scale sits beside the trace, not under it: peak at the
                 top, baseline at the bottom, the half mark in between. -->
            <div class="chart">
              <div class="scale">
                <span>{maxFiles}</span>
                <span>{Math.round(maxFiles / 2)}</span>
                <span>0</span>
              </div>
              <div class="bars">
                {#each c.per_hour as h}
                  <div class="bar" style:height="{Math.max(1, (h.files / maxFiles) * 100)}%" title="{fmtTime(h.hour)}: {h.files} reads, {fmtBytes(h.bytes)}"></div>
                {/each}
              </div>
            </div>
            <div class="axis mono">
              <span>{fmtTime(c.per_hour[0].hour)}</span>
              <span>now</span>
            </div>
            <h2 style="margin:20px 0 8px">Top readers</h2>
            <table>
              <thead><tr><th><span class="th">User</span></th><th><span class="th">Folder</span></th><th class="num"><span class="th">Reads</span></th></tr></thead>
              <tbody>{#each c.top.slice(0, 6) as t}<tr><td>{t.user_display}</td><td><div class="ellipsis" style="max-width:200px">{t.path}</div></td><td class="num">{t.files}</td></tr>{/each}</tbody>
            </table>
          {:else}<div class="empty"><span class="ico"><Icon name="chart" size={24} /></span><b>No counts</b><span>No protected folder was read in this period.</span></div>{/if}
        </div>
      </div>

      <div class="card pad small">
        <h2>Central server</h2>
        <div class="kv">
          <span class="k">Version</span><span class="mono">{o.server_version}{#if o.server_build}<span class="cell-2" title="First 12 characters of the server file's SHA-256 — compare with sha256sum on the host"> · {o.server_build}</span>{/if}</span>
          <span class="k">Running since</span><span>{fmtTime(o.server_started)}</span>
          <span class="k">CA fingerprint</span><span class="mono">{o.ca_fingerprint}</span>
          <span class="k">API version</span><span>{o.api_version}</span>
        </div>
      </div>
    </div>
  </div>
{:else if !res.error}
  <div class="cards">{#each Array(4) as _}<div class="stat"><div class="skel" style="width:70%"></div><div class="skel" style="width:45%;height:26px;margin-top:8px"></div></div>{/each}</div>
{/if}

<style>
  /* Only the plotting area itself — everything else is carried by the design system. */
  .chart { display: grid; grid-template-columns: 28px minmax(0, 1fr); gap: 8px; }
  .scale {
    display: flex; flex-direction: column; justify-content: space-between; height: 112px;
    font-family: var(--font-mono); font-size: 9.5px; color: var(--muted); text-align: right;
    font-variant-numeric: tabular-nums; line-height: 1;
  }
  .axis {
    display: flex; justify-content: space-between; margin: 6px 0 0 36px;
    font-size: 9.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em;
  }
</style>

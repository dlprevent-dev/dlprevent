<script lang="ts">
  import { api, ago, fmtTime } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { showAlertsFor } from '../lib/router.svelte';
  import { notify, isAdmin } from '../lib/session.svelte';
  import { createSort, sortRows, matches } from '../lib/sort.svelte';
  import type { Source } from '../lib/types';
  import Modal from '../lib/Modal.svelte';
  import Icon from '../lib/Icon.svelte';
  import PageHead from '../lib/PageHead.svelte';
  import SearchBox from '../lib/SearchBox.svelte';
  import SortHeader from '../lib/SortHeader.svelte';
  import { ask } from '../lib/confirm.svelte';

  const res = resource(() => api<Source[]>('/api/sources'), { poll: 15000 });
  const sources = $derived(res.data ?? []);
  const load = res.reload;
  let editing = $state<Source | null>(null);
  let q = $state('');
  const sort = createSort('name');
  const admin = $derived(isAdmin());
  const kinds = [['synology', 'Synology'], ['qnap', 'QNAP'], ['truenas', 'TrueNAS'], ['samba', 'Samba (full_audit)'], ['unknown', 'Unknown']];
  const kindLabel = (k: string) => kinds.find((x) => x[0] === k)?.[1] ?? k;

  const view = $derived(sortRows(
    sources.filter((s) => matches(`${s.name} ${s.address} ${kindLabel(s.kind)}`, q)),
    sort,
    (s, k) => ({ name: s.name, kind: kindLabel(s.kind), address: s.address, last: s.last_seen, lines: s.lines, unparsed: s.unparsed, first: s.first_seen }[k]),
  ));

  async function save(e: Event) {
    e.preventDefault();
    if (!editing) return;
    try { await api(`/api/sources/${editing.id}`, { method: 'PUT', body: { name: editing.name, kind: editing.kind } }); notify('Saved'); editing = null; load(); } catch (err) { notify((err as Error).message, true); }
  }
  async function confirmSource(s: Source) {
    if (!(await ask({ title: 'Confirm source', body: `Is "${s.name}" at ${s.address} one of your devices?`, detail: 'Syslog is not authenticated. Once confirmed, lines from this address raise alerts.', confirmLabel: 'Confirm' }))) return;
    try { await api(`/api/sources/${s.id}`, { method: 'PUT', body: { name: s.name, kind: s.kind, confirmed: true } }); notify('Confirmed'); load(); } catch (err) { notify((err as Error).message, true); }
  }
  async function remove(s: Source) {
    if (!(await ask({ title: 'Delete source', body: `"${s.name}" disappears from the list.`, detail: 'It comes back unconfirmed with the next syslog packet from that address. Its alerts stay.', confirmLabel: 'Delete', danger: true }))) return;
    try { await api(`/api/sources/${s.id}`, { method: 'DELETE' }); load(); } catch (err) { notify((err as Error).message, true); }
  }
</script>

<PageHead title="Syslog sources" />

<div class="toolbar">
  <SearchBox bind:value={q} placeholder="Search name, address or kind…" />
  <span class="spacer"></span>
  <span class="muted small">{view.length} of {sources.length}</span>
</div>

<div class="card" style="margin-bottom:18px">
  {#if res.loading}
    <div style="padding:16px" class="stack">{#each Array(3) as _}<div class="skel"></div>{/each}</div>
  {:else if res.error}
    <p class="error" style="padding:16px">{res.error}</p>
  {:else if view.length === 0}
    <div class="empty">
      <span class="ico"><Icon name={sources.length ? 'search' : 'sources'} size={26} /></span>
      <b>{sources.length ? 'Nothing found' : 'No source seen yet'}</b>
      <span>{sources.length ? 'Try other words.' : 'As soon as the first syslog packet arrives, the device shows up here. It raises alerts once you confirm it.'}</span>
    </div>
  {:else}
  <div class="tablewrap">
    <table>
      <thead><tr>
        <SortHeader {sort} key="name" label="Name" />
        <SortHeader {sort} key="kind" label="Kind" />
        <SortHeader {sort} key="address" label="Address" />
        <SortHeader {sort} key="last" label="Last seen" />
        <SortHeader {sort} key="lines" label="Lines" num />
        <SortHeader {sort} key="unparsed" label="Not understood" num />
        <SortHeader {sort} key="first" label="Since" />
        <th><span class="th"></span></th>
      </tr></thead>
      <tbody>
        {#each view as s (s.id)}
          <tr>
            <td><strong>{s.name}</strong>{#if !s.confirmed} <span class="badge warn" title="Raises no alerts until an administrator confirms it">Unconfirmed</span>{/if}</td>
            <td>{kindLabel(s.kind)}</td>
            <td class="mono">{s.address}</td>
            <td class="nowrap">{ago(s.last_seen)}</td>
            <td class="num">{s.lines}</td>
            <td class="num">{#if s.lines && s.unparsed / s.lines > 0.5}<span class="badge warn" title="More than half the lines match no pattern: check the kind of the source.">{s.unparsed}</span>{:else}{s.unparsed}{/if}</td>
            <td class="nowrap muted">{fmtTime(s.first_seen)}</td>
            <td class="nowrap">
              <button class="btn sm ghost" onclick={() => showAlertsFor({ source: s.id, name: s.name })} title="Show only alerts from this source">Alerts</button>
              {#if admin}
                {#if !s.confirmed}<button class="btn sm" onclick={() => confirmSource(s)} title="Let this source raise alerts">Confirm</button>{/if}
                <button class="btn sm ghost" onclick={() => (editing = { ...s })} title="Edit" aria-label="Edit"><Icon name="edit" size={14} /></button>
                <button class="btn sm ghost danger" onclick={() => remove(s)} title="Delete" aria-label="Delete"><Icon name="trash" size={14} /></button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {/if}
</div>

<div class="card pad small">
  <h2>Setup on the NAS</h2>
  <div class="kv">
    <span class="k">Synology DSM</span><span>Log Center → Log Sending → server: this machine, port 514, UDP or TCP, format BSD. Plus Control Panel → File Services → SMB → Advanced → enable transfer log (events: read, download).</span>
    <span class="k">QNAP QTS/QuTS</span><span>QuLog Center → Log Sending → syslog server: this machine, port 514. Turn on the connection log for SMB.</span>
    <span class="k">TrueNAS / Samba</span><span>Share with <code>vfs objects = full_audit</code>, <code>full_audit:success = open pread</code>, <code>full_audit:prefix = %u|%I|%m|%S</code>, forward syslog to this machine.</span>
  </div>
</div>

{#if editing}
  <Modal title="Edit source" subtitle={editing.address} onclose={() => (editing = null)}>
    <form id="source-form" onsubmit={save}>
      <div class="field"><label for="sn">Name</label><input id="sn" type="text" bind:value={editing.name} required /></div>
      <div class="field" style="margin-bottom:0"><label for="sk">Kind</label>
        <select id="sk" bind:value={editing.kind}>{#each kinds as [v, l]}<option value={v}>{l}</option>{/each}</select>
        <div class="hint">The kind decides which pattern the syslog lines are read with.</div>
      </div>
    </form>
    {#snippet actions()}
      <button type="button" class="btn" onclick={() => (editing = null)}>Cancel</button>
      <button type="submit" form="source-form" class="btn primary">Save</button>
    {/snippet}
  </Modal>
{/if}

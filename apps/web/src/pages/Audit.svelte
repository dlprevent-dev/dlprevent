<script lang="ts">
  import { onMount } from 'svelte';
  import { api, fmtTime, fmtUtc, tzName } from '../lib/api';
  import type { AuditRow } from '../lib/types';
  import { createSort } from '../lib/sort.svelte';
  import Icon from '../lib/Icon.svelte';
  import PageHead from '../lib/PageHead.svelte';
  import SearchBox from '../lib/SearchBox.svelte';
  import SortHeader from '../lib/SortHeader.svelte';

  const PAGE = 200;
  let rows = $state<AuditRow[]>([]);
  let q = $state('');
  let action = $state('');
  let more = $state(false);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');
  let timer: ReturnType<typeof setTimeout> | undefined;
  // The log grows without limit, so the database does the sorting.
  const sort = createSort('id', { asc: false, descFirst: true, onchange: () => load() });

  const labels: Record<string, string> = {
    login: 'Sign in', login_failed: 'Sign-in failed', alert_ack: 'Alert marked done', rule_create: 'Rule created', rule_update: 'Rule changed', rule_delete: 'Rule deleted',
    agent_enroll: 'Agent enrolled', agent_revoke: 'Agent revoked', source_new: 'New source', source_update: 'Source changed', source_delete: 'Source deleted',
    token_create: 'Token created', token_delete: 'Token deleted', user_create: 'User created', user_delete: 'User deleted', password_change: 'Password changed', settings_update: 'Settings changed',
  };
  const bad = new Set(['login_failed', 'rule_delete', 'agent_revoke', 'source_delete', 'user_delete']);

  async function load(append = false) {
    busy = true;
    try {
      const p = new URLSearchParams({ limit: String(PAGE), sort: sort.key, dir: sort.asc ? 'asc' : 'desc' });
      if (q.trim()) p.set('q', q.trim());
      if (action) p.set('action', action);
      if (append) p.set('offset', String(rows.length));
      const r = await api<AuditRow[]>('/api/audit?' + p);
      const seen = append ? new Set(rows.map((a) => a.id)) : new Set<number>();
      rows = append ? [...rows, ...r.filter((a) => !seen.has(a.id))] : r;
      more = r.length === PAGE;
      error = '';
    } catch (e) { error = (e as Error).message; } finally { loading = false; busy = false; }
  }
  function debounced() { clearTimeout(timer); timer = setTimeout(() => load(), 250); }
  onMount(() => { load(); return () => clearTimeout(timer); });
</script>

<PageHead title="Audit log" />

<div class="toolbar">
  <SearchBox bind:value={q} placeholder="User, action, detail…" oninput={debounced} />
  <select bind:value={action} onchange={() => load()} aria-label="Action">
    <option value="">Any action</option>
    {#each Object.entries(labels) as [v, l]}<option value={v}>{l}</option>{/each}
  </select>
  <span class="spacer"></span>
  <span class="muted small">{rows.length}{more ? '+' : ''} entries</span>
</div>

{#if error}<p class="error">{error}</p>{/if}

<div class="card">
  {#if loading}
    <div style="padding:16px" class="stack">{#each Array(6) as _}<div class="skel"></div>{/each}</div>
  {:else if rows.length === 0}
    <div class="empty"><span class="ico"><Icon name="audit" size={26} /></span><b>Nothing found</b><span>Try other words or a different action.</span></div>
  {:else}
  <div class="tablewrap">
    <table>
      <thead><tr>
        <SortHeader {sort} key="id" label="Time ({tzName()})" />
        <SortHeader {sort} key="user" label="User" />
        <SortHeader {sort} key="action" label="Action" />
        <th><span class="th">Details</span></th>
      </tr></thead>
      <tbody>
        {#each rows as r (r.id)}
          <tr>
            <td class="nowrap" title={fmtUtc(r.at)}>{fmtTime(r.at)}</td>
            <td><strong>{r.user_name}</strong></td>
            <td class="nowrap"><span class="badge {bad.has(r.action) ? 'bad' : 'accent'}">{labels[r.action] ?? r.action}</span></td>
            <td class="mono small" style="word-break:break-all">{JSON.stringify(r.detail)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {/if}
</div>
{#if more}<div style="margin-top:12px"><button class="btn" onclick={() => load(true)} disabled={busy}>{busy ? 'Loading…' : 'Load more'}</button></div>{/if}

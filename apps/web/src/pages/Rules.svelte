<script lang="ts">
  import { onMount } from 'svelte';
  import { resource } from '../lib/resource.svelte';
  import { takeRuleDraft } from '../lib/router.svelte';
  import { api, fmtTime } from '../lib/api';
  import { notify, isAdmin } from '../lib/session.svelte';
  import { createSort, sortRows, matches } from '../lib/sort.svelte';
  import type { Rule, Agent, Source } from '../lib/types';
  import Modal from '../lib/Modal.svelte';
  import Icon from '../lib/Icon.svelte';
  import PageHead from '../lib/PageHead.svelte';
  import SearchBox from '../lib/SearchBox.svelte';
  import SortHeader from '../lib/SortHeader.svelte';
  import PickList from '../lib/PickList.svelte';
  import { ask } from '../lib/confirm.svelte';

  let editing = $state<Partial<Rule> | null>(null);
  /// Allowed destinations as text, one line per entry: a list is typed the
  /// way it is read, and the server checks every line separately.
  let allowText = $state('');
  /// The form only. The error from loading lives in `res.error`.
  let error = $state('');
  let q = $state('');
  const sort = createSort('name');
  const admin = $derived(isAdmin());

  const res = resource(() => Promise.all([api<Rule[]>('/api/rules'), api<Agent[]>('/api/agents'), api<Source[]>('/api/sources')]));
  const load = res.reload;
  const rules = $derived(res.data?.[0] ?? []);
  const agents = $derived(res.data?.[1] ?? []);
  const sources = $derived(res.data?.[2] ?? []);

  onMount(async () => {
    // `ready` instead of a second `load()`: the draft may only be picked up
    // once the lists are there — but also when the loading failed, otherwise
    // the form never opens.
    await res.ready;
    // If somebody arrives from the agents page ("Create rule" on a share),
    // the path is already settled; the form opens straight away.
    const draft = takeRuleDraft();
    if (draft) {
      edit();
      editing.path = draft.path;
      editing.name = draft.name;
      setScope('agent');
      editing.agent_id = draft.agent_id;
    }
  });

  /// Absolute means: drive (C:\), UNC (\\srv\...) or Unix root — the same
  /// check as in the agent (deelpe-winagent::agent::is_absolute).
  function isAbsolute(p = '') {
    const t = p.trim();
    return t.startsWith('\\\\') || t.startsWith('/') || /^[A-Za-z]:/.test(t);
  }

  function scopeLabel(r: Rule) {
    if (r.scope === 'agent') return 'Agent: ' + (agents.find((a) => a.id === r.agent_id)?.name ?? '?');
    if (r.scope === 'source') return 'Source: ' + (sources.find((s) => s.id === r.source_id)?.name ?? '?');
    return 'Everywhere';
  }

  const view = $derived(sortRows(
    rules.filter((r) => matches(`${r.name} ${r.path} ${scopeLabel(r)} ${r.allowed_groups.join(' ')}`, q)),
    sort,
    (r, k) => ({ name: r.name, path: r.path, scope: scopeLabel(r), hard: r.hard_max_files, enabled: r.enabled, updated: r.updated_at }[k]),
  ));

  function edit(r?: Rule) {
    editing = r ? { ...r } : { name: '', path: '', scope: 'all', agent_id: null, source_id: null, allowed_groups: [], lockdown: false, strict: false, allow_destinations: [], enforce: false, hard_max_files: 100, window_secs: 60, ad_lock: false, enabled: true };
    editing.allowed_groups ??= [];
    editing.allow_destinations ??= [];
    allowText = (editing.allow_destinations ?? []).join('\n');
    error = '';
  }

  /// Shares **of the selected agent**. Before that there is nothing to show:
  /// a rule applies to one server, and another server's shares do not belong
  /// in the list.
  const agentShares = $derived.by(() => {
    if (!editing || editing.scope !== 'agent' || !editing.agent_id) return [];
    const a = agents.find((x) => x.id === editing!.agent_id);
    return (a?.status?.shares ?? [])
      .filter((sh) => sh.path)
      .map((sh) => ({
        value: sh.path!,
        label: sh.name,
        hint: sh.path!,
        tag: sh.path_from === 'events' ? 'learned' : undefined,
      }));
  });

  /// The selected agent, for labels and for the group search.
  const chosenAgent = $derived(editing?.scope === 'agent' ? agents.find((a) => a.id === editing!.agent_id) : undefined);

  /// Groups come from the central server, not from the browser: in a
  /// customer environment there are tens of thousands. The search is
  /// restricted to the selected agent.
  async function searchGroups(q: string) {
    const p = new URLSearchParams({ limit: '50' });
    if (q.trim()) p.set('q', q.trim());
    if (editing?.scope === 'agent' && editing.agent_id) p.set('agent', editing.agent_id);
    const rows = await api<{ name: string; kind: string; agent_name: string }[]>(`/api/groups?${p}`);
    return rows.map((g) => ({ value: g.name, label: g.name, tag: g.kind === 'local' ? 'local' : undefined, hint: g.agent_name }));
  }

  /// Takes a path over from the share picker.
  function useSharePath(paths: string[]) {
    if (!editing || !paths.length) return;
    editing.path = paths[0];
    if (!editing.name.trim()) {
      const sh = agentShares.find((x) => x.value === paths[0]);
      if (sh) editing.name = sh.label;
    }
  }

  function setScope(s: 'all' | 'agent' | 'source') {
    if (!editing) return;
    editing.scope = s;
    if (s === 'agent') editing.agent_id ??= agents.find((a) => !a.revoked_at)?.id ?? null;
    if (s === 'source') editing.source_id ??= sources[0]?.id ?? null;
  }

  async function save(e: Event) {
    e.preventDefault();
    if (!editing) return;
    const body = {
      ...editing,
      allowed_groups: editing.allowed_groups ?? [],
      allow_destinations: allowText.split(/[\n,;]+/).map((d) => d.trim()).filter(Boolean),
    };
    try {
      if (editing.id) await api(`/api/rules/${editing.id}`, { method: 'PUT', body });
      else await api('/api/rules', { method: 'POST', body });
      notify('Rule saved');
      editing = null;
      load();
    } catch (err) { error = (err as Error).message; }
  }

  async function remove(r: Rule) {
    if (!(await ask({ title: 'Delete rule', body: `"${r.name}" stops being watched.`, detail: 'Agents drop the folder with their next report. Alerts it already produced stay.', confirmLabel: 'Delete', danger: true }))) return;
    try { await api(`/api/rules/${r.id}`, { method: 'DELETE' }); notify('Rule deleted'); load(); } catch (err) { notify((err as Error).message, true); }
  }
</script>

<PageHead title="Rules">
  {#snippet actions()}
    {#if admin}<button class="btn primary" onclick={() => edit()}><Icon name="plus" size={15} /> New rule</button>{/if}
  {/snippet}
</PageHead>

<div class="toolbar">
  <SearchBox bind:value={q} placeholder="Search rule, path or group…" />
  <span class="spacer"></span>
  <span class="muted small">{view.length} of {rules.length}</span>
</div>

<div class="card">
  {#if res.loading}
    <div style="padding:16px" class="stack">{#each Array(4) as _}<div class="skel"></div>{/each}</div>
  {:else if res.error}
    <p class="error" style="padding:16px">{res.error}</p>
  {:else if view.length === 0}
    <div class="empty">
      <span class="ico"><Icon name={rules.length ? 'search' : 'folder'} size={26} /></span>
      <b>{rules.length ? 'Nothing found' : 'No rules yet'}</b>
      <span>{rules.length ? 'Try other words.' : 'A rule names the folder to protect and the hard limit that goes with it.'}</span>
      {#if admin && !rules.length}<button class="btn primary" onclick={() => edit()}><Icon name="plus" size={15} /> New rule</button>{/if}
    </div>
  {:else}
  <div class="tablewrap">
    <table>
      <thead><tr>
        <SortHeader {sort} key="name" label="Name" />
        <SortHeader {sort} key="path" label="Path" />
        <SortHeader {sort} key="scope" label="Applies to" />
        <SortHeader {sort} key="hard" label="Hard limit" num />
        <th><span class="th">Enforcement (Z3)</span></th>
        <SortHeader {sort} key="enabled" label="Status" />
        <SortHeader {sort} key="updated" label="Changed" />
        <th><span class="th"></span></th>
      </tr></thead>
      <tbody>
        {#each view as r (r.id)}
          <tr>
            <td><strong>{r.name}</strong></td>
            <td class="mono">{r.path}</td>
            <td>{scopeLabel(r)}</td>
            <td class="num nowrap">{r.hard_max_files} files<div class="cell-2">in {r.window_secs} s</div></td>
            <td>
              {#if r.strict}<span class="badge bad"><Icon name="lock" size={11} /> Strict{r.enforce ? ' + enforce' : ''}</span>{/if}
              {#if r.lockdown}<span class="badge warn"><Icon name="lock" size={11} /> Lockdown</span>{/if}
              {#if r.ad_lock}<span class="badge warn">AD lock</span>{/if}
              {#if !r.lockdown && !r.ad_lock && !r.strict}<span class="muted">–</span>{/if}
              {#if r.allowed_groups.length}<div class="cell-2">allowed: {r.allowed_groups.join(', ')}</div>{/if}
            </td>
            <td>{#if r.enabled}<span class="badge ok"><span class="dot"></span> on</span>{:else}<span class="badge">off</span>{/if}</td>
            <td class="nowrap muted">{fmtTime(r.updated_at)}</td>
            <td class="nowrap">{#if admin}
              <button class="btn sm ghost" onclick={() => edit(r)} title="Edit" aria-label="Edit"><Icon name="edit" size={14} /></button>
              <button class="btn sm ghost danger" onclick={() => remove(r)} title="Delete" aria-label="Delete"><Icon name="trash" size={14} /></button>
            {/if}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {/if}
</div>

{#if editing}
  <Modal wide title={editing.id ? 'Edit rule' : 'New rule'}
    subtitle="One protected folder, where the rule applies and what happens on mass access."
    onclose={() => (editing = null)}>
    <form id="rule-form" onsubmit={save}>
      <fieldset class="fset">
        <legend>Protected folder</legend>
        <div class="row">
          <div class="field"><label for="rn">Name</label><input id="rn" type="text" bind:value={editing.name} placeholder="Management" required /></div>
          <div class="field"><label for="rp">Path</label><input id="rp" class="mono" type="text" bind:value={editing.path} placeholder="GL" required />
            <div class="hint">Relative (<code>GL</code>) matches every folder of that name on a NAS or file server;
              absolute (<code>/volume1/GL</code>, <code>D:\Shares\GL</code>) only there.
              {#if !isAbsolute(editing.path)}
                <strong>A workstation cannot use this path</strong> and will report the rule as unusable. For the same
                folder seen from a client, add a second rule with <code class="mono">\\server\share</code>.
              {/if}</div></div>
        </div>
      </fieldset>

      <fieldset class="fset">
        <legend>Applies to</legend>
        <div class="seg" style="margin-bottom:10px">
          <button type="button" class:on={editing.scope === 'all'} onclick={() => setScope('all')}>Everywhere</button>
          <button type="button" class:on={editing.scope === 'agent'} onclick={() => setScope('agent')}>One agent</button>
          <button type="button" class:on={editing.scope === 'source'} onclick={() => setScope('source')}>One syslog source</button>
        </div>
        {#if editing.scope === 'agent'}
          <div class="field"><label for="ra">Agent</label>
            <select id="ra" bind:value={editing.agent_id}>{#each agents.filter((a) => !a.revoked_at) as a}<option value={a.id}>{a.name} ({a.kind})</option>{/each}</select>
            {#if !agents.some((a) => !a.revoked_at)}<div class="hint">No agent enrolled yet.</div>{/if}
          </div>
          {#if editing.agent_id}
            <div class="field" style="margin-top:10px"><label for="rsh">Share on {chosenAgent?.name ?? 'this server'}</label>
              <PickList
                id="rsh"
                items={agentShares}
                selected={editing.path ? [editing.path] : []}
                onselect={useSharePath}
                placeholder="Search shares…"
                empty={agentShares.length === 0 ? 'This agent has not reported any share yet.' : 'No share matches.'} />
              <div class="hint">Picking a share fills the path above. The list comes from the agent itself, so nobody has to look up paths on the server.</div>
            </div>
          {/if}
        {:else if editing.scope === 'source'}
          <div class="field"><label for="rq">Syslog source</label>
            <select id="rq" bind:value={editing.source_id}>{#each sources as s}<option value={s.id}>{s.name} ({s.address})</option>{/each}</select>
            {#if !sources.length}<div class="hint">No source seen yet.</div>{/if}
          </div>
        {:else}
          <div class="hint" style="margin-top:0">All agents and all syslog sources.</div>
        {/if}
      </fieldset>

      <fieldset class="fset">
        <legend>Where data may go</legend>
        <label class="check"><input type="checkbox" bind:checked={editing.strict} />
          <span class="t"><b>Strict folder (block all)</b><span>Once a process has read from this folder, every destination is forbidden except the ones below — browser upload, AI service, PowerShell, all the same.</span></span></label>
        {#if editing.strict}
          <div class="field" style="margin-top:12px"><label for="rad">Allowed destinations</label>
            <textarea id="rad" class="mono" rows="4" bind:value={allowText} placeholder="ethical-ai.example&#10;10.0.0.7&#10;192.168.10.0/24:445"></textarea>
            <div class="hint">One per line: a host name (<code>chatgpt.com</code>, covering its subdomains), or an IP or network with an optional <code>:port</code>.
              Host names are honoured where the browser tells us the destination — a file upload through the content-analysis connector.
              On the plain network path only IPs count: the endpoint service has no outbound network of its own and cannot resolve a name, so name the network behind the link there.
              An empty list means nothing may leave at all.</div>
          </div>
          <label class="check" style="margin-top:12px"><input type="checkbox" bind:checked={editing.enforce} />
            <span class="t"><b>Enforce</b><span>Act, do not just report: a Windows workstation refuses a browser upload out of the folder before the first byte, takes the network away from a program that read from it, and deletes a copy that left the folder.</span></span></label>
          <div class="hint">The sending process is never stopped — that was the old behaviour and it took a user's <code>explorer.exe</code> with it on 2026-09-09.
            The Mac has no lever of its own yet and reports; blocking before the first byte needs the network extension there (stage Z5).</div>
        {/if}
      </fieldset>

      <fieldset class="fset">
        <legend>Hard limit</legend>
        <div class="row">
          <div class="field"><label for="rh">Distinct files</label><input id="rh" type="number" min="1" max="100000" bind:value={editing.hard_max_files} /></div>
          <div class="field"><label for="rw">Window (seconds)</label><input id="rw" type="number" min="10" max="3600" bind:value={editing.window_secs} /></div>
        </div>
        <div class="hint" style="margin-top:0">
          Alerts as soon as <strong>one user</strong> reads more than {editing.hard_max_files} distinct files
          within {editing.window_secs} seconds. Applies during the learning phase too.
        </div>
      </fieldset>

      <fieldset class="fset">
        <legend>Enforcement (from stage Z3)</legend>
        <div class="checks">
          <label class="check"><input type="checkbox" bind:checked={editing.lockdown} />
            <span class="t"><b>Lockdown</b><span>Only the allowed groups may read the folder at all.</span></span></label>
          <label class="check"><input type="checkbox" bind:checked={editing.ad_lock} />
            <span class="t"><b>Lock AD account</b><span>On mass access also lock the directory account. Opt-in.</span></span></label>
        </div>
        <div class="field" style="margin-top:12px"><label for="rg">Allowed groups</label>
          <PickList id="rg" search={searchGroups} bind:selected={editing.allowed_groups} multiple
            placeholder="Search groups…" empty="No group matches. The agent reports its groups with the next report." />
          <div class="hint">Comma separated. Effective with lockdown once a Windows agent with enforcement runs.</div>
        </div>
      </fieldset>

      <label class="check"><input type="checkbox" bind:checked={editing.enabled} />
        <span class="t"><b>Rule active</b><span>Disabled rules are not sent to the agents.</span></span></label>
      {#if error}<p class="error" style="margin:12px 0 0">{error}</p>{/if}
    </form>
    {#snippet actions()}
      <button type="button" class="btn" onclick={() => (editing = null)}>Cancel</button>
      <button type="submit" form="rule-form" class="btn primary">Save</button>
    {/snippet}
  </Modal>
{/if}

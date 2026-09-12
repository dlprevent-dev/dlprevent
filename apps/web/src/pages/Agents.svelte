<script lang="ts">
  import { go, handoff, showAlertsFor } from '../lib/router.svelte';
  import { onMount } from 'svelte';
  import { resource } from '../lib/resource.svelte';
  import { agentOutdated, api, ago, certState, fmtBytes, fmtTime, fmtUtc, platformFor, updateStuck } from '../lib/api';
  import { notify, isAdmin } from '../lib/session.svelte';
  import { createSort, sortRows, matches } from '../lib/sort.svelte';
  import type { Agent, Binary, LogRow, ReleaseView, Token, TokenCreated } from '../lib/types';
  import Modal from '../lib/Modal.svelte';
  import Icon from '../lib/Icon.svelte';
  import PageHead from '../lib/PageHead.svelte';
  import SearchBox from '../lib/SearchBox.svelte';
  import SortHeader from '../lib/SortHeader.svelte';
  import { ask } from '../lib/confirm.svelte';

  let uploading = $state<string | null>(null);
  let created = $state<TokenCreated | null>(null);
  let label = $state('');
  let hours = $state(24);
  /// Only decides which command the dashboard offers for copying — the token
  /// itself is valid for every kind.
  let platform = $state<'mac' | 'linux' | 'windows_server' | 'windows_client'>('mac');
  /// Windows is the only platform with a role underneath it, so the dialog
  /// asks this twice and the answer belongs in one place.
  const isWindows = $derived(platform === 'windows_client' || platform === 'windows_server');
  let showToken = $state(false);
  let expanded = $state<string | null>(null);
  // Log of the expanded agent. Only one: it is fetched on expanding and
  // refreshed together with the list every 15 seconds.
  let log = $state<LogRow[]>([]);
  let logLevel = $state('');
  let logQ = $state('');
  let logError = $state('');
  let logLoading = $state(false);
  let logTimer: ReturnType<typeof setTimeout> | undefined;
  let q = $state('');
  const sort = createSort('name');
  const tokenSort = createSort('created', { descFirst: true });
  const admin = $derived(isAdmin());
  const kinds: Record<string, string> = { mac: 'macOS', linux: 'Linux', windows_server: 'Windows Server', windows_client: 'Windows Client' };
  /// Not the same list: `kinds` names an agent's role, this one names the
  /// binary's platform (`Binary.platform`), where the two Windows roles share
  /// a single file.
  const platformNames: Record<string, string> = { windows: 'Windows', mac: 'macOS' };
  /// The glob names the architecture on purpose: a plain `deelpe_*.deb` in a
  /// directory holding both builds matches the wrong one just as happily,
  /// and `dpkg` only says so once it is on the target machine.
  const DEB_INSTALL = 'sudo apt install ./deelpe_*_amd64.deb\nsudo systemctl enable --now deelpe';

  const res = resource(async () => {
    const r = await Promise.all([api<Agent[]>('/api/agents'), api<Token[]>('/api/tokens'), api<Binary[]>('/api/binaries')]);
    // The expanded log belongs to the same round: otherwise the row shows a
    // fresh list above a stale log.
    if (expanded) await loadLog();
    return r;
  }, { poll: 15000 });
  const load = res.reload;
  const agents = $derived(res.data?.[0] ?? []);
  const tokens = $derived(res.data?.[1] ?? []);
  const binaries = $derived(res.data?.[2] ?? []);

  /// Where the file sits on the device. Shown in the dashboard so that
  /// somebody on site can keep reading where the central server's reach ends
  /// — and so they still have something when the agent no longer reports.
  function logPath(a: Agent) {
    return a.kind.startsWith('windows') ? 'C:\\ProgramData\\deelpe\\agent.log' : '/var/lib/deelpe/agent.log';
  }

  async function loadLog() {
    const id = expanded;
    if (!id) return;
    const level = logLevel, term = logQ.trim();
    logLoading = true;
    try {
      const p = new URLSearchParams({ limit: '300' });
      if (level) p.set('level', level);
      // Shorter terms are filtered out by the server.
      if (term.length > 2) p.set('q', term);
      const r = await api<LogRow[]>(`/api/agents/${id}/log?` + p);
      // The 15-second refresh and a click on a filter can overtake each
      // other. Only take what matches what is currently set on screen —
      // otherwise every level would sit under a highlighted "Error"
      // button.
      if (expanded !== id || logLevel !== level || logQ.trim() !== term) return;
      log = r;
      logError = '';
    } catch (e) {
      logError = (e as Error).message;
    } finally {
      logLoading = false;
    }
  }

  function toggle(a: Agent) {
    if (expanded === a.id) { expanded = null; return; }
    expanded = a.id;
    log = [];
    logError = '';
    loadLog();
  }

  function logSearch() { clearTimeout(logTimer); logTimer = setTimeout(loadLog, 250); }

  /// Which binary belongs to the role in the enrollment dialog? Workstation
  /// and file server share the same EXE on Windows — the role decides the
  /// enrollment, not the file.
  function binFor(p: string): Binary | undefined {
    // The enrollment dialog carries the role (`windows_server`), the table
    // the same one — both go through the same mapping as the server.
    return binaries.find((b) => b.platform === platformFor(p));
  }

  /// With the master switch on, uploading is rolling out at the same time:
  /// whatever lands here is picked up by the agents on their next report. On
  /// 2026-09-10 we walked into exactly that in the lab — an old file was
  /// still staged, and the file server replaced itself with a build without
  /// self-renewal. After that only the manual route helped.
  ///
  /// Hence the same confirmation as for fetching from a release, and hence it
  /// says what is currently running: a checksum you recognise is the only
  /// protection against a slip.
  async function uploadBinary(platform: string, file: File) {
    const cur = binaries.find((b) => b.platform === platform);
    const running = [...new Set(agents.filter((a) => platformFor(a.kind) === platform && a.status?.build).map((a) => a.status!.build!))];
    if (rel?.rolls_out_at_once) {
      if (!(await ask({
        title: 'Upload and roll out',
        body: `"${file.name}" replaces ${cur?.present ? cur.file_name : 'nothing'} on the server — and goes straight to the agents.`,
        detail:
          '"Update agents from here" is on, so every agent running something else picks this up on its next report, within about half a minute.' +
          (running.length ? ` Right now they run: ${running.join(', ')}. Make sure this file is newer than that — an agent replaced by an older one cannot update itself again.` : ''),
        confirmLabel: 'Upload and roll out',
        danger: true,
      }))) return;
    }
    uploading = platform;
    try {
      await api(`/api/binaries/${platform}`, { method: 'POST', body: file });
      notify(`${file.name} uploaded`);
      await load();
      // The command carries the checksum of the binary — after an upload the
      // old one is out of date. Creating a new one costs a token, so only a
      // hint.
      if (created) notify('Create the token again so the command picks up the new file', true);
    } catch (e) {
      notify(`Upload failed: ${e instanceof Error ? e.message : e}`, true);
    } finally {
      uploading = null;
    }
  }

  function pickFile(platform: string) {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = platform === 'windows' ? '.exe' : '.zip';
    input.onchange = () => { const f = input.files?.[0]; if (f) uploadBinary(platform, f); };
    input.click();
  }
  onMount(() => () => clearTimeout(logTimer));

  /// Create a rule from a share: path and agent are set by that, the rest is
  /// filled in by the form on the rules page.
  function ruleFromShare(a: Agent, sh: { name: string; path?: string }) {
    if (!sh.path) return;
    handoff.rule = { path: sh.path, name: sh.name, agent_id: a.id };
    go('/rules');
  }

  function agentState(a: Agent) { return a.revoked_at ? 'revoked' : a.online ? 'online' : 'offline'; }
  /// Prefer the agent's own addresses as it reports them. Behind a proxy,
  /// Docker or a tunnel the server only sees the last hop (last_addr), which
  /// is then identical for every agent and worthless.
  ///
  /// If an agent reports nothing (build too old), the hop is marked as such
  /// instead of being printed as the device address. Without that the
  /// dashboard convincingly shows the wrong address, and the next
  /// investigation starts in the wrong place — on 2026-09-07 exactly that
  /// happened: an agent on an old build stood there with the Docker gateway.
  function agentAddr(a: Agent): string {
    const own = a.status?.addrs;
    if (own && own.length) return own.join(', ');
    return a.last_addr ? `via ${a.last_addr}` : '–';
  }

  const view = $derived(sortRows(
    agents.filter((a) => matches(`${a.name} ${a.id} ${kinds[a.kind] ?? a.kind} ${a.version} ${a.status?.build ?? ''} ${agentAddr(a)} ${agentState(a)} ${a.status?.hostname ?? ''} ${a.status?.fqdn ?? ''}`, q)),
    sort,
    (a, k) => ({ name: a.name, kind: kinds[a.kind] ?? a.kind, version: a.version, state: agentState(a), seen: a.last_seen, addr: agentAddr(a), cert: a.cert_not_after }[k]),
  ));

  const tokenView = $derived(sortRows(tokens, tokenSort, (t, k) => ({
    label: t.label, created: t.created_at, expires: t.expires_at,
    state: t.used_at ? 'used' : new Date(t.expires_at) < new Date() ? 'expired' : 'open',
  }[k])));

  async function createToken(e: Event) {
    e.preventDefault();
    try { created = await api<TokenCreated>('/api/tokens', { method: 'POST', body: { label, hours, platform } }); label = ''; load(); } catch (err) { notify((err as Error).message, true); }
  }
  async function copy(t: string) { await navigator.clipboard.writeText(t); notify('Copied'); }
  async function revoke(a: Agent) {
    if (!(await ask({ title: 'Revoke agent', body: `"${a.name}" will no longer be let in.`, detail: 'Its certificate is rejected from the next report on. The device keeps running and keeps its local log; it just cannot report any more.', confirmLabel: 'Revoke', danger: true }))) return;
    try { await api(`/api/agents/${a.id}`, { method: 'DELETE' }); notify('Agent revoked'); load(); } catch (err) { notify((err as Error).message, true); }
  }
  /// Let this one agent fetch its binary. The master switch under Settings
  /// applies to all of them — this is about the first device, before the
  /// whole workforce's turn.
  async function updateAgent(a: Agent) {
    const bin = binFor(a.kind);
    if (!(await ask({ title: 'Update this agent', body: `"${a.name}" will replace its program with ${bin?.file_name ?? 'the uploaded one'}.`, detail: 'It fetches the file on its next report, checks the checksum and restarts into it. If the new program does not come up, the agent goes offline and the previous one is still on the device as .old.', confirmLabel: 'Update' }))) return;
    try { await api(`/api/agents/${a.id}/update`, { method: 'POST' }); notify('Update requested — it goes out with the next report'); load(); } catch (err) { notify((err as Error).message, true); }
  }
  // Delete only after revoking: the revocation locks the certificate out,
  // the delete merely tidies up the list.
  async function deleteAgent(a: Agent) {
    if (!(await ask({ title: 'Delete agent for good', body: `"${a.name}" disappears from the list.`, detail: 'Its alerts stay — they are the record. Rules that applied only to this device, and its access counts, go with it.', confirmLabel: 'Delete', danger: true }))) return;
    try { await api(`/api/agents/${a.id}/delete`, { method: 'DELETE' }); notify('Agent deleted'); load(); } catch (err) { notify((err as Error).message, true); }
  }
  /// What the release has on offer. Administrators only — a viewer cannot
  /// fetch anything anyway.
  let rel = $state<ReleaseView | null>(null);
  let relBusy = $state('');
  async function loadRelease() {
    if (!admin) return;
    try { rel = await api<ReleaseView>('/api/release'); } catch { rel = null; }
  }
  onMount(loadRelease);

  async function checkRelease() {
    relBusy = 'check';
    try { await api('/api/release/check', { method: 'POST' }); await loadRelease(); notify('Checked'); }
    catch (e) { notify((e as Error).message, true); await loadRelease(); }
    finally { relBusy = ''; }
  }

  /// Fetching is **not** rolling out: the file lands in the staging slot,
  /// onto the devices it is carried afterwards by the button on the row or by
  /// the master switch. The dialog says so too, so that nobody believes they
  /// have already distributed it.
  async function fetchRelease() {
    // The dialog has to tell the truth, and the truth hangs on the master
    // switch: with it on, the agents fetch the binary by themselves on their
    // next report — then fetching is rolling out at the same time.
    if (!(await ask({
      title: rel?.rolls_out_at_once ? 'Fetch and roll out' : 'Fetch this version',
      body: `${rel?.tag ?? 'The latest release'} is downloaded and its signature checked against the configured key.`,
      detail: rel?.rolls_out_at_once
        ? '"Update agents from here" is on, so this does not stop at the server: every agent picks the new program up on its next report, within about half a minute. Switch it off first if you want to try one device.'
        : 'Nothing is rolled out by this. The program lands on the server, ready to send to agents — that stays a separate, deliberate step.',
      confirmLabel: rel?.rolls_out_at_once ? 'Fetch and roll out' : 'Fetch',
      danger: rel?.rolls_out_at_once,
    }))) return;
    relBusy = 'fetch';
    try {
      const r = await api<{ tag: string; platforms: string[]; refused: string[] }>('/api/release/fetch', { method: 'POST' });
      // What was refused must not get lost: a build that only half arrived
      // is exactly what you go looking for later.
      if (r.refused.length) notify(`${r.tag}: ${r.platforms.join(', ')} stored, refused ${r.refused.join('; ')}`, true);
      else notify(`${r.tag} stored for ${r.platforms.join(', ')}${rel?.rolls_out_at_once ? ' — agents pick it up now' : ' — roll it out when you are ready'}`);
      await Promise.all([loadRelease(), load()]);
    } catch (e) { notify((e as Error).message, true); }
    finally { relBusy = ''; }
  }

  async function delToken(t: Token) {
    try { await api(`/api/tokens/${t.id}`, { method: 'DELETE' }); load(); } catch (err) { notify((err as Error).message, true); }
  }
</script>

<PageHead title="Agents">
  {#snippet actions()}
    {#if admin}<button class="btn primary" onclick={() => { showToken = true; created = null; }}><Icon name="plus" size={15} /> Enroll agent</button>{/if}
  {/snippet}
</PageHead>

{#if admin}
  {@const fresh = rel?.tag && rel.tag !== rel.installed_tag}
  <div class="card release">
    <!-- What sits here is two things in one: the binary the enrollment
         command installs, and the one an agent fetches when it renews. The
         start of the checksum is deliberately shown large — it is the same
         value as in the "Version" column of the table below, so you can see
         without any arithmetic who is already on it. -->
    <div class="bins">
      <div class="binhead">Agent programs<span class="spacer"></span><span class="muted">what the enrollment command installs</span></div>
      <!-- Windows only, as long as nothing else is staged. The Mac service
           sits inside a bundle and cannot replace itself
           (`binaries::self_replacing_platform`) — a row saying "nothing
           stored" that nobody needs only makes the card restless. If one is
           staged after all, it appears here and can be replaced; uploading it
           still works from the enrollment dialog. -->
      {#each binaries.filter((b) => b.platform === 'windows' || b.present) as b (b.platform)}
        <div class="bin">
          <b class="plat">{platformNames[b.platform] ?? b.platform}</b>
          <div>
            <span class="mono">{b.file_name}</span>
            {#if b.present}
              <div class="cell-2">
                <span class="mono" title="SHA-256 of the file; the first twelve characters appear in the Version column">{b.sha256.slice(0, 12)}</span>
                <span class="muted">· {fmtBytes(b.size)}{b.uploaded_at ? ` · ${fmtTime(b.uploaded_at)}` : ''}</span>
              </div>
            {:else}
              <div class="cell-2 muted">nothing stored — the enrollment command can only enrol, not install</div>
            {/if}
          </div>
          <span class="spacer"></span>
          <button class="btn sm" disabled={uploading === b.platform}
                  onclick={() => pickFile(b.platform)}>
            {uploading === b.platform ? 'Uploading…' : b.present ? 'Replace' : 'Upload'}
          </button>
        </div>
      {/each}
      <!-- Not a gap and not a "nothing stored yet": Linux never gets a file
           here. The `.deb` is built per architecture, and `apt` owns the
           updates — `binaries::platform_for` returns `None` for it. Saying so
           beats letting somebody hunt for an upload button that would be
           wrong even if it existed. -->
      <div class="bin">
        <b class="plat">Linux</b>
        <div>
          <span class="muted">not kept here — <span class="mono">apt</span> owns it</span>
          <div class="cell-2 muted">The <span class="mono">.deb</span> is per architecture and goes out through your own channel; from here comes only the enrollment command.</div>
        </div>
      </div>
    </div>
    <div class="rel-row">
      <div>
        <b>Release</b>
        <div class="cell-2">
          {#if rel?.error}
            <span class="badge bad">check failed</span> <span class="muted">{rel.error}</span>
          {:else if fresh}
            <span class="badge warn">{rel.tag} available</span>
            <span class="muted">{rel!.installed_tag ? `you fetched ${rel!.installed_tag}` : 'nothing fetched here yet'}{rel!.platforms.length ? ` · ${rel!.platforms.join(', ')}` : ''}</span>
          {:else if rel?.tag}
            <span class="badge ok">{rel.tag} is what you have</span>
            {#if rel!.installed_platforms.length && rel!.installed_platforms.length < 2}
              <span class="muted">for {rel.installed_platforms.join(', ')} — the other program is whatever was stored before</span>
            {/if}
          {:else if !rel?.repo}
            <span class="muted">No repository configured — new versions arrive by upload only. Settings, Interfaces.</span>
          {:else}
            <span class="muted">not checked yet</span>
          {/if}
          {#if rel?.repo && !rel.key_set}
            <div class="muted">No signing key configured — nothing from a release is trusted. Settings, Interfaces.</div>
          {/if}
        </div>
      </div>
      <span class="spacer"></span>
      {#if rel?.url}<a class="btn sm ghost" href={rel.url} target="_blank" rel="noreferrer noopener">Release notes</a>{/if}
      <button class="btn sm" disabled={!!relBusy || !rel?.repo} onclick={checkRelease}>{relBusy === 'check' ? 'Checking…' : 'Check now'}</button>
      {#if fresh && rel?.key_set && rel.platforms.length}
        <button class="btn sm primary" disabled={!!relBusy} onclick={fetchRelease}>{relBusy === 'fetch' ? 'Fetching…' : 'Fetch'}</button>
      {/if}
    </div>
  </div>
{/if}

<div class="toolbar">
  <SearchBox bind:value={q} placeholder="Name, address, version, state…" />
  <span class="spacer"></span>
  <span class="muted small">{view.length} of {agents.length}</span>
</div>

<div class="card" style="margin-bottom:18px">
  {#if res.loading}
    <div style="padding:16px" class="stack">{#each Array(3) as _}<div class="skel"></div>{/each}</div>
  {:else if res.error}
    <p class="error" style="padding:16px">{res.error}</p>
  {:else if view.length === 0}
    <div class="empty">
      <span class="ico"><Icon name={agents.length ? 'search' : 'agents'} size={26} /></span>
      <b>{agents.length ? 'Nothing found' : 'No agents yet'}</b>
      <span>{agents.length ? 'Try other words.' : '"Enroll agent" creates a token and the command to run on the device.'}</span>
    </div>
  {:else}
  <div class="tablewrap">
    <table>
      <thead><tr>
        <SortHeader {sort} key="name" label="Name" />
        <SortHeader {sort} key="kind" label="Kind" />
        <SortHeader {sort} key="version" label="Version" />
        <SortHeader {sort} key="state" label="State" />
        <SortHeader {sort} key="seen" label="Last report" />
        <SortHeader {sort} key="addr" label="Address" />
        <SortHeader {sort} key="cert" label="Certificate until" />
        <th><span class="th"></span></th>
      </tr></thead>
      <tbody>
        {#each view as a (a.id)}
          {@const cert = certState(a.cert_not_after)}
          <tr class="click" class:open={expanded === a.id} onclick={() => toggle(a)}>
            <td><strong>{a.name}</strong><div class="cell-2 mono">{a.id}</div></td>
            <td>{kinds[a.kind] ?? a.kind}</td>
            <td class="mono">{a.version || '–'}{#if a.status?.build}<div class="cell-2 mono" title="First 12 characters of the agent file's SHA-256 — compare with Get-FileHash on the device">{a.status.build}</div>{/if}
              {#if agentOutdated(a, binaries)}<div class="cell-2"><span class="badge warn" title="This agent runs a different program than the one uploaded here. With &quot;Update agents from here&quot; on (Settings → Interfaces) it fetches the new one by itself on its next report; otherwise roll it out the way you always do.">outdated</span></div>{/if}</td>
            <td>{#if a.revoked_at}<span class="badge bad">revoked</span>{:else if a.online}<span class="badge ok"><span class="dot"></span> online</span>{:else}<span class="badge warn"><span class="dot"></span> offline</span>{/if}</td>
            <td class="nowrap">{ago(a.last_seen)}</td>
            <td class="mono">{agentAddr(a)}</td>
            <td class="nowrap">
              {#if cert === 'ok'}{fmtTime(a.cert_not_after)}
              {:else}
                {#if cert === 'expired'}
                  <span class="badge bad" title="The agent can no longer connect — renewal needs a certificate that still works. Enroll the device again, then revoke and delete this entry.">expired</span>
                {:else}
                  <span class="badge warn" title="The agent renews it by itself on its next report.">renews now</span>
                {/if}
                <div class="cell-2">{fmtTime(a.cert_not_after)}</div>
              {/if}
            </td>
            <td class="nowrap">
              <button class="btn sm ghost" onclick={(e) => { e.stopPropagation(); showAlertsFor({ agent: a.id, name: a.name }); }} title="Show only alerts from this agent">Alerts</button>
              {#if admin}
                {#if a.revoked_at}
                  <button class="btn sm ghost danger" onclick={(e) => { e.stopPropagation(); deleteAgent(a); }}>Delete</button>
                {:else}
                  {#if a.update_requested && updateStuck(a)}
                    <button class="btn sm ghost danger" onclick={(e) => { e.stopPropagation(); updateAgent(a); }} title="Requested {fmtTime(a.update_requested)}, and the agent has reported since without acting on it. Almost always this means it runs a version from before self-update and cannot see the order — that one version has to be rolled out by hand once (docs/INSTALL.md). Its own log, below, says so if it tried and failed.">not picked up</button>
                  {:else if a.update_requested}
                    <button class="btn sm ghost" disabled title="Requested {fmtTime(a.update_requested)} — it goes out with the agent's next report and clears itself once the agent runs the uploaded program.">Update sent</button>
                  {:else if agentOutdated(a, binaries)}
                    <button class="btn sm ghost" onclick={(e) => { e.stopPropagation(); updateAgent(a); }} title="Have this one agent fetch the uploaded program on its next report — without the switch under Settings, which applies to all of them.">Update</button>
                  {/if}
                  <button class="btn sm ghost danger" onclick={(e) => { e.stopPropagation(); revoke(a); }}>Revoke</button>
                {/if}
              {/if}
            </td>
          </tr>
          {#if expanded === a.id}
            <tr class="sub"><td colspan="8">
              {#if a.status}
                <div class="kv">
                  <span class="k">Host</span><span>{a.status.hostname}{#if a.status.fqdn}<div class="cell-2 mono" title="Fully qualified name. The short name above is resolved by mechanisms that can be spoofed — this is the one that counts as evidence.">{a.status.fqdn}</div>{/if}</span>
                  <span class="k">Service running since</span><span>{fmtTime(a.status.started_at)}</span>
                  <span class="k">Learning phase</span><span>{a.status.learn_phase}</span>
                  <span class="k">Sensors</span><span>{#each a.status.sensors as s}<span class="badge {s.ok ? 'ok' : 'bad'}" title={s.error ?? ''}><span class="dot"></span> {s.name}</span> {/each}</span>
                  <span class="k">Protected folders</span><span>{#each a.status.watched as w}<div class="mono">{w}</div>{:else}<span class="muted">none</span>{/each}</span>
                  {#if a.status.shares?.length}
                    <span class="k">Shares</span>
                    <span>
                      {#each a.status.shares as sh}
                        <div class="share">
                          <span class="mono">{sh.name}</span>
                          {#if sh.path}<span class="mono muted">{sh.path}</span>
                          {:else}<span class="muted">path not readable — the service account may not read the share table</span>{/if}
                          {#if sh.path_from === 'events'}<span class="badge" title="Learned from access events, not from the share table">learned</span>{/if}
                          {#if admin && sh.path}
                            <button class="btn sm ghost" onclick={(e) => { e.stopPropagation(); ruleFromShare(a, sh); }}>Create rule</button>
                          {/if}
                        </div>
                      {/each}
                    </span>
                  {/if}
                  <span class="k">Fingerprint</span><span class="mono">{a.cert_fingerprint}</span>
                </div>
              {:else}<span class="muted">No status report yet.</span>{/if}

              <!-- The device's log. It comes in line by line with the
                   reports, so also what happened during an outage —
                   delivered later, as soon as the agent gets through
                   again. -->
              <div class="logbox">
                <div class="logbar">
                  <b>Log</b>
                  <div class="seg">
                    {#each [['', 'All'], ['info', 'Info'], ['warn', 'Warn'], ['error', 'Error']] as [v, l]}
                      <button type="button" class:on={logLevel === v} onclick={() => { logLevel = v; loadLog(); }}>{l}</button>
                    {/each}
                  </div>
                  <input type="search" placeholder="Search the log…" bind:value={logQ} oninput={logSearch} aria-label="Search the log" />
                  <span class="spacer"></span>
                  <span class="muted small">on the device: <span class="mono">{logPath(a)}</span></span>
                </div>
                {#if logError}
                  <p class="error">{logError}</p>
                {:else if logLoading && log.length === 0}
                  <div class="stack">{#each Array(3) as _}<div class="skel"></div>{/each}</div>
                {:else if log.length === 0}
                  <p class="muted small">
                    Nothing yet. Lines arrive with the agent's next report — an agent on an older version does not
                    send any, and the file on the device is the full record either way.
                  </p>
                {:else}
                  <div class="loglines">
                    {#each log as l (l.id)}
                      <div class="logline {l.level}">
                        <span class="mono" title={fmtUtc(l.at)}>{fmtTime(l.at)}</span>
                        <span class="badge {l.level === 'error' ? 'bad' : l.level === 'warn' ? 'warn' : ''}">{l.level}</span>
                        <span class="msg">{l.msg}<span class="tgt">{l.target}</span></span>
                      </div>
                    {/each}
                  </div>
                {/if}
              </div>
            </td></tr>
          {/if}
        {/each}
      </tbody>
    </table>
  </div>
  {/if}
</div>

<div class="card">
  <div class="card-head"><h2>Enrollment tokens</h2><span class="spacer"></span><span class="muted small">good for exactly one enrollment</span></div>
  {#if tokens.length === 0}
    <div class="empty"><span class="ico"><Icon name="key" size={24} /></span><b>No tokens</b><span>Open tokens stay here until they are used or expire.</span></div>
  {:else}
  <div class="tablewrap">
    <table>
      <thead><tr>
        <SortHeader sort={tokenSort} key="label" label="Label" />
        <SortHeader sort={tokenSort} key="created" label="Created" />
        <SortHeader sort={tokenSort} key="expires" label="Valid until" />
        <SortHeader sort={tokenSort} key="state" label="State" />
        <th><span class="th"></span></th>
      </tr></thead>
      <tbody>
        {#each tokenView as t (t.id)}
          <tr>
            <td><strong>{t.label}</strong></td><td class="nowrap">{fmtTime(t.created_at)}</td><td class="nowrap">{fmtTime(t.expires_at)}</td>
            <td>{#if t.used_at}<span class="badge ok">used {ago(t.used_at)}</span>{:else if new Date(t.expires_at) < new Date()}<span class="badge">expired</span>{:else}<span class="badge accent">open</span>{/if}</td>
            <td class="nowrap">{#if admin && !t.used_at}<button class="btn sm ghost danger" onclick={() => delToken(t)} title="Delete" aria-label="Delete"><Icon name="trash" size={14} /></button>{/if}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {/if}
</div>

{#if showToken}
  <Modal title="Enroll agent" subtitle={created ? 'The token is shown only once.' : 'One token per device.'} onclose={() => (showToken = false)}>
    {#if !created}
      <form id="token-form" onsubmit={createToken}>
        <div class="row">
          <div class="field"><label for="tl">Label (device)</label><input id="tl" type="text" bind:value={label} placeholder="mac-hans, fileserver-01" required /></div>
          <div class="field" style="max-width:150px"><label for="th">Valid (hours)</label><input id="th" type="number" min="1" max="336" bind:value={hours} /></div>
        </div>
        <div class="field" style="margin-top:10px"><span class="lbl">Device</span>
          <div class="seg">
            <button type="button" class:on={platform === 'mac'} onclick={() => (platform = 'mac')}>macOS</button>
            <button type="button" class:on={platform === 'linux'} onclick={() => (platform = 'linux')}>Linux</button>
            <button type="button" class:on={isWindows} onclick={() => (platform = 'windows_client')}>Windows</button>
          </div>
          {#if platform === 'mac'}
            <div class="hint">Watches reads from the protected folders and outbound traffic of the same process.</div>
          {:else if platform === 'linux'}
            <div class="hint">
              The same, through fanotify and <span class="mono">ss</span>. The next screen gives you both commands:
              installing the <span class="mono">.deb</span>, which does not come from this server, and enrolling.
            </div>
          {/if}
        </div>

        {#if isWindows}
          <!-- One binary, two loops. The role is fixed at enrollment time;
               pick the wrong one and it silently reports nothing (b2f776c).
               Hence one level deeper instead of next to the platform. -->
          <div class="field" style="margin-top:10px"><span class="lbl">Role</span>
            <div class="seg">
              <button type="button" class:on={platform === 'windows_client'} onclick={() => (platform = 'windows_client')}>Workstation</button>
              <button type="button" class:on={platform === 'windows_server'} onclick={() => (platform = 'windows_server')}>File server</button>
            </div>
            <div class="hint">
              {#if platform === 'windows_client'}
                Watches what processes read from the protected folders and where they send it — the only place an upload
                to a browser or an AI service can be seen. The file server cannot: for it, reading a file looks the same
                whether it is opened in Word or dropped into a chat.
              {:else}
                Watches who reads how much from the shares. Mass access raises an alert; a single file does not.
              {/if}
              Same program either way; the role is fixed at enrollment and can only be changed by enrolling again.
            </div>
          </div>
        {/if}
        <p class="hint" style="margin:0">The token is good for exactly one enrollment and is burned afterwards. The agent creates its own key; the central server only signs.</p>
      </form>
    {:else}
      {#if binFor(platform)?.present}
        <p style="margin-top:0">
          Run on the device {platform === 'mac' ? 'in Terminal' : 'in Windows PowerShell as administrator'}. It fetches
          <span class="mono">{binFor(platform)!.file_name}</span> ({fmtBytes(binFor(platform)!.size)}) from this
          server, checks the fingerprint and {created.enroll_command ? 'installs the app' : 'enrolls'}:
        </p>
      {:else if platform === 'linux'}
        <!-- Two commands, not one, and the first one says where the file
             comes from. Windows and macOS get their program from this server,
             Linux never does — so a dialog that only prints the enrolment
             leaves the reader with "install what, from where?", which is
             exactly the question this platform kept raising. -->
        <p style="margin-top:0">
          <b>1.</b> Install the package on the device. It does <b>not</b> come from this server — build it with
          <span class="mono">scripts/build-agent-deb.sh</span> or take it from your own apt repository
          (<span class="mono">apt install deelpe</span>), see INSTALL.md section 4. For arm64 machines, the
          <span class="mono">arm64</span> package instead:
        </p>
        <div class="copy"><code style="white-space:pre-wrap">{DEB_INSTALL}</code><button class="btn sm" onclick={() => copy(DEB_INSTALL)}><Icon name="copy" size={14} /> Copy</button></div>
        <p style="margin-bottom:6px"><b>2.</b> Enroll. Updates afterwards are <span class="mono">apt</span>'s job, not this dashboard's:</p>
      {:else}
        <p class="hint" style="margin-top:0">
          No agent program stored on the server for this platform, so the command below only enrolls — you have to
          bring the file onto the device yourself.
          {#if admin}
            <button class="btn sm" style="margin-left:6px" disabled={uploading === (platform === 'mac' ? 'mac' : 'windows')}
                    onclick={() => pickFile(platform === 'mac' ? 'mac' : 'windows')}>
              {uploading ? 'Uploading…' : 'Upload it now'}
            </button>
          {:else}
            An administrator can upload it here.
          {/if}
        </p>
      {/if}
      <div class="copy"><code style="white-space:pre-wrap">{created.command}</code><button class="btn sm" onclick={() => copy(created!.command)}><Icon name="copy" size={14} /> Copy</button></div>
      {#if created.enroll_command}
        <p style="margin-bottom:6px">
          Then in the app, lock icon in the menu bar: <strong>Install service…</strong>. It asks for the admin
          password and puts <span class="mono">/usr/local/bin/deelpe</span> in place — until it has, the command
          below does not exist on the device. Only then:
        </p>
        <div class="copy"><code style="white-space:pre-wrap">{created.enroll_command}</code><button class="btn sm" onclick={() => copy(created!.enroll_command!)}><Icon name="copy" size={14} /> Copy</button></div>
      {/if}
      <div class="kv small" style="margin-top:14px">
        <span class="k">Central server (agents)</span><span class="mono">{created.agent_url}</span>
        <span class="k">CA SHA-256</span><span class="mono">{created.ca_sha256}</span>
        <span class="k">Token valid until</span><span>{fmtTime(created.expires_at)}</span>
      </div>
      <p class="hint">If the server answers under a different name than in the command, adjust the address; the CA fingerprint stays the same.</p>
    {/if}
    {#snippet actions()}
      {#if !created}
        <button type="button" class="btn" onclick={() => (showToken = false)}>Cancel</button>
        <button type="submit" form="token-form" class="btn primary">Create token</button>
      {:else}
        <button class="btn primary" onclick={() => (showToken = false)}>Done</button>
      {/if}
    {/snippet}
  </Modal>
{/if}

<style>
  .release { margin-bottom: 14px; padding: 12px 14px; }
  .rel-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .bins { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
  .bin { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  /* A fixed width, so the file names line up under one another and the eye
     finds the platform before it reads anything. */
  .bin .plat { min-width: 74px; flex: none; }
  .binhead { display: flex; align-items: baseline; gap: 10px; font-weight: 600; margin-bottom: 2px; }
  .bin .spacer { flex: 1; }
  .rel-row .spacer { flex: 1; }

  .logbox { margin-top: 14px; border-top: var(--rule); padding-top: 12px; }
  .logbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
  .logbar input { width: 200px; }
  /* A fixed line height would be wrong: an error message with paths is long,
     and truncated it helps nobody. */
  .loglines { max-height: 340px; overflow-y: auto; border: var(--rule); background: var(--panel); }
  .logline { display: grid; grid-template-columns: 150px 62px minmax(0, 1fr); gap: 10px; align-items: baseline; padding: 4px 10px; border-top: var(--rule); font-size: 12px; }
  .logline:first-child { border-top: 0; }
  .logline.error { background: var(--bad-2); }
  .logline.warn { background: var(--warn-2); }
  .msg { overflow-wrap: anywhere; }
  /* The module name says which part of the agent is speaking — important
     enough to stand there, unimportant enough not to glow. */
  .tgt { color: var(--muted); font-family: var(--font-mono); font-size: 10.5px; margin-left: 8px; }
</style>

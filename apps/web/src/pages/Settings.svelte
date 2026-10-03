<script lang="ts">
  import { onMount } from 'svelte';
  import { api, fmtTime } from '../lib/api';
  import { notify, isAdmin } from '../lib/session.svelte';
  import type { ApiKey, ApiKeyCreated, AssistProbe, AssistView, NotifyView, ReputationView, Settings } from '../lib/types';
  import Icon from '../lib/Icon.svelte';
  import Modal from '../lib/Modal.svelte';
  import PageHead from '../lib/PageHead.svelte';
  import { ask } from '../lib/confirm.svelte';

  let s = $state<Settings | null>(null);
  let error = $state('');
  let busy = $state(false);
  const admin = $derived(isAdmin());
  onMount(async () => { try { s = await api<Settings>('/api/settings'); } catch (e) { error = (e as Error).message; } });

  /** One page per topic instead of one long scroll: the settings keep
   *  growing, and whoever wants the save button should not have to hunt for
   *  it — it sits in the same place under every tab. */
  const TABS = [
    { id: 'general', label: 'General', icon: 'settings' },
    { id: 'detection', label: 'Detection', icon: 'shield' },
    { id: 'retention', label: 'Retention', icon: 'chart' },
    { id: 'interfaces', label: 'Interfaces', icon: 'key' },
    { id: 'signin', label: 'Sign-in', icon: 'lock' },
    { id: 'reputation', label: 'Reputation', icon: 'search' },
    { id: 'assistant', label: 'Assistant', icon: 'edit' },
    { id: 'notify', label: 'Notifications', icon: 'mail' },
  ] as const;
  type Tab = (typeof TABS)[number]['id'];
  /** The tab survives a reload: someone working on AbuseIPDB does not land
   *  back on "Detection" after saving. `localStorage` does not exist when
   *  rendering on the server and not always in a private window; both
   *  accesses therefore have to be wrapped. */
  function storedTab(): Tab {
    try {
      const t = localStorage.getItem('settings.tab');
      return TABS.some((x) => x.id === t) ? (t as Tab) : 'detection';
    } catch { return 'detection'; }
  }
  let tab = $state<Tab>(storedTab());
  function pick(t: Tab) { tab = t; try { localStorage.setItem('settings.tab', t); } catch { /* private window */ } }

  /** `key` overrides the key field: empty leaves the stored one in place, a
   *  dash deletes it (see `api::settings`). */
  async function save(e: Event, key?: string, aiKey?: string) {
    e.preventDefault(); error = ''; busy = true;
    try {
      s = await api<Settings>('/api/settings', { method: 'PUT', body: { ...s, abuseipdb_key: key ?? keyDraft.trim(), smtp_pass: mailPass.trim(), assist_key: aiKey ?? aiKeyDraft.trim() } });
      keyDraft = '';
      mailPass = '';
      aiKeyDraft = '';
      notify('Settings saved');
      loadRep();
      loadNotify();
      loadAssist();
    } catch (err) { error = (err as Error).message; } finally { busy = false; }
  }

  // ---------- AbuseIPDB ----------
  /** The key is never handed out; the field is therefore always empty and is
   *  only sent along on save when something is actually in it. */
  let keyDraft = $state('');
  let rep = $state<ReputationView | null>(null);
  async function loadRep() {
    if (!admin) return;
    try { rep = await api<ReputationView>('/api/reputation'); } catch { rep = null; }
  }
  onMount(loadRep);
  /** A single dash is the server's sign for delete. */
  async function dropKey(e: Event) {
    if (!s || !(await ask({ title: 'Remove the AbuseIPDB key', body: 'Reputation lookups stop.', detail: 'What has already been looked up is kept, so existing alerts keep their score.', confirmLabel: 'Remove', danger: true }))) return;
    save(e, '-');
  }
  const paused = $derived(rep?.paused_until && new Date(rep.paused_until).getTime() > Date.now() ? rep.paused_until : null);

  // ---------- AI assistance ----------
  /** Like the AbuseIPDB key: the field is always empty, the server never
   *  sends the stored one back. Ollama needs none at all. */
  let aiKeyDraft = $state('');
  let assist = $state<AssistView | null>(null);
  let probing = $state(false);
  async function loadAssist() {
    if (!admin) return;
    try { assist = await api<AssistView>('/api/assist'); } catch { assist = null; }
  }
  onMount(loadAssist);
  async function dropAiKey(e: Event) {
    if (!s || !(await ask({ title: 'Remove the AI API key', body: 'Explanations stop, unless the endpoint needs no key.', detail: 'Explanations already written stay — they are the record of what the model said.', confirmLabel: 'Remove', danger: true }))) return;
    save(e, undefined, '-');
  }
  /** Checks address, key and model name in one go — without an alert leaving
   *  the building. With the **stored** state, so save first. */
  async function probe() {
    probing = true;
    try {
      const r = await api<AssistProbe>('/api/assist/test', { method: 'POST' });
      notify(`${r.model} answered: ${r.reply}`);
      loadAssist();
    } catch (err) { notify((err as Error).message, true); } finally { probing = false; }
  }

  /** Presets for the two cases that actually come up. Otherwise you would
   *  have to type an address you must look up first — and the most common
   *  mistake is a missing `/v1`. */
  function preset(kind: 'ollama' | 'infomaniak') {
    if (!s) return;
    s.assist_base_url = kind === 'ollama' ? 'http://localhost:11434/v1' : 'https://api.infomaniak.com/2/ai/PRODUCT_ID/openai/v1';
    if (!s.assist_model) s.assist_model = kind === 'ollama' ? 'llama3.1:8b' : 'llama3';
  }

  // ---------- Mail ----------
  let mail = $state<NotifyView | null>(null);
  let mailPass = $state('');
  let testing = $state(false);
  async function loadNotify() {
    if (!admin) return;
    try { mail = await api<NotifyView>('/api/notifications'); } catch { mail = null; }
  }
  onMount(loadNotify);
  /** The test takes the **stored** settings, not the form: so save first,
   *  then send. That way the button checks what the worker will actually use
   *  later. */
  async function sendTest(e: Event) {
    error = ''; testing = true;
    try {
      await save(e);
      // `save` catches its own error; unchecked, the test would otherwise go
      // off with the old state and report success.
      if (error) return;
      mail = await api<NotifyView>('/api/notifications/test', { method: 'POST' });
      notify('Test email sent');
    } catch (err) { error = (err as Error).message; loadNotify(); } finally { testing = false; }
  }
  async function dropPass(e: Event) {
    if (!s || !(await ask({ title: 'Remove the SMTP password', body: 'Sending stops if the server needs one.', detail: 'The other mail settings stay as they are.', confirmLabel: 'Remove', danger: true }))) return;
    mailPass = '-';
    save(e);
  }

  // ---------- API keys ----------
  let keys = $state<ApiKey[]>([]);
  let keysError = $state('');
  /** The create dialog. As with users and enrollment: a modal, not a form
   *  row inside the card — that one never lined up cleanly with the fields
   *  above it. */
  let creating = $state(false);
  let form = $state({ label: '', days: 365 });
  /** The freshly created key in plaintext. The central server shows it
   *  exactly once; after that only the hash is there. */
  let fresh = $state<ApiKeyCreated | null>(null);

  async function loadKeys() {
    if (!admin) return;
    try { keys = await api<ApiKey[]>('/api/keys'); keysError = ''; } catch (e) { keysError = (e as Error).message; }
  }
  onMount(loadKeys);

  function openNew() { creating = true; fresh = null; keysError = ''; form = { label: '', days: 365 }; }

  async function createKey(e: Event) {
    e.preventDefault(); keysError = '';
    try { fresh = await api<ApiKeyCreated>('/api/keys', { method: 'POST', body: form }); loadKeys(); }
    catch (err) { keysError = (err as Error).message; }
  }
  async function removeKey(k: ApiKey) {
    if (!(await ask({ title: 'Delete API key', body: `"${k.label}" stops working at once.`, detail: 'Anything using it — scripts, integrations — loses access with the next request.', confirmLabel: 'Delete', danger: true }))) return;
    try { await api(`/api/keys/${k.id}`, { method: 'DELETE' }); notify('API key deleted'); loadKeys(); }
    catch (err) { notify((err as Error).message, true); }
  }
  async function copy(t: string) { await navigator.clipboard.writeText(t); notify('Copied'); }
  const expired = (k: ApiKey) => !!k.expires_at && new Date(k.expires_at).getTime() < Date.now();
</script>

<PageHead title="Settings" />

{#if !admin}
  <p class="error" style="background:var(--warn-2);color:var(--warn)"><Icon name="lock" size={13} /> Your account is read only. The values are shown for reference.</p>
{/if}
{#if error && !s}<p class="error">{error}</p>{/if}

{#if s}
<div class="settings">
  <nav class="tabs" aria-label="Settings sections">
    {#each TABS as t}
      <button type="button" class:on={tab === t.id} aria-current={tab === t.id ? 'page' : undefined} onclick={() => pick(t.id)}>
        <Icon name={t.icon} size={14} /> {t.label}
        {#if t.id === 'reputation' && rep?.last_error}<span class="dot" title="Lookups have a problem"></span>{/if}
        {#if t.id === 'notify' && mail?.last_error}<span class="dot" title="Sending has a problem"></span>{/if}
      </button>
    {/each}
  </nav>

  <div class="pane">
    <form class="card pad" onsubmit={save}>
      {#if tab === 'general'}
        <fieldset class="fset">
          <legend>General</legend>
            <div class="field" style="margin-bottom:0"><label for="ntz">Time zone</label>
              <input id="ntz" type="text" bind:value={s.report_timezone} disabled={!admin} autocomplete="off" spellcheck="false" placeholder="Europe/Zurich" />
              <div class="hint">IANA name, for the emails <em>and</em> every time shown here. One zone for everybody, so the same alert reads the same to two people at different desks. Summer and winter time follow from the name. Reload the page after saving.</div></div>
        </fieldset>

      {:else if tab === 'detection'}
        <fieldset class="fset">
          <legend>Detection</legend>
          <div class="field"><label for="ld">Learning phase (days)</label><input id="ld" type="number" min="0" max="90" bind:value={s.learn_days} disabled={!admin} />
            <div class="hint">Per rule and source: for that long only the hard limit applies, after that the learned baseline per user as well.</div></div>
          <div class="field" style="margin-bottom:0"><label for="ri">Agent report interval (seconds)</label><input id="ri" type="number" min="10" max="3600" bind:value={s.report_interval_secs} disabled={!admin} />
            <div class="hint">Agents report on this beat and pick up their rules while doing so. "Offline" means: three reports missed.</div></div>
        </fieldset>

        <fieldset class="fset">
          <legend>Processes without alerts</legend>
          <div class="field" style="margin-bottom:0"><label for="ap">Allowed processes</label>
            <textarea id="ap" class="mono" rows="5" bind:value={s.allow_processes} disabled={!admin} placeholder="# backup and sync clients&#10;onedrive.exe&#10;backup-agent.exe"></textarea>
            <div class="hint">One program name per line, <code>#</code> starts a comment. These processes produce no learning-phase, <code>new</code> or <code>deviation</code> alert on any agent.
              A <b>strict folder still applies</b>: a forbidden destination stays a <code>denied</code> alert and the intervention still happens. The list only removes the noise of a process you already know.
              Matching is by program name, so a piece of malware calling itself <code>teams.exe</code> gets past this list — but not past a strict folder.
              Agents pick the list up with their next report.</div></div>
        </fieldset>

      {:else if tab === 'retention'}
        <fieldset class="fset">
          <legend>Retention</legend>
          <div class="row">
            <div class="field" style="margin-bottom:0"><label for="ar">Alerts (days)</label><input id="ar" type="number" min="30" max={s.alert_retain_max_days} bind:value={s.alert_retain_days} disabled={!admin} /></div>
            <div class="field" style="margin-bottom:0"><label for="cr">Counts (days)</label><input id="cr" type="number" min="1" max="365" bind:value={s.count_retain_days} disabled={!admin} /></div>
          </div>
          <div class="hint">Alerts are the evidence: each is kept with its process chain, its timestamps and its destination, 30 to {s.alert_retain_max_days} days, two years by default. How long your record has to be kept is for your company and its lawyers to say. The hourly counts only feed the overview.</div>
        </fieldset>

      {:else if tab === 'interfaces'}
        <fieldset class="fset">
          <legend>Interfaces</legend>
          <div class="checks">
            <label class="check"><input type="checkbox" bind:checked={s.learn_push_enabled} disabled={!admin} />
              <span class="t"><b>Let the central server silence a pair on an agent</b>
              <span>Turns on "Remember" in the alert list: the agent learns that this process and destination belong together and stops reporting them. Leave it off if nobody needs it. Without it an unknown pair reports again on every flow.</span></span></label>
            <label class="check"><input type="checkbox" bind:checked={s.agent_update_enabled} disabled={!admin} />
              <span class="t"><b>Update agents from here</b>
              <span>An agent that runs a different program than the one uploaded under Agents fetches it on its next report, verifies the checksum and restarts into it. Off means the agent list only marks who is outdated and you roll out the way you always do. This replaces the program on every enrolled device — upload it under Agents first and check the checksum there.</span></span></label>
            <label class="check"><input type="checkbox" bind:checked={s.release_check_enabled} disabled={!admin} />
              <span class="t"><b>Watch for new agent versions</b>
              <span>Looks at the release repository below every six hours and says in the agent list when there is a newer version. It never downloads anything by itself — fetching is a click, and rolling out to the devices is another one.</span></span></label>
            <label class="check"><input type="checkbox" bind:checked={s.syslog_enabled} disabled={!admin} />
              <span class="t"><b>Syslog receiver (UDP and TCP)</b>
              <span>For NAS sources. Off means the port is not bound at all, not just ignored — syslog is unauthenticated and UDP is easy to forge, so an unused receiver should be closed. Takes effect within a few seconds.</span></span></label>
            <label class="check"><input type="checkbox" bind:checked={s.api_keys_enabled} disabled={!admin} />
              <span class="t"><b>API keys (access without signing in)</b>
              <span>The master switch for the keys below. Off means no key is accepted at all, however many exist — only a browser sign-in reaches the API. Switch it off to shut every integration out in one step, without deleting anything.</span></span></label>
          </div>
          <div class="field"><label for="relrepo">Release repository</label>
            <input id="relrepo" type="text" bind:value={s.release_repo} disabled={!admin} placeholder="owner/repo" autocomplete="off" />
            <div class="hint">Either <span class="mono">owner/repo</span> for GitHub, or the full API address of your own Gitea
              (<span class="mono">https://git.example.com/api/v1/repos/owner/repo</span>). Empty means nothing is watched.</div></div>
          <div class="field"><label for="reltok">Release access token</label>
            <input id="reltok" type="password" bind:value={s.release_token} disabled={!admin} autocomplete="off"
                   placeholder={s.release_token_set ? '••••••••  (leave empty to keep)' : 'only for a private repository'} />
            <div class="hint">Only needed if the repository is private — a public one needs nothing. Read access is enough.
              Empty keeps what is stored, a single <span class="mono">-</span> deletes it.</div></div>
          <div class="field" style="margin-bottom:0"><label for="relkey">Release signing key (public)</label>
            <input id="relkey" type="text" bind:value={s.release_pubkey} disabled={!admin || s.release_pubkey_built_in} autocomplete="off"
                   placeholder="base64, 32 bytes (ed25519)" />
            <div class="hint">
              {#if s.release_pubkey_built_in}
                A key is compiled into this server, and it wins — nothing here can replace it.
              {:else}
                Only a program carrying a signature from this key is accepted. A checksum from the release itself would prove
                nothing: whoever can change the release changes it too. Create the key with <span class="mono">deelpe-sign keygen</span>
                and keep the private half away from this server. Without a key nothing is ever fetched.
              {/if}
            </div></div>
          <div class="field"><label for="chrometok">Chrome enrollment token</label>
            <input id="chrometok" type="text" bind:value={s.chrome_enrollment_token} disabled={!admin} autocomplete="off"
                   placeholder="from Chrome Browser Cloud Management" />
            <div class="hint">Chrome blocks an upload before it leaves a strict folder only on a cloud-managed browser —
              without this it reads the policy but shows <span class="mono">Error</span> and lets the upload through. Paste the
              token from the Google Admin console (<span class="mono">Devices → Chrome → Managed browsers → Enroll</span>); the
              agent writes it to the browser on its next report. Empty = not enrolled. Firefox needs none of this.</div></div>
          <div class="field" style="margin-bottom:0"><label for="edgetok">Edge enrollment token</label>
            <input id="edgetok" type="text" bind:value={s.edge_enrollment_token} disabled={!admin} autocomplete="off"
                   placeholder="from the Microsoft Edge management service" />
            <div class="hint">The same for Microsoft Edge, from the Microsoft Edge management service in the Microsoft 365 admin
              center. Empty = not enrolled.</div></div>
        </fieldset>

      {:else if tab === 'signin'}
        <fieldset class="fset">
          <legend>Sign-in</legend>
          <div class="checks">
            <label class="check"><input type="checkbox" bind:checked={s.require_2fa_admin} disabled={!admin} />
              <span class="t"><b>Administrators need a second factor</b>
              <span>Authenticator app or passkey, set up under Account. An administrator without one sees only the Account page after signing in until it is done. Set up your own first — the server refuses to switch this on otherwise.</span></span></label>
            <label class="check"><input type="checkbox" bind:checked={s.require_2fa_viewer} disabled={!admin} />
              <span class="t"><b>Read-only accounts need a second factor</b>
              <span>Same rule for read-only accounts. Someone who loses the phone gets the factor reset under Users; the password stays.</span></span></label>
          </div>
        </fieldset>

      {:else if tab === 'reputation'}
        <fieldset class="fset">
          <legend>IP reputation (AbuseIPDB)</legend>
          <div class="checks">
            <label class="check"><input type="checkbox" bind:checked={s.abuseipdb_enabled} disabled={!admin} />
              <span class="t"><b>Check destination addresses against AbuseIPDB</b>
              <span>The central server looks up the destination address of every alert and shows how badly it is known. <strong>Only the IP address leaves this network</strong> — never a user, a process, a folder or a file name. Each address is asked at most once a week and the answer is cached here, so the same destination never costs the quota twice.</span></span></label>
          </div>

          <div class="field" style="margin-top:14px"><label for="ak">API key (v2)</label>
            <input id="ak" type="password" bind:value={keyDraft} disabled={!admin} autocomplete="off" spellcheck="false"
              placeholder={s.abuseipdb_key_set ? 'A key is stored — type a new one to replace it' : 'Paste the key from abuseipdb.com'} />
            <div class="hint">
              The key is stored on the server and never sent back to the browser.
              <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noreferrer noopener">Get a key at abuseipdb.com</a> — the free plan gives 1000 lookups a day.
            </div>
          </div>

          <div class="field" style="margin-bottom:0"><label for="dl">Lookups per day</label>
            <input id="dl" type="number" min="1" max="100000" bind:value={s.abuseipdb_daily_limit} disabled={!admin} />
            <div class="hint">The central server stops for the day once it has used this many. Set it to what your plan allows; running into the provider's own limit locks you out for longer.</div></div>
        </fieldset>

        {#if admin}
        <fieldset class="fset">
          <legend>Status</legend>
          {#if rep}
            <div class="kv">
              <span class="k">State</span>
              <span>
                {#if rep.last_error}<span class="badge warn">problem</span> {rep.last_error}
                {:else if !s.abuseipdb_enabled}<span class="badge">off</span> the switch above is off
                {:else if !s.abuseipdb_key_set}<span class="badge">off</span> no API key stored yet
                {:else}<span class="badge ok">active</span>{/if}
              </span>
              <span class="k">Today</span><span>{rep.today} of {rep.daily_limit} lookups{#if rep.today >= rep.daily_limit} — budget spent, resumes tomorrow{/if}</span>
              <span class="k">Cached</span><span>{rep.cached} addresses</span>
              <span class="k">Since restart</span><span>{rep.lookups} lookups</span>
              {#if paused}<span class="k">Paused until</span><span>{fmtTime(paused)}</span>{/if}
            </div>
          {:else}
            <p class="hint" style="margin:0">Status is not available.</p>
          {/if}
          <div class="row" style="margin-top:12px">
            <div style="flex:none"><button type="button" class="btn sm" onclick={loadRep}><Icon name="refresh" size={14} /> Refresh status</button></div>
            {#if s.abuseipdb_key_set}<div style="flex:none"><button type="button" class="btn sm ghost danger" onclick={dropKey}><Icon name="trash" size={14} /> Remove key</button></div>{/if}
          </div>
        </fieldset>
        {/if}

      {:else if tab === 'assistant'}
        <fieldset class="fset">
          <legend>AI assistance</legend>
          <div class="checks">
            <label class="check"><input type="checkbox" bind:checked={s.assist_enabled} disabled={!admin} />
              <span class="t"><b>Let a language model explain an alert on request</b>
              <span>An <b>Explain</b> button appears in every expanded alert. The central server gathers what you would otherwise look up by hand — the rule that matched, the destination's reputation, the same user's other alerts this week, the same process across the fleet, and the agent's log around that minute — and asks the model to summarise it in three short paragraphs. <strong>It never decides anything</strong>: no verdict changes, no alert is closed, no agent is instructed. Nothing is asked on its own; only what somebody clicks.</span></span></label>
          </div>

          <div class="field" style="margin-top:14px"><label for="ab">Base URL</label>
            <input id="ab" type="text" bind:value={s.assist_base_url} disabled={!admin} autocomplete="off" spellcheck="false"
              placeholder="http://localhost:11434/v1" />
            <div class="hint">
              Any OpenAI-compatible endpoint, <strong>without</strong> <code>/chat/completions</code> — the server appends that.
              {#if admin}
                Fill in for <button type="button" class="linkish" onclick={() => preset('ollama')}>Ollama</button>
                or <button type="button" class="linkish" onclick={() => preset('infomaniak')}>Infomaniak</button>.
              {/if}
              For Infomaniak, replace <code>PRODUCT_ID</code> with your own (<code>GET /1/ai</code> lists it).
            </div>
          </div>

          <div class="field"><label for="am">Model</label>
            <input id="am" type="text" bind:value={s.assist_model} disabled={!admin} autocomplete="off" spellcheck="false" placeholder="llama3.1:8b" />
            <div class="hint">Exactly as the endpoint spells it — <code>ollama list</code> on the machine that runs Ollama, or the provider's model list. A wrong name comes back as “model not found”, not as a bad answer.</div></div>

          <div class="field"><label for="ak2">API key</label>
            <input id="ak2" type="password" bind:value={aiKeyDraft} disabled={!admin} autocomplete="off" spellcheck="false"
              placeholder={s.assist_key_set ? 'A key is stored — type a new one to replace it' : 'Leave empty for Ollama in your own network'} />
            <div class="hint">Stored on the server and never sent back to the browser. Ollama needs none; Infomaniak needs its API token. Pointing the base URL at a <b>different host</b> drops the stored key — a key belongs to the service it was issued for.</div></div>

          <div class="field" style="margin-bottom:0"><label for="al">Explanations per day</label>
            <input id="al" type="number" min="1" max="10000" bind:value={s.assist_daily_limit} disabled={!admin} />
            <div class="hint">The server refuses further explanations once this many were asked for today. Asking the same alert again counts again — it costs again, and so does <b>Test connection</b>. The count comes from the audit log, so a restart does not reset it.</div></div>
        </fieldset>

        <fieldset class="fset">
          <legend>What leaves this network</legend>
          <p class="hint" style="margin-top:0">
            The dossier holds alert metadata: user name, process, folder and file <em>names</em>, destination address, rule, and the agent's log lines around the event.
            <strong>Never file contents</strong> — the central server does not have them. Every dossier is stored word for word with its answer and can be read back under <b>What was sent to the model</b> in the alert.
          </p>
          <p class="hint" style="margin-bottom:0">
            Where it goes is decided by the base URL alone. <b>Ollama in your own network:</b> nothing leaves the house.
            <b>Infomaniak:</b> the dossier leaves this network; the provider states the data stays in Switzerland and is not used to train models. Any other endpoint is your own call — and reading this metadata is exactly what this tool exists to prevent elsewhere.
          </p>
        </fieldset>

        {#if admin}
        <fieldset class="fset">
          <legend>Status</legend>
          {#if assist}
            <div class="kv">
              <span class="k">State</span>
              <span>
                {#if !s.assist_enabled}<span class="badge">off</span> the switch above is off
                {:else if !assist.active}<span class="badge">off</span> base URL or model is missing
                {:else}<span class="badge ok">active</span>{/if}
              </span>
              {#if assist.active}
                <span class="k">Endpoint</span>
                <span class="mono">{assist.endpoint}
                  {#if assist.external}<span class="badge warn" title="This address is outside your network">leaves the network</span>
                  {:else}<span class="badge ok" title="This address is inside your own network">stays in your network</span>{/if}
                </span>
                <span class="k">Model</span><span class="mono">{assist.model}</span>
              {/if}
              <span class="k">Today</span><span>{assist.today} of {assist.daily_limit} explanations{#if assist.today >= assist.daily_limit} — budget spent, resumes tomorrow{/if}</span>
              <span class="k">Stored</span><span>{assist.stored} explanations</span>
            </div>
          {:else}
            <p class="hint" style="margin:0">Status is not available.</p>
          {/if}
          <div class="row" style="margin-top:12px">
            <div style="flex:none"><button type="button" class="btn sm" onclick={probe} disabled={probing || !assist?.active}>
              {probing ? 'Asking…' : 'Test connection'}</button></div>
            <div style="flex:none"><button type="button" class="btn sm ghost" onclick={loadAssist}><Icon name="refresh" size={14} /> Refresh status</button></div>
            {#if s.assist_key_set}<div style="flex:none"><button type="button" class="btn sm ghost danger" onclick={dropAiKey}><Icon name="trash" size={14} /> Remove key</button></div>{/if}
          </div>
          <p class="hint" style="margin-bottom:0">The test sends no alert data — just the word “ready”. It uses the <b>saved</b> settings, so save first.</p>
        </fieldset>
        {/if}

      {:else if tab === 'notify'}
        <fieldset class="fset">
          <legend>Email notifications</legend>
          <div class="checks">
            <label class="check"><input type="checkbox" bind:checked={s.smtp_enabled} disabled={!admin} />
              <span class="t"><b>Send email</b>
              <span>The master switch. Nobody sits in front of the dashboard at three in the morning; this is how the central server reaches someone. Off means it opens no connection to a mail server at all.</span></span></label>
          </div>

          <div class="row" style="margin-top:14px">
            <div class="field" style="flex:2;margin-bottom:0"><label for="sh">SMTP server</label>
              <input id="sh" type="text" bind:value={s.smtp_host} disabled={!admin} autocomplete="off" spellcheck="false" placeholder="smtp.example.com or 127.0.0.1" /></div>
            <div class="field" style="flex:0 0 110px;margin-bottom:0"><label for="sp">Port</label>
              <input id="sp" type="number" min="1" max="65535" bind:value={s.smtp_port} disabled={!admin} /></div>
          </div>
          <div class="field" style="margin-top:12px"><label for="ss">Transport security</label>
            <select id="ss" bind:value={s.smtp_security} disabled={!admin}>
              <option value="starttls">STARTTLS (usually port 587)</option>
              <option value="tls">TLS from the start (usually port 465)</option>
              <option value="none">None — plain text</option>
            </select>
            <div class="hint">Pick <strong>none</strong> only for a relay on this very machine, such as a local mail bridge. Anywhere else it puts the password on the wire in the clear.</div></div>

          <div class="row">
            <div class="field" style="margin-bottom:0"><label for="su">Username</label>
              <input id="su" type="text" bind:value={s.smtp_user} disabled={!admin} autocomplete="off" spellcheck="false" />
              <div class="hint">Leave empty for a relay that accepts mail without signing in.</div></div>
            <div class="field" style="margin-bottom:0"><label for="spw">Password</label>
              <input id="spw" type="password" bind:value={mailPass} disabled={!admin} autocomplete="new-password" spellcheck="false"
                placeholder={s.smtp_pass_set ? 'A password is stored — type a new one to replace it' : ''} />
              <div class="hint">Stored on the server and never sent back to the browser.</div></div>
          </div>

          <div class="row" style="margin-top:12px">
            <div class="field" style="margin-bottom:0"><label for="sf">Sender</label>
              <input id="sf" type="text" bind:value={s.smtp_from} disabled={!admin} autocomplete="off" spellcheck="false" placeholder="dlprevent@example.com" /></div>
            <div class="field" style="margin-bottom:0"><label for="st">Recipients</label>
              <input id="st" type="text" bind:value={s.smtp_to} disabled={!admin} autocomplete="off" spellcheck="false" placeholder="ops@example.com, duty@example.com" />
              <div class="hint">Comma separated. A longer list belongs on the mail server, as a distribution address.</div></div>
          </div>

          <div class="field" style="margin-bottom:0;margin-top:12px"><label for="sb">Dashboard address</label>
            <input id="sb" type="url" bind:value={s.notify_base_url} disabled={!admin} autocomplete="off" spellcheck="false" placeholder="https://dlprevent.example.com" />
            <div class="hint">Used for the links in the email. The central server does not know under which address you reach it; leave it empty and the email carries no links.</div></div>
        </fieldset>

        <fieldset class="fset">
          <legend>What is worth an email</legend>
          <div class="checks">
            <label class="check"><input type="checkbox" bind:checked={s.notify_alerts} disabled={!admin} />
              <span class="t"><b>Alerts</b>
              <span>Forbidden destination, hard limit, deviation from the baseline — the same three the overview counts. This is the case of somebody hauling the management share away.</span></span></label>
            <label class="check"><input type="checkbox" bind:checked={s.notify_agent_down} disabled={!admin} />
              <span class="t"><b>An agent stops reporting</b>
              <span>No report for as long as you set below. A silent agent looks like a quiet day on the dashboard, which is the most dangerous state this system has. One email when it falls out, one when it comes back.</span></span></label>
            <label class="check"><input type="checkbox" bind:checked={s.notify_abuse_ip} disabled={!admin} />
              <span class="t"><b>A destination with a bad reputation</b>
              <span>Also mail when the destination address is known bad at AbuseIPDB, even if the flow itself stayed under every limit. Needs IP reputation switched on under Reputation; only what is already cached is used, this never triggers a lookup.</span></span></label>
          </div>

          <div class="row" style="margin-top:14px">
            <div class="field" style="margin-bottom:0"><label for="ns">Bad from a score of</label>
              <input id="ns" type="number" min="0" max="100" bind:value={s.notify_abuse_min_score} disabled={!admin} />
              <div class="hint">AbuseIPDB confidence, 0 to 100. 50 is a fair line.</div></div>
            <div class="field" style="margin-bottom:0"><label for="nd">Collect for (minutes)</label>
              <input id="nd" type="number" min="1" max="1440" bind:value={s.notify_digest_mins} disabled={!admin} />
              <div class="hint">At most one email per window, with everything that came up in it. A mass copy costs one email, not two hundred.</div></div>
          </div>
          <div class="row" style="margin-top:14px">
            <div class="field" style="margin-bottom:0"><label for="ndm">An agent counts as down after (minutes)</label>
              <input id="ndm" type="number" min="1" max="1440" bind:value={s.notify_agent_down_mins} disabled={!admin} />
              <div class="hint">Only for the email. The agent list still colours after three missed reports — a colour wakes nobody, an email does. Raise this if a laptop going to sleep keeps sending you down and up again.</div></div>
          </div>
        </fieldset>

        {#if admin}
        <fieldset class="fset">
          <legend>Status</legend>
          {#if mail}
            <div class="kv">
              <span class="k">State</span>
              <span>
                {#if mail.last_error}<span class="badge warn">problem</span> {mail.last_error}
                {:else if !s.smtp_enabled}<span class="badge">off</span> the switch above is off
                {:else if !mail.active}<span class="badge">off</span> server, sender or recipient is still missing
                {:else}<span class="badge ok">active</span> {mail.recipients} recipient{mail.recipients === 1 ? '' : 's'}{/if}
              </span>
              <span class="k">Since restart</span><span>{mail.sent} email{mail.sent === 1 ? '' : 's'} sent</span>
              {#if mail.last_sent_at}<span class="k">Last one</span><span>{fmtTime(mail.last_sent_at)}</span>{/if}
            </div>
          {:else}
            <p class="hint" style="margin:0">Status is not available.</p>
          {/if}
          <div class="row" style="margin-top:12px">
            <div style="flex:none"><button type="button" class="btn sm" onclick={sendTest} disabled={testing || busy}><Icon name="mail" size={14} /> {testing ? 'Sending…' : 'Save and send a test email'}</button></div>
            <div style="flex:none"><button type="button" class="btn sm" onclick={loadNotify}><Icon name="refresh" size={14} /> Refresh status</button></div>
            {#if s.smtp_pass_set}<div style="flex:none"><button type="button" class="btn sm ghost danger" onclick={dropPass}><Icon name="trash" size={14} /> Remove password</button></div>{/if}
          </div>
        </fieldset>
        {/if}
      {/if}

      <!-- The error sits by the button, not at the top of the page:
           otherwise whoever presses Save down here only sees nothing
           happen. -->
      {#if error}<p class="error">{error}</p>{/if}
      <div class="row savebar" style="align-items:center">
        <span class="muted small">Configuration generation: {s.config_generation}</span>
        {#if admin}<div style="flex:none"><button class="btn primary" type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></div>{/if}
      </div>
    </form>

    {#if admin && tab === 'interfaces'}
    <div class="card" style="margin-top:20px">
      <div class="card-head">
        <h2>API keys</h2><span class="spacer"></span>
        <button class="btn sm primary" onclick={openNew}><Icon name="plus" size={14} /> New key</button>
      </div>

      <p class="hint" style="margin:0;padding:12px 16px;border-bottom:var(--rule)">
        For a SIEM or a script that reads alerts without a browser. A key <strong>only reads</strong> the monitoring views
        (<code>/api/overview</code>, <code>/api/alerts</code>, <code>/api/counts</code>) — it can change nothing and reaches
        nothing else, not the agent installer and not the audit log. Send it as <code>Authorization: Bearer …</code>.
        {#if !s.api_keys_enabled}<br /><strong>The master switch above is off, so no key is being accepted right now.</strong>{/if}
      </p>

      {#if keysError && !creating}<p class="error" style="margin:12px 16px">{keysError}</p>{/if}

      {#if keys.length}
        <div class="tablewrap">
          <table>
            <thead><tr>
              <th style="width:100%"><span class="th">Label</span></th>
              <th><span class="th">Expires</span></th>
              <th><span class="th">Last used</span></th>
              <th><span class="th"></span></th>
            </tr></thead>
            <tbody>
              {#each keys as k (k.id)}
                <tr>
                  <td><strong>{k.label}</strong>{#if expired(k)}<div class="cell-2">expired</div>{/if}</td>
                  <td class="nowrap" class:muted={!k.expires_at}>{k.expires_at ? fmtTime(k.expires_at) : 'never'}</td>
                  <td class="nowrap">{fmtTime(k.last_used_at)}</td>
                  <td class="nowrap"><button class="btn sm ghost danger" onclick={() => removeKey(k)} title="Delete" aria-label="Delete"><Icon name="trash" size={14} /></button></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <div class="empty"><span class="ico"><Icon name="key" size={26} /></span><b>No keys yet</b><span>Create one for a SIEM or a script.</span></div>
      {/if}
    </div>
    {/if}
  </div>
</div>
{:else if !error}
  <div class="card pad" style="max-width:640px"><div class="stack">{#each Array(4) as _}<div class="skel"></div>{/each}</div></div>
{/if}

{#if creating}
  <Modal title="New API key" subtitle={fresh ? 'The key is shown only once.' : 'It reads the monitoring views and nothing else.'} onclose={() => (creating = false)}>
    {#if !fresh}
      <form id="key-form" onsubmit={createKey}>
        <div class="field"><label for="kl">Label</label><input id="kl" type="text" bind:value={form.label} required maxlength="64" autocomplete="off" placeholder="e.g. Splunk collector" />
          <div class="hint">What uses this key. It stands in the list and in the audit log.</div></div>
        <div class="field" style="margin-bottom:0"><label for="kd">Valid for (days)</label><input id="kd" type="number" min="0" max="3650" bind:value={form.days} />
          <div class="hint">0 means the key never expires.</div></div>
        {#if keysError}<p class="error" style="margin:12px 0 0">{keysError}</p>{/if}
      </form>
    {:else}
      <p class="hint" style="margin-top:0">Copy it now — only its hash is stored, there is no second look.</p>
      <div class="copy"><code>{fresh.key}</code><button type="button" class="btn sm" onclick={() => copy(fresh!.key)}><Icon name="copy" size={14} /> Copy</button></div>
      <div class="kv" style="margin-top:14px">
        <span class="k">Label</span><span>{fresh.label}</span>
        <span class="k">Valid until</span><span>{fresh.expires_at ? fmtTime(fresh.expires_at) : 'no expiry'}</span>
        <span class="k">Header</span><span class="mono">Authorization: Bearer …</span>
      </div>
    {/if}
    {#snippet actions()}
      {#if !fresh}
        <button type="button" class="btn" onclick={() => (creating = false)}>Cancel</button>
        <button type="submit" form="key-form" class="btn primary">Create</button>
      {:else}
        <button type="button" class="btn primary" onclick={() => (creating = false)}>Done</button>
      {/if}
    {/snippet}
  </Modal>
{/if}

<style>
  /* Tabs on the left, content on the right: each group fills a short card of
     its own, instead of everything turning into one scroll. Below 760 px the
     tabs slide above it as a row. */
  .settings { display: flex; gap: 20px; align-items: flex-start; max-width: 900px; }
  .tabs { display: flex; flex-direction: column; gap: 2px; flex: 0 0 168px; position: sticky; top: 0; }
  .tabs button {
    display: flex; align-items: center; gap: 8px; width: 100%; text-align: left; cursor: pointer;
    border: 0; border-left: 2px solid transparent; background: none; padding: 8px 10px; border-radius: 0;
    font-family: var(--font-mono); font-size: 11px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted);
  }
  .tabs button:hover { color: var(--text); background: var(--panel-2); }
  .tabs button.on { color: var(--accent); border-left-color: var(--accent); background: var(--accent-2); }
  /* The dot says "something is stuck here" without having to open the tab. */
  .tabs .dot { margin-left: auto; width: 6px; height: 6px; border-radius: 50%; background: var(--warn); }
  .pane { flex: 1; min-width: 0; }
  /* The save button sits in the same place under every tab. */
  .savebar { border-top: var(--rule); padding-top: 14px; margin-top: 4px; }

  @media (max-width: 760px) {
    .settings { flex-direction: column; }
    .tabs { flex-direction: row; flex-wrap: wrap; flex: none; width: 100%; position: static; }
    .tabs button { width: auto; border-left: 0; border-bottom: 2px solid transparent; }
    .tabs button.on { border-left: 0; border-bottom-color: var(--accent); }
  }
</style>

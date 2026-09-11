<script lang="ts">
  import { api, fmtTime } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { notify, session } from '../lib/session.svelte';
  import { createSort, sortRows, matches } from '../lib/sort.svelte';
  import type { UserRow } from '../lib/types';
  import Modal from '../lib/Modal.svelte';
  import Icon from '../lib/Icon.svelte';
  import PageHead from '../lib/PageHead.svelte';
  import SearchBox from '../lib/SearchBox.svelte';
  import SortHeader from '../lib/SortHeader.svelte';
  import { ask } from '../lib/confirm.svelte';

  let creating = $state(false);
  let pwFor = $state<UserRow | null>(null);
  let form = $state({ name: '', password: '', role: 'viewer' });
  let pw = $state('');
  let oldPw = $state('');
  let q = $state('');
  /// The forms only. The error from loading lives in `res.error` — otherwise
  /// a failed dialog would overwrite the list's message.
  let error = $state('');
  const sort = createSort('name');
  const roleLabel = (r: string) => (r === 'admin' ? 'Administrator' : 'Read only');

  const res = resource(() => api<UserRow[]>('/api/users'));
  const load = res.reload;
  const users = $derived(res.data ?? []);

  const view = $derived(sortRows(
    users.filter((u) => matches(`${u.name} ${roleLabel(u.role)}`, q)),
    sort,
    (u, k) => ({ name: u.name, role: roleLabel(u.role), created: u.created_at, login: u.last_login }[k]),
  ));

  async function create(e: Event) {
    e.preventDefault(); error = '';
    try { await api('/api/users', { method: 'POST', body: form }); notify('User created'); creating = false; form = { name: '', password: '', role: 'viewer' }; load(); } catch (err) { error = (err as Error).message; }
  }
  async function setPw(e: Event) {
    e.preventDefault(); error = '';
    if (!pwFor) return;
    const self = pwFor.id === session.user?.id;
    try {
      await api(`/api/users/${pwFor.id}/password`, { method: 'POST', body: self ? { password: pw, old_password: oldPw } : { password: pw } });
      notify('Password changed');
      pwFor = null; pw = ''; oldPw = '';
      if (self) session.user = null;
    } catch (err) { error = (err as Error).message; }
  }
  async function remove(u: UserRow) {
    if (!(await ask({ title: 'Delete user', body: `"${u.name}" loses access at once.`, detail: 'Open sessions of this account end. What the account did stays in the audit log.', confirmLabel: 'Delete', danger: true }))) return;
    try { await api(`/api/users/${u.id}`, { method: 'DELETE' }); notify('User deleted'); load(); } catch (err) { notify((err as Error).message, true); }
  }
  function openPw(u: UserRow) { pwFor = u; pw = ''; oldPw = ''; error = ''; }
  async function resetSecond(u: UserRow) {
    if (!(await ask({ title: 'Reset second factor', body: `The second factor of "${u.name}" is removed.`, detail: 'The authenticator app and all passkeys stop working. The password stays; the account sets a new second factor up itself.', confirmLabel: 'Reset', danger: true }))) return;
    try { await api(`/api/users/${u.id}/second-factor`, { method: 'DELETE' }); notify('Second factor reset'); load(); } catch (err) { notify((err as Error).message, true); }
  }
</script>

<PageHead title="Users">
  {#snippet actions()}
    <button class="btn primary" onclick={() => { creating = true; error = ''; }}><Icon name="plus" size={15} /> New user</button>
  {/snippet}
</PageHead>

<div class="toolbar">
  <SearchBox bind:value={q} placeholder="Search name or role…" />
  <span class="spacer"></span>
  <span class="muted small">{view.length} of {users.length}</span>
</div>

{#if res.error && !creating && !pwFor}<p class="error">{res.error}</p>{/if}

<div class="card">
  {#if res.loading}
    <div style="padding:16px" class="stack">{#each Array(3) as _}<div class="skel"></div>{/each}</div>
  {:else if view.length === 0}
    <div class="empty"><span class="ico"><Icon name="users" size={26} /></span><b>Nothing found</b><span>Try other words.</span></div>
  {:else}
  <div class="tablewrap">
    <table>
      <thead><tr>
        <SortHeader {sort} key="name" label="Name" />
        <SortHeader {sort} key="role" label="Role" />
        <SortHeader {sort} key="created" label="Created" />
        <SortHeader {sort} key="login" label="Last sign-in" />
        <th><span class="th">2FA</span></th>
        <th><span class="th"></span></th>
      </tr></thead>
      <tbody>
        {#each view as u (u.id)}
          <tr>
            <td><strong>{u.name}</strong>{#if u.id === session.user?.id}<span class="muted">&nbsp;(you)</span>{/if}{#if u.disabled}<div class="cell-2">disabled</div>{/if}</td>
            <td><span class="badge {u.role === 'admin' ? 'accent' : ''}">{roleLabel(u.role)}</span></td>
            <td class="nowrap muted">{fmtTime(u.created_at)}</td>
            <td class="nowrap">{fmtTime(u.last_login)}</td>
            <td class="nowrap">
              {#if u.totp_enabled}<span class="badge accent">App</span>{/if}
              {#if u.passkeys > 0}<span class="badge accent">{u.passkeys} {u.passkeys === 1 ? 'passkey' : 'passkeys'}</span>{/if}
              {#if !u.totp_enabled && u.passkeys === 0}<span class="muted">–</span>{/if}
            </td>
            <td class="nowrap">
              <button class="btn sm ghost" onclick={() => openPw(u)}><Icon name="key" size={14} /> Password</button>
              {#if u.totp_enabled || u.passkeys > 0}<button class="btn sm ghost" onclick={() => resetSecond(u)} title="Reset second factor"><Icon name="refresh" size={14} /> Reset 2FA</button>{/if}
              {#if u.id !== session.user?.id}<button class="btn sm ghost danger" onclick={() => remove(u)} title="Delete" aria-label="Delete"><Icon name="trash" size={14} /></button>{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {/if}
</div>

{#if creating}
  <Modal title="New user" subtitle="The role decides what the account may change." onclose={() => (creating = false)}>
    <form id="user-form" onsubmit={create}>
      <div class="field"><label for="un">Name</label><input id="un" type="text" bind:value={form.name} required autocomplete="off" /></div>
      <div class="field"><label for="up">Password</label><input id="up" type="password" bind:value={form.password} required autocomplete="new-password" minlength="12" />
        <div class="hint">At least 12 characters.</div></div>
      <div class="field" style="margin-bottom:0"><label for="ur">Role</label>
        <select id="ur" bind:value={form.role}><option value="viewer">Read only</option><option value="admin">Administrator</option></select>
        <div class="hint">{form.role === 'admin' ? 'May change rules, agents, sources, users and settings, and mark alerts done.' : 'Sees everything, changes nothing.'}</div>
      </div>
      {#if error}<p class="error" style="margin:12px 0 0">{error}</p>{/if}
    </form>
    {#snippet actions()}
      <button type="button" class="btn" onclick={() => (creating = false)}>Cancel</button>
      <button type="submit" form="user-form" class="btn primary">Create</button>
    {/snippet}
  </Modal>
{/if}

{#if pwFor}
  <Modal title="Change password" subtitle={pwFor.name} onclose={() => (pwFor = null)}>
    <form id="pw-form" onsubmit={setPw}>
      {#if pwFor.id === session.user?.id}
        <div class="field"><label for="po">Current password</label><input id="po" type="password" bind:value={oldPw} required autocomplete="current-password" /></div>
      {/if}
      <div class="field" style="margin-bottom:0"><label for="pp">New password</label><input id="pp" type="password" bind:value={pw} required autocomplete="new-password" minlength="12" />
        <div class="hint">At least 12 characters. {pwFor.id === session.user?.id ? 'You will have to sign in again afterwards.' : 'All open sessions of this account end.'}</div>
      </div>
      {#if error}<p class="error" style="margin:12px 0 0">{error}</p>{/if}
    </form>
    {#snippet actions()}
      <button type="button" class="btn" onclick={() => (pwFor = null)}>Cancel</button>
      <button type="submit" form="pw-form" class="btn primary">Change</button>
    {/snippet}
  </Modal>
{/if}

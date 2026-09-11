<script lang="ts">
  import { api, fmtTime, setDisplayTz, passkeysSupported, passkeyCreate, passkeyError } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { notify, session } from '../lib/session.svelte';
  import type { Account, Passkey, TotpSetup, User } from '../lib/types';
  import Icon from '../lib/Icon.svelte';
  import Modal from '../lib/Modal.svelte';
  import PageHead from '../lib/PageHead.svelte';
  import { ask } from '../lib/confirm.svelte';

  const res = resource(() => api<Account>('/api/account'));
  const acct = $derived(res.data);

  /** After every change to the second factor: reload the list, and reload the
   *  account — `second_factor_required` flips with it, and the navigation
   *  comes back. */
  async function refresh() {
    res.reload();
    try { session.user = await api<User>('/api/me'); setDisplayTz(session.user?.timezone); } catch { /* 401: the sign-in screen appears */ }
  }

  // ---------- Password ----------
  let oldPw = $state('');
  let pw = $state('');
  let pwError = $state('');
  async function changePw(e: Event) {
    e.preventDefault(); pwError = '';
    try {
      await api(`/api/users/${session.user?.id}/password`, { method: 'POST', body: { password: pw, old_password: oldPw } });
      notify('Password changed, sign in again');
      session.user = null;
    } catch (err) { pwError = (err as Error).message; }
  }

  // ---------- Authenticator app ----------
  let setup = $state<TotpSetup | null>(null);
  let code = $state('');
  let totpError = $state('');
  async function startTotp() {
    totpError = ''; code = '';
    try { setup = await api<TotpSetup>('/api/account/totp', { method: 'POST' }); } catch (err) { notify((err as Error).message, true); }
  }
  async function enableTotp(e: Event) {
    e.preventDefault(); totpError = '';
    try { await api('/api/account/totp/enable', { method: 'POST', body: { code } }); setup = null; notify('Authenticator app is on'); refresh(); }
    catch (err) { totpError = (err as Error).message; }
  }
  async function disableTotp() {
    if (!(await ask({ title: 'Turn off the authenticator app', body: 'Signing in will need the password only.', detail: 'If your role requires a second factor, you will be asked to set one up again at the next sign-in.', confirmLabel: 'Turn off', danger: true }))) return;
    try { await api('/api/account/totp', { method: 'DELETE' }); notify('Authenticator app is off'); refresh(); } catch (err) { notify((err as Error).message, true); }
  }

  // ---------- Passkeys ----------
  let adding = $state(false);
  let label = $state('');
  let pkPassword = $state('');
  let pkError = $state('');
  let pkBusy = $state(false);
  async function addPasskey(e: Event) {
    e.preventDefault(); pkError = ''; pkBusy = true;
    try {
      const options = await api<{ publicKey: PublicKeyCredentialCreationOptionsJSON }>('/api/account/passkeys', { method: 'POST', body: { password: pkPassword } });
      const credential = await passkeyCreate(options);
      await api<Passkey>('/api/account/passkeys/finish', { method: 'POST', body: { label, credential } });
      adding = false; label = ''; pkPassword = '';
      notify('Passkey added'); refresh();
    } catch (err) { pkError = passkeyError(err); } finally { pkBusy = false; }
  }
  async function removePasskey(k: Passkey) {
    if (!(await ask({ title: 'Remove passkey', body: `"${k.label}" can no longer be used to sign in.`, detail: 'The key stays on your device — remove it there as well if you do not want it offered any more.', confirmLabel: 'Remove', danger: true }))) return;
    try { await api(`/api/account/passkeys/${k.id}`, { method: 'DELETE' }); notify('Passkey removed'); refresh(); } catch (err) { notify((err as Error).message, true); }
  }
  async function copy(t: string) { await navigator.clipboard.writeText(t); notify('Copied'); }
</script>

<PageHead title="Account" />

{#if session.user?.second_factor_required}
  <p class="error" style="background:var(--warn-2);color:var(--warn)"><Icon name="lock" size={13} /> Your role must sign in with a second factor. Set up the authenticator app or a passkey below; until then the other pages stay closed.</p>
{/if}
{#if res.error}<p class="error">{res.error}</p>{/if}

<div class="card" style="max-width:640px">
  <div class="card-head"><h2>Authenticator app</h2><span class="spacer"></span>
    {#if acct?.totp_enabled}<span class="badge ok">On</span>{:else if acct}<span class="badge">Off</span>{/if}
  </div>
  <div class="pad" style="padding:14px 16px">
    <p class="hint" style="margin:0 0 12px">After the password, a six-digit code from an app such as Google Authenticator, Microsoft Authenticator, Aegis or 1Password. Lost the phone? An administrator resets it under Users.</p>
    {#if setup}
      <form onsubmit={enableTotp}>
        <div class="row" style="align-items:flex-start">
          <div style="flex:none;background:#fff;padding:8px;border:var(--rule)">{@html setup.qr_svg}</div>
          <div>
            <div class="hint" style="margin:0 0 6px">Scan the code with the app, <a href={setup.otpauth}>open it in an app on this device</a>, or enter the secret by hand:</div>
            <div class="mono" style="overflow-wrap:anywhere">{setup.secret} <button type="button" class="iconbtn" onclick={() => copy(setup!.secret)} title="Copy" aria-label="Copy secret"><Icon name="copy" size={13} /></button></div>
            <div class="field" style="margin:12px 0 0"><label for="tc">Code from the app</label><input id="tc" type="text" inputmode="numeric" autocomplete="one-time-code" bind:value={code} required /></div>
          </div>
        </div>
        {#if totpError}<p class="error" style="margin:12px 0 0">{totpError}</p>{/if}
        <div style="display:flex;gap:8px;margin-top:12px">
          <button class="btn primary" type="submit">Turn on</button>
          <button class="btn" type="button" onclick={() => (setup = null)}>Cancel</button>
        </div>
      </form>
    {:else if acct?.totp_enabled}
      <button class="btn" onclick={disableTotp}>Turn off</button>
    {:else if acct}
      <button class="btn primary" onclick={startTotp}>Set up</button>
    {/if}
  </div>
</div>

<div class="card" style="max-width:640px;margin-top:20px">
  <div class="card-head"><h2>Passkeys</h2><span class="spacer"></span>
    {#if passkeysSupported}<button class="btn sm primary" onclick={() => { adding = true; pkError = ''; label = ''; pkPassword = ''; }}><Icon name="plus" size={14} /> Add passkey</button>{/if}
  </div>
  <p class="hint" style="margin:0;padding:12px 16px;border-bottom:var(--rule)">
    Sign in without a password: the device unlocks the key with fingerprint, face or PIN, and the key only works on this server's name.
    {#if !passkeysSupported}<br /><strong>This browser cannot create passkeys.</strong>{/if}
  </p>
  {#if acct && acct.passkeys.length === 0}
    <div class="empty" style="padding:22px"><span class="ico"><Icon name="key" size={22} /></span><b>No passkeys</b></div>
  {:else if acct}
    <div class="tablewrap"><table>
      <thead><tr><th><span class="th">Name</span></th><th><span class="th">Added</span></th><th><span class="th">Last used</span></th><th></th></tr></thead>
      <tbody>
        {#each acct.passkeys as k (k.id)}
          <tr><td><strong>{k.label}</strong></td><td class="nowrap muted">{fmtTime(k.created_at)}</td><td class="nowrap">{fmtTime(k.last_used_at)}</td>
            <td class="nowrap"><button class="btn sm ghost danger" onclick={() => removePasskey(k)} title="Remove" aria-label="Remove"><Icon name="trash" size={14} /></button></td></tr>
        {/each}
      </tbody>
    </table></div>
  {/if}
</div>

<form class="card pad" style="max-width:640px;margin-top:20px" onsubmit={changePw}>
  <h2 style="margin:0 0 12px">Password</h2>
  <div class="field"><label for="po">Current password</label><input id="po" type="password" bind:value={oldPw} required autocomplete="current-password" /></div>
  <div class="field"><label for="pp">New password</label><input id="pp" type="password" bind:value={pw} required autocomplete="new-password" minlength="12" />
    <div class="hint">At least 12 characters. You will have to sign in again afterwards.</div></div>
  {#if pwError}<p class="error">{pwError}</p>{/if}
  <button class="btn primary" type="submit">Change password</button>
</form>

{#if adding}
  <Modal title="Add passkey" subtitle="Your password confirms it is you; then the device asks for fingerprint, face or PIN." onclose={() => (adding = false)}>
    <form id="pk-form" onsubmit={addPasskey}>
      <div class="field"><label for="pl">Name</label><input id="pl" type="text" bind:value={label} required maxlength="64" placeholder="e.g. Phone, Work laptop, YubiKey" /></div>
      <div class="field" style="margin-bottom:0"><label for="pw2">Current password</label><input id="pw2" type="password" bind:value={pkPassword} required autocomplete="current-password" /></div>
      {#if pkError}<p class="error" style="margin:12px 0 0">{pkError}</p>{/if}
    </form>
    {#snippet actions()}
      <button type="button" class="btn" onclick={() => (adding = false)}>Cancel</button>
      <button type="submit" form="pk-form" class="btn primary" disabled={pkBusy}>{pkBusy ? 'Waiting for the device…' : 'Continue'}</button>
    {/snippet}
  </Modal>
{/if}

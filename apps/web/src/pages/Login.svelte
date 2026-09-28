<script lang="ts">
  import { api, passkeysSupported, passkeyGet, passkeyError } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import type { User } from '../lib/types';
  import Brand from '../lib/Brand.svelte';
  import { onMount } from 'svelte';
  let { onlogin }: { onlogin: () => void } = $props();
  let name = $state('');
  let password = $state('');
  let code = $state('');
  let error = $state('');
  let busy = $state(false);
  /** The password was right, the code from the app is still missing. The
   *  token binds the second step to the first; without a code it is worth
   *  nothing. */
  let totpToken = $state('');
  /** Offered once an administrator has set it up; the server decides. */
  let sso = $state(false);
  onMount(async () => {
    try { sso = (await api<{ enabled: boolean }>('/api/sso/available')).enabled; } catch { /* no button */ }
  });

  async function submit(e: Event) {
    e.preventDefault();
    busy = true; error = '';
    try {
      const r = await api<User | { totp: string } | { passkey: true }>('/api/login', { method: 'POST', body: { name, password } });
      if ('totp' in r) { totpToken = r.totp; code = ''; return; }
      // Second factor required, but passkeys only: the password alone is not enough.
      if ('passkey' in r) { await withPasskey(); return; }
      session.user = r;
      onlogin();
    } catch (err) {
      error = (err as Error).message;
    } finally { busy = false; }
  }

  async function submitCode(e: Event) {
    e.preventDefault();
    busy = true; error = '';
    try {
      session.user = await api<User>('/api/login/totp', { method: 'POST', body: { token: totpToken, code } });
      onlogin();
    } catch (err) {
      error = (err as Error).message;
    } finally { busy = false; }
  }

  async function withPasskey() {
    busy = true; error = '';
    try {
      const options = await api<{ publicKey: PublicKeyCredentialRequestOptionsJSON }>('/api/login/passkey', { method: 'POST', body: { name } });
      const credential = await passkeyGet(options);
      session.user = await api<User>('/api/login/passkey/finish', { method: 'POST', body: { name, credential } });
      onlogin();
    } catch (err) {
      error = passkeyError(err);
    } finally { busy = false; }
  }
</script>

<div class="login">
  {#if totpToken}
    <form class="card" onsubmit={submitCode}>
      <Brand />
      <p class="muted small" style="margin:0 0 18px">Enter the code your authenticator app shows for DLPrevent.</p>
      <div class="field"><label for="c">Code</label><input id="c" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" bind:value={code} required autofocus /></div>
      {#if error}<p class="error">{error}</p>{/if}
      <button class="btn primary" type="submit" disabled={busy} style="width:100%;justify-content:center">{busy ? 'Checking…' : 'Continue'}</button>
      <button class="btn ghost" type="button" onclick={() => { totpToken = ''; error = ''; }} style="width:100%;justify-content:center;margin-top:8px">Back</button>
    </form>
  {:else}
    <form class="card" onsubmit={submit}>
      <Brand />
      <p class="muted small" style="margin:0 0 18px">Detect and stop data leaving the company.</p>
      <div class="field"><label for="n">User</label><input id="n" type="text" bind:value={name} autocomplete="username webauthn" required /></div>
      <div class="field"><label for="p">Password</label><input id="p" type="password" bind:value={password} autocomplete="current-password" required /></div>
      {#if error}<p class="error">{error}</p>{/if}
      <button class="btn primary" type="submit" disabled={busy} style="width:100%;justify-content:center">{busy ? 'Checking…' : 'Sign in'}</button>
      {#if passkeysSupported}
        <button class="btn" type="button" onclick={withPasskey} disabled={busy || !name.trim()} style="width:100%;justify-content:center;margin-top:8px" title={name.trim() ? '' : 'Enter your user name first'}>Sign in with a passkey</button>
      {/if}
      {#if sso}
        <a class="btn" href="/api/sso/start" style="width:100%;justify-content:center;margin-top:8px">Sign in with single sign-on</a>
      {/if}
    </form>
  {/if}
</div>

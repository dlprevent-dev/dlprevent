<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { notify } from '../lib/session.svelte';
  import PageHead from '../lib/PageHead.svelte';

  type View = { issuer: string; client_id: string; auth_method: string; username_claim: string; groups_claim: string; admin_group: string; viewer_group: string; auto_create: boolean; ca_pem: string; secret_set: boolean; redirect_uri: string };
  let v = $state<View | null>(null);
  let secret = $state('');
  let error = $state('');
  let busy = $state(false);

  onMount(async () => {
    try { v = await api<View>('/api/sso'); } catch (e) { error = (e as Error).message; }
  });

  async function save(e: Event) {
    e.preventDefault();
    busy = true;
    try { v = await api<View>('/api/sso', { method: 'PUT', body: { ...v, secret } }); secret = ''; notify('Single sign-on saved'); }
    catch (e) { notify((e as Error).message, true); } finally { busy = false; }
  }

  async function test() {
    try { await api('/api/sso/test', { method: 'POST' }); notify('The provider answers and its discovery document fits'); }
    catch (e) { notify((e as Error).message, true); }
  }
</script>

<PageHead title="Single sign-on" />

{#if error}
  <div class="card pad empty"><b>{error}</b></div>
{:else if v}
<form class="card pad" onsubmit={save}>
  <fieldset class="fset">
    <legend>Identity provider (OpenID Connect)</legend>
    <div class="field"><label for="ru">Redirect URI to register at the provider</label>
      <input id="ru" class="mono" value={v.redirect_uri} readonly /></div>
    <div class="field"><label for="is">Issuer</label>
      <input id="is" bind:value={v.issuer} placeholder="https://login.microsoftonline.com/<tenant>/v2.0" />
      <div class="hint">Entra ID: <code>https://login.microsoftonline.com/&lt;tenant-id&gt;/v2.0</code> · Keycloak: <code>https://&lt;host&gt;/realms/&lt;realm&gt;</code> · Okta: <code>https://&lt;org&gt;.okta.com</code></div></div>
    <div class="row">
      <div class="field"><label for="ci">Client ID</label><input id="ci" bind:value={v.client_id} /></div>
      <div class="field"><label for="cs">Client secret</label><input id="cs" type="password" bind:value={secret} placeholder={v.secret_set ? 'stored — leave empty to keep, - to delete' : ''} autocomplete="off" /></div>
    </div>
    <div class="field"><label for="am">Client authentication</label>
      <select id="am" bind:value={v.auth_method}><option value="post">Secret in the request body (client_secret_post)</option><option value="basic">HTTP Basic (client_secret_basic)</option></select></div>
    <div class="field"><label for="ca">Provider's CA certificate (optional)</label>
      <textarea id="ca" class="mono" rows="12" style="font-size:11px" bind:value={v.ca_pem} placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"></textarea>
      <div class="hint">Only when the provider's certificate comes from your own CA (an on-premises Keycloak or ADFS). Empty for a public certificate.</div></div>
  </fieldset>
  <fieldset class="fset">
    <legend>Accounts and roles</legend>
    <div class="row">
      <div class="field"><label for="uc">User name claim</label><input id="uc" bind:value={v.username_claim} /></div>
      <div class="field"><label for="gc">Groups claim</label><input id="gc" bind:value={v.groups_claim} /></div>
    </div>
    <div class="row">
      <div class="field"><label for="ag">Administrator group</label><input id="ag" bind:value={v.admin_group} placeholder="empty: nobody becomes administrator through SSO" /></div>
      <div class="field"><label for="vg">Allowed group (read only)</label><input id="vg" bind:value={v.viewer_group} placeholder="empty: everyone the provider lets through" /></div>
    </div>
    <label class="check"><input type="checkbox" bind:checked={v.auto_create} /> Create an account on its first sign-in</label>
    <p class="hint">Entra ID sends group object IDs, not names: put the IDs here, and add the groups claim under Token configuration. The role follows the groups on every sign-in. A local account with the same name is never taken over, and the provider's MFA replaces the local second factor for these accounts.</p>
  </fieldset>
  <div class="row">
    <div style="flex:none"><button class="btn primary" disabled={busy}>Save</button></div>
    <div style="flex:none"><button type="button" class="btn" onclick={test}>Test provider</button></div>
  </div>
</form>
{/if}

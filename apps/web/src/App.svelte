<script lang="ts">
  import { onMount } from 'svelte';
  import { api, setDisplayTz } from './lib/api';
  import { session, toast, isAdmin } from './lib/session.svelte';
  import ConfirmDialog from './lib/ConfirmDialog.svelte';
  import { route, go } from './lib/router.svelte';
  import type { User, Overview as OverviewT } from './lib/types';
  import Icon from './lib/Icon.svelte';
  import Brand from './lib/Brand.svelte';
  import Login from './pages/Login.svelte';
  import Overview from './pages/Overview.svelte';
  import Alerts from './pages/Alerts.svelte';
  import Rules from './pages/Rules.svelte';
  import Agents from './pages/Agents.svelte';
  import Sources from './pages/Sources.svelte';
  import Users from './pages/Users.svelte';
  import Settings from './pages/Settings.svelte';
  import Audit from './pages/Audit.svelte';
  import Account from './pages/Account.svelte';
  import Sso from './pages/Sso.svelte';
  import { pages as extraPages, banner as Banner } from '$extension';

  let openAlerts = $state(0);

  onMount(async () => {
    try { session.user = await api<User>('/api/me'); setDisplayTz(session.user?.timezone); } catch { session.user = null; }
    session.checked = true;
    refreshBadge();
    setInterval(refreshBadge, 30000);
  });

  async function refreshBadge() {
    if (!session.user) return;
    try { openAlerts = (await api<OverviewT>('/api/overview')).alerts_open; } catch { /* session gone: the login screen appears */ }
  }

  // Groups instead of one long list: first what you look at daily, then what
  // you set up, last the plumbing. `admin` means: administrators only.
  const groups = [
    { title: 'Monitoring', items: [['/', 'Overview', 'overview', false], ['/alerts', 'Alerts', 'alert', false]] },
    { title: 'Setup', items: [['/rules', 'Rules', 'rules', true], ['/agents', 'Agents', 'agents', true], ['/sources', 'Sources', 'sources', true]] },
    { title: 'System', items: [['/users', 'Users', 'users', true], ['/settings', 'Settings', 'settings', true], ['/sso', 'Single sign-on', 'lock', true], ['/audit', 'Audit log', 'audit', true], ['/account', 'Account', 'key', false]] },
    ...(extraPages.length ? [{ title: 'Enterprise', items: extraPages.map((p) => [p.path, p.label, p.icon, p.admin] as const) }] : []),
  ] as const;
  const extra = $derived(extraPages.find((p) => p.path === route.path));

  const admin = $derived(isAdmin());
  /// The role demands a second factor, the account has none: the server only
  /// lets the account page through any more, so the UI shows nothing but
  /// that one either.
  const mustEnrol = $derived(!!session.user?.second_factor_required);
  const adminPage = $derived(groups.some((g) => g.items.some(([p, , , onlyAdmin]) => p === route.path && onlyAdmin)));
  const initials = $derived((session.user?.name ?? '?').trim().slice(0, 2).toUpperCase());

  async function logout() {
    await api('/api/logout', { method: 'POST' });
    session.user = null;
  }

  function nav_click(e: MouseEvent, p: string) { e.preventDefault(); go(p); }
</script>

{#if !session.checked}
  <div class="login"><div class="muted">Loading…</div></div>
{:else if !session.user}
  <Login onlogin={refreshBadge} />
{:else}
  <div class="layout">
    <aside class="sidebar">
      <Brand />
      <nav class="nav">
        {#each groups as g}
          {@const items = g.items.filter(([p, , , onlyAdmin]) => (admin || !onlyAdmin) && (!mustEnrol || p === '/account'))}
          {#if items.length}
            <div class="group">
              <h3>{g.title}</h3>
              {#each items as [p, label, icon]}
                <a href={p} class:active={route.path === p} onclick={(e) => nav_click(e, p)}>
                  <Icon name={icon} />
                  {label}
                  {#if p === '/alerts' && openAlerts > 0}<span class="badge bad">{openAlerts}</span>{/if}
                </a>
              {/each}
            </div>
          {/if}
        {/each}
      </nav>
      <div class="foot">
        <div class="userbox">
          <span class="avatar">{initials}</span>
          <span class="who">
            <strong title={session.user.name}>{session.user.name}</strong>
            <span>{admin ? 'Administrator' : 'Read only'}</span>
          </span>
          <button class="iconbtn" onclick={logout} title="Sign out" aria-label="Sign out"><Icon name="logout" /></button>
        </div>
      </div>
    </aside>
    <main class="main">
      {#if Banner && admin && !mustEnrol}<Banner />{/if}
      {#if mustEnrol || route.path === '/account'}<Account />
      {:else if adminPage && !admin}
        <div class="card pad empty"><Icon name="lock" size={22} /><b>Administrators only</b><span>Your account can view monitoring, not administration.</span></div>
      {:else if route.path === '/'}<Overview />
      {:else if route.path === '/alerts'}<Alerts onchange={refreshBadge} />
      {:else if route.path === '/rules'}<Rules />
      {:else if route.path === '/agents'}<Agents />
      {:else if route.path === '/sources'}<Sources />
      {:else if route.path === '/users'}<Users />
      {:else if route.path === '/settings'}<Settings />
      {:else if route.path === '/sso'}<Sso />
      {:else if route.path === '/audit'}<Audit />
      {:else if extra}<extra.component />
      {:else}<div class="card pad empty"><b>Page not found</b><a href="/" onclick={(e) => nav_click(e, '/')}>Back to overview</a></div>{/if}
    </main>
  </div>
{/if}
{#if toast.text}<div class="toast" class:bad={toast.bad}>{toast.text}</div>{/if}
<ConfirmDialog />

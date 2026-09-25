import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'vite';

// The client router needs these browser globals; rendering itself uses Svelte SSR.
test('dashboard restricts administration and presents alarms separately from notices', async () => {
  globalThis.location = { pathname: '/' };
  globalThis.window = { addEventListener() {} };
  const server = await createServer({ server: { middlewareMode: true }, logLevel: 'error' });
  try {
    const { render } = await server.ssrLoadModule('svelte/server');
    const { default: App } = await server.ssrLoadModule('/src/App.svelte');
    const { session } = await server.ssrLoadModule('/src/lib/session.svelte.ts');
    const { route } = await server.ssrLoadModule('/src/lib/router.svelte.ts');
    const { isAlarm, verdictClass } = await server.ssrLoadModule('/src/lib/api.ts');
    for (const verdict of ['hard_limit', 'deviation', 'new', 'flagged', 'no_profile', 'known', 'learning']) {
      const alarm = ['hard_limit', 'deviation'].includes(verdict);
      assert.equal(isAlarm(verdict), alarm, verdict);
      assert.equal(verdictClass(verdict) === 'bad', alarm, `${verdict}: red badge`);
    }
    session.checked = true;
    const restricted = ['/rules', '/agents', '/sources', '/users', '/settings'];
    for (const role of ['viewer', 'admin']) {
      session.user = { id: 'test-user', name: 'Test', role, second_factor_required: false };
      for (const path of ['/', '/alerts', '/account', ...restricted]) {
        route.path = path;
        const { body } = render(App);
        for (const href of restricted) {
          assert.equal(body.includes(`href="${href}"`), role === 'admin', `${role}: navigation ${href}`);
        }
        assert.ok(body.includes('href="/"') && body.includes('href="/alerts"') && body.includes('href="/account"'), `${role}: everyone has an account page`);
        assert.equal(body.includes('<h1>Account</h1>'), path === '/account', `${role}: account page at ${path}`);
        assert.equal(body.includes('Administrators only'), role === 'viewer' && restricted.includes(path), `${role}: direct URL ${path}`);
        if (path === '/alerts') {
          assert.match(body, /aria-label="Category"/);
          assert.match(body, /aria-pressed="true"[^>]*>Alerts<\/button>/);
          assert.match(body, /aria-pressed="false"[^>]*>Notices<\/button>/);
          const verdicts = body.match(/<select[^>]*aria-label="Verdict"[^>]*>(.*?)<\/select>/s)?.[1];
          assert.ok(verdicts, 'verdict filter exists');
          assert.match(verdicts, /value="hard_limit"/);
          assert.match(verdicts, /value="deviation"/);
          assert.doesNotMatch(verdicts, /value="(?:new|flagged|no_profile|known|learning)"/);
        }
      }
    }
    // Second factor required and none set up: nothing but the account page,
    // whatever the URL — the server allows nothing else anyway.
    session.user = { id: 'test-user', name: 'Test', role: 'admin', second_factor_required: true };
    for (const path of ['/', '/rules']) {
      route.path = path;
      const { body } = render(App);
      assert.ok(body.includes('<h1>Account</h1>') && body.includes('second factor'), `enrolment forced at ${path}`);
      assert.ok(!body.includes('href="/rules"') && body.includes('href="/account"'), `navigation reduced at ${path}`);
    }
  } finally {
    await server.close();
    delete globalThis.location;
    delete globalThis.window;
  }
});

// When an agent is deleted, the foreign key sets the alert's `agent_id` to
// NULL; the row deliberately stays. Without the fallback to the name it would
// afterwards be the only one in the list that could not be filtered.
test('every alert row can be filtered to its origin, deleted agent or not', async () => {
  globalThis.location = { pathname: '/alerts' };
  globalThis.window = { addEventListener() {} };
  const server = await createServer({ server: { middlewareMode: true }, logLevel: 'error' });
  try {
    const { originOf } = await server.ssrLoadModule('/src/lib/router.svelte.ts');
    assert.deepEqual(originOf({ agent_id: 'a1', source_id: null, origin_name: 'mac' }), { agent: 'a1', source: undefined, name: 'mac' });
    assert.deepEqual(originOf({ agent_id: null, source_id: 's1', origin_name: 'syslog' }), { agent: undefined, source: 's1', name: 'syslog' });
    assert.deepEqual(originOf({ agent_id: null, source_id: null, origin_name: 'DESKTOP-EXAMPLE' }), { agent: undefined, source: undefined, name: 'DESKTOP-EXAMPLE' });
  } finally { await server.close(); }
});

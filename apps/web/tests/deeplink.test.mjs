import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'vite';

// The link from the alarm mail: `/alerts?alert=<id>`. The number comes out of
// a mail and therefore out of the world — it is checked like any other input
// before the page filters with it.
test('the link from an alert email names exactly one alert', async () => {
  globalThis.location = { pathname: '/alerts', search: '' };
  globalThis.window = { addEventListener() {} };
  const server = await createServer({ server: { middlewareMode: true }, logLevel: 'error' });
  try {
    const { deepLinkAlert } = await server.ssrLoadModule('/src/lib/router.svelte.ts');
    assert.equal(deepLinkAlert('?alert=42'), 42);
    assert.equal(deepLinkAlert('?alert=42&utm_source=mail'), 42, 'ein Mailklient haengt gern etwas an');
    for (const search of ['', '?', '?alert=', '?alert=abc', '?alert=0', '?alert=-3', '?alert=1.5', '?alert=9e9', '?other=42']) {
      assert.equal(deepLinkAlert(search), null, search);
    }
  } finally {
    await server.close();
  }
});

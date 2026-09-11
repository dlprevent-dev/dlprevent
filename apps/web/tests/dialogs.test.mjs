import assert from 'node:assert/strict';
import test from 'node:test';
import { readdir, readFile } from 'node:fs/promises';
import { createServer } from 'vite';

async function sources(dir = 'src') {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) out.push(...(await sources(p)));
    else if (/\.(svelte|ts)$/.test(e.name)) out.push(p);
  }
  return out;
}

/** `window.confirm` brings along a box that looks like the operating system
 *  and not like this application — and in which "Delete" and "Cancel" look
 *  the same, even though one of them shuts a device down.
 *
 *  The bolt is here because the relapse would be especially quiet: `ask`
 *  returns a promise, and a promise is always truthy. Write
 *  `if (!confirm(…)) return;` again out of habit and you get no error — the
 *  confirmation simply disappears, the cancel never arrives, and the action
 *  goes through **always**. */
test('nothing asks through the browser any more', async () => {
  const offenders = [];
  for (const f of await sources()) {
    const src = await readFile(f, 'utf8');
    src.split('\n').forEach((line, i) => {
      // Comments may talk about `confirm` — what is checked is code.
      const code = line.trim();
      if (code.startsWith('*') || code.startsWith('//') || code.startsWith('/*')) return;
      // `confirmLabel` is a field name, not a call.
      const hit = /(?<![\w.])(confirm|alert|prompt)\s*\(/.exec(line);
      if (hit && !line.includes('confirmLabel')) offenders.push(`${f}:${i + 1} ${code}`);
    });
  }
  assert.deepEqual(offenders, [], `use ask() from lib/confirm.svelte.ts instead:\n${offenders.join('\n')}`);
});

/** A confirmation always ends — including the one nobody answers. If a
 *  promise stays open, the caller waits in silence and the page looks as if
 *  the button had done nothing. */
test('every question gets an answer, even when a second one interrupts it', async () => {
  const server = await createServer({ server: { middlewareMode: true }, logLevel: 'error' });
  try {
    const { ask, answer, dialog } = await server.ssrLoadModule('/src/lib/confirm.svelte.ts');

    const first = ask({ title: 'A', body: 'a', confirmLabel: 'Go' });
    assert.equal(dialog.ask.confirmLabel, 'Go');
    // With nothing specified, nothing is dangerous and the button is not called "OK".
    assert.equal(dialog.ask.danger, false);

    // A second question displaces the first — that one counts as declined
    // instead of staying open forever.
    const second = ask({ title: 'B', body: 'b', confirmLabel: 'Delete', danger: true });
    assert.equal(await first, false);
    assert.equal(dialog.ask.danger, true);

    answer(true);
    assert.equal(await second, true);
    assert.equal(dialog.ask, null, 'nach der Antwort ist kein Fenster mehr offen');

    // Cancel means false, and answering a second time does nothing.
    const third = ask({ title: 'C', body: 'c' });
    answer(false);
    assert.equal(await third, false);
    answer(true);
    assert.equal(dialog.ask, null);
  } finally {
    await server.close();
  }
});

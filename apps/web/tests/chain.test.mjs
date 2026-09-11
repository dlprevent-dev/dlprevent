import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'vite';

/** An alert as the server delivers it — the shapes come from the lab
 *  (contracts via the RDP clipboard, a copy onto the desktop). */
function alert(over = {}) {
  return {
    id: 7090, kind: 'endpoint', agent_id: 'a', source_id: null, origin_name: 'DESKTOP-EXAMPLE',
    external_id: '677', at: '2026-09-09T08:13:13Z', last_at: null, user_key: null, user_display: null,
    rule_id: null, path: null, process: 'MpDefenderCoreService.exe',
    files: ['\\\\fs-01\\GL\\Vertraege\\Vertraege-034.dat', '\\\\fs-01\\GL\\Vertraege\\Vertraege-033.dat'],
    file_count: 2, bytes: 5567, remote: '52.123.129.14:443', verdict: 'deviation',
    reason: 'destination is not on the allowlist of \\\\FS-01\\GL',
    detail: { pid: 3404, via: 'read by rdpclip.exe (PID 5980)' },
    acknowledged_at: null, acknowledged_by: null, received_at: '2026-09-09T08:13:14Z',
    ...over,
  };
}

test('the chain of an alert reads from the protected file to the destination', async () => {
  const server = await createServer({ server: { middlewareMode: true }, logLevel: 'error' });
  try {
    const { chainOf } = await server.ssrLoadModule('/src/lib/chain.ts');

    // The case this is all about: rdpclip reads, a different process sends.
    const c = chainOf(alert());
    assert.deepEqual(c.map((n) => n.role), ['source', 'reader', 'sender', 'destination']);
    assert.equal(c[0].label, '\\\\fs-01\\GL\\Vertraege\\Vertraege-034.dat');
    assert.equal(c[0].sub, '+ 1 more');
    assert.equal(c[1].label, 'rdpclip.exe');
    assert.equal(c[1].sub, 'PID 5980');
    assert.equal(c[1].edge, 'read by');
    assert.equal(c[2].label, 'MpDefenderCoreService.exe');
    assert.equal(c[2].sub, 'PID 3404');
    // The sender did not read the file itself — that is exactly what
    // explains why it was not stopped.
    assert.equal(c[2].edge, 'taint inherited');
    assert.equal(c[3].label, '52.123.129.14:443');
    assert.equal(c[3].edge, '5.4 KB out');

    // With an intermediate copy one node is added, in the order of the chain.
    const copied = chainOf(alert({ detail: { pid: 3404, via: 'read by rdpclip.exe (PID 5980), via copy C:\\WINDOWS\\system32\\catroot2' } }));
    assert.deepEqual(copied.map((n) => n.role), ['source', 'reader', 'copy', 'sender', 'destination']);
    assert.equal(copied[2].label, 'C:\\WINDOWS\\system32\\catroot2');

    // The note about a link-local peer is tacked on the end and must not
    // swallow the path of the copy.
    const ll = chainOf(alert({ detail: { pid: 3404, via: 'read by cat (PID 11), link-local peer (AirDrop or local network)' } }));
    assert.deepEqual(ll.map((n) => n.role), ['source', 'reader', 'sender', 'destination']);
    assert.equal(ll[1].label, 'cat');

    // One that read the file itself gets no reader node and the other edge.
    // `via` is a sentence for humans here, not a blueprint.
    const copy = chainOf(alert({
      process: 'EXPLORER.EXE.MUI', bytes: 0, remote: 'copy to C:\\Users\\dl-anna\\Desktop', file_count: 14,
      detail: { pid: 900, sender_read_directly: true, via: '14 files copied out of the protected folder to C:\\Users\\dl-anna\\Desktop' },
    }));
    assert.deepEqual(copy.map((n) => n.role), ['source', 'sender', 'destination']);
    assert.equal(copy[1].edge, 'read directly');
    assert.equal(copy[2].label, 'C:\\Users\\dl-anna\\Desktop');
    assert.equal(copy[2].sub, 'copy target');
    assert.equal(copy[2].edge, undefined, 'ohne gesendete Bytes keine Mengenangabe');

    // Without a destination the chain ends at the sender, instead of drawing an empty box.
    assert.deepEqual(chainOf(alert({ remote: null })).map((n) => n.role), ['source', 'reader', 'sender']);

    // An access alert from the file server has no process chain.
    assert.deepEqual(chainOf(alert({ kind: 'access', process: null })), []);
  } finally {
    await server.close();
  }
});

test('the badge says what was actually done, not what the verdict is called', async () => {
  const server = await createServer({ server: { middlewareMode: true }, logLevel: 'error' });
  try {
    const { interventionOf } = await server.ssrLoadModule('/src/lib/api.ts');
    const withReason = (reason, over = {}) => interventionOf(alert({ reason, ...over }));

    // The case that set off the confusion: it says "Denied", nothing was
    // done -- the sender had never read the file.
    assert.deepEqual(withReason('destination is not on the allowlist of \\\\FS-01\\GL — sender not stopped (did not read the file itself)'),
      { label: 'reported only', tone: '' });
    // With no note at all, nothing happened either.
    assert.deepEqual(withReason(null), { label: 'reported only', tone: '' });

    // What the agent can still do today.
    assert.deepEqual(withReason('denied — copy deleted'), { label: 'copy deleted', tone: 'ok' });
    assert.deepEqual(withReason('denied — copy locked, deletion pending (os error 32)'), { label: 'deletion pending', tone: 'warn' });
    assert.deepEqual(withReason('denied — copy NOT deleted: unknown target'), { label: 'copy not deleted', tone: 'bad' });
    assert.deepEqual(withReason('denied — copy NOT deleted (os error 32) and NOT locked (denied), retrying'), { label: 'copy not deleted', tone: 'bad' });

    // Rows from before 6240af9: killing the process is gone, but the alerts
    // from back then are still in the list.
    assert.deepEqual(withReason('denied — sender stopped'), { label: 'sender stopped', tone: 'ok' });
    assert.deepEqual(withReason('denied — sender NOT stopped: access denied'), { label: 'reported only', tone: '' });

    // No badge where there was nothing to intervene in: harmless verdicts
    // and the file server's access alerts.
    for (const verdict of ['new', 'known', 'learning', 'flagged', 'no_profile']) {
      assert.equal(interventionOf(alert({ verdict })), null, verdict);
    }
    assert.equal(interventionOf(alert({ kind: 'access', verdict: 'hard_limit' })), null, 'Zugriffswarnung');
    // For the remaining alarms there is one.
    assert.deepEqual(interventionOf(alert({ verdict: 'hard_limit', reason: null })), { label: 'reported only', tone: '' });
  } finally {
    await server.close();
  }
});

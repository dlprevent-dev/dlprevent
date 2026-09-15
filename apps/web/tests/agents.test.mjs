import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'vite';

/** The full checksum of the uploaded file; `build` is the start of it. */
const SHA = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';

function bin(over = {}) {
  return { platform: 'windows', file_name: 'deelpe-winagent.exe', present: true, size: 4700000, sha256: SHA, uploaded_at: null, ...over };
}

test('the agent list marks who runs a different program than the one uploaded', async () => {
  const server = await createServer({ server: { middlewareMode: true }, logLevel: 'error' });
  try {
    const { agentOutdated, platformFor, selfReplacingPlatform, updateStuck } = await server.ssrLoadModule('/src/lib/api.ts');

    // The same mapping as `binaries::platform_for` on the server. Get it
    // wrong here and you show an agent as outdated that the server does not
    // mean at all.
    assert.equal(platformFor('windows_server'), 'windows');
    assert.equal(platformFor('windows_client'), 'windows');
    assert.equal(platformFor('mac'), 'mac');
    // `null`, not `'mac'`: there is no Linux program in the store, and
    // falling through to the Mac branch would offer a Linux machine the
    // macOS bundle. The server fixed exactly this in `platform_for`; this
    // side kept the old answer until the Linux agent shipped.
    assert.equal(platformFor('linux'), null);
    assert.equal(selfReplacingPlatform('windows_server'), 'windows');
    assert.equal(selfReplacingPlatform('windows_client'), 'windows');
    assert.equal(selfReplacingPlatform('mac', 'arm64'), null);
    // Linux by architecture, and not at all from an agent that does not say
    // it (older than 0.1.4, and unable to replace itself anyway).
    assert.equal(selfReplacingPlatform('linux', 'amd64'), 'linux-amd64');
    assert.equal(selfReplacingPlatform('linux', 'arm64'), 'linux-arm64');
    assert.equal(selfReplacingPlatform('linux'), null);

    const agent = (build, kind = 'windows_server', arch) => ({ kind, status: build === null ? null : { build, arch } });

    // The most common case: the fingerprint is the start of the checksum.
    assert.equal(agentOutdated(agent(SHA.slice(0, 12)), [bin()]), false);
    assert.equal(agentOutdated(agent('0123456789ab'), [bin()]), true);

    // An agent from before the fingerprint does not say what it runs — that
    // one is not shown as outdated on suspicion.
    assert.equal(agentOutdated(agent(undefined), [bin()]), false);
    assert.equal(agentOutdated(agent(null), [bin()]), false);
    assert.equal(agentOutdated(agent('aabb'), [bin()]), false);

    // And with no staged binary nobody is outdated: an empty prefix would
    // otherwise match everything.
    assert.equal(agentOutdated(agent('0123456789ab'), []), false);
    assert.equal(agentOutdated(agent('0123456789ab'), [bin({ present: false, sha256: '' })]), false);

    // A Mac agent is not compared at all: it reports the fingerprint of its
    // executable, but what is staged is the zip around the bundle — the one
    // checksum can never be the start of the other. A comparison would label
    // every Mac "outdated" forever. `binaries::self_replacing_platform` draws
    // the same line on the server.
    assert.equal(agentOutdated(agent('0123456789ab', 'mac'), [bin({ platform: 'mac' })]), false);
    assert.equal(agentOutdated(agent('0123456789ab', 'linux'), [bin({ platform: 'mac' })]), false);
    // A Linux agent is compared against its architecture's program only.
    const linuxBin = bin({ platform: 'linux-amd64', file_name: 'deelpe-linux-amd64' });
    assert.equal(agentOutdated(agent('0123456789ab', 'linux', 'amd64'), [linuxBin]), true);
    assert.equal(agentOutdated(agent(SHA.slice(0, 12), 'linux', 'amd64'), [linuxBin]), false);
    assert.equal(agentOutdated(agent('0123456789ab', 'linux', 'arm64'), [linuxBin]), false, 'no arm64 program staged');
    assert.equal(agentOutdated(agent('0123456789ab', 'linux'), [linuxBin]), false, 'no architecture reported');

    // An order the agent has seen and not carried out. Without that
    // distinction the dashboard says "Update sent" forever and nobody knows
    // what they are waiting for — exactly what happened in the lab on
    // 2026-09-10: both Windows agents ran a build from before self-renewal
    // and could not see the order at all.
    const at = (s) => new Date(s).toISOString();
    const req = '2026-09-10T13:39:00Z';
    assert.equal(updateStuck({ update_requested: req, last_seen: at('2026-09-10T13:48:00Z') }), true);
    // Just issued, the agent has had no chance yet: that is not being left
    // lying, that is waiting.
    assert.equal(updateStuck({ update_requested: req, last_seen: at('2026-09-10T13:39:20Z') }), false);
    // And an agent that has not checked in at all since the order is
    // offline — that is not being left lying either.
    assert.equal(updateStuck({ update_requested: req, last_seen: at('2026-09-10T13:20:00Z') }), false);
    assert.equal(updateStuck({ update_requested: req, last_seen: null }), false);
    assert.equal(updateStuck({ update_requested: null, last_seen: at('2026-09-10T13:48:00Z') }), false);
  } finally {
    await server.close();
  }
});

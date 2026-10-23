'use strict';

/**
 * CBHR ENDPOINT AGENT — cross-process durability probe (workstream W7 test support).
 *
 * NOT a test file. Spawned by `test/durability.test.js` as a REAL SECOND PROCESS, because the claim
 * under test is specifically that a nonce survives a restart: an in-process check cannot test it, and
 * a test that fakes a restart by clearing an object would be testing the fake.
 *
 * usage: node test/_replay-probe.js <agentRoot> <frameJsonFile> <nowMs>
 *
 * Output (one JSON line on stdout):
 *   {"process": <pid>, "verdict": "accepted"|"refused", "code": ..., "entries": n, "replayFile": ...}
 *
 * The probe verifies the SAME frame bytes from a file, with a FIXED clock, so the only variable
 * between two runs is the persisted replay state on disk.
 */

const fs = require('node:fs');
const { verifyCommandFrame } = require('../src/verify');
const { buildPinSet } = require('../src/pinnedKeys');
const { createDurableReplayWindow } = require('../src/replayWindow');

async function main() {
  const [, , agentRoot, frameFile, nowMsRaw] = process.argv;
  const nowMs = Number(nowMsRaw);
  const frame = JSON.parse(fs.readFileSync(frameFile, 'utf8'));
  const descriptor = JSON.parse(fs.readFileSync(`${frameFile}.meta.json`, 'utf8'));

  const replayWindow = createDurableReplayWindow({
    rootDir: agentRoot,
    now: () => nowMs,
  });
  const verdict = await verifyCommandFrame({
    frame,
    pins: buildPinSet([
      { keyId: descriptor.keyId, publicKeySpkiB64u: descriptor.publicKeySpkiB64u },
    ]),
    deviceId: descriptor.deviceId,
    deviceKeyId: descriptor.deviceKeyId,
    now: () => nowMs,
    replayWindow,
  });

  process.stdout.write(
    `${JSON.stringify({
      process: process.pid,
      verdict: verdict.ok === true ? 'accepted' : 'refused',
      code: verdict.ok === true ? null : verdict.error.code,
      entries: replayWindow.size(),
      loadedEntries: replayWindow.loadedEntries,
      replayFile: replayWindow.replayFile(),
    })}\n`,
  );
}

main().catch((err) => {
  process.stdout.write(
    `${JSON.stringify({ process: process.pid, verdict: 'threw', code: err.code ?? 'UNKNOWN' })}\n`,
  );
  process.exitCode = 1;
});
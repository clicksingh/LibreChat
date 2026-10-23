'use strict';

/**
 * W7 spec — THE REPLAY WINDOW IS DURABLE, PROVEN ACROSS A REAL PROCESS RESTART.
 *
 * GM-34 assigns the durable replay authority to the relay's DO ring AND the endpoint's own persisted
 * window. The endpoint half is the one an attacker can target directly: they hold a captured frame,
 * they wait for the agent to be restarted (an update, a crash, a reboot — none of which is under the
 * platform's control), and they replay it while it is still inside the 60 s freshness window. An
 * in-memory ring cannot survive that, and no in-process test can show the difference.
 *
 * So these tests spawn a SECOND, REAL Node process (`test/_replay-probe.js`) that verifies the same
 * frame bytes with a FIXED clock. The only thing that differs between the two runs is what the first
 * process wrote to disk:
 *
 *   process 1 : accepted      -> writes (grantId, nonce) to replay-window.json, then EXITS
 *   process 2 : refused       -> REPLAY_DETECTED, loaded from the file process 1 left behind
 *
 * The file is the evidence, so the tests also assert its contents: an entry keyed `grantId:nonce`
 * with an expiry at least the retention horizon away, inside the same agent root the keystore and the
 * tool config live in (never in the repository worktree).
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { describe, it } = require('node:test');

const fixtures = require('./_fixtures');
const { createDurableReplayWindow } = require('../src/replayWindow');
const { writeOwnerOnlyFile } = require('../src/permissions');

const PROBE = path.resolve(__dirname, '_replay-probe.js');
const T = fixtures.T0;

/** Writes a frame plus the descriptor the probe needs, both inside the agent root. */
function stageFrame(agentRoot, name, { sign, keyId, deviceId, deviceKeyId, core }) {
  const built = fixtures.buildFrame({
    sign,
    keyId,
    core: { issuedAt: String(T), deadlineMs: String(T + 60000), ...core },
  });
  const frameFile = path.join(agentRoot, `${name}.frame.json`);
  writeOwnerOnlyFile(frameFile, JSON.stringify(built.frame));
  writeOwnerOnlyFile(
    `${frameFile}.meta.json`,
    JSON.stringify({
      keyId,
      publicKeySpkiB64u: sign.publicKeySpkiB64u ?? null,
      deviceId,
      deviceKeyId,
    }),
  );
  return { frameFile, built };
}

function runProbe(agentRoot, frameFile, nowMs) {
  const result = spawnSync(process.execPath, [PROBE, agentRoot, frameFile, String(nowMs)], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, `probe failed: ${result.stderr}`);
  return JSON.parse(result.stdout.trim());
}

describe('the replay window survives a process restart', () => {
  it('accepts a nonce in one process and refuses it in the NEXT process', () => {
    const root = fixtures.makeTempRoot();
    try {
      const backend = fixtures.makeKeypair();
      const nonce = Buffer.alloc(16, 0x42).toString('base64url');
      const deviceId = 'device-durability-1';
      const deviceKeyId = fixtures.WORKED_EXAMPLE.deviceKeyId;

      // The probe needs the public key; attach it to the signer for the descriptor.
      const sign = backend.sign;
      sign.publicKeySpkiB64u = backend.publicKeySpkiB64u;
      const { frameFile } = stageFrame(root, 'durable', {
        sign,
        keyId: backend.keyId,
        deviceId,
        deviceKeyId,
        core: { nonce, deviceId, deviceKeyId },
      });

      const first = runProbe(root, frameFile, T + 1000);
      assert.equal(first.verdict, 'accepted', JSON.stringify(first));
      assert.equal(first.entries, 1);

      // The file is the durable record, and it is where the agent root says it is.
      const replayFile = path.join(root, 'replay-window.json');
      assert.equal(first.replayFile, replayFile);
      assert.equal(fs.existsSync(replayFile), true);
      const persisted = JSON.parse(fs.readFileSync(replayFile, 'utf8'));
      assert.equal(persisted.version, 1);
      assert.equal(persisted.entries.length, 1);
      assert.equal(persisted.entries[0].key, `${fixtures.WORKED_EXAMPLE.grantId}:${nonce}`);

      // SECOND PROCESS: nothing in memory carries over; only the file does.
      const second = runProbe(root, frameFile, T + 2000);
      assert.notEqual(second.process, first.process, 'the probe must be a different process');
      assert.equal(second.verdict, 'refused');
      assert.equal(second.code, 'ENDPOINT_REPLAY_DETECTED');
      assert.equal(second.loadedEntries, 1, 'the second process must LOAD the first process`s entry');
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('the SAME frame bytes are refused only because of the persisted file: the in-memory control accepts them', () => {
    const root = fixtures.makeTempRoot();
    try {
      const backend = fixtures.makeKeypair();
      const nonce = Buffer.alloc(16, 0x43).toString('base64url');
      const deviceId = 'device-durability-2';
      const deviceKeyId = fixtures.WORKED_EXAMPLE.deviceKeyId;
      const grantId = fixtures.WORKED_EXAMPLE.grantId;

      // CONTROL A: a window with NO file (equivalent to two restarts of an in-memory ring) accepts
      // the nonce in both "processes".
      const memoryA = createDurableReplayWindow({ persist: false, now: () => T + 1000 });
      const memoryB = createDurableReplayWindow({ persist: false, now: () => T + 1000 });
      assert.equal(memoryA.checkAndRemember({ grantId, nonce }).ok, true);
      assert.equal(memoryB.checkAndRemember({ grantId, nonce }).ok, true, 'the in-memory control accepts the replay');
      assert.equal(memoryA.keyOf({ grantId, nonce }), `${grantId}:${nonce}`);

      // CONTROL B: with the file, the second window refuses. Same bytes, same clock, same key — the
      // only difference is durability.
      const durableA = createDurableReplayWindow({ rootDir: root, now: () => T + 1000 });
      assert.equal(durableA.checkAndRemember({ grantId, nonce }).ok, true);
      const durableB = createDurableReplayWindow({ rootDir: root, now: () => T + 1000 });
      const refused = durableB.checkAndRemember({ grantId, nonce });
      assert.equal(refused.ok, false);
      assert.equal(refused.error.code, 'ENDPOINT_REPLAY_DETECTED');

      // And the frames under test really are one and the same document, byte for byte.
      const sign = backend.sign;
      sign.publicKeySpkiB64u = backend.publicKeySpkiB64u;
      const { frameFile } = stageFrame(root, 'volatile', {
        sign,
        keyId: backend.keyId,
        deviceId,
        deviceKeyId,
        core: { nonce, deviceId, deviceKeyId },
      });
      const frame = JSON.parse(fs.readFileSync(frameFile, 'utf8'));
      const rebuilt = fixtures.buildFrame({
        sign: backend.sign,
        keyId: backend.keyId,
        core: { nonce, deviceId, deviceKeyId, issuedAt: String(T), deadlineMs: String(T + 60000) },
      });
      assert.equal(frame.argsDigestHex, rebuilt.frame.argsDigestHex);
      assert.equal(frame.signatureB64u, rebuilt.frame.signatureB64u, 'Ed25519 is deterministic: same bytes, same signature');
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('the persist flag is what makes the difference, on the same agent root', () => {
    const root = fixtures.makeTempRoot();
    try {
      const now = () => T + 1000;
      const durable = createDurableReplayWindow({ rootDir: root, now });
      const grantId = fixtures.WORKED_EXAMPLE.grantId;
      const nonce = Buffer.alloc(16, 0x44).toString('base64url');

      assert.equal(durable.checkAndRemember({ grantId, nonce }).ok, true);
      assert.equal(durable.checkAndRemember({ grantId, nonce }).ok, false);

      // A SECOND durable window on the same root already sees the nonce.
      const reloaded = createDurableReplayWindow({ rootDir: root, now });
      assert.equal(reloaded.loadedEntries, 1);
      const verdict = reloaded.checkAndRemember({ grantId, nonce });
      assert.equal(verdict.ok, false);
      assert.equal(verdict.error.code, 'ENDPOINT_REPLAY_DETECTED');

      // An explicit in-memory window on the same root does NOT (that is the failure mode being fixed).
      const volatile = createDurableReplayWindow({ persist: false, rootDir: root, now });
      assert.equal(volatile.loadedEntries, 0);
      assert.equal(volatile.checkAndRemember({ grantId, nonce }).ok, true);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('retention cannot be configured below the widest freshness window', () => {
    const root = fixtures.makeTempRoot();
    try {
      assert.throws(
        () => createDurableReplayWindow({ rootDir: root, retentionMs: 1000 }),
        (err) => err.code === 'ENDPOINT_ENVELOPE_SHAPE_INVALID',
      );
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('a nonce is kept until it can no longer be fresh, and dropped after', () => {
    const root = fixtures.makeTempRoot();
    try {
      let clockMs = T;
      const window = createDurableReplayWindow({ rootDir: root, now: () => clockMs });
      const grantId = fixtures.WORKED_EXAMPLE.grantId;
      const nonce = Buffer.alloc(16, 0x45).toString('base64url');
      assert.equal(window.checkAndRemember({ grantId, nonce }).ok, true);

      // Exactly at the reservation expiry the entry must still be present (strict `<` pruning).
      clockMs = T + window.retentionMs;
      assert.equal(window.has(grantId, nonce), true, 'an entry at exactly its expiry must be retained');

      clockMs = T + window.retentionMs + 1;
      assert.equal(window.has(grantId, nonce), false);
      // And the prune is persisted, not just in memory.
      const reloaded = createDurableReplayWindow({ rootDir: root, now: () => clockMs });
      assert.equal(reloaded.loadedEntries, 0);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('a corrupt replay file FAILS CLOSED rather than starting with an empty window', () => {
    const root = fixtures.makeTempRoot();
    try {
      writeOwnerOnlyFile(path.join(root, 'replay-window.json'), '{ this is not json');
      assert.throws(
        () => createDurableReplayWindow({ rootDir: root, now: () => T }),
        (err) => err.code === 'ENDPOINT_REPLAY_STORE_UNAVAILABLE',
      );
    } finally {
      fixtures.removeTempRoot(root);
    }
  });
});
'use strict';

/**
 * W13 spec — THE RUNTIME AS A LIVE PARTICIPANT (real relay, real sockets, real child processes).
 *
 * This is the file that answers "can this thing actually be left running on a PC?". Everything it
 * does is real:
 *
 *   - a REAL relay artifact: the audited `dist/worker.js`, booted through Miniflare/workerd in this
 *     process with the compatibility configuration read out of the relay's own `wrangler.toml`
 *     (`test/_relay-harness.cjs`, the same approach `apps/cbhr-relay/run-reconciliation.mjs` uses);
 *   - a REAL device socket: `node run-agent.js serve` as a CHILD PROCESS, connecting to the relay's
 *     device route, held open for the length of a case;
 *   - a REAL platform reader socket (`?tag=platform`), which is where a dispatched call's result has
 *     to turn up for the platform to correlate it;
 *   - REAL frames: signed by a lab backend key the endpoint has PINNED, verified by the endpoint's own
 *     independent verifier, executed against real files, and returned device-signed;
 *   - REAL shutdown: the child is asked to stop the way an operator or a service manager stops it.
 *
 * What each case is allowed to prove is bounded on purpose. The result frame is checked with the
 * endpoint's own `verifyResultFrame` against the DEVICE public key the same agent prints in
 * `describe` — so "the platform can verify this" is a statement about the device signature, not about
 * trusting the runtime's log line. Where a case cannot prove something (a replayed frame whose
 * execution we cannot observe directly), it says so and proves the strongest available proxy
 * (`executed:false` on the signed refusal path plus the absence of the file's content anywhere).
 *
 * The suite REFUSES to run without the relay rather than skipping: a missing end-to-end proof must not
 * read as a passing one.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { before, after, describe, it } = require('node:test');

const fixtures = require('./_fixtures');
const { verifyResultFrame } = require('../src/resultFrame');
const { loadDeviceKeystore } = require('../src/keystore');
const { createDurableReplayWindow } = require('../src/replayWindow');
const { writeOwnerOnlyFile } = require('../src/permissions');
const harnessLib = require('./_relay-harness.cjs');

const AGENT_DIR = path.resolve(__dirname, '..');
const AGENT_ENTRY = path.join(AGENT_DIR, 'run-agent.js');
const RELAY_DEVICE_TAG = 'device';
const { waitFor, sleep, childEnvironment, ORIGINAL_TEMP_DIR } = harnessLib;

/**
 * Agent roots live in the REAL OS temp directory, never in the relay's scratch tree: the endpoint is
 * an ordinary Node process and has to be exercised where it will actually run. `ORIGINAL_TEMP_DIR` is
 * captured before the harness redirects `TMP` for workerd, and every child process gets it back
 * explicitly (`childEnvironment`).
 */
const ROOTS_DIR = fs.mkdtempSync(path.join(ORIGINAL_TEMP_DIR, 'cbhr-w13-agent-roots-'));

/** The parsed shape of one runtime log line: `<ts> LEVEL event {json}`. */
const LINE_PATTERN = /^(\d{4}-\d{2}-\d{2}T\S+) ([A-Z]+)\s+(\S+)(?: (\{.*\}))?$/;

function parseLine(stream, text) {
  const match = LINE_PATTERN.exec(text);
  if (match === null) {
    return { stream, text, event: null, level: null, fields: null };
  }
  let fields = null;
  try {
    fields = match[4] === undefined ? null : JSON.parse(match[4]);
  } catch {
    fields = null;
  }
  return { stream, text, level: match[2], event: match[3], fields };
}

/** Runs one shipped CLI command as a real process and returns its stdout. */
function runCli(args, options = {}) {
  const result = spawnSync(process.execPath, [AGENT_ENTRY, ...args], {
    cwd: AGENT_DIR,
    encoding: 'utf8',
    env: childEnvironment(),
    ...options,
  });
  assert.equal(result.status, 0, `run-agent.js ${args.join(' ')} failed: ${result.stderr}`);
  return result.stdout;
}

/**
 * Starts `run-agent.js serve` as a real child process, capturing every log line it writes.
 */
function startRuntime({ root, relayBase, extraArgs = [] }) {
  const child = spawn(
    process.execPath,
    [
      AGENT_ENTRY,
      'serve',
      '--root',
      root,
      '--relay',
      relayBase,
      '--shutdown-on-stdin-eof',
      '--backoff-initial-ms',
      '50',
      '--backoff-max-ms',
      '200',
      '--verdict-timeout-ms',
      '8000',
      '--drain-ms',
      '3000',
      ...extraArgs,
    ],
    { cwd: AGENT_DIR, stdio: ['pipe', 'pipe', 'pipe'], env: childEnvironment() },
  );
  const lines = [];
  const collect = (stream) => (chunk) => {
    for (const text of chunk.toString('utf8').split(/\r?\n/)) {
      if (text.trim().length > 0) {
        lines.push(parseLine(stream, text));
      }
    }
  };
  child.stdout.on('data', collect('stdout'));
  child.stderr.on('data', collect('stderr'));
  const exited = new Promise((resolve) => {
    child.on('exit', (code, signal) => resolve({ code, signal }));
  });

  return {
    child,
    lines,
    exited,
    events: () => lines.filter((line) => line.event !== null),
    found: (event, count = 1) => lines.filter((line) => line.event === event).length >= count,
    async waitForEvent(event, count = 1, timeout = 15000) {
      const found = await waitFor(() => (lines.filter((line) => line.event === event).length >= count ? true : null), {
        timeout,
      });
      assert.ok(found, `the runtime never logged ${event}; saw:\n${lines.map((line) => line.text).join('\n')}`);
      return lines.filter((line) => line.event === event);
    },
    /** Clean shutdown through the control channel this runtime exposes (see the signal note below). */
    async stop(timeout = 15000) {
      child.stdin.end();
      const result = await Promise.race([exited, sleep(timeout).then(() => null)]);
      if (result === null) {
        child.kill();
        assert.fail('the runtime did not exit after its stdin reached EOF');
      }
      return result;
    },
  };
}

/** Creates an initialised agent root (real CLI, real key, real pin) plus a workspace with one file. */
function makeRoot({ deviceId, backend, tools, file = { name: 'hello.txt', content: 'the quick brown fox' } }) {
  // Deliberately NOT `fixtures.makeTempRoot()`: this suite's TMP points at workerd's scratch tree, so
  // the agent root goes under ROOTS_DIR (the real OS temp directory) instead.
  const root = fs.mkdtempSync(path.join(ROOTS_DIR, 'root-'));
  runCli(['init', '--root', root, '--device-id', deviceId]);
  const spkiFile = path.join(root, 'lab-backend-spki.txt');
  fs.writeFileSync(spkiFile, backend.publicKeySpkiB64u, 'utf8');
  runCli(['pin-backend', '--root', root, '--spki-file', spkiFile]);
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(workspace, { recursive: true });
  if (file !== null) {
    fs.writeFileSync(path.join(workspace, file.name), file.content, 'utf8');
  }
  if (tools !== undefined) {
    // The device floor: the employee's own (narrowing) choice, written where the agent reads it.
    writeOwnerOnlyFile(path.join(root, 'tools.json'), `${JSON.stringify({ version: 1, enabled: tools }, null, 2)}\n`);
  }
  const described = JSON.parse(runCli(['describe', '--root', root]));
  return { root, workspace, describe: described.agent, spkiFile };
}

/** A fresh, correctly signed command frame addressed to this endpoint. */
function signedFrame({ describe, backend, toolName, args, callId, nonce, argsB64u }) {
  const now = Date.now();
  return fixtures.buildFrame({
    sign: backend.sign,
    keyId: backend.keyId,
    core: {
      deviceId: describe.deviceId,
      deviceKeyId: describe.deviceKeyId,
      issuedAt: String(now),
      deadlineMs: String(now + 60000),
      nonce: nonce ?? nodeCrypto.randomBytes(16).toString('base64url'),
      toolName,
    },
    args,
    ...(argsB64u === undefined ? {} : { argsB64u }),
    extra: { callId },
  }).frame;
}

/** The device public key the same agent publishes, used to verify what the platform received. */
function verifyPlatformResult({ describe, pushed }) {
  const frame = JSON.parse(pushed.payload);
  const verdict = verifyResultFrame({ frame, devicePublicKeySpkiB64u: describe.devicePublicKeySpkiB64u });
  assert.equal(verdict.ok, true, verdict.ok === false ? `result refused: ${verdict.error.code}` : '');
  return { frame, verdict, payload: JSON.parse(verdict.payloadBytes.toString('utf8')) };
}

describe('the runtime is a live participant: real relay, real socket, real child process', () => {
  let relay;
  /** @type {Array<{close: () => void}>} */
  const openSockets = [];

  before(async () => {
    relay = await harnessLib.startRelay();
    const health = await relay.health();
    assert.equal(health.body.ok, true, 'the local relay artifact must answer /health before the suite runs');
    assert.equal(health.body.role, 'keyless-forwarder');
  });

  after(async () => {
    for (const socket of openSockets) {
      socket.close();
    }
    await relay.stop();
    try {
      fs.rmSync(ROOTS_DIR, { recursive: true, force: true, maxRetries: 3 });
    } catch {
      // Best effort, like `fixtures.removeTempRoot`.
    }
  });

  async function platformSocket(deviceId) {
    const socket = await relay.connect(deviceId, 'platform');
    openSockets.push(socket);
    return socket;
  }

  it('a dispatched command reaches the running agent, executes a real tool, and its result is correlated by the platform', async () => {
    const backend = fixtures.makeKeypair();
    const deviceId = 'device-w13-e2e-happy';
    const root = makeRoot({ deviceId, backend });
    const runtime = startRuntime({ root: root.root, relayBase: relay.base });
    try {
      const granted = await relay.grant(deviceId);
      assert.equal(granted.body.ok, true);
      const platform = await platformSocket(deviceId);

      const frame = signedFrame({
        describe: root.describe,
        backend,
        toolName: 'read_file',
        args: { path: 'hello.txt' },
        callId: 'w13-call-happy',
      });
      await runtime.waitForEvent('relay.connected');
      const connected = runtime.events().find((line) => line.event === 'relay.connected');
      assert.equal(connected.fields.deviceKeyId, root.describe.deviceKeyId, 'the SAME device identity `describe` reports');
      assert.match(connected.fields.relay, new RegExp(`/d/${deviceId}/ws\\?tag=${RELAY_DEVICE_TAG}$`));

      const dispatched = await relay.dispatch(deviceId, { payload: JSON.stringify(frame), callId: 'w13-call-happy' });
      assert.equal(dispatched.body.admitted, true, JSON.stringify(dispatched.body));

      const pushed = await platform.waitFor('result', 1);
      assert.ok(pushed, 'the platform reader socket must receive the result');
      const [first] = pushed;
      assert.equal(first.callId, 'w13-call-happy', 'correlation is by callId, as the relay ledger is keyed');
      assert.equal(first.replay, false);

      const { frame: resultFrame, verdict, payload } = verifyPlatformResult({ describe: root.describe, pushed: first });
      assert.equal(resultFrame.outcome, 'succeeded');
      assert.equal(resultFrame.audience, 'relay');
      assert.equal(verdict.core.callId, 'w13-call-happy');
      assert.equal(payload.status, 'succeeded');
      assert.equal(payload.toolName, 'read_file');
      assert.equal(payload.result.content, 'the quick brown fox', 'the real file, read by the real tool');
      assert.equal(payload.result.sha256Hex, nodeCrypto.createHash('sha256').update('the quick brown fox').digest('hex'));

      // The relay holds the device's own bytes for the platform, byte for byte.
      const pending = await relay.pendingResults(deviceId);
      assert.equal(pending.body.count, 1);
      assert.equal(pending.body.pending[0].callId, 'w13-call-happy');
      assert.equal(pending.body.pending[0].payload, first.payload, 'the relay never rewrites a payload');
      const acked = await relay.ackResults(deviceId, [pending.body.pending[0].resultSeq]);
      assert.deepEqual(acked.body.acked, [pending.body.pending[0].resultSeq]);

      // What the endpoint itself said about the frame it handled.
      const outcome = await runtime.waitForEvent('frame.outcome');
      assert.equal(outcome[0].fields.outcome, 'succeeded');
      assert.equal(outcome[0].fields.executed, true);
      await runtime.waitForEvent('result.verdict');
      const verdictLine = runtime.events().find((line) => line.event === 'result.verdict');
      assert.equal(verdictLine.fields.accepted, true);
      assert.equal(verdictLine.fields.resultSeq, pending.body.pending[0].resultSeq);
      await runtime.waitForEvent('frame.acked');

      // The relay's own state: one call, completed, nothing left pending for redelivery.
      const state = await relay.state(deviceId);
      assert.equal(state.body.storage.callLedger.length, 1);
      assert.equal(state.body.storage.callLedger[0].state, 'completed');
      assert.deepEqual(state.body.storage.pending, []);

      const exit = await runtime.stop();
      assert.equal(exit.code, 0, 'a clean shutdown exits 0');
      assert.equal(exit.signal, null);
      const stopped = await runtime.waitForEvent('runtime.stopped');
      assert.equal(stopped[0].fields.reason, 'stdin-eof');
      assert.equal(stopped[0].fields.counters.framesAcked, 1);
      assert.equal(stopped[0].fields.counters.resultsAccepted, 1);
      assert.equal(stopped[0].fields.counters.resultsUnanswered, 0);
      assert.ok(runtime.found('runtime.replay.pruned'), 'the shutdown reports the durable window it left behind');
      assert.ok(runtime.found('runtime.keys.intact'));
    } finally {
      if (runtime.child.exitCode === null && runtime.child.signalCode === null) {
        runtime.child.kill();
      }
      fixtures.removeTempRoot(root.root);
    }
  });

  it('refuses a tampered frame, reports `refused`, and never executes the tampered arguments', async () => {
    const backend = fixtures.makeKeypair();
    const deviceId = 'device-w13-e2e-tamper';
    const root = makeRoot({ deviceId, backend, file: { name: 'hello.txt', content: 'harmless' } });
    fs.writeFileSync(path.join(root.workspace, 'secret.txt'), 'TOP SECRET', 'utf8');
    const runtime = startRuntime({ root: root.root, relayBase: relay.base });
    try {
      await relay.grant(deviceId);
      const platform = await platformSocket(deviceId);
      await runtime.waitForEvent('relay.connected');

      // Signed over hello.txt; the transported argument bytes name secret.txt. Same frame shape, one
      // field swapped after signing — exactly what an attacker who cannot sign can still do.
      const tampered = signedFrame({
        describe: root.describe,
        backend,
        toolName: 'read_file',
        args: { path: 'hello.txt' },
        argsB64u: fixtures.b64u(Buffer.from(JSON.stringify({ path: 'secret.txt' }), 'utf8')),
        callId: 'w13-call-tampered',
      });
      const dispatched = await relay.dispatch(deviceId, { payload: JSON.stringify(tampered), callId: 'w13-call-tampered' });
      assert.equal(dispatched.body.admitted, true);

      const pushed = await platform.waitFor('result', 1);
      const { frame: resultFrame, payload } = verifyPlatformResult({ describe: root.describe, pushed: pushed[0] });
      assert.equal(resultFrame.outcome, 'refused', 'a verification failure is a refusal, never a success');
      assert.equal(resultFrame.errorCode, 'ENDPOINT_ARGS_DIGEST_MISMATCH');
      assert.equal(resultFrame.correlation, 'unverified-claim', 'the correlation is a claim: the core was never authentic');
      assert.equal(payload.status, 'refused');
      assert.equal(payload.code, 'ENDPOINT_ARGS_DIGEST_MISMATCH');

      // Nothing about the file the tampered bytes named appears anywhere the platform can see.
      const everythingThePlatformSaw = JSON.stringify(pushed) + JSON.stringify(resultFrame);
      assert.doesNotMatch(everythingThePlatformSaw, /TOP SECRET/);

      const outcome = await runtime.waitForEvent('frame.outcome');
      assert.equal(outcome[0].fields.executed, false, 'the endpoint says plainly that nothing ran');
      assert.equal(outcome[0].fields.refusalCode, 'ENDPOINT_ARGS_DIGEST_MISMATCH');

      await runtime.stop();
    } finally {
      if (runtime.child.exitCode === null && runtime.child.signalCode === null) {
        runtime.child.kill();
      }
      fixtures.removeTempRoot(root.root);
    }
  });

  it('refuses the SAME frame after a process restart: the replay window is on disk, not in memory', async () => {
    const backend = fixtures.makeKeypair();
    const deviceId = 'device-w13-e2e-replay';
    const root = makeRoot({ deviceId, backend });
    const nonce = nodeCrypto.randomBytes(16).toString('base64url');

    const first = startRuntime({ root: root.root, relayBase: relay.base });
    let firstResultSeq;
    try {
      await relay.grant(deviceId);
      const platform = await platformSocket(deviceId);
      await first.waitForEvent('relay.connected');
      const frame = signedFrame({
        describe: root.describe,
        backend,
        toolName: 'read_file',
        args: { path: 'hello.txt' },
        callId: 'w13-call-replay-1',
        nonce,
      });
      await relay.dispatch(deviceId, { payload: JSON.stringify(frame), callId: 'w13-call-replay-1' });
      const pushed = await platform.waitFor('result', 1);
      const { frame: resultFrame } = verifyPlatformResult({ describe: root.describe, pushed: pushed[0] });
      assert.equal(resultFrame.outcome, 'succeeded', 'the first delivery is genuine and must execute');
      firstResultSeq = (await relay.pendingResults(deviceId)).body.pending[0].resultSeq;
      await relay.ackResults(deviceId, [firstResultSeq]);
      const exit = await first.stop();
      assert.equal(exit.code, 0);
    } finally {
      if (first.child.exitCode === null && first.child.signalCode === null) {
        first.child.kill();
      }
    }

    // The window process 1 left behind is the ONLY thing that can refuse the frame now.
    const replayFile = path.join(root.root, 'replay-window.json');
    const persisted = JSON.parse(fs.readFileSync(replayFile, 'utf8'));
    assert.equal(persisted.version, 1);
    assert.equal(persisted.entries.length, 1, 'the spent nonce must have been persisted before execution');
    assert.equal(persisted.entries[0].key, `${fixtures.WORKED_EXAMPLE.grantId}:${nonce}`);

    const second = startRuntime({ root: root.root, relayBase: relay.base });
    try {
      const platform = await platformSocket(deviceId);
      await second.waitForEvent('relay.connected');
      const startLine = second.events().find((line) => line.event === 'runtime.start');
      assert.ok(
        startLine.fields.replayWindowLoadedEntries >= 1,
        'the SECOND process must LOAD the first process`s entry, not start with an empty window',
      );

      // The same signed core (same grantId and nonce), a different transport callId — the callId is
      // outside the signature, so this is the replay an attacker can actually mount.
      const replay = signedFrame({
        describe: root.describe,
        backend,
        toolName: 'read_file',
        args: { path: 'hello.txt' },
        callId: 'w13-call-replay-2',
        nonce,
      });
      const dispatched = await relay.dispatch(deviceId, { payload: JSON.stringify(replay), callId: 'w13-call-replay-2' });
      assert.equal(dispatched.body.admitted, true);

      const pushed = await platform.waitFor('result', 1);
      assert.equal(pushed[0].callId, 'w13-call-replay-2');
      const { frame: resultFrame, payload } = verifyPlatformResult({ describe: root.describe, pushed: pushed[0] });
      assert.equal(resultFrame.outcome, 'refused');
      assert.equal(resultFrame.errorCode, 'ENDPOINT_REPLAY_DETECTED');
      assert.equal(payload.code, 'ENDPOINT_REPLAY_DETECTED');
      assert.equal(payload.status, 'refused');

      const outcome = second.events().find((line) => line.event === 'frame.outcome');
      assert.equal(outcome.fields.executed, false, 'the replayed frame must not execute a second time');
      assert.equal(outcome.fields.replay, false, 'the relay delivered it as a fresh frame, not as a resync');

      await second.stop();
    } finally {
      if (second.child.exitCode === null && second.child.signalCode === null) {
        second.child.kill();
      }
      fixtures.removeTempRoot(root.root);
    }
  });

  it('a clean shutdown leaves the key store and the replay window intact AND usable by the next start', async () => {
    const backend = fixtures.makeKeypair();
    const deviceId = 'device-w13-e2e-shutdown';
    const root = makeRoot({ deviceId, backend });
    const keyFile = path.join(root.root, 'device-key.json');
    const keyBytesBefore = fs.readFileSync(keyFile);

    const first = startRuntime({ root: root.root, relayBase: relay.base });
    try {
      await relay.grant(deviceId);
      const platform = await platformSocket(deviceId);
      await first.waitForEvent('relay.connected');
      const frame = signedFrame({
        describe: root.describe,
        backend,
        toolName: 'get_file_info',
        args: { path: 'hello.txt' },
        callId: 'w13-call-shutdown-1',
      });
      await relay.dispatch(deviceId, { payload: JSON.stringify(frame), callId: 'w13-call-shutdown-1' });
      const pushed = await platform.waitFor('result', 1);
      const { frame: resultFrame } = verifyPlatformResult({ describe: root.describe, pushed: pushed[0] });
      assert.equal(resultFrame.outcome, 'succeeded');
      const exit = await first.stop();
      assert.equal(exit.code, 0);
      // A clean shutdown says so: the socket is closed deliberately with a normal code, and at no
      // point does the runtime report the socket as LOST.
      const closing = first.events().find((line) => line.event === 'relay.closing');
      assert.ok(closing, 'a clean shutdown must report the deliberate socket close');
      assert.equal(closing.fields.code, 1000);
      assert.equal(first.found('relay.socket.lost'), false, 'a deliberate close is not an outage');
    } finally {
      if (first.child.exitCode === null && first.child.signalCode === null) {
        first.child.kill();
      }
    }

    // Nothing was deleted, and every store is still readable by a process that did not create it.
    assert.deepEqual(fs.readFileSync(keyFile), keyBytesBefore, 'the device key file is byte-identical after shutdown');
    const keystore = loadDeviceKeystore({ rootDir: root.root, createIfMissing: false });
    assert.equal(keystore.keyId(), root.describe.deviceKeyId);
    const window = createDurableReplayWindow({ rootDir: root.root });
    assert.equal(window.loadedEntries, 1, 'the next process loads the spent nonce');
    assert.equal(JSON.parse(fs.readFileSync(path.join(root.root, 'tools.json'), 'utf8')).enabled.length, 3);

    // ...and the store is USABLE: a fresh frame still executes on the next start.
    const second = startRuntime({ root: root.root, relayBase: relay.base });
    try {
      const platform = await platformSocket(deviceId);
      await second.waitForEvent('relay.connected');
      const frame = signedFrame({
        describe: root.describe,
        backend,
        toolName: 'read_file',
        args: { path: 'hello.txt' },
        callId: 'w13-call-shutdown-2',
      });
      await relay.dispatch(deviceId, { payload: JSON.stringify(frame), callId: 'w13-call-shutdown-2' });
      const pushed = await platform.waitFor('result', 1);
      const { frame: resultFrame, payload } = verifyPlatformResult({ describe: root.describe, pushed: pushed[0] });
      assert.equal(resultFrame.outcome, 'succeeded', 'a genuine frame after a restart is not blocked by the window');
      assert.equal(payload.result.content, 'the quick brown fox');
      await second.stop();
    } finally {
      if (second.child.exitCode === null && second.child.signalCode === null) {
        second.child.kill();
      }
      fixtures.removeTempRoot(root.root);
    }
  });

  it('refuses a tool outside the policy without executing it, and reports WHICH side refused', async () => {
    const backend = fixtures.makeKeypair();

    // (1) Tier 1: `write_file` is a stage-B tool, so it is outside the SERVER ceiling for this endpoint.
    const ceilingDevice = 'device-w13-e2e-policy-ceiling';
    const ceilingRoot = makeRoot({ deviceId: ceilingDevice, backend });
    const ceilingRuntime = startRuntime({ root: ceilingRoot.root, relayBase: relay.base });
    try {
      await relay.grant(ceilingDevice);
      const platform = await platformSocket(ceilingDevice);
      await ceilingRuntime.waitForEvent('relay.connected');
      const frame = signedFrame({
        describe: ceilingRoot.describe,
        backend,
        toolName: 'write_file',
        args: { path: 'created-by-policy.txt', content: 'this must never be written' },
        callId: 'w13-call-policy-ceiling',
      });
      await relay.dispatch(ceilingDevice, { payload: JSON.stringify(frame), callId: 'w13-call-policy-ceiling' });
      const pushed = await platform.waitFor('result', 1);
      const { frame: resultFrame, payload } = verifyPlatformResult({ describe: ceilingRoot.describe, pushed: pushed[0] });
      assert.equal(resultFrame.outcome, 'refused');
      assert.equal(resultFrame.errorCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');
      assert.equal(payload.status, 'refused');
      const outcome = ceilingRuntime.events().find((line) => line.event === 'frame.outcome');
      assert.equal(outcome.fields.executed, false);
      assert.equal(outcome.fields.refusalCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');
      assert.equal(
        fs.existsSync(path.join(ceilingRoot.workspace, 'created-by-policy.txt')),
        false,
        'a refused tool must not have written anything',
      );
      await ceilingRuntime.stop();
    } finally {
      if (ceilingRuntime.child.exitCode === null && ceilingRuntime.child.signalCode === null) {
        ceilingRuntime.child.kill();
      }
      fixtures.removeTempRoot(ceilingRoot.root);
    }

    // (2) Tier 2: `read_file` is inside the ceiling, but THIS PC switched it off (the device may
    // narrow). The refusal must name the device floor, not the ceiling.
    const floorDevice = 'device-w13-e2e-policy-floor';
    const floorRoot = makeRoot({ deviceId: floorDevice, backend, tools: ['get_file_info', 'list_directory'] });
    const floorRuntime = startRuntime({ root: floorRoot.root, relayBase: relay.base });
    try {
      await relay.grant(floorDevice);
      const platform = await platformSocket(floorDevice);
      await floorRuntime.waitForEvent('relay.connected');
      const frame = signedFrame({
        describe: floorRoot.describe,
        backend,
        toolName: 'read_file',
        args: { path: 'hello.txt' },
        callId: 'w13-call-policy-floor',
      });
      await relay.dispatch(floorDevice, { payload: JSON.stringify(frame), callId: 'w13-call-policy-floor' });
      const pushed = await platform.waitFor('result', 1);
      const { frame: resultFrame, payload } = verifyPlatformResult({ describe: floorRoot.describe, pushed: pushed[0] });
      assert.equal(resultFrame.outcome, 'refused');
      assert.equal(resultFrame.errorCode, 'ENDPOINT_TOOL_NOT_ENABLED_ON_DEVICE');
      assert.equal(payload.code, 'ENDPOINT_TOOL_NOT_ENABLED_ON_DEVICE');
      const outcome = floorRuntime.events().find((line) => line.event === 'frame.outcome');
      assert.equal(outcome.fields.executed, false);
      await floorRuntime.stop();
    } finally {
      if (floorRuntime.child.exitCode === null && floorRuntime.child.signalCode === null) {
        floorRuntime.child.kill();
      }
      fixtures.removeTempRoot(floorRoot.root);
    }
  });

  it('two frames arriving together each produce exactly one result, correlated correctly', async () => {
    const backend = fixtures.makeKeypair();
    const deviceId = 'device-w13-e2e-concurrent';
    const root = makeRoot({ deviceId, backend, file: { name: 'one.txt', content: 'first' } });
    fs.writeFileSync(path.join(root.workspace, 'two.txt'), 'second', 'utf8');
    const runtime = startRuntime({ root: root.root, relayBase: relay.base });
    try {
      await relay.grant(deviceId);
      const platform = await platformSocket(deviceId);
      await runtime.waitForEvent('relay.connected');

      const frames = [
        { callId: 'w13-call-conc-a', args: { path: 'one.txt' } },
        { callId: 'w13-call-conc-b', args: { path: 'two.txt' } },
      ].map((entry) =>
        signedFrame({ describe: root.describe, backend, toolName: 'read_file', args: entry.args, callId: entry.callId }),
      );

      // Both dispatched BEFORE either result is awaited: they are outstanding at the relay together.
      const dispatched = await Promise.all(
        frames.map((frame, index) =>
          relay.dispatch(deviceId, { payload: JSON.stringify(frame), callId: `w13-call-conc-${index === 0 ? 'a' : 'b'}` }),
        ),
      );
      assert.deepEqual(dispatched.map((entry) => entry.body.admitted), [true, true]);

      const pushed = await platform.waitFor('result', 2);
      const byCall = new Map(pushed.map((entry) => [entry.callId, entry]));
      assert.deepEqual([...byCall.keys()].sort(), ['w13-call-conc-a', 'w13-call-conc-b']);
      assert.equal(new Set(pushed.map((entry) => entry.resultSeq)).size, 2, 'two distinct transport sequence numbers');

      const contents = {};
      for (const [callId, entry] of byCall) {
        const { frame: resultFrame, payload } = verifyPlatformResult({ describe: root.describe, pushed: entry });
        assert.equal(resultFrame.outcome, 'succeeded');
        contents[callId] = payload.result.content;
      }
      assert.deepEqual(contents, { 'w13-call-conc-a': 'first', 'w13-call-conc-b': 'second' });

      // Both deliveries are acknowledged and gone; the relay's ledger shows two reported calls (the
      // platform completes a call when it acks the held result, which this test does not do).
      await runtime.waitForEvent('frame.acked', 2);
      const acks = runtime.events().filter((line) => line.event === 'frame.acked');
      assert.deepEqual(acks.map((line) => line.fields.seq).sort((left, right) => left - right), [1, 2]);
      const state = await relay.state(deviceId);
      assert.equal(state.body.storage.callLedger.length, 2);
      assert.deepEqual(state.body.storage.callLedger.map((entry) => entry.state).sort(), ['reported', 'reported']);
      assert.deepEqual(state.body.storage.pending, [], 'both deliveries are acknowledged and gone');

      // And when the platform does ack them, the calls complete with the honest outcomes it saw.
      const pending = await relay.pendingResults(deviceId);
      const acked = await relay.ackResults(
        deviceId,
        pending.body.pending.map((entry) => entry.resultSeq),
      );
      assert.equal(acked.body.remaining, 0);
      const completed = await relay.state(deviceId);
      assert.deepEqual(completed.body.storage.callLedger.map((entry) => entry.state), ['completed', 'completed']);

      await runtime.stop();
    } finally {
      if (runtime.child.exitCode === null && runtime.child.signalCode === null) {
        runtime.child.kill();
      }
      fixtures.removeTempRoot(root.root);
    }
  });
});
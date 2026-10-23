'use strict';

/**
 * W7 spec — THE RUNNABLE ENTRY POINT, AS A REAL PROCESS.
 *
 * The other specs call the agent's modules directly. This one runs `run-agent.js` and
 * `tools/lab-backend.cjs` exactly the way the owner will: separate Node processes, files on disk, an
 * exit code and stdout to read. That is the difference between "the library works" and "the thing the
 * owner types works", and it is where two real bugs were found:
 *
 *   1. a pretty-printed `sign --out frame.json` was not accepted by `handle --in`, and
 *   2. `--swap-args --out <file>` swallowed `--out` as the FLAG'S VALUE, so the tampered frame was
 *      never written and the operator's next command read a missing file.
 *
 * Both are caught below, because the assertions read the FILES the tools claim to write rather than
 * trusting their stdout.
 *
 * The whole loop is exercised: init → keygen → pin → sign → handle → tamper → handle → replay.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync, execFileSync } = require('node:child_process');
const { describe, it, before, after } = require('node:test');

const fixtures = require('./_fixtures');

const AGENT_DIR = path.resolve(__dirname, '..');
const RUN_AGENT = path.join(AGENT_DIR, 'run-agent.js');
const LAB_BACKEND = path.join(AGENT_DIR, 'tools', 'lab-backend.cjs');

let root = null;
let labDir = null;
let deviceKeyId = null;

/** Runs a Node entry point and returns `{status, stdout, stderr}`, asserting it succeeded. */
function run(entry, args, { expectStatus = 0 } = {}) {
  const result = spawnSync(process.execPath, [entry, ...args], { encoding: 'utf8', cwd: AGENT_DIR });
  assert.equal(result.status, expectStatus, `expected exit ${expectStatus}, got ${result.status}\n${result.stderr}`);
  return result;
}

function runJson(entry, args) {
  const result = run(entry, args);
  const lines = result.stdout.trim().split(/\r?\n/);
  const last = lines[lines.length - 1];
  return JSON.parse(last);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

describe('the CLI runs the whole loop as real processes', () => {
  before(() => {
    root = fixtures.makeTempRoot('cbhr-cli-e2e-');
    labDir = path.join(root, 'lab');

    // 1. init the endpoint: key, device id, narrowest tool config.
    const init = runJson(RUN_AGENT, ['init', '--root', root, '--device-id', 'device-cli-e2e']);
    assert.equal(init.command, 'init');
    assert.equal(init.deviceId, 'device-cli-e2e');
    assert.deepEqual(init.enabledTools, ['get_file_info', 'list_directory', 'read_file']);
    assert.equal(fs.existsSync(init.deviceKeyFile), true);
    deviceKeyId = init.deviceKeyId;

    // 2. create the lab signing key, 3. pin its public half.
    run(LAB_BACKEND, ['keygen', '--out', labDir]);
    const spkiFile = path.join(labDir, 'lab-backend-spki.txt');
    const pinned = runJson(RUN_AGENT, ['pin-backend', '--root', root, '--spki-file', spkiFile]);
    assert.equal(pinned.keys.length, 1);

    // A file for the agent to read INSIDE its containment root.
    fs.mkdirSync(path.join(root, 'workspace'), { recursive: true });
    fs.writeFileSync(path.join(root, 'workspace', 'hello.txt'), 'hello from the endpoint workspace', 'utf8');
  });

  after(() => {
    fixtures.removeTempRoot(root);
  });

  it('init wrote the device key, the config and the pin file where it said it did', () => {
    for (const name of ['device-key.json', 'device.json', 'tools.json', 'backend-keys.json']) {
      assert.equal(fs.existsSync(path.join(root, name)), true, `${name} must exist`);
    }
    assert.equal(require(path.join(AGENT_DIR, 'src', 'permissions')).ownerAccountName().length > 0, true);
  });

  it('lab-backend selftest reproduces the published golden vector', () => {
    const result = run(LAB_BACKEND, ['selftest']);
    const parsed = JSON.parse(result.stdout);
    assert.deepEqual(parsed, {
      ok: true,
      spkiMatches: true,
      canonicalMatches: true,
      signatureMatches: true,
    });
  });

  it('sign writes a frame file, and handle executes it into a signed result', () => {
    const frameFile = path.join(root, 'frame.json');
    const signOut = run(LAB_BACKEND, [
      'sign',
      '--key',
      path.join(labDir, 'lab-backend-key.txt'),
      '--device-id',
      'device-cli-e2e',
      '--device-key-id',
      deviceKeyId,
      '--tool',
      'read_file',
      '--args',
      '{"path":"hello.txt"}',
      '--call-id',
      'call-cli-1',
      '--out',
      frameFile,
    ]);
    assert.match(signOut.stdout, /wrote /);
    assert.equal(fs.existsSync(frameFile), true, 'a claim to write a file must produce that file');
    const frame = readJson(frameFile);
    assert.equal(frame.callId, 'call-cli-1');
    assert.equal(frame.audience, 'endpoint');

    const resultFile = path.join(root, 'result.json');
    run(RUN_AGENT, ['handle', '--root', root, '--in', frameFile, '--out', resultFile]);
    const result = readJson(resultFile);

    assert.equal(result.outcome, 'succeeded');
    assert.equal(result.callId, 'call-cli-1');
    assert.equal(result.audience, 'relay');
    assert.equal(result.correlation, 'verified');
    const payload = JSON.parse(Buffer.from(result.argsB64u, 'base64url').toString('utf8'));
    assert.equal(payload.result.content, 'hello from the endpoint workspace');

    // The platform can verify it with the DEVICE public key alone — which the relay does not have.
    const { verifyResultFrame } = require('../src/resultFrame');
    const verdict = verifyResultFrame({
      frame: result,
      devicePublicKeySpkiB64u: runJson(RUN_AGENT, ['describe', '--root', root]).agent.devicePublicKeySpkiB64u,
    });
    assert.equal(verdict.ok, true, verdict.ok === false ? verdict.error.code : '');
  });

  it('tamper writes its output file (the boolean-flag parsing bug), and the tampered frame is REFUSED', () => {
    const source = path.join(root, 'frame.json');
    const tampered = path.join(root, 'tampered.json');
    const out = run(LAB_BACKEND, ['tamper', '--in', source, '--swap-args', '--out', tampered]);
    assert.match(out.stdout, /wrote /);
    assert.equal(fs.existsSync(tampered), true, '--swap-args must not swallow --out');

    const before = readJson(source);
    const after = readJson(tampered);
    assert.equal(after.argsDigestHex, before.argsDigestHex, 'the SIGNED digest is untouched');
    assert.notEqual(after.argsB64u, before.argsB64u, 'only the transported bytes are swapped');
    assert.equal(after.signatureB64u, before.signatureB64u);

    // A DIFFERENT nonce, so the refusal is the args check and not the replay window.
    const freshFrame = path.join(root, 'frame-tamper.json');
    run(LAB_BACKEND, [
      'sign',
      '--key',
      path.join(labDir, 'lab-backend-key.txt'),
      '--device-id',
      'device-cli-e2e',
      '--device-key-id',
      deviceKeyId,
      '--tool',
      'read_file',
      '--args',
      '{"path":"hello.txt"}',
      '--call-id',
      'call-cli-2',
      '--out',
      freshFrame,
    ]);
    const freshTampered = path.join(root, 'frame-tamper-tampered.json');
    run(LAB_BACKEND, ['tamper', '--in', freshFrame, '--swap-args', '--out', freshTampered]);
    const resultFile = path.join(root, 'tamper-result.json');
    run(RUN_AGENT, ['handle', '--root', root, '--in', freshTampered, '--out', resultFile]);
    const result = readJson(resultFile);

    assert.equal(result.outcome, 'refused');
    assert.equal(result.errorCode, 'ENDPOINT_ARGS_DIGEST_MISMATCH');
    assert.equal(result.callId, 'call-cli-2');
    assert.equal(result.correlation, 'unverified-claim');
  });

  it('a broken signature is refused with its own code', () => {
    const source = path.join(root, 'frame.json');
    const broken = path.join(root, 'broken.json');
    run(LAB_BACKEND, ['tamper', '--in', source, '--break-signature', '--out', broken]);
    assert.equal(fs.existsSync(broken), true);
    const resultFile = path.join(root, 'broken-result.json');
    run(RUN_AGENT, ['handle', '--root', root, '--in', broken, '--out', resultFile]);
    const result = readJson(resultFile);
    assert.equal(result.outcome, 'refused');
    assert.equal(result.errorCode, 'ENDPOINT_SIGNATURE_INVALID');
  });

  it('replaying the first frame is refused, across PROCESS runs (the window is on disk)', () => {
    const resultFile = path.join(root, 'replay-result.json');
    run(RUN_AGENT, ['handle', '--root', root, '--in', path.join(root, 'frame.json'), '--out', resultFile]);
    const result = readJson(resultFile);
    assert.equal(result.outcome, 'refused');
    assert.equal(result.errorCode, 'ENDPOINT_REPLAY_DETECTED');

    // The durable window is a real file in the agent root, holding the spent nonce.
    const replay = readJson(path.join(root, 'replay-window.json'));
    assert.equal(replay.version, 1);
    assert.ok(replay.entries.length >= 2, 'both admitted frames must be recorded');
    assert.ok(replay.entries.every((entry) => entry.key.includes(':')), 'keys are (grantId, nonce)');
  });

  it('an unpinned backend key is refused, and the pin set is the only thing that changed', () => {
    const otherDir = path.join(root, 'other-lab');
    run(LAB_BACKEND, ['keygen', '--out', otherDir]);
    const frameFile = path.join(root, 'unpinned.json');
    run(LAB_BACKEND, [
      'sign',
      '--key',
      path.join(otherDir, 'lab-backend-key.txt'),
      '--device-id',
      'device-cli-e2e',
      '--device-key-id',
      deviceKeyId,
      '--tool',
      'list_directory',
      '--args',
      '{"path":"."}',
      '--call-id',
      'call-cli-unpinned',
      '--out',
      frameFile,
    ]);
    const resultFile = path.join(root, 'unpinned-result.json');
    run(RUN_AGENT, ['handle', '--root', root, '--in', frameFile, '--out', resultFile]);
    const result = readJson(resultFile);
    assert.equal(result.outcome, 'refused');
    assert.equal(result.errorCode, 'ENDPOINT_KEY_UNPINNED');
  });

  it('tools lists the effective set and explains every refusal, and describe prints no secrets', () => {
    const tools = runJson(RUN_AGENT, ['tools', '--root', root]);
    assert.deepEqual(tools.effective, ['get_file_info', 'list_directory', 'read_file']);
    const ceilingOnly = tools.decisions.find((entry) => entry.tool === 'start_search');
    assert.equal(ceilingOnly.allowed, false);
    assert.equal(ceilingOnly.refusalCode, 'ENDPOINT_TOOL_NOT_ENABLED_ON_DEVICE');
    const outsideCeiling = tools.decisions.find((entry) => entry.tool === 'edit_block');
    assert.equal(outsideCeiling.refusalCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');
    // `track_ui_event` is an internal handler, NOT one of the 26 catalog tools, so it is absent from
    // the stage index by design — and still refused, which is the point (GM-72: never user-
    // configurable at any tier, never dispatchable). The `tools` listing reports it explicitly.
    const internal = tools.decisions.find((entry) => entry.tool === 'track_ui_event');
    assert.ok(internal, 'the hard-denied internal handler must be listed');
    assert.equal(internal.withinCeiling, false);
    assert.equal(internal.refusalCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');
    assert.equal(internal.enabledOnDevice, false);

    // A catalog tool above the current stage: in the snapshot's stage index, outside the ceiling.
    const aboveStage = tools.decisions.find((entry) => entry.tool === 'write_file');
    assert.ok(aboveStage);
    assert.equal(aboveStage.withinCeiling, false);
    assert.equal(aboveStage.refusalCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');

    const describe = runJson(RUN_AGENT, ['describe', '--root', root]).agent;
    const keyRecord = readJson(path.join(root, 'device-key.json'));
    const text = JSON.stringify(describe);
    assert.equal(text.includes(keyRecord.privateKeyPkcs8B64u), false, 'describe must never print key material');
    assert.equal(describe.verificationOrder.length, 10);
    assert.equal(describe.ceiling.ceilingTools, 8);

    // The non-enumerable refusal detail never reaches stdout either.
    assert.equal(text.includes('"detail"'), false);
  });

  it('a JSON-lines input file is handled frame by frame', () => {
    const lines = [];
    for (let index = 0; index < 2; index++) {
      const frameFile = path.join(root, `line-${index}.json`);
      run(LAB_BACKEND, [
        'sign',
        '--key',
        path.join(labDir, 'lab-backend-key.txt'),
        '--device-id',
        'device-cli-e2e',
        '--device-key-id',
        deviceKeyId,
        '--tool',
        'get_file_info',
        '--args',
        '{"path":"hello.txt"}',
        '--call-id',
        `call-line-${index}`,
        '--out',
        frameFile,
      ]);
      lines.push(JSON.stringify(readJson(frameFile)));
    }
    const linesFile = path.join(root, 'frames.jsonl');
    fs.writeFileSync(linesFile, `${lines.join('\n')}\n`, 'utf8');
    const resultFile = path.join(root, 'lines-result.jsonl');
    run(RUN_AGENT, ['handle', '--root', root, '--in', linesFile, '--out', resultFile]);

    const outputs = fs
      .readFileSync(resultFile, 'utf8')
      .trim()
      .split(/\r?\n/)
      .map((line) => JSON.parse(line));
    assert.equal(outputs.length, 2);
    assert.deepEqual(outputs.map((entry) => entry.callId), ['call-line-0', 'call-line-1']);
    assert.ok(outputs.every((entry) => entry.outcome === 'succeeded'));
  });

  it('verify-only reports the verdict and NEVER executes', () => {
    const frameFile = path.join(root, 'verify-only.json');
    run(LAB_BACKEND, [
      'sign',
      '--key',
      path.join(labDir, 'lab-backend-key.txt'),
      '--device-id',
      'device-cli-e2e',
      '--device-key-id',
      deviceKeyId,
      '--tool',
      'read_file',
      '--args',
      '{"path":"hello.txt"}',
      '--call-id',
      'call-verify-only',
      '--out',
      frameFile,
    ]);
    const out = run(RUN_AGENT, ['verify-only', '--root', root, '--in', frameFile]);
    const verdict = JSON.parse(out.stdout.trim());
    assert.equal(verdict.verdict, 'verified');
    assert.equal(verdict.toolName, 'read_file');
    assert.equal(verdict.callId, 'call-verify-only');
    // No result frame at all: nothing executed, so there is nothing to report as an outcome.
    assert.equal(verdict.outcome, undefined);
  });

  it('an unknown command exits non-zero without a stack', () => {
    const result = run(RUN_AGENT, ['not-a-command'], { expectStatus: 2 });
    assert.match(result.stderr, /unknown command/);
    assert.equal(result.stderr.includes('at '), false, 'no stack trace may be printed');
  });

  it('a missing pinned key file is reported as a typed refusal, not a crash', () => {
    const emptyRoot = fixtures.makeTempRoot('cbhr-cli-nopin-');
    try {
      run(RUN_AGENT, ['init', '--root', emptyRoot, '--device-id', 'device-nopin']);
      const result = run(RUN_AGENT, ['describe', '--root', emptyRoot], { expectStatus: 1 });
      assert.match(result.stderr, /ENDPOINT_KEY_UNPINNED/);
      assert.equal(result.stderr.includes('at '), false, 'no stack trace may be printed');
    } finally {
      fixtures.removeTempRoot(emptyRoot);
    }
  });
});
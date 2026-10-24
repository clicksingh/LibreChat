'use strict';

/**
 * W13 spec — THE RUNTIME, WITHOUT A RELAY.
 *
 * The end-to-end proof (a real relay, a real socket, a real child process) lives in
 * `runtime-relay.test.js`. This file covers the parts that a real relay cannot show you cheaply and
 * deterministically: the URL the device connects to, the backoff arithmetic, the log line, the
 * shutdown wiring, and the exact sequence of control frames for cases that need a *scripted* peer —
 * an unparsable payload, a saturated result outbox, a verdict that never comes, two frames arriving
 * at the same moment.
 *
 * THE TRANSPORT IS STUBBED; THE ENDPOINT IS NOT. Every case below runs a REAL `createEndpointAgent`
 * on a throwaway root with a real pinned key, so verification, policy, execution and the result
 * signature are the shipped ones. Only the socket is scripted — and the scripted socket reproduces
 * the two Node behaviours that were MEASURED while building this (a refused connection reports
 * `error` with no `close`; a duplicate delivery arrives on the same `seq`).
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { spawnSync } = require('node:child_process');
const { describe, it } = require('node:test');

const fixtures = require('./_fixtures');
const { createEndpointAgent } = require('../src/agent');
const { buildPinSet } = require('../src/pinnedKeys');
const { writeOwnerOnlyFile } = require('../src/permissions');
const {
  DEVICE_SOCKET_TAG,
  PLATFORM_SOCKET_TAG,
  buildDeviceSocketUrl,
  backoffDelayMs,
  formatRuntimeEvent,
  createRuntimeLogSink,
  installShutdownHandlers,
  createAgentRuntime,
  usableTransportText,
} = require('../src/runtime');

const DEVICE_ID = 'device-runtime-0001';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(predicate, { timeout = 4000, interval = 10 } = {}) {
  const started = Date.now();
  for (;;) {
    const value = await predicate();
    if (value) {
      return value;
    }
    if (Date.now() - started > timeout) {
      return null;
    }
    await sleep(interval);
  }
}

/** A real agent on a throwaway root: real key, real ceiling, real durable replay window. */
function makeAgent() {
  const root = fixtures.makeTempRoot('cbhr-runtime-test-');
  const backend = fixtures.makeKeypair();
  writeOwnerOnlyFile(path.join(root, 'device.json'), JSON.stringify({ version: 1, deviceId: DEVICE_ID }));
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(workspace, { recursive: true });
  const agent = createEndpointAgent({
    rootDir: root,
    deviceId: DEVICE_ID,
    pins: buildPinSet([{ keyId: backend.keyId, publicKeySpkiB64u: backend.publicKeySpkiB64u }]),
    workspaceRoot: workspace,
  });
  return { root, backend, workspace, agent };
}

/** A frame signed by the pinned backend key, addressed to this agent, fresh right now. */
function commandFrame({ agent, backend, toolName = 'read_file', args = { path: 'note.txt' }, callId = 'call-runtime-1', argsB64u, core = {} }) {
  const now = Date.now();
  return fixtures.buildFrame({
    sign: backend.sign,
    keyId: backend.keyId,
    core: {
      deviceId: agent.deviceId(),
      deviceKeyId: agent.deviceKeyId(),
      issuedAt: String(now),
      deadlineMs: String(now + 60000),
      nonce: nodeCrypto.randomBytes(16).toString('base64url'),
      toolName,
      ...core,
    },
    args,
    ...(argsB64u === undefined ? {} : { argsB64u }),
    extra: { callId },
  }).frame;
}

/**
 * A scripted device socket. Records what the runtime sent, and lets a test drive the relay's side of
 * the conversation: `frame(...)`, `verdict(...)`, `drop(...)`.
 */
function makeSocketFactory() {
  const instances = [];
  class StubSocket {
    static CONNECTING = 0;

    static OPEN = 1;

    static CLOSING = 2;

    static CLOSED = 3;

    constructor(url) {
      this.url = url;
      this.readyState = 0;
      this.sent = [];
      this.listeners = new Map();
      this.closeCalls = [];
      instances.push(this);
      // Auto-open, like a relay that is up.
      queueMicrotask(() => {
        if (this.readyState === 0) {
          this.readyState = 1;
          this.emit('open', {});
        }
      });
    }

    addEventListener(type, listener) {
      const list = this.listeners.get(type) ?? [];
      list.push(listener);
      this.listeners.set(type, list);
    }

    emit(type, event) {
      for (const listener of [...(this.listeners.get(type) ?? [])]) {
        listener(event);
      }
    }

    send(text) {
      if (this.readyState !== 1) {
        throw new Error('stub socket is not open');
      }
      this.sent.push(JSON.parse(text));
    }

    close(code, reason) {
      this.closeCalls.push({ code, reason });
      this.readyState = 3;
      this.emit('close', { code, reason });
    }

    /** Delivers one relay command frame. */
    frame(payload, seq, replay = false) {
      this.emit('message', { data: JSON.stringify({ t: 'frame', seq, payload, replay }) });
    }

    /** Delivers one relay verdict for a result the runtime sent. */
    verdict(value) {
      this.emit('message', { data: JSON.stringify(value) });
    }

    sentOfType(type) {
      return this.sent.filter((message) => message.t === type);
    }
  }
  return { instances, ctor: StubSocket, latest: () => instances[instances.length - 1] };
}

describe('the device socket URL is built from the relay route, never guessed', () => {
  it('appends the relay device route to a path-less base URL, with tag=device', () => {
    const url = new URL(buildDeviceSocketUrl({ relay: 'http://127.0.0.1:8787', deviceId: DEVICE_ID }));
    assert.equal(url.protocol, 'ws:');
    assert.equal(url.pathname, `/d/${DEVICE_ID}/ws`);
    assert.equal(url.searchParams.get('tag'), DEVICE_SOCKET_TAG);
    assert.equal(url.searchParams.has('replay'), false, 'replay-on-connect is the relay default and must stay ON');
  });

  it('uses a URL that already carries a path as the device route, and forces the role it may claim', () => {
    const url = new URL(
      buildDeviceSocketUrl({ relay: 'https://relay.example/d/device-x/ws?tag=platform&replay=1', deviceId: DEVICE_ID }),
    );
    assert.equal(url.protocol, 'wss:');
    assert.equal(url.pathname, '/d/device-x/ws', 'an operator-supplied route is respected');
    assert.equal(url.searchParams.get('tag'), DEVICE_SOCKET_TAG);
    assert.equal(url.searchParams.get('tag') === PLATFORM_SOCKET_TAG, false);
  });

  it('encodes the device id and can turn replay-on-connect off explicitly', () => {
    const url = new URL(
      buildDeviceSocketUrl({ relay: 'http://127.0.0.1:8787', deviceId: 'device/a b', replayOnConnect: false }),
    );
    assert.equal(url.pathname, '/d/device%2Fa%20b/ws');
    assert.equal(url.searchParams.get('replay'), '0');
  });

  it('refuses an absent relay, an absent device id, an unparsable URL and a foreign protocol', () => {
    for (const params of [
      { relay: undefined, deviceId: DEVICE_ID },
      { relay: '   ', deviceId: DEVICE_ID },
      { relay: 'http://127.0.0.1:8787', deviceId: '' },
      { relay: 'not a url', deviceId: DEVICE_ID },
      { relay: 'ftp://127.0.0.1:8787', deviceId: DEVICE_ID },
    ]) {
      assert.throws(
        () => buildDeviceSocketUrl(params),
        (err) => err.code === 'ENDPOINT_RUNTIME_CONFIG_INVALID',
        `expected a typed refusal for ${JSON.stringify(params)}`,
      );
    }
  });

  it('accepts only the transport-text the relay itself accepts for a callId', () => {
    assert.equal(usableTransportText('call-1'), 'call-1');
    assert.equal(usableTransportText(''), null);
    assert.equal(usableTransportText('x'.repeat(201)), null);
    assert.equal(usableTransportText('call\u001f1'), null);
    assert.equal(usableTransportText(42), null);
  });
});

describe('reconnect backoff is arithmetic an operator can predict', () => {
  it('doubles from the initial delay and stops at the cap', () => {
    const schedule = [1, 2, 3, 4, 5, 6, 7, 8].map((attempt) => backoffDelayMs(attempt));
    assert.deepEqual(schedule, [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000]);
  });

  it('honours explicit bounds and never returns more than the cap', () => {
    assert.deepEqual(
      [1, 2, 3, 4].map((attempt) => backoffDelayMs(attempt, { initialMs: 100, maxMs: 350 })),
      [100, 200, 350, 350],
    );
  });

  it('refuses an attempt counter or bounds that are not positive integers', () => {
    for (const attempt of [0, -1, 1.5, Number.NaN, '2']) {
      assert.throws(() => backoffDelayMs(attempt), (err) => err.code === 'ENDPOINT_RUNTIME_CONFIG_INVALID');
    }
    assert.throws(
      () => backoffDelayMs(1, { initialMs: 500, maxMs: 100 }),
      (err) => err.code === 'ENDPOINT_RUNTIME_CONFIG_INVALID',
    );
  });
});

describe('the log an operator reads', () => {
  it('is one line per event, with the level, the event name and a JSON tail', () => {
    const line = formatRuntimeEvent({ ts: '2026-10-23T00:00:00.000Z', level: 'warn', event: 'relay.socket.lost', code: 1006 });
    assert.match(line, /^2026-10-23T00:00:00\.000Z WARN {2}relay\.socket\.lost \{"code":1006\}\n$/);
  });

  it('sends info to stdout and warn/error to stderr, and survives a closed stream', () => {
    const capture = () => {
      const chunks = [];
      return { chunks, write: (text) => chunks.push(text) };
    };
    const out = capture();
    const err = capture();
    const sink = createRuntimeLogSink({ out, err });
    sink({ ts: 't', level: 'info', event: 'a' });
    sink({ ts: 't', level: 'debug', event: 'b' });
    sink({ ts: 't', level: 'warn', event: 'c' });
    sink({ ts: 't', level: 'error', event: 'd' });
    assert.equal(out.chunks.length, 2, 'info and debug go to stdout');
    assert.match(out.chunks[0], /INFO {2}a/);
    assert.match(out.chunks[1], /DEBUG b/);
    assert.equal(err.chunks.length, 2, 'warn and error go to stderr');
    assert.match(err.chunks[0], /WARN {2}c/);
    assert.match(err.chunks[1], /ERROR d/);
    // A stream that throws (a rotated pipe) must not take the endpoint down with it.
    const broken = createRuntimeLogSink({
      out: {
        write: () => {
          throw new Error('EPIPE');
        },
      },
      err,
    });
    assert.doesNotThrow(() => broken({ ts: 't', level: 'info', event: 'e' }));
  });
});

describe('shutdown is one path, wired to both signals', () => {
  it('registers SIGINT and SIGTERM, routes both to the same callback, and uninstalls cleanly', () => {
    const emitter = new EventEmitter();
    const seen = [];
    const uninstall = installShutdownHandlers({ emitter, onSignal: (signal) => seen.push(signal) });
    assert.equal(emitter.listenerCount('SIGINT'), 1);
    assert.equal(emitter.listenerCount('SIGTERM'), 1);
    emitter.emit('SIGINT');
    emitter.emit('SIGTERM');
    assert.deepEqual(seen, ['SIGINT', 'SIGTERM']);
    uninstall();
    uninstall(); // idempotent
    assert.equal(emitter.listenerCount('SIGINT'), 0);
    assert.equal(emitter.listenerCount('SIGTERM'), 0);
    emitter.emit('SIGINT');
    assert.deepEqual(seen, ['SIGINT', 'SIGTERM'], 'nothing runs after uninstall');
  });

  it('refuses an emitter or callback it cannot use', () => {
    assert.throws(() => installShutdownHandlers({ emitter: null, onSignal: () => {} }));
    assert.throws(() => installShutdownHandlers({ emitter: new EventEmitter(), onSignal: null }));
  });

  it('MEASURED: on Windows a parent cannot deliver SIGINT to a child — this is why the E2E drives the shutdown path, not an OS signal', () => {
    const root = fixtures.makeTempRoot('cbhr-runtime-signal-');
    try {
      const script = path.join(root, 'signal-child.js');
      fs.writeFileSync(
        script,
        [
          "process.on('SIGINT', () => { process.stdout.write('HANDLER-RAN\\n'); process.exit(0); });",
          "process.stdout.write('CHILD-READY\\n');",
          'setInterval(() => {}, 1000);',
        ].join('\n'),
        'utf8',
      );
      const result = spawnSync(
        process.execPath,
        [
          '-e',
          [
            'const { spawn } = require("node:child_process");',
            `const child = spawn(process.execPath, [${JSON.stringify(script)}], { stdio: ["ignore", "pipe", "pipe"] });`,
            'let out = "";',
            'child.stdout.on("data", (chunk) => { out += chunk.toString(); });',
            'child.on("exit", (code, signal) => { process.stdout.write(JSON.stringify({ out, code, signal })); });',
            'setTimeout(() => child.kill("SIGINT"), 400);',
            'setTimeout(() => process.exit(0), 2500);',
          ].join('\n'),
        ],
        { encoding: 'utf8' },
      );
      const observed = JSON.parse(result.stdout.trim());
      assert.match(observed.out, /CHILD-READY/, 'the child must have started');
      assert.doesNotMatch(observed.out, /HANDLER-RAN/, 'the handler must NOT have run');
      assert.equal(observed.signal, 'SIGINT', 'the child was killed unconditionally by the transport');
    } finally {
      fixtures.removeTempRoot(root);
    }
  });
});

describe('the runtime over a scripted socket (real agent, real verification, real execution)', () => {
  it('delivers a signed frame, executes the tool, sends the result and acks only after the verdict', async () => {
    const { root, backend, workspace, agent } = makeAgent();
    const sockets = makeSocketFactory();
    const events = [];
    try {
      fs.writeFileSync(path.join(workspace, 'note.txt'), 'the quick brown fox', 'utf8');
      const runtime = createAgentRuntime({
        agent,
        relay: 'http://127.0.0.1:8787',
        webSocketImpl: sockets.ctor,
        onEvent: (event) => events.push(event),
        verdictTimeoutMs: 2000,
      });
      runtime.start();
      const socket = await waitFor(() => sockets.latest());
      await waitFor(() => sockets.latest()?.readyState === 1);

      const frame = commandFrame({ agent, backend, callId: 'call-live-1' });
      socket.frame(JSON.stringify(frame), 1);

      const sent = await waitFor(() => socket.sentOfType('result')[0]);
      assert.ok(sent, 'the runtime must send a result');
      assert.equal(sent.callId, 'call-live-1', 'the result envelope correlates on the TRANSPORT callId');
      const resultFrame = JSON.parse(sent.payload);
      assert.equal(resultFrame.tag, 'CBHR-RPC-RESULT-V2');
      assert.equal(resultFrame.outcome, 'succeeded');
      assert.equal(resultFrame.audience, 'relay');
      const payload = JSON.parse(Buffer.from(resultFrame.argsB64u, 'base64url').toString('utf8'));
      assert.equal(payload.result.content, 'the quick brown fox', 'the tool really ran');
      assert.equal(socket.sentOfType('ack').length, 0, 'the frame must NOT be acked before the relay judges the result');

      socket.verdict({ t: 'result-ok', accepted: true, callId: 'call-live-1', resultSeq: 7 });
      const ack = await waitFor(() => socket.sentOfType('ack')[0]);
      assert.deepEqual(ack, { t: 'ack', seq: 1 });
      const outcomeEvent = events.find((event) => event.event === 'frame.outcome');
      assert.equal(outcomeEvent.outcome, 'succeeded');
      assert.equal(outcomeEvent.executed, true);
      assert.equal(events.find((event) => event.event === 'relay.connected').replayWindowLoadedEntries, 0);

      await runtime.stop('test-over');
      const stopped = await runtime.whenStopped();
      assert.equal(stopped.gaveUp, false);
      assert.equal(socket.closeCalls[0].code, 1000, 'a clean close code, not a drop');
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('refuses a tampered frame, reports refused, and never executes it', async () => {
    const { root, backend, workspace, agent } = makeAgent();
    const sockets = makeSocketFactory();
    const events = [];
    try {
      fs.writeFileSync(path.join(workspace, 'hello.txt'), 'harmless', 'utf8');
      fs.writeFileSync(path.join(workspace, 'secret.txt'), 'TOP SECRET', 'utf8');
      const runtime = createAgentRuntime({
        agent,
        relay: 'http://127.0.0.1:8787',
        webSocketImpl: sockets.ctor,
        onEvent: (event) => events.push(event),
        backoff: { initialMs: 20, maxMs: 40 },
      });
      runtime.start();
      await waitFor(() => sockets.latest()?.readyState === 1);
      const socket = sockets.latest();

      // Signed over `hello.txt`, transported as `secret.txt`: the digest cannot match.
      const tampered = commandFrame({
        agent,
        backend,
        callId: 'call-tampered-1',
        args: { path: 'hello.txt' },
        argsB64u: fixtures.b64u(Buffer.from(JSON.stringify({ path: 'secret.txt' }), 'utf8')),
      });
      socket.frame(JSON.stringify(tampered), 3);
      const sent = await waitFor(() => socket.sentOfType('result')[0]);
      const resultFrame = JSON.parse(sent.payload);
      assert.equal(resultFrame.outcome, 'refused');
      assert.equal(resultFrame.errorCode, 'ENDPOINT_ARGS_DIGEST_MISMATCH');
      assert.equal(resultFrame.correlation, 'unverified-claim');
      const payloadText = Buffer.from(resultFrame.argsB64u, 'base64url').toString('utf8');
      assert.doesNotMatch(payloadText, /TOP SECRET/, 'the tampered argument must never have been read');
      const outcomeEvent = events.find((event) => event.event === 'frame.outcome');
      assert.equal(outcomeEvent.executed, false);
      assert.equal(outcomeEvent.refusalCode, 'ENDPOINT_ARGS_DIGEST_MISMATCH');

      socket.verdict({ t: 'result-ok', accepted: true, callId: 'call-tampered-1', resultSeq: 1 });
      await waitFor(() => socket.sentOfType('ack')[0]);
      await runtime.stop('test-over');
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('handles two frames arriving together: exactly one result each, correlated by callId', async () => {
    const { root, backend, workspace, agent } = makeAgent();
    const sockets = makeSocketFactory();
    try {
      fs.writeFileSync(path.join(workspace, 'one.txt'), '1', 'utf8');
      fs.writeFileSync(path.join(workspace, 'two.txt'), '2', 'utf8');
      const runtime = createAgentRuntime({
        agent,
        relay: 'http://127.0.0.1:8787',
        webSocketImpl: sockets.ctor,
        onEvent: () => {},
        verdictTimeoutMs: 2000,
      });
      runtime.start();
      await waitFor(() => sockets.latest()?.readyState === 1);
      const socket = sockets.latest();

      const first = commandFrame({ agent, backend, callId: 'call-a', args: { path: 'one.txt' } });
      const second = commandFrame({ agent, backend, callId: 'call-b', args: { path: 'two.txt' } });
      socket.frame(JSON.stringify(first), 11);
      socket.frame(JSON.stringify(second), 12);

      const results = await waitFor(() => (socket.sentOfType('result').length === 2 ? socket.sentOfType('result') : null));
      assert.ok(results, 'both frames must produce a result');
      const byCall = new Map(results.map((entry) => [entry.callId, JSON.parse(entry.payload)]));
      assert.deepEqual([...byCall.keys()].sort(), ['call-a', 'call-b']);
      assert.equal(byCall.get('call-a').outcome, 'succeeded');
      assert.equal(
        JSON.parse(Buffer.from(byCall.get('call-a').argsB64u, 'base64url').toString('utf8')).result.content,
        '1',
      );
      assert.equal(
        JSON.parse(Buffer.from(byCall.get('call-b').argsB64u, 'base64url').toString('utf8')).result.content,
        '2',
      );
      assert.equal(results.filter((entry) => entry.callId === 'call-a').length, 1, 'exactly one result for call-a');
      assert.equal(results.filter((entry) => entry.callId === 'call-b').length, 1, 'exactly one result for call-b');
      assert.equal(socket.sentOfType('ack').length, 0, 'neither frame is acked before its verdict');
      // Both deliveries are settled independently: each gets its own verdict and its own ack.
      socket.verdict({ t: 'result-ok', accepted: true, callId: 'call-a', resultSeq: 1 });
      socket.verdict({ t: 'result-ok', accepted: true, callId: 'call-b', resultSeq: 2 });
      const acks = await waitFor(() => (socket.sentOfType('ack').length === 2 ? socket.sentOfType('ack') : null));
      assert.deepEqual(acks.map((entry) => entry.seq).sort((left, right) => left - right), [11, 12]);
      assert.equal(runtime.status().inFlight, 0);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('ignores a second copy of a delivery seq that is still in flight', async () => {
    const { root, backend, workspace, agent } = makeAgent();
    const sockets = makeSocketFactory();
    const events = [];
    try {
      fs.writeFileSync(path.join(workspace, 'note.txt'), 'x', 'utf8');
      const runtime = createAgentRuntime({
        agent,
        relay: 'http://127.0.0.1:8787',
        webSocketImpl: sockets.ctor,
        onEvent: (event) => events.push(event),
        verdictTimeoutMs: 2000,
      });
      runtime.start();
      await waitFor(() => sockets.latest()?.readyState === 1);
      const socket = sockets.latest();
      const frame = commandFrame({ agent, backend, callId: 'call-dup' });
      socket.frame(JSON.stringify(frame), 5);
      socket.frame(JSON.stringify(frame), 5); // the same delivery, twice
      await waitFor(() => socket.sentOfType('result')[0]);
      await sleep(60);
      assert.equal(socket.sentOfType('result').length, 1, 'a duplicate delivery must not produce a second result');
      assert.equal(events.filter((event) => event.event === 'relay.frame.duplicate').length, 1);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('sends nothing for a payload it cannot parse, acks it, and says so loudly', async () => {
    const { root, agent } = makeAgent();
    const sockets = makeSocketFactory();
    const events = [];
    try {
      const runtime = createAgentRuntime({
        agent,
        relay: 'http://127.0.0.1:8787',
        webSocketImpl: sockets.ctor,
        onEvent: (event) => events.push(event),
      });
      runtime.start();
      await waitFor(() => sockets.latest()?.readyState === 1);
      const socket = sockets.latest();
      socket.frame('{ this is not json', 9);
      const ack = await waitFor(() => socket.sentOfType('ack')[0]);
      assert.deepEqual(ack, { t: 'ack', seq: 9 });
      assert.equal(socket.sentOfType('result').length, 0, 'no result can be produced without a frame');
      const loud = events.find((event) => event.event === 'frame.unparsable');
      assert.equal(loud.level, 'error');
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('leaves the frame UNACKED when the relay could not hold the result, and acks a terminal refusal', async () => {
    const { root, backend, workspace, agent } = makeAgent();
    const sockets = makeSocketFactory();
    try {
      fs.writeFileSync(path.join(workspace, 'note.txt'), 'x', 'utf8');
      const runtime = createAgentRuntime({
        agent,
        relay: 'http://127.0.0.1:8787',
        webSocketImpl: sockets.ctor,
        onEvent: () => {},
        verdictTimeoutMs: 300,
      });
      runtime.start();
      await waitFor(() => sockets.latest()?.readyState === 1);
      const socket = sockets.latest();

      socket.frame(JSON.stringify(commandFrame({ agent, backend, callId: 'call-sat', args: { path: 'note.txt' } })), 21);
      await waitFor(() => socket.sentOfType('result')[0]);
      socket.verdict({ t: 'result-refused', accepted: false, code: 'RESULT_OUTBOX_SATURATED', callId: 'call-sat' });
      await sleep(80);
      assert.equal(socket.sentOfType('ack').length, 0, 'a retryable refusal must leave the frame for redelivery');

      socket.frame(
        JSON.stringify(
          commandFrame({
            agent,
            backend,
            callId: 'call-terminal',
            args: { path: 'note.txt' },
            core: { nonce: nodeCrypto.randomBytes(16).toString('base64url') },
          }),
        ),
        22,
      );
      await waitFor(() => socket.sentOfType('result').length === 2);
      socket.verdict({ t: 'result-refused', accepted: false, code: 'UNKNOWN_CALL_ID', callId: 'call-terminal' });
      const ack = await waitFor(() => socket.sentOfType('ack')[0]);
      assert.deepEqual(ack, { t: 'ack', seq: 22 });

      // And a result nobody ever judges is left unacked, rather than being acked on a hope.
      socket.frame(
        JSON.stringify(
          commandFrame({
            agent,
            backend,
            callId: 'call-silent',
            args: { path: 'note.txt' },
            core: { nonce: nodeCrypto.randomBytes(16).toString('base64url') },
          }),
        ),
        23,
      );
      await waitFor(() => socket.sentOfType('result').length === 3);
      await sleep(400);
      assert.equal(socket.sentOfType('ack').some((entry) => entry.seq === 23), false);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('reconnects after an error EVEN WHEN NO CLOSE EVER ARRIVES (the measured Node behaviour)', async () => {
    const { root, agent } = makeAgent();
    const sockets = makeSocketFactory();
    const events = [];
    try {
      const runtime = createAgentRuntime({
        agent,
        relay: 'http://127.0.0.1:8787',
        webSocketImpl: sockets.ctor,
        onEvent: (event) => events.push(event),
        backoff: { initialMs: 20, maxMs: 40 },
      });
      runtime.start();
      await waitFor(() => sockets.latest()?.readyState === 1);
      const first = sockets.latest();
      first.emit('error', { message: 'Received network error or non-101 status code.' });
      // NO close event: this is exactly what Node 22's global WebSocket does for a refused
      // connection. The reconnect must not depend on it.
      assert.equal(events.some((event) => event.event === 'relay.error'), true);
      assert.equal(events.some((event) => event.event === 'relay.socket.lost'), true);
      const scheduled = await waitFor(() => events.find((event) => event.event === 'relay.reconnect.scheduled'));
      assert.equal(scheduled.delayMs, 20);
      const reconnected = await waitFor(() => (sockets.instances.length === 2 ? sockets.instances[1] : null));
      assert.ok(reconnected, 'a second socket must have been opened');
      assert.equal(events.filter((event) => event.event === 'relay.reconnect.scheduled').length, 1, 'one outage, one attempt');
      await waitFor(() => events.filter((event) => event.event === 'relay.connected').length === 2);
      assert.equal(runtime.status().counters.connections, 2);
      await runtime.stop('test-over');
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('refuses to run at all when this machine has no WebSocket client', () => {
    const { root, agent } = makeAgent();
    try {
      const runtime = createAgentRuntime({ agent, relay: 'http://127.0.0.1:8787', webSocketImpl: null, onEvent: () => {} });
      assert.throws(() => runtime.start(), (err) => err.code === 'ENDPOINT_RUNTIME_UNAVAILABLE');
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('reports a status an operator can act on, and refuses to start twice', async () => {
    const { root, agent } = makeAgent();
    const sockets = makeSocketFactory();
    try {
      const runtime = createAgentRuntime({ agent, relay: 'http://127.0.0.1:8787', webSocketImpl: sockets.ctor, onEvent: () => {} });
      runtime.start();
      await waitFor(() => sockets.latest()?.readyState === 1);
      const status = runtime.status();
      assert.equal(status.deviceId, DEVICE_ID);
      assert.equal(status.tag, DEVICE_SOCKET_TAG);
      assert.match(status.relay, /\/d\/device-runtime-0001\/ws\?tag=device$/);
      assert.equal(status.replayWindowFile, path.join(root, 'replay-window.json'));
      await runtime.stop('test-over');
      assert.throws(() => runtime.start(), (err) => err.code === 'ENDPOINT_RUNTIME_CONFIG_INVALID');
      const stopped = await runtime.whenStopped();
      assert.equal(stopped.reason, 'test-over');
      // Shutdown deletes nothing: the durable replay window and the key store are still there.
      assert.equal(fs.existsSync(path.join(root, 'device-key.json')), true);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });
});
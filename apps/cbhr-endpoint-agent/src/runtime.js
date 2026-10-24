'use strict';

/**
 * CBHR ENDPOINT AGENT — the RUNTIME (workstream W13).
 *
 * W7 built the endpoint's *logic*: one frame in, one device-signed result out, with verification,
 * policy, execution and the outcome law all inside `src/agent.js`. What it did not build is a
 * participant. `run-agent.js handle --in <file>` processes one batch and exits, so the loop could only
 * ever be driven by a test harness — never by an owner who started the app and walked away.
 *
 * This module is that participant. It is deliberately a THIN, TRANSPARENT shell around the existing
 * core, and the thinness is the design:
 *
 *   - it does NOT verify anything            (`src/verify.js` does, unchanged)
 *   - it does NOT decide policy              (`src/dispatch.js` does, unchanged)
 *   - it does NOT execute anything           (`src/tools.js` does, unchanged)
 *   - it does NOT decide an outcome          (`src/agent.js` does, unchanged)
 *
 * What it owns is transport and time: connecting to the relay as a DEVICE, feeding each received
 * command frame through `agent.handleFrame`, sending the resulting `CBHR-RPC-RESULT-V2` frame back as
 * `{t:'result', callId, payload}`, acking the delivery, reconnecting with backoff when the socket
 * dies, and shutting down cleanly when asked. A runtime that re-implemented any step above would make
 * the W7 argument ("the endpoint refuses what the backend did not sign") untestable, because there
 * would be two endpoint verifiers and the tests would only cover the new one.
 *
 * ---------------------------------------------------------------------------------------------
 * THE RELAY'S ACTUAL DEVICE PROTOCOL (read from `apps/cbhr-relay/src/device-relay.js`, not invented)
 * ---------------------------------------------------------------------------------------------
 *
 * 1. CONNECT. The relay's Worker ingress maps `/d/<deviceId>/...` onto
 *    `DEVICE_RELAY.idFromName(deviceId)`, so the device opens a WebSocket to
 *    `<relay>/d/<deviceId>/ws`. The DO's `fetch` checks the upgrade header FIRST
 *    (`if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') return
 *    this.acceptSocket(request, url)`), and `acceptSocket` reads its role from the query string:
 *    `const tag = url.searchParams.get('tag') ?? 'device'`. A platform-side reader connects with
 *    `?tag=platform`. THIS RUNTIME CONNECTS WITH `tag=device` AND CANNOT BE TOLD OTHERWISE — claiming
 *    the platform role would put the endpoint's own results on the platform's reader socket.
 *
 * 2. REPLAY ON CONNECT. `acceptSocket` calls `resync('connect')` unless `?replay=0` is passed, so
 *    every unacked frame in the DO's durable `pending` list is redelivered as
 *    `{t:'frame', seq, payload, replay:true}` the moment a device reconnects. That is the production
 *    path and this runtime keeps it ON: a frame that arrived while the agent was down is delivered
 *    when it comes back. (`--no-replay-on-connect` exists for a deployment that wants a clean start;
 *    it is not the default.)
 *
 * 3. COMMANDS. `{t:'frame', seq, payload, replay}` — `payload` is the device's opaque command bytes
 *    (for this agent, the JSON text of a flat `CBHR-RPC-V2` frame). `seq` is the relay's delivery
 *    number; acking it is the ONLY way the frame stops being redelivered (GM-21: the relay is the
 *    delivery guarantee, not the platform).
 *
 * 4. RESULTS. `{t:'result', callId, payload}` with an opaque string payload. The relay checks exactly
 *    three things (shape, opaque non-empty, ≤65536 chars) and then one thing more: the `callId` must
 *    name a call THIS object dispatched and has not already handed on. It never decodes the payload.
 *    The verdict comes back on the same socket: `{t:'result-ok', accepted:true, resultSeq, callId}`
 *    or `{t:'result-refused', accepted:false, code, ...}`.
 *
 * 5. ACK. `{t:'ack', seq}` → `{t:'ack-ok', ...}`. Sent AFTER the relay has given a verdict on the
 *    result, never before: the command frame is the only thing that can be redelivered, and acking it
 *    early would drop a call whose result never landed. A result the relay could not hold durably
 *    (`RESULT_OUTBOX_SATURATED`) is the one refusal that is RETRYABLE, so that frame is deliberately
 *    left unacked.
 *
 * 6. ERRORS. `{t:'error', reason}` for an unparsable or unknown control frame — logged, never fatal.
 *
 * ---------------------------------------------------------------------------------------------
 * THE CORRELATION RULE (and why the runtime, not the core, owns it)
 * ---------------------------------------------------------------------------------------------
 * `callId` is UNSIGNED TRANSPORT metadata on the command leg (GM-31): it is the platform's own name
 * for the call, echoed by the relay, and it is what the relay's ledger is keyed by. The runtime
 * therefore correlates the RESULT ENVELOPE on the *transport* `callId` of the frame it received —
 * never on a value the signed core happens to carry. That is not a shortcut around the outcome law:
 * the core's own `callId` field is signed and is what the platform re-verifies; the envelope's is
 * transport bookkeeping, exactly as it is on the way down. (A policy refusal raised after verification
 * carries the literal `unknown` in its SIGNED core — an observed W7/GM-80 wrinkle, recorded in the
 * README — and the transport field is what still lets the relay correlate it.)
 *
 * ---------------------------------------------------------------------------------------------
 * THE OUTCOME LAW IS NOT RE-DECIDED HERE
 * ---------------------------------------------------------------------------------------------
 * The runtime sends the frame `agent.handleFrame` returned and nothing else. It never upgrades an
 * outcome, never synthesises one, and when the core cannot assemble a result frame at all (a frame
 * whose claimed `callId` is not canonical, say) it sends NOTHING and says so loudly: a call left
 * unanswered is recoverable by the platform's `release`; a fabricated `uncertain` would not be.
 */

const { refusal, isEndpointRefusal, refusalCodeOf } = require('./errors');

/** The role this runtime claims on the relay socket. Never a parameter: see (1) above. */
const DEVICE_SOCKET_TAG = 'device';

/** The platform reader's tag. Named here only so the runtime can prove it never uses it. */
const PLATFORM_SOCKET_TAG = 'platform';

/** Backoff defaults: a resident agent on an owner's PC, so slow and patient rather than eager. */
const DEFAULT_BACKOFF_INITIAL_MS = 500;
const DEFAULT_BACKOFF_MAX_MS = 30000;

/** How long to wait for the relay's verdict on one result before giving up on the ack. */
const DEFAULT_VERDICT_TIMEOUT_MS = 15000;

/** How long a shutdown waits for frames already in flight before closing the socket anyway. */
const DEFAULT_DRAIN_MS = 5000;

/** The relay's own transport bound on a `callId` (`TRANSPORT_TEXT_MAX_CHARS` in device-relay.js). */
const TRANSPORT_TEXT_MAX_CHARS = 200;

/** The one control byte the canonical law reserves; transport text may never carry it. */
const RESERVED_SEPARATOR = '\u001f';

/** The single relay refusal that means "try again later" rather than "this is settled". */
const RETRYABLE_RESULT_REFUSALS = Object.freeze(['RESULT_OUTBOX_SATURATED']);

/** Levels, ordered. `warn` and above go to stderr so an operator watching either stream sees them. */
const LEVELS = Object.freeze(['debug', 'info', 'warn', 'error']);

function runtimeRefusal(detail, options = {}) {
  return refusal(
    options.code ?? 'ENDPOINT_RUNTIME_CONFIG_INVALID',
    detail,
    options.field === undefined ? {} : { field: options.field },
  );
}

/**
 * The relay's own transport-text rule, applied to a `callId` before it is echoed back.
 * Deliberately the same bounds as `device-relay.js`'s `usableTransportText`, so this runtime cannot
 * ask the relay to correlate with something it will refuse as malformed.
 * @param {unknown} value
 * @returns {string|null} the same string when usable, else null
 */
function usableTransportText(value) {
  if (typeof value !== 'string') {
    return null;
  }
  if (value.length === 0 || value.length > TRANSPORT_TEXT_MAX_CHARS) {
    return null;
  }
  if (value.includes(RESERVED_SEPARATOR)) {
    return null;
  }
  return value;
}

/**
 * Builds the device socket URL for a relay base URL.
 *
 * Accepts `http(s)://` or `ws(s)://`. A base URL with no path gets the relay's device route appended
 * (`/d/<deviceId>/ws`); a URL that already carries a path is used as given, so an operator behind a
 * proxy can point at the exact route. The role tag is always `device` and `replay=0` is added only
 * when replay-on-connect was explicitly turned off.
 *
 * @param {object} params
 * @param {string} params.relay relay base URL or full device route
 * @param {string} params.deviceId this endpoint's server-issued device id
 * @param {boolean} [params.replayOnConnect] default true (the relay's production path)
 * @returns {string} a `ws:`/`wss:` URL
 */
function buildDeviceSocketUrl(params = {}) {
  const { relay, deviceId } = params;
  if (typeof relay !== 'string' || relay.trim().length === 0) {
    throw runtimeRefusal('the runtime needs the relay URL to connect to', { field: 'relay' });
  }
  if (typeof deviceId !== 'string' || deviceId.length === 0) {
    throw runtimeRefusal('the runtime needs this endpoint\'s device id to address the relay', {
      field: 'deviceId',
    });
  }
  let url;
  try {
    url = new URL(relay.trim());
  } catch (err) {
    throw runtimeRefusal('the relay URL is not a URL this runtime can parse', {
      field: 'relay',
      cause: err,
    });
  }
  if (url.protocol === 'http:') {
    url.protocol = 'ws:';
  } else if (url.protocol === 'https:') {
    url.protocol = 'wss:';
  } else if (url.protocol !== 'ws:' && url.protocol !== 'wss:') {
    throw runtimeRefusal('the relay URL must be http(s) or ws(s)', { field: 'relay' });
  }
  if (url.pathname === '/' || url.pathname === '') {
    url.pathname = `/d/${encodeURIComponent(deviceId)}/ws`;
  }
  // Set, never inherit: a caller-supplied `?tag=platform` in the base URL must not survive.
  url.searchParams.set('tag', DEVICE_SOCKET_TAG);
  if (params.replayOnConnect === false) {
    url.searchParams.set('replay', '0');
  } else {
    url.searchParams.delete('replay');
  }
  return url.toString();
}

/**
 * The reconnect delay for the Nth consecutive failure: `initial * 2^(n-1)`, capped.
 * Deterministic by construction (no jitter): an operator reading the log, and a test asserting the
 * sequence, must see the same numbers. A single device reconnecting cannot stampede anything.
 *
 * @param {number} attempt 1-based count of consecutive failures
 * @param {object} [options]
 * @param {number} [options.initialMs]
 * @param {number} [options.maxMs]
 * @returns {number} milliseconds to wait
 */
function backoffDelayMs(attempt, options = {}) {
  const initialMs = options.initialMs ?? DEFAULT_BACKOFF_INITIAL_MS;
  const maxMs = options.maxMs ?? DEFAULT_BACKOFF_MAX_MS;
  if (!Number.isSafeInteger(attempt) || attempt < 1) {
    throw runtimeRefusal('the reconnect attempt counter must be an integer >= 1', { field: 'attempt' });
  }
  if (!Number.isSafeInteger(initialMs) || initialMs < 1 || !Number.isSafeInteger(maxMs) || maxMs < initialMs) {
    throw runtimeRefusal('the backoff bounds must be integers with 1 <= initial <= max', {
      field: 'backoff',
    });
  }
  const exponent = Math.min(attempt - 1, 30);
  return Math.min(maxMs, initialMs * 2 ** exponent);
}

/**
 * The one line an operator reads. JSON tail so a machine can also read it; the level word is padded so
 * a column of these is scannable.
 * @param {{ts: string, level: string, event: string}} record
 * @returns {string}
 */
function formatRuntimeEvent(record) {
  const { ts, level, event, ...fields } = record;
  const tail = Object.keys(fields).length > 0 ? ` ${JSON.stringify(fields)}` : '';
  return `${ts} ${String(level).toUpperCase().padEnd(5)} ${event}${tail}\n`;
}

/**
 * Builds an event record. Exported so a test can assert the exact shape a log consumer sees.
 * @param {string} level
 * @param {string} event
 * @param {object} [fields]
 * @param {() => number} [now]
 * @returns {object}
 */
function runtimeEvent(level, event, fields = {}, now = Date.now) {
  return { ts: new Date(now()).toISOString(), level, event, ...fields };
}

/**
 * The default sink: `info`/`debug` to stdout, `warn`/`error` to stderr. Never throws — a broken pipe
 * must not take the agent down (an agent that dies because its log rotated is the silent-death
 * failure mode this whole module exists to avoid).
 * @param {object} [streams]
 * @param {NodeJS.WritableStream} [streams.out]
 * @param {NodeJS.WritableStream} [streams.err]
 * @returns {(record: object) => void}
 */
function createRuntimeLogSink(streams = {}) {
  const out = streams.out ?? process.stdout;
  const err = streams.err ?? process.stderr;
  return (record) => {
    const target = record.level === 'warn' || record.level === 'error' ? err : out;
    try {
      target.write(formatRuntimeEvent(record));
    } catch {
      // A closed stdout/stderr is not a reason to stop being an endpoint.
    }
  };
}

/**
 * Registers the clean-shutdown signal handlers and returns the uninstaller.
 *
 * `SIGINT` (Ctrl+C) and `SIGTERM` (a service manager) both route to the SAME callback, so there is one
 * shutdown path to reason about and test. The emitter is injectable so a test can prove the wiring
 * without delivering an OS signal — which matters here, because on Windows a Node parent cannot
 * deliver a signal to a child at all: `child.kill('SIGINT')` terminates it unconditionally, and the
 * handler never runs (measured, see `test/runtime.test.js`).
 *
 * @param {object} params
 * @param {NodeJS.EventEmitter} params.emitter
 * @param {(signal: string) => void} params.onSignal
 * @returns {() => void} uninstall
 */
function installShutdownHandlers(params = {}) {
  const { emitter, onSignal } = params;
  if (emitter === null || typeof emitter !== 'object' || typeof emitter.on !== 'function') {
    throw runtimeRefusal('the shutdown installer needs an event emitter', { field: 'emitter' });
  }
  if (typeof onSignal !== 'function') {
    throw runtimeRefusal('the shutdown installer needs an onSignal callback', { field: 'onSignal' });
  }
  // One listener PER signal, each bound to its own name rather than reading an argument: Node does
  // pass the signal name to a signal listener, but nothing else does, and a shutdown path that only
  // works when the emitter is `process` is a shutdown path that cannot be tested.
  const handlers = new Map(
    ['SIGINT', 'SIGTERM'].map((signal) => [signal, () => onSignal(signal)]),
  );
  for (const [signal, handler] of handlers) {
    emitter.on(signal, handler);
  }
  let installed = true;
  return () => {
    if (!installed) {
      return;
    }
    installed = false;
    for (const [signal, handler] of handlers) {
      emitter.removeListener(signal, handler);
    }
  };
}

/** Pulls the transport `callId` out of an opaque payload string, without deciding anything. */
function callIdOfPayload(payload) {
  if (typeof payload !== 'string') {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }
  return usableTransportText(parsed.callId);
}

/**
 * Creates the runtime.
 *
 * @param {object} params
 * @param {object} params.agent a `createEndpointAgent(...)` instance — the ONLY place verification,
 *   policy and execution happen
 * @param {string} params.relay relay base URL (see `buildDeviceSocketUrl`)
 * @param {() => void} [params.onStop] called once when the runtime has fully stopped
 * @param {(record: object) => void} [params.onEvent] log sink; defaults to stdout/stderr
 * @param {() => number} [params.now]
 * @param {any} [params.webSocketImpl] the WebSocket constructor; defaults to the global one. `null`
 *   means "this machine has none", which is a refusal rather than a silent hang.
 * @param {boolean} [params.replayOnConnect]
 * @param {object} [params.backoff] `{initialMs, maxMs}`
 * @param {number} [params.verdictTimeoutMs]
 * @param {number} [params.drainMs]
 * @param {number} [params.maxReconnects] optional cap on consecutive reconnects (tests, and a
 *   deployment that would rather exit than retry forever)
 * @returns {Readonly<object>}
 */
function createAgentRuntime(params = {}) {
  const { agent } = params;
  if (agent === null || typeof agent !== 'object' || typeof agent.handleFrame !== 'function') {
    throw runtimeRefusal('the runtime needs a created endpoint agent to feed frames to', {
      field: 'agent',
      code: 'ENDPOINT_RUNTIME_CONFIG_INVALID',
    });
  }
  const now = typeof params.now === 'function' ? params.now : () => Date.now();
  const onEvent = typeof params.onEvent === 'function' ? params.onEvent : createRuntimeLogSink();
  const backoff = Object.freeze({
    initialMs: params.backoff?.initialMs ?? DEFAULT_BACKOFF_INITIAL_MS,
    maxMs: params.backoff?.maxMs ?? DEFAULT_BACKOFF_MAX_MS,
  });
  const verdictTimeoutMs = params.verdictTimeoutMs ?? DEFAULT_VERDICT_TIMEOUT_MS;
  const drainMs = params.drainMs ?? DEFAULT_DRAIN_MS;
  const maxReconnects =
    params.maxReconnects === undefined || params.maxReconnects === null ? null : params.maxReconnects;
  const deviceId = typeof params.deviceId === 'string' && params.deviceId.length > 0 ? params.deviceId : agent.deviceId();
  const socketUrl = buildDeviceSocketUrl({
    relay: params.relay,
    deviceId,
    replayOnConnect: params.replayOnConnect,
  });
  // Validate the backoff bounds now, so a bad flag fails at startup rather than at the first outage.
  backoffDelayMs(1, backoff);

  const webSocketImpl =
    params.webSocketImpl === undefined ? globalThis.WebSocket : params.webSocketImpl;

  /** @type {any} */
  let socket = null;
  let reconnectTimer = null;
  /** Sockets this runtime asked to close itself: their late `close` events are expected, not outages. */
  const closingSockets = new Set();
  let stopping = false;
  let stopped = false;
  let giveUp = false;
  let state = 'idle';
  let consecutiveFailures = 0;
  let stopReason = 'not-started';
  const counters = {
    framesReceived: 0,
    framesHandled: 0,
    framesAcked: 0,
    framesFailed: 0,
    framesDuplicate: 0,
    resultsSent: 0,
    resultsAccepted: 0,
    resultsRefused: 0,
    resultsUnanswered: 0,
    reconnects: 0,
    connections: 0,
  };
  const inFlight = new Set();
  /** @type {Map<string, {resolve: (value: object) => void, timer: any}>} */
  const awaitingVerdict = new Map();
  /** @type {Set<Promise<any>>} */
  const tasks = new Set();

  let resolveStopped;
  const stoppedPromise = new Promise((resolve) => {
    resolveStopped = resolve;
  });

  function emit(level, event, fields) {
    try {
      onEvent(runtimeEvent(level, event, fields, now));
    } catch {
      // A failing sink must never stop the endpoint from answering frames.
    }
  }

  function status() {
    return Object.freeze({
      state,
      relay: socketUrl,
      deviceId,
      deviceKeyId: agent.deviceKeyId(),
      tag: DEVICE_SOCKET_TAG,
      consecutiveFailures,
      counters: Object.freeze({ ...counters }),
      inFlight: inFlight.size,
      replayWindowLoadedEntries: agent._internal?.replayWindow?.loadedEntries ?? null,
      replayWindowFile: agent._internal?.replayWindow?.replayFile?.() ?? null,
    });
  }

  function track(task) {
    tasks.add(task);
    const cleanup = () => tasks.delete(task);
    task.then(cleanup, cleanup);
    return task;
  }

  /** Resolves the pending verdict for a call id, if one is waiting. */
  function settleVerdict(callId, verdict) {
    const key = usableTransportText(callId);
    if (key === null) {
      return false;
    }
    const pending = awaitingVerdict.get(key);
    if (pending === undefined) {
      return false;
    }
    awaitingVerdict.delete(key);
    clearTimeout(pending.timer);
    pending.resolve(verdict);
    return true;
  }

  function awaitVerdict(callId) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        awaitingVerdict.delete(callId);
        resolve({ t: 'timeout' });
      }, verdictTimeoutMs);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
      awaitingVerdict.set(callId, { resolve, timer });
    });
  }

  function sendControl(value) {
    if (socket === null || socket.readyState !== 1) {
      return false;
    }
    try {
      socket.send(JSON.stringify(value));
      return true;
    } catch {
      return false;
    }
  }

  function ackFrame(seq, why) {
    if (sendControl({ t: 'ack', seq })) {
      counters.framesAcked += 1;
      emit('debug', 'frame.acked', { seq, why });
      return true;
    }
    emit('warn', 'frame.ack.failed', { seq, why, detail: 'the socket was not open; the relay will redeliver' });
    return false;
  }

  /**
   * One received command frame: parse, hand to the core, send the result the core returned, and ack
   * only once the relay has judged the result.
   */
  async function handleFrameMessage(message) {
    const seq = message.seq;
    if (!Number.isSafeInteger(seq) || seq < 1) {
      emit('warn', 'relay.frame.malformed', { detail: 'a frame message carried no usable delivery seq' });
      return;
    }
    if (inFlight.has(seq)) {
      counters.framesDuplicate += 1;
      emit('warn', 'relay.frame.duplicate', {
        seq,
        detail: 'this delivery seq is already being handled; ignoring the second copy of it',
      });
      return;
    }
    inFlight.add(seq);
    counters.framesReceived += 1;
    const startedAt = now();
    const replay = message.replay === true;
    let frame = null;
    let parseError = null;
    try {
      frame = JSON.parse(message.payload);
    } catch (err) {
      parseError = err;
    }
    const transportCallId = parseError === null ? usableTransportText(frame?.callId) : null;
    emit('info', 'frame.received', {
      seq,
      replay,
      callId: parseError === null ? callIdOfPayload(message.payload) : null,
    });

    try {
      if (parseError !== null) {
        // The relay forwards bytes. A payload this endpoint cannot even parse has no claim to
        // correlate with, so nothing can be answered: ack (there is no point redelivering it) and say
        // so loudly. The call stays open at the platform, which is the honest place for it.
        counters.framesFailed += 1;
        emit('error', 'frame.unparsable', {
          seq,
          replay,
          detail: 'the relay payload is not the JSON text of a frame; no result can be produced for it',
        });
        ackFrame(seq, 'unparsable-payload');
        return;
      }

      let handled;
      try {
        handled = await agent.handleFrame(frame);
      } catch (err) {
        // The core itself could not produce a result (for example result assembly refused a claimed
        // callId that is not canonical). NOTHING is sent: an unanswered call can be released and
        // retried, a fabricated outcome cannot be taken back.
        counters.framesFailed += 1;
        counters.resultsUnanswered += 1;
        emit('error', 'frame.failed', {
          seq,
          replay,
          code: isEndpointRefusal(err) ? err.code : 'ENDPOINT_UNEXPECTED_FAILURE',
          detail: 'the agent core could not assemble a result; no result was sent for this frame',
        });
        ackFrame(seq, 'core-failure');
        return;
      }

      counters.framesHandled += 1;
      const resultFrame = handled.resultFrame;
      emit(handled.outcome === 'succeeded' ? 'info' : 'warn', 'frame.outcome', {
        seq,
        replay,
        callId: transportCallId,
        outcome: handled.outcome,
        executed: handled.executed === true,
        refusalCode: handled.refusalCode ?? null,
        ms: Math.max(0, now() - startedAt),
        ...(handled.outcome === 'succeeded'
          ? {}
          : { detail: 'nothing was reported as a success for this frame' }),
      });

      if (transportCallId === null) {
        counters.resultsUnanswered += 1;
        emit('error', 'result.uncorrelatable', {
          seq,
          detail:
            'the frame carries no usable transport callId, so the relay cannot correlate a result for it; nothing was sent',
        });
        ackFrame(seq, 'no-call-id');
        return;
      }

      let payload;
      try {
        payload = JSON.stringify(resultFrame);
      } catch (err) {
        counters.resultsUnanswered += 1;
        emit('error', 'result.unserialisable', { seq, callId: transportCallId });
        ackFrame(seq, 'result-unserialisable');
        return;
      }

      const verdictPromise = awaitVerdict(transportCallId);
      if (!sendControl({ t: 'result', callId: transportCallId, payload })) {
        // The socket died between receiving the frame and answering it. Do NOT ack: the relay still
        // holds the frame and will redeliver it on the next connect.
        counters.resultsUnanswered += 1;
        emit('warn', 'result.send.failed', {
          seq,
          callId: transportCallId,
          detail: 'the socket was not open; the frame is left unacked so the relay can redeliver it',
        });
        return;
      }
      counters.resultsSent += 1;
      emit('info', 'result.sent', {
        seq,
        callId: transportCallId,
        outcome: resultFrame.outcome,
        correlation: resultFrame.correlation ?? null,
        payloadChars: payload.length,
      });

      const verdict = await verdictPromise;
      if (verdict.t === 'result-ok') {
        counters.resultsAccepted += 1;
        emit('info', 'result.verdict', { seq, callId: transportCallId, accepted: true, resultSeq: verdict.resultSeq ?? null });
        ackFrame(seq, 'result-accepted');
        return;
      }
      if (verdict.t === 'result-refused') {
        counters.resultsRefused += 1;
        const retryable = RETRYABLE_RESULT_REFUSALS.includes(verdict.code);
        emit('warn', 'result.verdict', {
          seq,
          callId: transportCallId,
          accepted: false,
          code: verdict.code ?? null,
          retryable,
        });
        if (retryable) {
          // The relay could not hold the result durably. Leaving the frame unacked is the only way
          // the call can still be answered; the endpoint's durable replay window is what stops the
          // redelivery from re-executing the tool.
          emit('warn', 'frame.left-unacked', { seq, callId: transportCallId, code: verdict.code ?? null });
          return;
        }
        ackFrame(seq, 'result-refused-terminal');
        return;
      }
      counters.resultsUnanswered += 1;
      emit('warn', 'result.verdict.timeout', {
        seq,
        callId: transportCallId,
        verdictTimeoutMs,
        detail: 'the relay did not judge the result in time; the frame is left unacked so it can be redelivered',
      });
    } finally {
      inFlight.delete(seq);
    }
  }

  function handleSocketMessage(raw) {
    const text = typeof raw === 'string' ? raw : raw === null || raw === undefined ? '' : String(raw);
    let message;
    try {
      message = JSON.parse(text);
    } catch {
      emit('warn', 'relay.message.unparsable', { detail: 'the relay sent a control frame that is not JSON' });
      return;
    }
    if (message === null || typeof message !== 'object' || Array.isArray(message)) {
      emit('warn', 'relay.message.malformed', { detail: 'a relay control frame must be a JSON object' });
      return;
    }
    switch (message.t) {
      case 'frame':
        track(handleFrameMessage(message));
        return;
      case 'result-ok':
      case 'result-refused':
        // A verdict nobody is waiting for is still worth a line: it means the socket outlived the
        // handler that sent the result.
        if (!settleVerdict(message.callId, message)) {
          emit('debug', 'result.verdict.orphan', { callId: usableTransportText(message.callId) });
        }
        return;
      case 'ack-ok':
        emit('debug', 'frame.ack.ok', { seq: message.seq ?? null });
        return;
      case 'error':
        emit('warn', 'relay.error.frame', { reason: typeof message.reason === 'string' ? message.reason : 'unknown' });
        return;
      default:
        emit('warn', 'relay.message.unknown', {
          type: typeof message.t === 'string' ? message.t : null,
          detail: 'this runtime knows frame, result-ok, result-refused, ack-ok and error',
        });
    }
  }

  function scheduleReconnect() {
    // Idempotent per incident: the first caller arms the timer, a second event from the SAME dead
    // socket (undici reports a refused connection as BOTH an error and a close) finds the armed
    // timer and does nothing, so one outage is one attempt.
    if (stopping || reconnectTimer !== null) {
      return;
    }
    consecutiveFailures += 1;
    if (maxReconnects !== null && consecutiveFailures > maxReconnects) {
      giveUp = true;
      state = 'gave-up';
      emit('error', 'runtime.gave_up', {
        attempts: consecutiveFailures - 1,
        maxReconnects,
        detail: 'the relay did not come back within the configured number of attempts; exiting loudly rather than hanging silently',
      });
      finalise('gave-up');
      return;
    }
    const delayMs = backoffDelayMs(consecutiveFailures, backoff);
    state = 'waiting';
    emit('warn', 'relay.reconnect.scheduled', {
      attempt: consecutiveFailures,
      delayMs,
      relay: socketUrl,
      detail: 'the device socket is down; the runtime will reconnect on its own',
    });
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, delayMs);
    // DELIBERATELY NOT unref'd. An unref'd reconnect timer lets Node exit the moment the event loop
    // is otherwise empty — which is exactly the silent death this runtime exists to remove: the
    // process would end with a warning in the log and nobody watching. Waiting to reconnect IS the
    // agent's work, so it is allowed to hold the process open. `stop()` clears it.
  }

  function connect() {
    if (stopping || stopped) {
      return;
    }
    if (typeof webSocketImpl !== 'function') {
      throw refusal(
        'ENDPOINT_RUNTIME_UNAVAILABLE',
        'this runtime has no WebSocket client, so it cannot be a live participant; install nothing — the runtime refuses rather than pretending to listen',
        { field: 'webSocket' },
      );
    }
    state = 'connecting';
    emit('info', 'relay.connecting', { relay: socketUrl, attempt: consecutiveFailures + 1 });
    let ws;
    try {
      ws = new webSocketImpl(socketUrl);
    } catch (err) {
      emit('error', 'relay.connect.threw', { relay: socketUrl });
      scheduleReconnect();
      return;
    }
    socket = ws;
    ws.addEventListener('open', () => {
      counters.connections += 1;
      counters.reconnects = counters.connections - 1;
      state = 'connected';
      consecutiveFailures = 0;
      emit('info', 'relay.connected', {
        relay: socketUrl,
        deviceId,
        deviceKeyId: agent.deviceKeyId(),
        connections: counters.connections,
        replayWindowLoadedEntries: agent._internal?.replayWindow?.loadedEntries ?? null,
      });
    });
    ws.addEventListener('message', (event) => {
      handleSocketMessage(event?.data);
    });
    ws.addEventListener('error', (event) => {
      const detail = event && typeof event.message === 'string' && event.message.length > 0 ? event.message : 'socket error';
      emit('error', 'relay.error', { relay: socketUrl, detail, attempts: consecutiveFailures + 1 });
      // MEASURED BEHAVIOUR, and the reason this is not left to `close`: on a REFUSED connection
      // (relay down, wrong port, non-101 answer) Node 22's global WebSocket fires `error` and then
      // never fires `close` at all — `readyState` stays CONNECTING (0) forever. A reconnect driven
      // only by `close` would therefore never run, and the agent would sit dead in silence after the
      // first outage. Both events write the socket off; whichever arrives first wins.
      writeOffSocket(ws, { via: 'error', code: null, reason: detail });
    });
    ws.addEventListener('close', (event) => {
      const code = event && Number.isInteger(event.code) ? event.code : null;
      const reason = event && typeof event.reason === 'string' ? event.reason : '';
      writeOffSocket(ws, { via: 'close', code, reason });
    });
  }

  /**
   * Retires a socket that is down and arms the reconnect.
   *
   * `ws !== socket` means this event belongs to a connection that was already written off (the same
   * failure reported twice, or a late event from a socket we replaced), so it is ignored rather than
   * counted as a second outage — otherwise one outage could burn two attempts of a bounded
   * `--max-reconnects` budget without a single retry.
   *
   * @param {any} ws the socket the event came from
   * @param {{via: string, code: number|null, reason: string}} detail
   */
  function writeOffSocket(ws, detail) {
    const requestedByUs = closingSockets.delete(ws) || stopping;
    if (ws !== socket) {
      return;
    }
    socket = null;
    if (requestedByUs) {
      emit('info', 'relay.closed', { ...detail, expected: true });
      return;
    }
    emit('error', 'relay.socket.lost', {
      ...detail,
      expected: false,
      note: 'the device socket is gone; frames stop arriving until it is back',
    });
    scheduleReconnect();
  }

  function finalise(reason) {
    if (stopped) {
      return;
    }
    stopped = true;
    state = state === 'gave-up' ? 'gave-up' : 'stopped';
    stopReason = reason;
    emit('info', 'runtime.stopped', {
      reason,
      relay: socketUrl,
      counters: { ...counters },
      replayWindowEntries: agent._internal?.replayWindow?.size?.() ?? null,
      replayWindowFile: agent._internal?.replayWindow?.replayFile?.() ?? null,
    });
    if (typeof params.onStop === 'function') {
      try {
        params.onStop({ reason, gaveUp: giveUp, counters: { ...counters } });
      } catch {
        // An onStop throwing must not prevent the process from finishing its shutdown.
      }
    }
    resolveStopped({ reason, gaveUp: giveUp, counters: Object.freeze({ ...counters }) });
  }

  /**
   * Stops the runtime: no new frames, waiting frames drained (bounded), socket closed with a normal
   * code, and the durable replay window pruned-and-persisted so the next start sees exactly what this
   * one spent. Nothing is deleted: the key store and the window file are left for the next process.
   */
  async function stop(reason = 'requested') {
    if (stopped || stopping) {
      return stoppedPromise;
    }
    stopping = true;
    state = 'stopping';
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    emit('info', 'runtime.shutdown', {
      reason,
      inFlight: inFlight.size,
      counters: { ...counters },
      drainMs,
    });

    if (inFlight.size > 0) {
      // Not unref'd: a shutdown in progress must finish its own logging before the process ends.
      let drainTimer = null;
      const drained = await Promise.race([
        Promise.allSettled([...tasks]),
        new Promise((resolve) => {
          drainTimer = setTimeout(() => resolve('timeout'), drainMs);
        }),
      ]);
      if (drainTimer !== null) {
        clearTimeout(drainTimer);
      }
      if (drained === 'timeout') {
        emit('warn', 'runtime.drain.timeout', { inFlight: inFlight.size, drainMs });
      }
    }

    // Verdicts that never arrived are recorded, not hidden: the frames they belong to stay unacked.
    for (const [callId, pending] of awaitingVerdict) {
      clearTimeout(pending.timer);
      pending.resolve({ t: 'stopped' });
      emit('warn', 'result.verdict.abandoned', { callId });
    }
    awaitingVerdict.clear();

    if (socket !== null) {
      // Say it BEFORE doing it: the echo (`relay.closed`) depends on the relay answering a close
      // handshake the process may not wait around for, so the intent line is the evidence an operator
      // (and a test) can rely on: the socket was closed deliberately, with a normal code.
      emit('info', 'relay.closing', { code: 1000, reason: `agent shutdown: ${reason}` });
      try {
        closingSockets.add(socket);
        socket.close(1000, `agent shutdown: ${reason}`);
      } catch {
        // Already gone.
      }
      socket = null;
    }

    // The window is pruned-and-persisted on the way out; `prune()` is the module's own diagnostic
    // path and writes through `atomicReplaceOwnerOnlyFile`, so a crash here leaves the old window
    // rather than a truncated one.
    const replayWindow = agent._internal?.replayWindow;
    if (replayWindow !== undefined && typeof replayWindow.prune === 'function') {
      try {
        const removed = replayWindow.prune();
        emit('info', 'runtime.replay.pruned', {
          removed,
          entries: replayWindow.size(),
          file: replayWindow.replayFile(),
        });
      } catch (err) {
        emit('error', 'runtime.replay.prune.failed', { code: refusalCodeOf(err) ?? 'UNKNOWN' });
      }
    }
    emit('info', 'runtime.keys.intact', {
      deviceKeyFile: agent._internal?.keystore?.keyFile?.() ?? null,
      replayWindowFile: replayWindow?.replayFile?.() ?? null,
      detail: 'shutdown deletes nothing: the key store and the durable replay window stay for the next start',
    });
    finalise(reason);
    return stoppedPromise;
  }

  function start() {
    if (stopping || stopped) {
      throw runtimeRefusal('this runtime has already been stopped', { field: 'state' });
    }
    if (typeof webSocketImpl !== 'function') {
      throw refusal(
        'ENDPOINT_RUNTIME_UNAVAILABLE',
        'this runtime has no WebSocket client, so it cannot be a live participant; the runtime refuses rather than pretending to listen',
        { field: 'webSocket' },
      );
    }
    emit('info', 'runtime.start', {
      relay: socketUrl,
      deviceId,
      deviceKeyId: agent.deviceKeyId(),
      tag: DEVICE_SOCKET_TAG,
      replayOnConnect: params.replayOnConnect !== false,
      backoff,
      maxReconnects,
      replayWindowLoadedEntries: agent._internal?.replayWindow?.loadedEntries ?? null,
      replayWindowFile: agent._internal?.replayWindow?.replayFile?.() ?? null,
      deviceKeyFile: agent._internal?.keystore?.keyFile?.() ?? null,
    });
    connect();
    return status();
  }

  return Object.freeze({
    start,
    stop,
    status,
    /** Resolves when the runtime has stopped, for any reason. */
    whenStopped: () => stoppedPromise,
    /** The URL this runtime connects to — asserted by tests and printed by `--print-url`. */
    socketUrl: () => socketUrl,
  });
}

module.exports = {
  DEVICE_SOCKET_TAG,
  PLATFORM_SOCKET_TAG,
  DEFAULT_BACKOFF_INITIAL_MS,
  DEFAULT_BACKOFF_MAX_MS,
  DEFAULT_VERDICT_TIMEOUT_MS,
  DEFAULT_DRAIN_MS,
  TRANSPORT_TEXT_MAX_CHARS,
  RETRYABLE_RESULT_REFUSALS,
  LEVELS,
  usableTransportText,
  callIdOfPayload,
  buildDeviceSocketUrl,
  backoffDelayMs,
  formatRuntimeEvent,
  runtimeEvent,
  createRuntimeLogSink,
  installShutdownHandlers,
  createAgentRuntime,
};
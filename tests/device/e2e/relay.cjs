'use strict';

/**
 * W9 — the REAL local relay.
 *
 * This is the same runtime shape `apps/cbhr-relay/run-relay.mjs` and `run-reconciliation.mjs` use:
 * Miniflare (in-process workerd) booting the relay's OWN built artifact
 * (`apps/cbhr-relay/dist/worker.js`) with the compatibility configuration PARSED FROM
 * `wrangler.toml`, and the Durable Object class the config registers. Nothing is re-implemented: the
 * device socket, the frame admission, the result outbox and the keyless forwarder are the relay's.
 *
 * The relay lives in the SIBLING repository (`cbhr-rdc/apps/cbhr-relay`). It is resolved through an
 * explicit, overridable path so the harness says where it read it from rather than assuming.
 */

const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const { pathToFileURL } = require('node:url');

const REPO = path.resolve(__dirname, '..', '..', '..');
/** Default sibling checkout; overridable with CBHR_RELAY_ROOT. */
const RELAY_ROOT =
  process.env.CBHR_RELAY_ROOT ?? path.resolve(REPO, '..', 'cbhr-rdc', 'apps', 'cbhr-relay');

const WORKER = 'cbhr-device-relay';
const CLASS = 'DeviceRelay';

/** Requires an ESM module from a CJS harness without changing the harness to ESM. */
async function importFrom(relayRoot, specifier) {
  const requireFromRelay = Module.createRequire(path.join(relayRoot, 'run-relay.mjs'));
  const resolved = requireFromRelay.resolve(specifier);
  return import(pathToFileURL(resolved).href);
}

/**
 * Boots the relay worker in-process and returns a small HTTP/WS client for it.
 * @returns {Promise<object>}
 */
async function startRelay({ persistDir }) {
  const scriptPath = path.join(RELAY_ROOT, 'dist', 'worker.js');
  const wranglerPath = path.join(RELAY_ROOT, 'wrangler.toml');
  for (const required of [scriptPath, wranglerPath]) {
    if (!fs.existsSync(required)) {
      throw new Error(
        `HARNESS_REFUSAL: the real relay artifact is absent: ${required}. Build it with "cd ${RELAY_ROOT} && npm run build".`,
      );
    }
  }
  const { Miniflare, convertV4MiniflareOptions } = await importFrom(RELAY_ROOT, 'miniflare');
  const { parseWranglerToml, ensureProbeTemp } = await importFrom(RELAY_ROOT, './tools/effective-compat.mjs');
  const wrangler = parseWranglerToml(fs.readFileSync(wranglerPath, 'utf8'));
  // workerd creates its own scratch directories; on this host the OS temp directory is refused
  // ("CreateDirectory: #5 Access is denied.; path = miniflare-email-store"), which is exactly why the
  // relay's own runners call `ensureProbeTemp` before every boot. Same call, same reason.
  const osTmp = ensureProbeTemp(path.dirname(persistDir));
  fs.mkdirSync(persistDir, { recursive: true });

  // THE WORKING DIRECTORY IS LOAD-BEARING. `run-relay.mjs` is always launched from the relay
  // directory, and Miniflare's option converter + worker bootstrap resolve relative to the process
  // CWD. Booting the identical artifact from a different CWD fails at startup with a misleading
  // "no such Durable Object class is exported from the worker" (the real failure is an internal
  // workerd error raised while the module service initialises). The harness therefore reproduces the
  // relay's own invocation exactly: it enters the relay root for the boot and restores the repo CWD
  // afterwards. Measured, not assumed — see `relayBootCwd` in the evidence.
  const previousCwd = process.cwd();
  process.chdir(RELAY_ROOT);
  let mf;
  try {
    mf = new Miniflare(
      convertV4MiniflareOptions({
        workers: [
          {
            name: WORKER,
            modules: true,
            scriptPath,
            // The compatibility configuration is PARSED FROM `wrangler.toml` and passed EXPLICITLY,
            // exactly as the relay's own runners do (GM-51). Without these two keys sitting on the
            // worker options, the converter emits its own default `compatibilityDate: 2000-01-01`.
            compatibilityDate: wrangler.compatibilityDate,
            compatibilityFlags: wrangler.compatibilityFlags,
            durableObjects: { DEVICE_RELAY: { className: CLASS, useSQLite: true } },
          },
        ],
        resourcePersistencePath: persistDir,
        host: '127.0.0.1',
        port: 0,
      }),
    );
    const base = (await mf.ready).toString();
    return buildClient({
      mf,
      base,
      scriptPath,
      wranglerPath,
      osTmp,
      bootCwd: RELAY_ROOT,
      wranglerDate: wrangler.compatibilityDate,
      wranglerFlags: wrangler.compatibilityFlags,
    });
  } catch (error) {
    await mf?.dispose?.().catch(() => {});
    throw error;
  } finally {
    process.chdir(previousCwd);
  }
}

/**
 * The client surface handed to the harness. Split out so the boot above can restore the CWD in a
 * `finally` block without the returned object holding a stale one.
 */
function buildClient({
  mf,
  base,
  scriptPath,
  wranglerPath,
  osTmp,
  bootCwd,
  wranglerDate,
  wranglerFlags,
}) {
  const call = async (pathname, init) => {
    const res = await fetch(new URL(pathname, base), init);
    const text = await res.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: res.status, body };
  };
  const post = (pathname, payload) =>
    call(pathname, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload ?? {}),
    });

  return {
    base,
    mf,
    call,
    post,
    workerScript: scriptPath,
    wrangler: path.relative(RELAY_ROOT, wranglerPath),
    osTmp,
    relayBootCwd: bootCwd,
    compatibility: { date: wranglerDate, flags: wranglerFlags },
    /** The device socket, exactly as a device connects. */
    connectDeviceSocket: (deviceId, tag = 'device') => WsClient.connect(base, deviceId, tag),
    stateOf: (deviceId) => call(`/d/${encodeURIComponent(deviceId)}/state`).then((r) => r.body),
    pendingOf: (deviceId) =>
      call(`/d/${encodeURIComponent(deviceId)}/results/pending`).then((r) => r.body),
    grant: (deviceId, { epoch = 1, expiresAt = Date.now() + 3600000, arm = false } = {}) =>
      post(`/d/${encodeURIComponent(deviceId)}/grant`, { epoch, expiresAt, arm }),
    /** The relay's own frame admission — the transport the dispatch client's `transport` seam calls. */
    admitFrame: (deviceId, payload, callId = null) =>
      post(`/d/${encodeURIComponent(deviceId)}/frame`, {
        epoch: 1,
        payload: typeof payload === 'string' ? payload : JSON.stringify(payload),
        // The relay's `/frame` admission takes the call id as a SEPARATE transport argument and only
        // records correlation bookkeeping when it is present; without it `recordResult` refuses every
        // result as UNKNOWN_CALL_ID. The accepted dispatch client's transport seam signature is
        // `({deviceId, frame})` and the frame itself carries `callId`, so the caller derives it from
        // the frame. Measured, not assumed: the first full run of this harness was refused exactly
        // that way.
        ...(typeof callId === 'string' && callId.length > 0 ? { callId } : {}),
      }),
    ackResults: (deviceId, resultSeqs) =>
      post(`/d/${encodeURIComponent(deviceId)}/results/ack`, { resultSeqs }),
    releaseResult: (deviceId, callId) =>
      post(`/d/${encodeURIComponent(deviceId)}/results/release`, { callId }),
    dispose: () => mf.dispose(),
  };
}

/** A thin WebSocket client that records every message the relay sends, so verdicts are never guessed. */
class WsClient {
  constructor(ws) {
    this.ws = ws;
    this.messages = [];
    ws.addEventListener('message', (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch {
        data = event.data;
      }
      this.messages.push(data);
    });
    ws.addEventListener('close', (event) => {
      this.closed = { code: event.code, reason: event.reason };
    });
  }

  static async connect(base, device, tag, query = '') {
    const url = new URL(`/d/${encodeURIComponent(device)}/ws?tag=${encodeURIComponent(tag)}${query}`, base);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`ws open timeout ${url}`)), 5000);
      ws.addEventListener('open', () => {
        clearTimeout(timer);
        resolve();
      });
      ws.addEventListener('error', () => {
        clearTimeout(timer);
        reject(new Error(`ws error ${url}`));
      });
    });
    return new WsClient(ws);
  }

  send(value) {
    this.ws.send(typeof value === 'string' ? value : JSON.stringify(value));
  }

  of(type) {
    return this.messages.filter((message) => message && message.t === type);
  }

  /** Every frame the relay pushed to this socket, in arrival order. */
  frames() {
    return this.of('frame');
  }

  resultVerdicts() {
    return this.messages.filter((message) => message && (message.t === 'result-ok' || message.t === 'result-refused'));
  }

  async waitFor(predicate, options = {}) {
    const started = Date.now();
    const timeout = options.timeout ?? 5000;
    for (;;) {
      const value = predicate(this);
      if (value) {
        return value;
      }
      if (Date.now() - started >= timeout) {
        return null;
      }
      await new Promise((resolve) => setTimeout(resolve, options.interval ?? 25));
    }
  }

  async waitForFrames(count, timeout = 5000) {
    return this.waitFor((client) => (client.frames().length >= count ? client.frames() : null), { timeout });
  }

  /** Sends one result and waits for the relay's typed verdict, so the transport step is observable. */
  async sendResult({ callId, payload }) {
    const before = this.resultVerdicts().length;
    this.send({ t: 'result', callId, payload });
    const verdict = await this.waitFor((client) => {
      const seen = client.resultVerdicts();
      return seen.length > before ? seen[seen.length - 1] : null;
    });
    if (verdict === null) {
      throw new Error(`no relay verdict for result ${callId}`);
    }
    return verdict;
  }

  close() {
    this.ws.close(1000, 'w9-e2e');
  }
}

module.exports = { RELAY_ROOT, WORKER, CLASS, startRelay, WsClient };
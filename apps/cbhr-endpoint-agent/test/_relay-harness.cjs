'use strict';

/**
 * W13 test support — A REAL LOCAL RELAY, IN THIS PROCESS.
 *
 * NOT a test file. `runtime-relay.test.js` uses it to prove the runtime end to end against the actual
 * relay artifact, the way `apps/cbhr-relay/run-reconciliation.mjs` and `run-uplink.mjs` already do:
 * the relay's built Worker (`dist/worker.js`) is booted through **Miniflare/workerd in this process**,
 * with the compatibility configuration parsed out of the relay's own `wrangler.toml` by the relay's
 * own reader (`tools/effective-compat.mjs`). Nothing is deployed, no account is used, and no file
 * outside this agent's directory is written: the Miniflare persistence directory and every temp file
 * live under the OS temp directory.
 *
 * WHY THE RELAY'S OWN MODULES ARE IMPORTED BY ABSOLUTE PATH
 * `miniflare` is a devDependency of `apps/cbhr-relay`, not of this agent — and this workstream may not
 * add a dependency to either. So the harness resolves it from the RELAY's `node_modules` (via
 * `createRequire` on the relay's `package.json`) and imports it dynamically. The relay root can be
 * moved with `CBHR_RELAY_ROOT`; the default is the sibling worktree the audit route itself uses.
 *
 * WHAT THIS HARNESS IS NOT
 * It is not a relay implementation and not a stub of one: it starts the audited artifact and speaks
 * to it over real HTTP and real WebSockets. The only thing it "knows" about the protocol is what
 * `apps/cbhr-relay/src/device-relay.js` documents — `/d/<deviceId>/...`, `?tag=`, `/grant`, `/frame`,
 * `/results/pending`, `{t:'frame'|'result'|'ack'|...}`.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');

/** The sibling worktree the relay lives in, unless an operator points somewhere else. */
const DEFAULT_RELAY_ROOT = path.resolve(__dirname, '..', '..', '..', '..', 'cbhr-rdc', 'apps', 'cbhr-relay');

/**
 * WHERE WORKERD'S SCRATCH LIVES — and why it is not the OS temp directory.
 *
 * MEASURED ON THIS HOST, and the reason this whole suite once failed to boot: the Workers runtime
 * (`workerd`, which Miniflare drives) can only create and write files inside directories that carry
 * the session sandbox's own ACE. Outside them every `CreateDirectory` and every SQLite open fails —
 *
 *   kj/filesystem-disk-win32.c++:773: failed: CreateDirectory: #5 Access is denied.; path = ...
 *   workerd/util/sqlite.c++:1759: failed: ... attempt to write a readonly database: SQLITE_READONLY
 *
 * — even for a trivial worker with no relay code and even under `%TEMP%`, while an ordinary Node
 * process (this test) writes to the same places without complaint. The relay's own acceptance runners
 * keep every workerd file under the repository for exactly this reason
 * (`tools/effective-compat.mjs: ensureProbeTemp`, "sandboxed hosts can deny the OS temp dir to spawned
 * processes"), and their `.relay-state` layout is the same shape this harness creates.
 *
 * So the scratch root is inside the agent's own directory (the stamped tree), gitignored, and removed
 * when the relay stops. `CBHR_W13_SCRATCH` overrides it; `CBHR_W13_KEEP_SCRATCH=1` keeps it for
 * debugging a boot failure.
 */
const AGENT_DIR = path.resolve(__dirname, '..');
const DEFAULT_SCRATCH_ROOT =
  typeof process.env.CBHR_W13_SCRATCH === 'string' && process.env.CBHR_W13_SCRATCH.length > 0
    ? path.resolve(process.env.CBHR_W13_SCRATCH)
    : path.join(AGENT_DIR, '.runtime-e2e-state');

/**
 * The OS temp directory THIS PROCESS started with, captured before `startRelay` redirects
 * `TMP`/`TEMP`/`TMPDIR` into the scratch tree.
 *
 * Anything that is NOT workerd must be given these back: the endpoint agent under test is an ordinary
 * Node process, it can create and own files in the real temp directory exactly as it will on an
 * owner's PC, and the runtime writes its own agent roots there. Pointing the agent at the relay's
 * scratch tree instead would test it inside another program's sandbox ACLs.
 */
const ORIGINAL_TEMP_DIR = os.tmpdir();

/** The environment a child process should get so it sees the real temp directory, not workerd's. */
function childEnvironment(extra = {}) {
  return {
    ...process.env,
    TMP: ORIGINAL_TEMP_DIR,
    TEMP: ORIGINAL_TEMP_DIR,
    TMPDIR: ORIGINAL_TEMP_DIR,
    ...extra,
  };
}

/** Reserved names, frozen by the relay's build order. */
const WORKER = 'cbhr-device-relay';
const CLASS = 'DeviceRelay';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(predicate, { timeout = 8000, interval = 20 } = {}) {
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

function relayRoot() {
  return typeof process.env.CBHR_RELAY_ROOT === 'string' && process.env.CBHR_RELAY_ROOT.length > 0
    ? path.resolve(process.env.CBHR_RELAY_ROOT)
    : DEFAULT_RELAY_ROOT;
}

/**
 * The prerequisite this suite REFUSES to skip silently: a missing relay must fail the run loudly,
 * because "the end-to-end proof did not run" is not the same evidence as "the end-to-end proof
 * passed" — and silently skipping is how a missing proof gets read as a green one.
 */
function assertRelayAvailable() {
  const root = relayRoot();
  const dist = path.join(root, 'dist', 'worker.js');
  const toml = path.join(root, 'wrangler.toml');
  const problems = [];
  if (!fs.existsSync(root)) {
    problems.push(`the relay worktree is not at ${root} (set CBHR_RELAY_ROOT to point at it)`);
  } else {
    if (!fs.existsSync(dist)) {
      problems.push(`${dist} does not exist — build the relay artifact first (cd ${root} && npm run build)`);
    }
    if (!fs.existsSync(toml)) {
      problems.push(`${toml} does not exist, so the worker's compatibility configuration is unknown`);
    }
    try {
      createRequire(path.join(root, 'package.json')).resolve('miniflare');
    } catch {
      problems.push(`miniflare is not installed under ${root} (cd ${root} && npm install)`);
    }
  }
  if (problems.length > 0) {
    throw new Error(
      `the runtime end-to-end suite needs the LOCAL relay artifact and refuses to run without it:\n  - ${problems.join('\n  - ')}`,
    );
  }
  return root;
}

/**
 * Boots the relay artifact on a loopback port, in this process.
 * @param {object} [options]
 * @param {string} [options.persistDir] Miniflare persistence directory
 * @param {string} [options.scratchDir] where Miniflare/workerd state lives (default: a fresh
 *   directory under `DEFAULT_SCRATCH_ROOT`)
 * @returns {Promise<object>} harness
 */
async function startRelay(options = {}) {
  const root = assertRelayAvailable();
  const requireFromRelay = createRequire(path.join(root, 'package.json'));
  const miniflareEntry = requireFromRelay.resolve('miniflare');
  const miniflare = await import(pathToFileURL(miniflareEntry).href);
  const compat = await import(pathToFileURL(path.join(root, 'tools', 'effective-compat.mjs')).href);

  // The worker's compatibility configuration comes from ITS OWN wrangler.toml, read by ITS OWN
  // reader. This matters: the relay's Durable Object fails closed unless `nodejs_compat` is off, so a
  // harness that guessed the flags would either fail to boot or boot a different engine profile than
  // the artifact was audited under.
  const wrangler = compat.parseWranglerToml(fs.readFileSync(path.join(root, 'wrangler.toml'), 'utf8'));

  const scratchDir =
    options.scratchDir ??
    fs.mkdtempSync(path.join((fs.mkdirSync(DEFAULT_SCRATCH_ROOT, { recursive: true }), DEFAULT_SCRATCH_ROOT), 'run-'));
  const tempRoot = options.tempRoot ?? path.join(scratchDir, 'workerd-tmp');
  fs.mkdirSync(tempRoot, { recursive: true });
  // workerd's own scratch files, and anything it hands to a child, must live in the stamped tree too.
  process.env.TMP = tempRoot;
  process.env.TEMP = tempRoot;
  process.env.TMPDIR = tempRoot;

  const persistDir = options.persistDir ?? path.join(scratchDir, 'relay-state');

  // PRE-CREATE THE PER-RESOURCE STORAGE DIRECTORIES (measured workaround, not a preference).
  //
  // This Miniflare build lays resources out as `<resourcePersistencePath>/<plugin>/<uniqueKey>` but
  // does not create every one of those directories itself, and workerd's own `CreateDirectory` is
  // single-level: with the parent missing, workerd fails the boot with
  //
  //   kj/filesystem-disk-win32.c++:773: failed: CreateDirectory: #5 Access is denied.;
  //   path = cbhr-device-relay-DeviceRelay
  //
  // which reads like a permissions problem and is really a missing-parent problem. Reproduced with a
  // trivial worker that has nothing to do with this repository, so it is the runtime's behaviour and
  // not the relay's: on this host the very first service workerd brings up (the built-in cache
  // worker's `miniflare-CacheObject`) hits it. Creating the two directories miniflare expects makes
  // the relay boot; the `w9-*` probes left in the relay's `.relay-state` show the same layout.
  for (const directory of [
    path.join(persistDir, 'do', `${WORKER}-${CLASS}`),
    path.join(persistDir, 'cache', 'miniflare-CacheObject'),
  ]) {
    fs.mkdirSync(directory, { recursive: true });
    // ...and the one file workerd puts in each: an EMPTY `metadata.sqlite` is a valid empty database
    // for SQLite, so giving it the file means it only has to open and initialise it. Without this the
    // boot advances past the directory error and dies on `SQLITE_CANTOPEN: unable to open database
    // file`, which is the same missing-thing problem one level down. (The `w9-*` probe storage in the
    // relay's `.relay-state` shows exactly this layout: one directory and one 8 KiB `metadata.sqlite`
    // per resource.)
    const database = path.join(directory, 'metadata.sqlite');
    if (!fs.existsSync(database)) {
      fs.writeFileSync(database, Buffer.alloc(0));
    }
    // SQLite in WAL mode also needs its sidecar files to EXIST for the same reason; an empty file is
    // what it would have created itself.
    for (const sidecar of ['metadata.sqlite-wal', 'metadata.sqlite-shm']) {
      const file = path.join(directory, sidecar);
      if (!fs.existsSync(file)) {
        fs.writeFileSync(file, Buffer.alloc(0));
      }
    }
  }
  /**
   * BOOT FROM THE RELAY ROOT — THE ONE THING THIS HARNESS CANNOT OMIT.
   *
   * Booting this artifact from any other working directory fails at startup with a MISLEADING error:
   *
   *   A DurableObjectNamespace in the config referenced the class "DeviceRelay", but no such Durable
   *   Object class is exported from the worker.
   *
   * The artifact does export it (verified). The real failure is an internal workerd error raised while
   * the module service initialises, and Miniflare's option converter and worker bootstrap resolve
   * relative to the process CWD. `tests/device/e2e/relay.cjs` already documented and solved this:
   * enter the relay root for the boot, restore the directory afterwards.
   *
   * Worse than a wrong error, it is a SILENT one: Miniflare's `ready` still resolves, so a harness
   * without this hangs waiting for a socket that a dead Durable Object will never accept. That is
   * exactly how this test hung for thirteen minutes with one second of CPU while listing every test
   * body as if it were progressing.
   */
  const previousCwd = process.cwd();
  process.chdir(root);
  let mf;
  try {
    mf = new miniflare.Miniflare(
      miniflare.convertV4MiniflareOptions({
        workers: [
          {
            name: WORKER,
            modules: true,
            scriptPath: path.join(root, 'dist', 'worker.js'),
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
    await mf.ready;
  } finally {
    process.chdir(previousCwd);
  }
  const base = (await mf.ready).toString();

  const call = async (pathname, init) => {
    const response = await fetch(new URL(pathname, base), init);
    const text = await response.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: response.status, body };
  };
  const post = (pathname, payload) =>
    call(pathname, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload ?? {}),
    });

  const deviceRoute = (deviceId, pathname) => `/d/${encodeURIComponent(deviceId)}${pathname}`;

  /**
   * BOOT GUARD — PROVE THE DURABLE OBJECT IS ACTUALLY ALIVE, NOT JUST THAT MINIFLARE IS READY.
   *
   * `mf.ready` resolving is NOT evidence that the Durable Object class bound. When the class fails to
   * initialise, Miniflare still comes up and the ingress still answers; only a request that reaches
   * the object fails. So a harness that trusts `ready` will hang on the first socket that never
   * connects, which is precisely what happened here.
   *
   * This probe touches the object once. If it does not answer, the harness throws NAMING the cause
   * rather than letting a test wait forever — a fixture that cannot detect that its subject never
   * started proves nothing, no matter how many assertions it contains.
   */
  const probeDeviceId = 'harness-boot-probe';
  try {
    const probe = await call(deviceRoute(probeDeviceId, '/state'));
    if (!probe || typeof probe.status !== 'number') {
      throw new Error('the device route returned no HTTP status');
    }
  } catch (error) {
    await mf?.dispose?.().catch(() => {});
    throw new Error(
      `the relay booted but its Durable Object did not answer (probe ${deviceRoute(
        probeDeviceId,
        '/state',
      )}): ${error && error.message ? error.message : String(error)}. ` +
        'The usual cause is booting the artifact from the wrong working directory, which surfaces as a ' +
        'misleading "no such Durable Object class is exported from the worker" while the real failure ' +
        'is an internal workerd error during module-service initialisation.',
    );
  }

  const harness = {
    base,
    relayRoot: root,
    miniflareEntry,
    persistDir,
    tempRoot,
    scratchDir,
    wrangler,
    scriptPath: path.join(root, 'dist', 'worker.js'),
    call,
    post,
    url: (pathname) => new URL(pathname, base).toString(),
    deviceRoute,
    async health() {
      return call('/health');
    },
    /** Arms an active grant for one device, so the relay will admit frames for it. */
    async grant(deviceId, { epoch = 1, expiresAt = Date.now() + 300000, status = 'active' } = {}) {
      return post(deviceRoute(deviceId, '/grant'), { epoch, status, expiresAt, arm: false });
    },
    /** Dispatches one opaque command payload for a device, declaring the call it belongs to. */
    async dispatch(deviceId, { payload, callId, epoch = 1 }) {
      return post(deviceRoute(deviceId, '/frame'), { epoch, payload, callId });
    },
    async pendingResults(deviceId) {
      return call(deviceRoute(deviceId, '/results/pending'));
    },
    async ackResults(deviceId, resultSeqs) {
      return post(deviceRoute(deviceId, '/results/ack'), { resultSeqs });
    },
    async release(deviceId, callId) {
      return post(deviceRoute(deviceId, '/results/release'), { callId });
    },
    async state(deviceId) {
      return call(deviceRoute(deviceId, '/state'));
    },
    async connect(deviceId, tag) {
      return DeviceSocket.connect(base, deviceId, tag);
    },
    async stop() {
      await mf.dispose();
      // Nothing this suite created is left behind: the scratch tree is this run's, and only this
      // run's. `CBHR_W13_KEEP_SCRATCH=1` keeps it when a boot failure needs looking at.
      if (process.env.CBHR_W13_KEEP_SCRATCH !== '1' && options.scratchDir === undefined) {
        try {
          fs.rmSync(scratchDir, { recursive: true, force: true, maxRetries: 3 });
        } catch {
          // A locked SQLite file is not a test failure.
        }
      }
    },
  };
  return harness;
}

/**
 * A real WebSocket client, using the Node built-in — the same client the runtime uses. Deliberately
 * NOT a mock: the whole point of this suite is that a real socket carries real frames.
 */
class DeviceSocket {
  constructor(ws) {
    this.ws = ws;
    this.messages = [];
    this.closed = null;
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

  static async connect(base, deviceId, tag, query = '') {
    const url = new URL(`/d/${encodeURIComponent(deviceId)}/ws?tag=${encodeURIComponent(tag)}${query}`, base);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`device socket open timeout: ${url}`)), 8000);
      ws.addEventListener('open', () => {
        clearTimeout(timer);
        resolve();
      });
      ws.addEventListener('error', () => {
        clearTimeout(timer);
        reject(new Error(`device socket error: ${url}`));
      });
      ws.addEventListener('close', () => {
        clearTimeout(timer);
        reject(new Error(`device socket closed before it opened: ${url}`));
      });
    });
    return new DeviceSocket(ws);
  }

  send(value) {
    this.ws.send(typeof value === 'string' ? value : JSON.stringify(value));
  }

  of(type) {
    return this.messages.filter((message) => message && message.t === type);
  }

  async waitFor(type, count = 1, timeout = 8000) {
    return waitFor(() => (this.of(type).length >= count ? this.of(type) : null), { timeout });
  }

  close() {
    try {
      this.ws.close(1000, 'test-over');
    } catch {
      // already closed
    }
  }
}

module.exports = {
  DEFAULT_RELAY_ROOT,
  WORKER,
  CLASS,
  AGENT_DIR,
  DEFAULT_SCRATCH_ROOT,
  ORIGINAL_TEMP_DIR,
  childEnvironment,
  relayRoot,
  assertRelayAvailable,
  startRelay,
  DeviceSocket,
  waitFor,
  sleep,
};
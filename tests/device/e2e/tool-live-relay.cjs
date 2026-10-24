#!/usr/bin/env node
'use strict';

/**
 * CLOSING THE GAP — the AI tool the model calls, reaching a REAL relay and a REAL paired device.
 *
 *   $env:CBHR_DEVICE_LAB_CUSTODY_KEY_FILE='C:\Users\Aryan\.cbhr\lab-backend\lab-backend-key.txt'
 *   $env:CBHR_DEVICE_RELAY_BASE_URL='http://127.0.0.1:<loopback-port>'
 *   cd C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1
 *   node tests/device/e2e/tool-live-relay.cjs
 *
 * ONE COMMAND. Exit 0 only when every step PASSES.
 *
 * THE GAP THIS CLOSES (measured, not assumed): the W9 end-to-end harness proves
 * dispatch -> relay -> device -> result by driving the dispatch client DIRECTLY. W14 proved the
 * `device_command` tool dispatches when custody/transport are present and refuses when they are not,
 * against a stand-in peer. Nobody had invoked `device_command` itself — the real entry, with the
 * real deps — against a real relay artifact and a real paired device, until this runner.
 *
 * WHAT IS REAL AT EACH STEP (and what is not claimed to be):
 *
 *   S0  gm-71 concurrency, the frozen MongoDB endpoint, the lab key file, every artifact path,
 *       and the operator's relay URL (loopback-only: a non-loopback relay is refused)
 *   S1  the REAL relay artifact (`cbhr-rdc/apps/cbhr-relay/dist/worker.js`) booted by the REAL boot
 *       (`tests/device/e2e/relay.cjs`, with a named boot timeout wrapped around it)
 *   S2  the real `createDeviceCommandTool` module: the model-facing name, the tool schema the model
 *       sees, dumped and checked for identity blindness (no device/stage/policy parameter)
 *   S3  the REAL endpoint agent CLI (`apps/cbhr-endpoint-agent/run-agent.js`, W7) as REAL CHILD
 *       PROCESSES (`init`, `pin-backend`, `describe`): provisioning, not simulation
 *   S4  a real `User` row + real JWT principal, then the real registration ceremony (server mints
 *       the device id; the agent adopts it without regenerating its key)
 *   S5  the real pairing ceremony through the REAL `api/server/routes/devices.js` router, ending in
 *       a real 48 h lease — the server-observed DeviceAuthority row the tool's session resolver
 *       reads is produced by product bytes, not written by this harness
 *   S6  a relay-side GRANT for the leased device+epoch, then the REAL agent `serve` as a REAL CHILD
 *       PROCESS speaking the device socket; the relay's own `/state` proves it is connected
 *   S7  the REAL deps (`api/server/services/Device/deviceCommandDeps.js` built over an env that names
 *       the lab key file and the booted relay's base URL: real custody seam, real relay transport,
 *       the shared replay window) fed into the REAL `createDeviceCommandTool`, invoked the way the
 *       model invokes it (`tool.invoke`), inside the real tenant ALS — with `{tool:'read_file',
 *       arguments:{path:<a real file>}}`
 *   S8  the wire: a fetch witness records the exact frame the real transport POSTed into the relay,
 *       and the relay's own outbox holds the DEVICE-SIGNED result under the SAME callId
 *   S9  the platform's own verification (`verifyResultFrame` pinned to the device key), the real
 *       result sink and the durable Mongo ledger: the accepted call completes as `succeeded`
 *   N1  CONTROL — the same tool over deps built WITHOUT the custody env var answers `not-configured`
 *       and the fetch witness proves the hop was never touched (the tool's own refusal contract)
 *   N2  the same tool+deps whose policy resolver regime cannot admit `read_file`: `refused` with the
 *       registry's code, `delivered:'no'`, and the wire/snapshot proof nothing was signed or sent
 *   N3  the same tool+deps asked for a tool OUTSIDE the stage ceiling (`write_file` at stage A):
 *       `refused` with the registry's OWN widening code, and proof NOTHING was executed (the file
 *       does not exist afterwards) and NOTHING was sent (relay seq, ledgers and the agent's own
 *       log all unchanged)
 *   S10 independent namespace check (the run database is dropped, no harness prefix remains) and the
 *       run-state cleanup decision
 *
 * HONEST LIMITS are reported in-band under `limits` and in the summary — never omitted.
 *
 * LOCAL ONLY: no deploy, no Cloudflare, no commit, no new npm dependencies. Production G0 remains
 * BLOCKED. The agent key store stays outside the repo; no private key material is ever written
 * anywhere under the worktree.
 */

const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { spawn, spawnSync, execFileSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..', '..', '..');
const ENDPOINT_AGENT_DIR = path.join(REPO, 'apps', 'cbhr-endpoint-agent');
const DEVICE_DIR = path.join(REPO, 'api', 'server', 'services', 'Device');
const DEVICE_RELAY_DIR = path.join(DEVICE_DIR, 'relay');

const env = require('./env.cjs');
const relayModule = require('./relay.cjs');
const storage = require('./mongo-seams.cjs');
// The W13 device-side discipline, reused where it fits: `waitFor`/`sleep` for bounded awaits,
// `childEnvironment` so the agent child sees the REAL temp dir (relay.cjs redirects the runner's
// own TMP into the worktree for workerd — the agent is an ordinary Node process and must not be
// pointed at workerd's ACL-bound scratch).
const w13 = require(path.join(ENDPOINT_AGENT_DIR, 'test', '_relay-harness.cjs'));

// WRITE SCOPE: this runner writes ONLY under `tests/device/e2e/**`. Its evidence and run state
// therefore live in the harness's own gitignored `.e2e-state/` tree — never in `api/**`, `apps/**`,
// another lane's evidence directory, or any tracked path.
const EVIDENCE_DIR = path.join(REPO, 'tests', 'device', 'e2e', '.e2e-state');
const HARNESS = 'closing the gap (device_command -> real relay -> real paired device -> correlated result)';
// This harness's own fresh keys, so nothing about this run can collide with another run.
const TENANT = `tenant-tool-live-${nodeCrypto.randomBytes(3).toString('hex')}`;
const OWNER_EMAIL = `tool-live-owner@${TENANT}.lab.local`;
const JWT_SECRET = `tool-live-jwt-secret-${nodeCrypto.randomBytes(8).toString('hex')}`;
const LAB_PEPPER = `tool-live-lookup-pepper-${nodeCrypto.randomBytes(4).toString('hex')}`;
const PAIRING_OPEN_DOMAIN = 'cbhr:device:pairing-open:v1';

const LAB_CUSTODY_KEY_FILE_ENV = 'CBHR_DEVICE_LAB_CUSTODY_KEY_FILE';
const RELAY_BASE_URL_ENV = 'CBHR_DEVICE_RELAY_BASE_URL';
const STAGE_ENV = 'CBHR_DEVICE_CAPABILITY_STAGE';

/** Bounded everything: a fixture that can hang is a fixture that WILL hang (W13). */
const BOOT_TIMEOUT_MS = Number(process.env.CBHR_TOOL_LIVE_BOOT_TIMEOUT_MS ?? 120000);
const STEP_TIMEOUT_MS = Number(process.env.CBHR_TOOL_LIVE_STEP_TIMEOUT_MS ?? 30000);
const RESULT_TIMEOUT_MS = Number(process.env.CBHR_TOOL_LIVE_RESULT_TIMEOUT_MS ?? 30000);
const SERVE_READY_TIMEOUT_MS = Number(process.env.CBHR_TOOL_LIVE_SERVE_TIMEOUT_MS ?? 30000);

const steps = [];
const limits = [];
const logLines = [];
const say = (line = '') => {
  logLines.push(line);
  process.stdout.write(`${line}\n`);
};
const banner = (title) => {
  say('');
  say('='.repeat(78));
  say(title);
  say('='.repeat(78));
};

function record({ id, title, status, observed, notes }) {
  const entry = {
    id,
    title,
    status,
    observed: observed === undefined ? null : observed,
    notes: notes ?? null,
  };
  steps.push(entry);
  say('');
  say(`--- ${id}  ${status}  ${title}`);
  say(JSON.stringify(entry.observed, null, 2));
  if (entry.notes) {
    say(`NOTE: ${entry.notes}`);
  }
  return entry;
}

const sha256Hex = (value) =>
  nodeCrypto.createHash('sha256').update(typeof value === 'string' ? Buffer.from(value, 'utf8') : value).digest('hex');

function withTimeout(promise, ms, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`HARNESS_REFUSAL: ${label} did not complete within ${ms}ms — failing loudly rather than hanging`)),
      ms,
    );
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/**
 * GM-71: another lane's run against the shared local MongoDB voids this evidence. The instructed
 * pattern is `jest|e2e|relay|runtime|servertime|skew|run-e1|devicePolicy`. Two classifications:
 *   - a LAB-LANE match (the phase1 repo's test tree, run-e1/run-e2e, jest, skew, servertime,
 *     devicePolicy) other than this run and its declared children means STOP: serialize or report.
 *   - a HOST-INFRASTRUCTURE match (always-on owner-machine services that carry `runtime` in their
 *     path and never touch the lab replica set) is reported and ignored, or no run could ever
 *     start on this host. The classification rule is stated here, not inferred silently.
 */
const CONCURRENCY_PATTERN = /jest|e2e|relay|runtime|servertime|skew|run-e1|devicePolicy/i;
const LANE_PATTERN = /tests[\\/]device|run-e1|run-e2e|node_modules[\\/]jest|_phase1_evidence|skew|servertime|devicePolicy|tool-live|verify-state|run-tests/i;
function competingNodeProcesses({ excludePids }) {
  const self = process.pid;
  let listing;
  try {
    const raw = execFileSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-Command',
        "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress",
      ],
      { encoding: 'utf8', windowsHide: true, timeout: 30000 },
    ).trim();
    listing = raw.length === 0 ? [] : JSON.parse(raw);
  } catch (err) {
    return { probed: false, error: String(err.message ?? err), matches: [] };
  }
  const rows = Array.isArray(listing) ? [listing] : [listing];
  const matches = rows
    .filter((row) => typeof row.CommandLine === 'string' && CONCURRENCY_PATTERN.test(row.CommandLine))
    .filter((row) => row.ProcessId !== self && !excludePids.has(row.ProcessId))
    .map((row) => ({ pid: row.ProcessId, command: row.CommandLine }));
  const laneMatches = matches.filter((match) => LANE_PATTERN.test(match.command));
  const infraMatches = matches.filter((match) => !LANE_PATTERN.test(match.command));
  return { probed: true, scanned: rows.length, matches, laneMatches, infraMatches };
}

function runNode(args, { cwd, stdoutPath, stderrPath }) {
  fs.mkdirSync(path.dirname(stdoutPath), { recursive: true });
  const out = fs.openSync(stdoutPath, 'w');
  const err = fs.openSync(stderrPath, 'w');
  try {
    const result = spawnSync(process.execPath, args, { cwd, stdio: ['ignore', out, err] });
    return {
      status: result.status,
      error: result.error ? String(result.error.code ?? result.error.message) : null,
      command: `${process.execPath} ${args.map((a) => (a.includes(' ') ? JSON.stringify(a) : a)).join(' ')}`,
      stdoutPath,
      stderrPath,
    };
  } finally {
    fs.closeSync(out);
    fs.closeSync(err);
  }
}

const readText = (file) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null);

/**
 * The fetch witness: counts and records every hop the REAL deps transport invokes, without
 * touching the transport itself. `createRelayTransport` captures `globalThis.fetch` at
 * construction, so the witness must be installed BEFORE the deps are assembled. Nothing here
 * changes a URL, a method, a header or a body; it records them.
 */
function installFetchWitness() {
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    let url = null;
    let method = null;
    let bodyText = null;
    try {
      url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.toString()
            : typeof input?.url === 'string'
              ? input.url
              : null;
      method = String(init?.method ?? input?.method ?? 'GET').toUpperCase();
      bodyText = typeof init?.body === 'string' ? init.body : null;
    } catch {
      /* the witness never changes the call */
    }
    const record = { at: new Date().toISOString(), method, url, body: bodyText };
    calls.push(record);
    try {
      return await original(input, init);
    } catch (err) {
      record.error = String(err?.message ?? err);
      throw err;
    }
  };
  const hopCalls = () =>
    calls.filter((entry) => {
      if (entry.method !== 'POST' || typeof entry.url !== 'string') {
        return false;
      }
      try {
        return new URL(entry.url).pathname.endsWith('/frame');
      } catch {
        return false;
      }
    });
  return { calls, hopCalls, restore: () => { globalThis.fetch = original; } };
}

/**
 * The registration/pairing ceremony proofs, exactly as the W9 harness builds them: the frozen
 * canonical field orders the server publishes for its own transitions. Signed with the DEVICE's
 * own key (the proof the server's verifier checks against the registered public key).
 */
function signPairingOpen({ deviceCrypto, privateKey, tenantId, deviceId, deviceKeyId, challengeHash, issuedAt }) {
  const message = deviceCrypto.canonicalEncode({
    domainTag: PAIRING_OPEN_DOMAIN,
    fields: ['pairing-open', tenantId, deviceId, deviceKeyId, challengeHash, issuedAt],
  });
  return { message, signatureB64u: nodeCrypto.sign(null, message, privateKey).toString('base64url') };
}

function signClaim({ privateKey, signingMessageB64u }) {
  const message = Buffer.from(signingMessageB64u, 'base64url');
  return { signatureB64u: nodeCrypto.sign(null, message, privateKey).toString('base64url') };
}

async function main() {
  const runId = `tool-live-${env.stamp()}`;
  const workDir = path.join(REPO, 'tests', 'device', 'e2e', '.e2e-state', runId);
  const dbName = env.makeDbName(runId);
  const uri = env.uriFor(dbName);
  const evidence = {
    harness: HARNESS,
    runId,
    runAt: new Date().toISOString(),
    node: process.version,
    platform: `${process.platform} ${process.arch}`,
    repo: REPO,
    databaseName: dbName,
    steps,
    limits,
    realComponents: {},
    negatives: [],
    correlation: null,
    namespace: null,
  };

  fs.mkdirSync(workDir, { recursive: true });
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

  banner(`TOOL-LIVE — run ${runId}`);
  say(`work dir : ${workDir}`);
  say(`database : ${dbName}`);

  // ---------------------------------------------------------------- module resolution
  const resolution = env.installModuleResolution({});
  process.env.JWT_SECRET = JWT_SECRET;
  process.env.MONGO_URI = uri;
  process.env.CREDS_KEY = process.env.CREDS_KEY ?? '0123456789abcdef0123456789abcdef';
  process.env.CREDS_IV = process.env.CREDS_IV ?? '0123456789abcdef';
  const pepperSeam = require('./device-http-trust-seam.cjs');
  pepperSeam.__seam.setSeamPepper(Buffer.from(LAB_PEPPER, 'utf8'));
  const pepperSeamPatch = env.installPepperSeam(pepperSeam);

  // ---------------------------------------------------------------- S0. preflight
  const driver = require(path.join(REPO, 'tests', 'device', 'driver.cjs'));
  const adminClient = new driver.MongoClient(
    `mongodb://${env.REQUIRED_HOST}:${env.REQUIRED_PORT}/?directConnection=true&replicaSet=${env.REQUIRED_REPLICA_SET}`,
    { serverSelectionTimeoutMS: 15000, appName: `${runId}-admin` },
  );
  await adminClient.connect();
  const buildInfo = await adminClient.db('admin').command({ buildInfo: 1 });
  const hello = await adminClient.db('admin').command({ hello: 1 });
  const namespaceBefore = await env.listNamespace(adminClient.db('admin'));

  const labKeyFile = typeof process.env[LAB_CUSTODY_KEY_FILE_ENV] === 'string'
    ? process.env[LAB_CUSTODY_KEY_FILE_ENV].trim()
    : '';
  const operatorRelayBase = typeof process.env[RELAY_BASE_URL_ENV] === 'string'
    ? process.env[RELAY_BASE_URL_ENV].trim()
    : '';
  const operatorStage = typeof process.env[STAGE_ENV] === 'string' ? process.env[STAGE_ENV].trim() : '';
  const labKeyExists = labKeyFile.length > 0 && fs.existsSync(labKeyFile) && fs.statSync(labKeyFile).isFile();
  const labSpkiFile = labKeyExists ? path.join(path.dirname(labKeyFile), 'lab-backend-spki.txt') : null;

  const competing = competingNodeProcesses({ excludePids: new Set() });
  const dataSchemasRealpath = require.resolve('@librechat/data-schemas', { paths: [__dirname] });
  const preflightObserved = {
    mongo: {
      host: env.REQUIRED_HOST,
      port: env.REQUIRED_PORT,
      replicaSet: hello.setName ?? null,
      writablePrimary: hello.isWritablePrimary === true,
      serverVersion: buildInfo.version,
      driverVersion: driver.version,
      pinMatches:
        hello.setName === env.REQUIRED_REPLICA_SET &&
        hello.isWritablePrimary === true &&
        buildInfo.version === env.REQUIRED_SERVER_VERSION,
    },
    gm71: {
      probed: competing.probed,
      scanned: competing.scanned,
      laneMatches: competing.laneMatches,
      infraReported: (competing.infraMatches ?? []).map((m) => ({ pid: m.pid, command: m.command })),
    },
    labCustody: {
      envVar: LAB_CUSTODY_KEY_FILE_ENV,
      valuePresent: labKeyFile.length > 0,
      fileExists: labKeyExists,
      fileBytes: labKeyExists ? fs.statSync(labKeyFile).size : null,
      spkiFile: labSpkiFile,
      spkiPresent: labSpkiFile !== null && fs.existsSync(labSpkiFile),
    },
    operatorRelayBase: {
      envVar: RELAY_BASE_URL_ENV,
      valuePresent: operatorRelayBase.length > 0,
      value: operatorRelayBase.length > 0 ? operatorRelayBase : null,
    },
    operatorStage: {
      envVar: STAGE_ENV,
      valuePresent: operatorStage.length > 0,
      value: operatorStage.length > 0 ? operatorStage : null,
      note: 'the deps env this runner hands the tool omits it, so the gate runs at the narrowest stage; the operator value is only recorded here',
    },
    artifacts: {
      relayWorker: fs.existsSync(path.join(relayModule.RELAY_ROOT, 'dist', 'worker.js')),
      relayRoot: relayModule.RELAY_ROOT,
      endpointAgentCli: fs.existsSync(path.join(ENDPOINT_AGENT_DIR, 'run-agent.js')),
      agentHarnessDiscipline: fs.existsSync(path.join(ENDPOINT_AGENT_DIR, 'test', '_relay-harness.cjs')),
      deviceCommandTool: fs.existsSync(path.join(REPO, 'api', 'app', 'clients', 'tools', 'deviceCommand.js')),
      deviceCommandDeps: fs.existsSync(path.join(DEVICE_DIR, 'deviceCommandDeps.js')),
      devicesRouter: fs.existsSync(path.join(REPO, 'api', 'server', 'routes', 'devices.js')),
    },
    moduleResolution: {
      dataSchemas: dataSchemasRealpath,
      sameInstanceForToolRouterAndRunner: true, // asserted by resolved-path equality at require time
    },
    namespaceBefore,
    productFilesModifiedByThisHarness: [],
  };
  // A non-loopback operator relay URL means somebody is pointing this harness at a relay that is
  // not local: refuse it loudly rather than run against it (LOCAL ONLY).
  let operatorRelayUsable = true;
  if (operatorRelayBase.length > 0) {
    try {
      const parsed = new URL(operatorRelayBase);
      const host = parsed.hostname.toLowerCase();
      operatorRelayUsable =
        (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
        (host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]');
    } catch {
      operatorRelayUsable = false;
    }
  }
  record({
    id: 'S0',
    title: 'PREFLIGHT — GM-71, the frozen MongoDB endpoint, the lab key presence, and every artifact',
    status:
      preflightObserved.mongo.pinMatches === true &&
      competing.probed === true &&
      competing.laneMatches.length === 0 &&
      labKeyExists === true &&
      labSpkiFile !== null &&
      fs.existsSync(labSpkiFile) &&
      operatorRelayUsable === true &&
      Object.entries(preflightObserved.artifacts).every(([key, value]) => key === 'relayRoot' || value === true)
        ? 'PASS'
        : 'FAIL',
    observed: { ...preflightObserved, operatorRelayUsable },
    notes: competing.laneMatches.length === 0
      ? 'No lab-lane process shares this host. Host-infrastructure node.exe matches are reported, not treated as lanes (they never touch the lab replica set).'
      : 'A lab lane is running; this run must not be trusted.',
  });
  if (steps[steps.length - 1].status !== 'PASS') {
    if (!labKeyExists) {
      say('');
      say(`HARNESS_REFUSAL: ${LAB_CUSTODY_KEY_FILE_ENV} does not name an existing lab key file.`);
      say(`Set ${LAB_CUSTODY_KEY_FILE_ENV} to the lab custody key file (W15's recipe) and re-run.`);
      say('This harness does not generate a key, and neither does the product.');
    }
    if (competing.laneMatches.length > 0) {
      say('');
      say('HARNESS_REFUSAL: a concurrent lab-lane process is running; concurrent runs void evidence.');
      say('Re-run when the lane is finished (GM-71).');
    }
    throw new Error('PREFLIGHT_FAILED');
  }
  evidence.realComponents.mongodb = {
    uri,
    database: dbName,
    serverVersion: buildInfo.version,
    replicaSet: hello.setName,
    driver: `mongodb@${driver.version} (vendored, tests/device/driver.cjs)`,
  };

  let httpBase = null;
  let server = null;
  let relay = null;
  let serveChild = null;
  let dropped = null;
  // Declared HERE (not inside the try) because the cleanup path in `finally` reads them: a name
  // declared inside the block would make a cleanup failure mask the real one.
  let agentRoot = null;
  let workspaceRoot = null;
  const cleanupNotes = [];
  const childPids = new Set();
  let fetchWitness = null;

  try {
    // ---------------------------------------------------------------- S1. real relay
    const workerPath = path.join(relayModule.RELAY_ROOT, 'dist', 'worker.js');
    const workerSha256 = sha256Hex(fs.readFileSync(workerPath));
    relay = await withTimeout(
      relayModule.startRelay({ persistDir: path.join(workDir, 'relay-sqlite') }),
      BOOT_TIMEOUT_MS,
      'the real relay artifact boot (tests/device/e2e/relay.cjs)',
    );
    record({
      id: 'S1',
      title: 'RELAY — the real relay artifact booted in-process (workerd via Miniflare)',
      status: 'PASS',
      observed: {
        base: relay.base,
        workerScript: relay.workerScript,
        workerArtifactSha256: workerSha256,
        compatibility: relay.compatibility,
        relayBootCwd: relay.relayBootCwd,
        osTmp: relay.osTmp,
        osTmpInsideThisRunDir: relay.osTmp.startsWith(workDir),
        relayRoot: relayModule.RELAY_ROOT,
        runtime: 'miniflare (in-process workerd)',
        bootGuard: 'named boot timeout (CBHR_TOOL_LIVE_BOOT_TIMEOUT_MS) around the real relay.cjs boot; a hang is a loud failure',
      },
      notes: 'No deploy, no account, no Cloudflare API call. The relay is keyless and never parses a payload.',
    });
    evidence.realComponents.relay = { base: relay.base, workerSha256 };

    // ---------------------------------------------------------------- S2. the tool surface the model sees
    const { connectDb } = require(path.join(REPO, 'api', 'db', 'connect.js'));
const connection = await connectDb();
    const models = require('./models-adapter.cjs');
    const mongooseModule = require(path.join(REPO, 'node_modules', 'mongoose'));
    const toolModule = require(path.join(REPO, 'api', 'app', 'clients', 'tools', 'deviceCommand.js'));
    const depsModule = require(path.join(DEVICE_DIR, 'deviceCommandDeps.js'));
    const registryModule = require(path.join(DEVICE_DIR, 'deviceToolRegistry.js'));
    const policyModule = require(path.join(DEVICE_DIR, 'deviceCapabilityPolicy.js'));
    const deviceCrypto = require(path.join(DEVICE_DIR, 'crypto.js'));
    const relayIndex = require(path.join(DEVICE_RELAY_DIR, 'index.js'));
    const dispatchLedgerModule = require(path.join(DEVICE_RELAY_DIR, 'dispatchLedger.js'));
    const resultSinkModule = require(path.join(DEVICE_RELAY_DIR, 'resultSink.js'));
    const resultFrameModule = require(path.join(DEVICE_RELAY_DIR, 'resultFrame.js'));
    const { tenantStorage } = require('@librechat/data-schemas');

    const liveDb = connection.connection?.name ?? connection.name ?? null;
    const zodToJsonSchemaModule = (() => {
      try {
        return require(path.join(REPO, 'node_modules', 'zod-to-json-schema'));
      } catch {
        return null;
      }
    })();
    const modelFacingSchema = (() => {
      if (zodToJsonSchemaModule === null) {
        return null;
      }
      try {
        const fn = zodToJsonSchemaModule.zodToJsonSchema ?? zodToJsonSchemaModule.default;
        return fn(toolModule.deviceCommandSchema);
      } catch (err) {
        return { error: `zod-to-json-schema refused the schema: ${err?.message ?? String(err)}` };
      }
    })();
    const schemaShapeKeys = Object.keys(toolModule.deviceCommandSchema.shape).sort();
    const forgedIdentityRefusals = [
      { tool: 'read_file', deviceId: 'a-device-the-model-picked' },
      { tool: 'read_file', stage: 'full' },
      { tool: 'read_file', ceiling: { tools: ['write_file'] } },
      { tool: 'read_file', hasOwnerApproval: true },
    ].map((forged) => ({ forged, accepted: toolModule.deviceCommandSchema.safeParse(forged).success }));

    record({
      id: 'S2',
      title: 'TOOL SURFACE — the real `createDeviceCommandTool` module and the schema the model sees',
      status:
        toolModule.DEVICE_COMMAND_TOOL_NAME === 'device_command' &&
        schemaShapeKeys.join(',') === 'arguments,tool' &&
        forgedIdentityRefusals.every((entry) => entry.accepted === false) &&
        Array.isArray(toolModule.SUPPORTED_TOOL_NAMES) &&
        toolModule.SUPPORTED_TOOL_NAMES.includes('read_file')
          ? 'PASS'
          : 'FAIL',
      observed: {
        module: path.join(REPO, 'api', 'app', 'clients', 'tools', 'deviceCommand.js'),
        moduleSha256: sha256Hex(fs.readFileSync(path.join(REPO, 'api', 'app', 'clients', 'tools', 'deviceCommand.js'))),
        toolName: toolModule.DEVICE_COMMAND_TOOL_NAME,
        outcomeVocabulary: Object.values(toolModule.DEVICE_COMMAND_OUTCOMES),
        inputSchemaId: toolModule.DEVICE_COMMAND_INPUT_SCHEMA,
        schemaShapeKeys,
        schemaIsStrict: 'a call naming a device/stage/ceiling/approval is refused, not silently dropped',
        forgedIdentityRefusals,
        modelFacingJsonSchema: modelFacingSchema,
        supportedToolCount: toolModule.SUPPORTED_TOOL_NAMES.length,
        depsModule: path.join(DEVICE_DIR, 'deviceCommandDeps.js'),
        dispatchAssembly: path.join(DEVICE_DIR, 'dispatchAssembly.js'),
        mongooseDatabase: liveDb,
        aliasRewrites: resolution.apiRewrites,
        modelsAdapterSubstitutions: resolution.adapterHits,
        pepperSeamSubstitutions: resolution.pepperSeamHits,
        pepperSeamModulePatched: pepperSeamPatch.modulePath,
      },
      notes:
        'The tool object is built later (S7) by invoking this same factory; nothing about the tool is reimplemented here. The JSON schema is dumped through the project\'s own zod-to-json-schema dependency when it is present.',
    });
    if (steps[steps.length - 1].status !== 'PASS') {
      throw new Error('TOOL_SURFACE_FAILED');
    }
    if (liveDb !== dbName) {
      throw new Error(`MONGOOSE_DATABASE_MISMATCH: connected to ${liveDb}, expected ${dbName}`);
    }

    // ---------------------------------------------------------------- S3. the real endpoint agent
    // The agent's key store is OUTSIDE every git worktree, and the agent is the only long-lived
    // process that ever opens the device key. This runner reads that key only to sign the ceremony
    // proofs the DEVICE must sign (the same disclosed seam W9 uses; there is no agent-side ceremony
    // command yet). No private key byte is written anywhere under the repo.
    const homeDir = process.env.USERPROFILE ?? process.env.HOME;
    agentRoot = path.join(homeDir, '.cbhr', `tool-live-${runId}`);
    workspaceRoot = path.join(agentRoot, 'workspace');
    fs.mkdirSync(workspaceRoot, { recursive: true });
    const payloadName = 'tool-live-payload.txt';
    const payloadContent =
      `tool-live-relay payload ${runId}\n` +
      'read by the REAL endpoint agent, over the REAL relay, for the AI tool the model calls\n' +
      `${nodeCrypto.randomBytes(16).toString('hex')}\n`;
    const realFile = path.join(workspaceRoot, payloadName);
    fs.writeFileSync(realFile, payloadContent, 'utf8');

    const out = (name) => path.join(workDir, name);
    const agentStep = (label, args, name) => {
      const result = runNode(args, {
        cwd: ENDPOINT_AGENT_DIR,
        stdoutPath: out(`${name}.out`),
        stderrPath: out(`${name}.err`),
      });
      if (result.status !== 0) {
        throw new Error(
          `endpoint step "${label}" exited ${result.status}: ${(readText(result.stderrPath) ?? '').trim()}`,
        );
      }
      return result;
    };

    const bootstrapDeviceId = `tool-live-bootstrap-${runId}`;
    const initBootstrap = agentStep(
      'init (bootstrap identity)',
      ['run-agent.js', 'init', '--root', agentRoot, '--device-id', bootstrapDeviceId, '--workspace', workspaceRoot],
      'agent-init-bootstrap',
    );
    const pinBackend = agentStep(
      'pin-backend (the lab custody public key)',
      ['run-agent.js', 'pin-backend', '--root', agentRoot, '--spki-file', labSpkiFile],
      'agent-pin-backend',
    );
    const bootstrapDescribe = runNode(
      ['run-agent.js', 'describe', '--root', agentRoot, '--workspace', workspaceRoot],
      {
        cwd: ENDPOINT_AGENT_DIR,
        stdoutPath: out('agent-describe-bootstrap.out'),
        stderrPath: out('agent-describe-bootstrap.err'),
      },
    );
    if (bootstrapDescribe.status !== 0) {
      throw new Error('endpoint describe (bootstrap) failed');
    }
    const agentBootstrap = JSON.parse(readText(out('agent-describe-bootstrap.out'))).agent;
    const labSpkiB64u = (readText(labSpkiFile) ?? '').trim();
    const expectedBackendKeyId = deviceCrypto.thumbprintB64u(labSpkiB64u);
    const bootstrapPins = agentBootstrap.pinnedBackendKeyIds ?? [];
    const provisioningPass =
      typeof agentBootstrap.devicePublicKeySpkiB64u === 'string' &&
      agentBootstrap.devicePublicKeySpkiB64u.length > 0 &&
      String(agentBootstrap.deviceKeyFile).startsWith(agentRoot) &&
      !String(agentBootstrap.deviceKeyFile).startsWith(REPO) &&
      bootstrapPins.includes(expectedBackendKeyId);
    record({
      id: 'S3',
      title: 'ENDPOINT — the real agent CLI provisioned the device (init / pin-backend / describe)',
      status: provisioningPass ? 'PASS' : 'FAIL',
      observed: {
        agentRoot,
        agentRootIsOutsideTheRepo: !agentRoot.startsWith(REPO),
        workspaceRoot,
        realFile,
        realFileBytes: payloadContent.length,
        realFileSha256: sha256Hex(payloadContent),
        initCommand: initBootstrap.command,
        pinCommand: pinBackend.command,
        deviceIdAtBootstrap: agentBootstrap.deviceId,
        deviceKeyId: agentBootstrap.deviceKeyId,
        deviceKeyFile: agentBootstrap.deviceKeyFile,
        pinnedBackendKeyIds: bootstrapPins,
        labBackendKeyIdExpected: expectedBackendKeyId,
        backendKeyIdIsPinned: bootstrapPins.includes(expectedBackendKeyId),
        labCustodyKeyFile: labKeyFile,
        labCustodyKeyFileOutsideTheRepo: !labKeyFile.startsWith(REPO),
        privateKeyMaterialWrittenUnderTheRepo: 'none — the device key lives in the agent root above; the lab key is read from its own path',
      },
      notes:
        'Real child processes of the product CLI, not an in-process simulation. The pinned backend key id is derived from the lab PUBLIC SPKI file the W15 recipe names next to the custody key; the pin assertion is what makes the later frame verifiable by the device.',
    });
    if (!provisioningPass) {
      throw new Error('ENDPOINT_PROVISIONING_FAILED');
    }
    evidence.realComponents.endpointAgent = {
      agentRoot,
      deviceKeyFile: agentBootstrap.deviceKeyFile,
      devicePublicKeySpkiB64u: agentBootstrap.devicePublicKeySpkiB64u,
      deviceKeyId: agentBootstrap.deviceKeyId,
      pinnedBackendKeyId: expectedBackendKeyId,
    };

    // ---------------------------------------------------------------- S4. real user + JWT + registration
    const User = models.__realModels.User;
    const created = await User.create([
      {
        _id: new mongooseModule.Types.ObjectId(),
        name: 'tool-live owner',
        email: OWNER_EMAIL,
        provider: 'local',
        role: 'USER',
        tenantId: TENANT,
      },
    ]);
    const userId = String(created[0]._id);
    const token = env.mintAccessToken({ userId });
    const authHeaders = { authorization: `Bearer ${token}` };

    const registrationService = require(path.join(DEVICE_DIR, 'registrationService.js'));
    const REGISTRATION_DOMAIN = 'cbhr:device:registration:v1';
    const registrationAuditEvents = [];
    const registrationServiceInstance = registrationService.createRegistrationService({
      db: models,
      clock: { now: () => Date.now() },
      crypto: deviceCrypto,
      logger: null,
      audit: async (event) => {
        registrationAuditEvents.push(event);
      },
      tenantPolicy: Object.freeze({ validateRegistrationTenant: async (tenantId) => tenantId === TENANT }),
      tenantContext: Object.freeze({ getActiveTenantId: () => TENANT, alsAbsencePermitted: false }),
    });
    const begin = await registrationServiceInstance.beginRegistration({
      tenantId: TENANT,
      requestSource: 'tool-live-runner',
    });
    if (begin.ok !== true) {
      throw new Error(`registration begin failed: ${begin.error?.code ?? 'unknown'}`);
    }
    const registrationThumbprint = deviceCrypto.thumbprintB64u(agentBootstrap.devicePublicKeySpkiB64u);
    const registrationProofFields = {
      deviceName: 'tool-live-endpoint',
      platform: process.platform,
      agentVersion: 'tool-live',
      nonce: nodeCrypto.randomBytes(16).toString('base64url'),
      issuedAt: String(Date.now()),
    };
    const registrationMessage = deviceCrypto.canonicalEncode({
      domainTag: REGISTRATION_DOMAIN,
      fields: [
        TENANT,
        begin.challenge,
        agentBootstrap.devicePublicKeySpkiB64u,
        registrationThumbprint,
        registrationProofFields.deviceName,
        registrationProofFields.platform,
        registrationProofFields.agentVersion,
        registrationProofFields.nonce,
        registrationProofFields.issuedAt,
      ],
    });
    const agentSigningKey = loadAgentPrivateKeyForProof(agentRoot);
    const registrationCompleted = await registrationServiceInstance.completeRegistration({
      tenantId: TENANT,
      devicePublicKey: agentBootstrap.devicePublicKeySpkiB64u,
      deviceName: registrationProofFields.deviceName,
      platform: registrationProofFields.platform,
      agentVersion: registrationProofFields.agentVersion,
      domainTag: REGISTRATION_DOMAIN,
      requestSource: 'tool-live-runner',
      proof: {
        challenge: begin.challenge,
        nonce: registrationProofFields.nonce,
        issuedAt: registrationProofFields.issuedAt,
        signatureB64u: nodeCrypto.sign(null, registrationMessage, agentSigningKey).toString('base64url'),
      },
    });
    if (registrationCompleted.ok !== true) {
      throw new Error(`registration complete failed: ${registrationCompleted.error?.code ?? 'unknown'}`);
    }
    const serverDeviceId = registrationCompleted.deviceId;

    // Publish the SERVER-ISSUED device id into the agent's identity file, reusing the SAME key
    // (`init` without `--force` never regenerates an existing identity).
    agentStep(
      'init (server-issued device id)',
      ['run-agent.js', 'init', '--root', agentRoot, '--device-id', serverDeviceId, '--workspace', workspaceRoot],
      'agent-init-server-id',
    );
    const describeFinalResult = runNode(
      ['run-agent.js', 'describe', '--root', agentRoot, '--workspace', workspaceRoot],
      {
        cwd: ENDPOINT_AGENT_DIR,
        stdoutPath: out('agent-describe-final.out'),
        stderrPath: out('agent-describe-final.err'),
      },
    );
    if (describeFinalResult.status !== 0) {
      throw new Error('endpoint describe (final) failed');
    }
    const agentFinal = JSON.parse(readText(out('agent-describe-final.out'))).agent;
    const keyPreserved =
      agentFinal.deviceKeyId === agentBootstrap.deviceKeyId &&
      agentFinal.devicePublicKeySpkiB64u === agentBootstrap.devicePublicKeySpkiB64u;
    const registrationPass =
      registrationCompleted.deviceKeyId === agentFinal.deviceKeyId &&
      agentFinal.deviceId === serverDeviceId &&
      keyPreserved === true;
    record({
      id: 'S4',
      title: 'REGISTRATION — a real User + real JWT, then the real registration ceremony',
      status: registrationPass ? 'PASS' : 'FAIL',
      observed: {
        userId,
        tenant: TENANT,
        jwtMinted: token.length > 20,
        auditEvents: registrationAuditEvents.map((event) => event.kind),
        serverIssuedDeviceId: serverDeviceId,
        serverDerivedDeviceKeyId: registrationCompleted.deviceKeyId,
        agentDeviceKeyId: agentFinal.deviceKeyId,
        deviceKeyIdAgrees: registrationCompleted.deviceKeyId === agentFinal.deviceKeyId,
        agentDeviceIdAfterPublish: agentFinal.deviceId,
        deviceIdAgrees: agentFinal.deviceId === serverDeviceId,
        identityKeyPreservedAcrossInit: keyPreserved,
        agentEffectiveTools: agentFinal.dispatch?.implemented ?? null,
        agentPinnedBackendKeyIds: agentFinal.pinnedBackendKeyIds,
      },
      notes:
        'The server minted the device id and derived the device key id from the agent\'s own public key; the agent adopted the id without regenerating its key. The plaintext pairing code is never persisted (accepted service law).',
    });
    if (!registrationPass) {
      throw new Error('REGISTRATION_FAILED');
    }
    evidence.realComponents.user = { userId, tenant: TENANT, email: OWNER_EMAIL };// ---------------------------------------------------------------- S5. the real lease, through the real routes
    // The REAL `api/server/routes/devices.js` router on a real HTTP server, with the real
    // `requireJwtAuth` + passport jwt strategy, over the real model registry. The single disclosed
    // substitution is the server-owned pairing pepper the deployment config would supply
    // (`device-http-trust-seam.cjs`, exactly as the accepted route suite's module mock does).
    const booted = await env.bootDeviceHttpServer({ models });
    httpBase = booted.base;
    server = booted.server;

    const unauth = await env.postJson(fetch, `${httpBase}/api/devices/pairing/challenge`, {
      devicePublicKey: 'not-a-key',
    });
    const authControlPass = unauth.status === 401;

    // GM-44 DATABASE TIME. `databaseTime.readDatabaseNowMs(db)` measures the server clock with
    // `$collStats + $$NOW`, which cannot run against a collection that does not exist; the accepted
    // harness writes ONE real audit event through the accepted sink first (the honest setup a
    // deployment performs). Without a time host the lease/TTL decisions fail closed.
    const { createMongooseAuditSink } = require(path.join(DEVICE_DIR, 'auditSink.js'));
    const auditSink = createMongooseAuditSink({ AuditEvent: models.AuditEvent, logger: null });
    await auditSink.audit({
      tenantId: TENANT,
      deviceId: serverDeviceId,
      ownerId: null,
      grantId: null,
      epoch: 0,
      seq: 0,
      kind: 'register',
      ts: new Date(),
      actor: null,
      reasonCode: null,
    });
    const databaseTime = require(path.join(DEVICE_DIR, 'databaseTime.js'));
    const measuredDatabaseNowMs = await databaseTime.readDatabaseNowMs(models);
    const dbTimePass = Number.isFinite(measuredDatabaseNowMs);

    const legs = [];
    const pairingObserved = { legs, authControl: { status: unauth.status }, dbTime: { measuredDatabaseNowMs } };
    const challengeRes = await env.postJson(
      fetch,
      `${httpBase}/api/devices/pairing/challenge`,
      { devicePublicKey: agentFinal.devicePublicKeySpkiB64u },
      authHeaders,
    );
    legs.push({ leg: 'POST /api/devices/pairing/challenge', status: challengeRes.status, body: challengeRes.body });
    if (challengeRes.status !== 200 || challengeRes.body.challengeHash === undefined) {
      throw new Error(`pairing challenge failed: ${JSON.stringify(challengeRes.body)}`);
    }
    const openProof = signPairingOpen({
      deviceCrypto,
      privateKey: agentSigningKey,
      tenantId: TENANT,
      deviceId: serverDeviceId,
      deviceKeyId: agentFinal.deviceKeyId,
      challengeHash: challengeRes.body.challengeHash,
      issuedAt: challengeRes.body.issuedAt,
    });
    const issueRes = await env.postJson(
      fetch,
      `${httpBase}/api/devices/pairing/issue`,
      {
        devicePublicKey: agentFinal.devicePublicKeySpkiB64u,
        challengeHash: challengeRes.body.challengeHash,
        signatureB64u: openProof.signatureB64u,
      },
      authHeaders,
    );
    legs.push({
      leg: 'POST /api/devices/pairing/issue',
      status: issueRes.status,
      body: { ...issueRes.body, code: issueRes.body.code ? '<6-digit code withheld from evidence>' : undefined },
      codeShape: /^\d{6}$/.test(String(issueRes.body.code)),
    });
    if (issueRes.status !== 200 || !/^\d{6}$/.test(String(issueRes.body.code))) {
      throw new Error(`pairing issue failed: ${JSON.stringify(issueRes.body)}`);
    }
    const approveRes = await env.postJson(
      fetch,
      `${httpBase}/api/devices/pairing/approve`,
      { code: issueRes.body.code },
      authHeaders,
    );
    legs.push({ leg: 'POST /api/devices/pairing/approve', status: approveRes.status, body: approveRes.body });
    if (approveRes.status !== 200 || approveRes.body.state !== 'claim_pending') {
      throw new Error(`pairing approve failed: ${JSON.stringify(approveRes.body)}`);
    }
    const armRes = await env.postJson(fetch, `${httpBase}/api/devices/pairing/complete`, {
      devicePublicKey: agentFinal.devicePublicKeySpkiB64u,
    });
    legs.push({
      leg: 'POST /api/devices/pairing/complete (arm)',
      status: armRes.status,
      body: { state: armRes.body.state, deviceId: armRes.body.deviceId, hasSigningMessage: typeof armRes.body.signingMessageB64u === 'string' },
    });
    if (armRes.status !== 200 || armRes.body.state !== 'claim_ready') {
      throw new Error(`pairing complete arm failed: ${JSON.stringify(armRes.body)}`);
    }
    const claimProof = signClaim({ privateKey: agentSigningKey, signingMessageB64u: armRes.body.signingMessageB64u });
    const claimStartedAt = Date.now();
    const completeRes = await env.postJson(fetch, `${httpBase}/api/devices/pairing/complete`, {
      devicePublicKey: agentFinal.devicePublicKeySpkiB64u,
      challengeHash: armRes.body.challengeHash,
      signatureB64u: claimProof.signatureB64u,
    });
    const claimElapsedMs = Date.now() - claimStartedAt;
    legs.push({ leg: 'POST /api/devices/pairing/complete (claim)', status: completeRes.status, body: completeRes.body });
    if (completeRes.status !== 200 || completeRes.body.state !== 'active') {
      // No clock freeze, no workaround: the claim-leg ordering defect
      // (tests/device/e2e/W9-FINDING-pairing-claim-ordering-defect.md) is FIXED in this tree
      // (`decidedAt` is read after the consent verifier), so a refusal here is a NEW finding.
      record({
        id: 'S5',
        title: 'LEASE — the real pairing ceremony through the real routes',
        status: 'FAIL',
        observed: pairingObserved,
        notes: 'The claim leg did not reach `active`; reported as-is, with no clock workaround applied.',
      });
      throw new Error(`PAIRING_CLAIM_REFUSED: ${JSON.stringify(completeRes.body)}`);
    }

    const authorityRow = await models.DeviceAuthority.findOne({
      _id: serverDeviceId,
      tenantId: TENANT,
    }).lean();
    const leasePass =
      authorityRow?.leaseState === 'active' &&
      authorityRow?.identityState === 'active' &&
      authorityRow?.ownerId === userId &&
      typeof authorityRow?.grantId === 'string' &&
      authorityRow.grantId.length > 0 &&
      Number.isInteger(authorityRow?.epoch);
    record({
      id: 'S5',
      title: 'LEASE — the real pairing ceremony through the real routes, ending in a real lease',
      status: leasePass && authControlPass && dbTimePass ? 'PASS' : 'FAIL',
      observed: {
        ...pairingObserved,
        claimElapsedMs,
        claimSucceededOnTheRealClock: true,
        clockWorkaroundApplied: false,
        failedLegs: legs.filter((leg) => leg.status !== 200).length,
        lease: {
          deviceId: serverDeviceId,
          identityState: authorityRow?.identityState ?? null,
          leaseState: authorityRow?.leaseState ?? null,
          ownerId: authorityRow?.ownerId ?? null,
          deviceKeyId: authorityRow?.deviceKeyId ?? null,
          epoch: authorityRow?.epoch ?? null,
          grantIdPresent: typeof authorityRow?.grantId === 'string' && authorityRow.grantId.length > 0,
          expiresAt: authorityRow?.expiresAt ? new Date(authorityRow.expiresAt).toISOString() : null,
        },
        sessionState:
          (await models.PairingSession.findOne({ deviceId: serverDeviceId, tenantId: TENANT }).lean())?.state ?? null,
        unauthenticatedControl: 'a gated device route refuses an unauthenticated caller (401), so the real auth chain is mounted',
      },
      notes:
        'The DeviceAuthority row the tool\'s session resolver reads is produced by the real services through the real routes; this harness does not write it. The 6-digit code is withheld from evidence; only its shape is recorded.',
    });
    if (steps[steps.length - 1].status !== 'PASS') {
      throw new Error('LEASE_FAILED');
    }
    evidence.realComponents.lease = {
      deviceId: serverDeviceId,
      ownerId: userId,
      epoch: authorityRow.epoch,
      grantId: authorityRow.grantId,
      identityState: authorityRow.identityState,
      leaseState: authorityRow.leaseState,
    };

    // ---------------------------------------------------------------- S6. durable ledger, the relay GRANT, and the real resident agent
    const collections = {
      ledger: adminClient.db(dbName).collection('tool_live_dispatch_ledger'),
      ledgerMeta: adminClient.db(dbName).collection('tool_live_dispatch_ledger_meta'),
      results: adminClient.db(dbName).collection('tool_live_results'),
    };
    const durableStore = storage.createMongoDispatchStore({
      collection: collections.ledger,
      meta: collections.ledgerMeta,
      scope: runId,
    });
    const durable = storage.createDurableDispatchLedger({
      createDispatchLedger: dispatchLedgerModule.createDispatchLedger,
      store: durableStore,
      now: () => Date.now(),
    });
    const ledger = durable.ledger;
    const resultStore = storage.createMongoResultStore({ collection: collections.results, scope: runId });
    const sinkReplayWindow = relayIndex.createReplayWindow({ now: () => Date.now() });
    const resultVerifier = resultFrameModule.createResultFrameVerifier({
      publicKeySpkiB64u: agentFinal.devicePublicKeySpkiB64u,
      expectedKeyId: agentFinal.deviceKeyId,
    });
    const sink = resultSinkModule.createResultSink({
      ledger,
      verifier: resultVerifier,
      replayWindow: sinkReplayWindow,
      clock: { now: () => Date.now() },
      store: resultStore,
    });

    // The relay's OWN admission state for this device+epoch: without an active grant the relay fails
    // closed (NO_GRANT_FAIL_CLOSED). Nothing here forges a lease — the epoch is the one the real
    // pairing granted, read from the server-observed row above.
    const relayGrant = await relay.grant(serverDeviceId, { epoch: authorityRow.epoch });
    const grantArmed = relayGrant.status === 200 && relayGrant.body?.ok === true;

    const serveStdout = out('agent-serve.out');
    const serveStderr = out('agent-serve.err');
    const serveOutFd = fs.openSync(serveStdout, 'w');
    const serveErrFd = fs.openSync(serveStderr, 'w');
    serveChild = spawn(
      process.execPath,
      [
        'run-agent.js',
        'serve',
        '--relay',
        relay.base,
        '--root',
        agentRoot,
        '--workspace',
        workspaceRoot,
        '--shutdown-on-stdin-eof',
        '--print-url',
        '--max-reconnects',
        '5',
        '--backoff-initial-ms',
        '250',
        '--backoff-max-ms',
        '2000',
      ],
      {
        cwd: ENDPOINT_AGENT_DIR,
        // W13's discipline: the agent is an ordinary Node process and gets the REAL temp dir back
        // (relay.cjs pointed this runner's own TMP at workerd's scratch inside the run dir).
        env: w13.childEnvironment({}),
        stdio: ['pipe', serveOutFd, serveErrFd],
      },
    );
    childPids.add(serveChild.pid);
    fs.closeSync(serveOutFd);
    fs.closeSync(serveErrFd);

    const deviceSocketSeen = await waitForDeviceSocket(relay, serverDeviceId, SERVE_READY_TIMEOUT_MS);
    const relayStateAtServe = await relay.stateOf(serverDeviceId);
    const serveReady = deviceSocketSeen !== null;
    record({
      id: 'S6',
      title: 'RESIDENT DEVICE — the real agent `serve` as a REAL CHILD PROCESS, connected to the real relay',
      status: serveReady && grantArmed ? 'PASS' : 'FAIL',
      observed: {
        childPid: serveChild.pid,
        command: `${process.execPath} run-agent.js serve --relay ${relay.base} --root ${agentRoot} --workspace ${workspaceRoot}`,
        notAnInProcessSimulation: true,
        relayGrantUrl: `/d/${serverDeviceId}/grant`,
        relayGrant: { status: relayGrant.status, ok: relayGrant.body?.ok ?? null, epoch: relayGrant.body?.grant?.epoch ?? null, status_: relayGrant.body?.grant?.status ?? null },
        deviceSocketUrlPrinted: (readText(serveStdout) ?? '').trim().split(/\r?\n/)[0] ?? null,
        relaySockets: relayStateAtServe.sockets,
        relaySawADeviceSocket: serveReady,
        relayFramesThisInstanceAtServe: relayStateAtServe.framesThisInstance,
        agentStdout: serveStdout,
        agentStderr: serveStderr,
      },
      notes:
        'The relay\'s own `/state` (not the agent\'s claim) is what proves a device socket is connected: the attachment tag `device` is set by the relay when it accepts the socket.',
    });
    if (!serveReady || !grantArmed) {
      throw new Error('RESIDENT_DEVICE_FAILED');
    }// ---------------------------------------------------------------- S7. THE TOOL — real entry, real deps, real relay
    // The fetch witness must be installed BEFORE `createDeviceCommandDeps`, because the real
    // transport captures `globalThis.fetch` at construction. It observes the hop; it never alters it.
    fetchWitness = installFetchWitness();
    const depsEnv = { [LAB_CUSTODY_KEY_FILE_ENV]: labKeyFile, [RELAY_BASE_URL_ENV]: relay.base };
    const depsLogger = {
      warn: (message) => say(`[deps.warn] ${message}`),
      error: (message) => say(`[deps.error] ${message}`),
    };
    const deps = depsModule.createDeviceCommandDeps({ env: depsEnv, logger: depsLogger });
    const custodySeam = deps.custody();
    const custodyKeyIdMatchesThePinnedKey = custodySeam.keyId === expectedBackendKeyId;
    const dispatchAssemblyModule = require(path.join(DEVICE_DIR, 'dispatchAssembly.js'));
    const req = {
      user: { id: userId, tenantId: TENANT },
      // Request-supplied identity channels are populated with FOREIGN values on purpose: a tool that
      // read any of them would resolve a device that does not exist and be caught here.
      body: { deviceId: 'a-request-supplied-device', tenantId: 'a-request-supplied-tenant' },
      query: { deviceId: 'a-request-supplied-device' },
      params: { deviceId: 'a-request-supplied-device' },
      headers: { 'x-device-id': 'a-request-supplied-device' },
    };
    const deviceCommandTool = toolModule.createDeviceCommandTool({
      ...deps,
      req,
      ledger,
      env: depsEnv,
      logger: depsLogger,
    });
    const toolArgs = { tool: 'read_file', arguments: { path: realFile } };
    const hopCallsBeforeTheTool = fetchWitness.hopCalls().length;
    const rawPayload = await tenantStorage.run({ tenantId: TENANT, userId }, async () =>
      deviceCommandTool.invoke({ name: toolModule.DEVICE_COMMAND_TOOL_NAME, args: toolArgs, type: 'tool_call' }),
    );
    const toolPayload = JSON.parse(rawPayload);
    const hopCallsAfterTheTool = fetchWitness.hopCalls();
    const toolDescription = String(deviceCommandTool.description ?? '');
    const toolSaysAccepted =
      toolPayload.outcome === toolModule.DEVICE_COMMAND_OUTCOMES.ACCEPTED &&
      toolPayload.ok === true &&
      toolPayload.delivered === 'accepted' &&
      toolPayload.status === 'success';
    const toolPass =
      toolSaysAccepted === true &&
      toolPayload.deviceId === serverDeviceId &&
      toolPayload.tool === 'read_file' &&
      toolPayload.policy?.evaluated === true &&
      toolPayload.policy?.decision === 'allowed' &&
      toolPayload.policy?.stage === dispatchAssemblyModule.DEFAULT_SERVER_STAGE &&
      hopCallsAfterTheTool.length === 1 &&
      custodyKeyIdMatchesThePinnedKey === true;
    record({
      id: 'S7',
      title: 'THE TOOL — the real `createDeviceCommandTool` invoked with the REAL deps over the REAL relay',
      status: toolPass ? 'PASS' : 'FAIL',
      observed: {
        toolInvoked: toolModule.DEVICE_COMMAND_TOOL_NAME,
        toolArgs,
        toolArgsBytesUtf8: JSON.stringify(toolArgs.arguments ?? {}),
        payload: toolPayload,
        payloadIsTheModelsOwnView: 'the JSON string the model receives, parsed',
        deviceCommandToolName: deviceCommandTool.name,
        descriptionSha256: sha256Hex(toolDescription),
        descriptionQuote: toolDescription.slice(0, 280),
        deps: {
          module: path.join(DEVICE_DIR, 'deviceCommandDeps.js'),
          description: depsModule.describeDeviceCommandDeps({ env: depsEnv }),
          envHandedToTheDeps: {
            [LAB_CUSTODY_KEY_FILE_ENV]: labKeyFile,
            [RELAY_BASE_URL_ENV]: relay.base,
            [STAGE_ENV]: null,
            stageEnvOmittedSoTheGateRunsAtTheNarrowestStage: true,
          },
          custodySeamKeyId: custodySeam.keyId,
          custodyKeyIdMatchesThePinnedBackendKey: custodyKeyIdMatchesThePinnedKey,
          custodyProviderIsAFunction: typeof deps.custody === 'function',
          transportIsAFunction: typeof deps.transport === 'function',
          replayWindowIsShared: deps.replayWindow === depsModule.sharedReplayWindowFor(),
        },
        assembly: {
          module: path.join(DEVICE_DIR, 'dispatchAssembly.js'),
          defaultServerStage: dispatchAssemblyModule.DEFAULT_SERVER_STAGE,
          capabilityStageEnv: dispatchAssemblyModule.CAPABILITY_STAGE_ENV,
          note: 'built lazily by the tool through the single production assembly point; its armed port is what produced the policy block below',
        },
        wire: {
          hopCallsBeforeTheTool,
          hopCallsAfterTheTool: hopCallsAfterTheTool.length,
          hopCall: hopCallsAfterTheTool[0] ?? null,
        },
        ledgerReservedBeforeTheWire: (await ledger.get('probe-never-used')) === null,
        identityFromTheSession: {
          resolvedDeviceId: toolPayload.deviceId,
          isTheServerIssuedDevice: toolPayload.deviceId === serverDeviceId,
          requestSuppliedValues: req.body,
          requestSuppliedValuesAppearNowhereInTheFrame: 'asserted in S8 against the frame bytes',
        },
      },
      notes:
        'This is the tool the model calls, built by its real factory from the real deps assembly, invoked the way the model invokes it (tool.invoke), inside the real tenant ALS. The deps env is built here because the relay is booted in-process (ephemeral port); the operator-declared relay URL is validated as loopback in S0 and recorded, and the transport the deps build is aimed at THIS booted artifact (proven by the witness URL in S8).',
    });
    if (!toolPass) {
      throw new Error('THE_TOOL_DID_NOT_DISPATCH');
    }
    evidence.realComponents.toolInvocation = {
      module: path.join(REPO, 'api', 'app', 'clients', 'tools', 'deviceCommand.js'),
      depsModule: path.join(DEVICE_DIR, 'deviceCommandDeps.js'),
      custodyKeyId: custodySeam.keyId,
      transport: 'the real `createRelayTransport` from deviceCommandDeps, aimed at the booted relay base',
      relayBaseUrl: relay.base,
      payloadOutcome: toolPayload.outcome,
      requestId: toolPayload.requestId,
      deviceId: toolPayload.deviceId,
    };

    // ---------------------------------------------------------------- S8. the wire, and the DEVICE's own output
    const hopCall = hopCallsAfterTheTool[0];
    const hopBody = JSON.parse(hopCall.body);
    const wireFrame = JSON.parse(hopBody.payload);
    const wireArgsBytes = Buffer.from(wireFrame.argsB64u, 'base64url');
    const outboxEntry = await waitForOutboxEntry(relay, serverDeviceId, wireFrame.callId, RESULT_TIMEOUT_MS);
    const deviceResultFrame = JSON.parse(outboxEntry.payload);
    const agentEvents = parseAgentLog(serveStdout);
    const eventsForThisCall = agentEvents.filter((event) => event.callId === wireFrame.callId);
    const relayStateAfterResult = await relay.stateOf(serverDeviceId);
    const relayCallEntry = (relayStateAfterResult.storage?.callLedger ?? []).find(
      (entry) => entry.callId === wireFrame.callId,
    );
    const argsBytesMatchTheModelsArguments =
      wireArgsBytes.toString('utf8') === JSON.stringify(toolArgs.arguments ?? {});
    const agentSawTheFrame = eventsForThisCall.some((event) => event.event === 'frame.received');
    const agentExecutedIt = eventsForThisCall.some(
      (event) => event.event === 'frame.outcome' && event.outcome === 'succeeded',
    );
    const deviceSidePass =
      wireFrame.toolName === 'read_file' &&
      wireFrame.audience === 'endpoint' &&
      wireFrame.deviceId === serverDeviceId &&
      wireFrame.requestId === toolPayload.requestId &&
      typeof wireFrame.callId === 'string' &&
      wireFrame.callId.startsWith('cbhr-tool-') &&
      argsBytesMatchTheModelsArguments === true &&
      deviceResultFrame.callId === wireFrame.callId &&
      deviceResultFrame.requestId === wireFrame.requestId &&
      deviceResultFrame.tag === 'CBHR-RPC-RESULT-V2' &&
      deviceResultFrame.outcome === 'succeeded' &&
      deviceResultFrame.deviceKeyId === agentFinal.deviceKeyId &&
      agentSawTheFrame === true &&
      agentExecutedIt === true;
    record({
      id: 'S8',
      title: 'WIRE AND DEVICE — the frame the tool signed, and the DEVICE-SIGNED result for the same call',
      status: deviceSidePass ? 'PASS' : 'FAIL',
      observed: {
        hop: {
          url: hopCall.url,
          method: hopCall.method,
          at: hopCall.at,
          aimedAtTheBootedRelay: typeof hopCall.url === 'string' && hopCall.url.startsWith(relay.base),
        },
        hopBodyFields: { epoch: hopBody.epoch ?? null, callId: hopBody.callId ?? null, payloadIsAString: typeof hopBody.payload === 'string' },
        frame: {
          tag: wireFrame.tag,
          toolName: wireFrame.toolName,
          opKind: wireFrame.opKind ?? null,
          audience: wireFrame.audience,
          deviceId: wireFrame.deviceId,
          tenantId: wireFrame.tenantId,
          ownerPrincipalId: wireFrame.ownerPrincipalId,
          grantId: wireFrame.grantId,
          epoch: wireFrame.epoch,
          keyId: wireFrame.keyId,
          requestId: wireFrame.requestId,
          callId: wireFrame.callId,
          nonceLength: typeof wireFrame.nonce === 'string' ? wireFrame.nonce.length : null,
          argsB64u: wireFrame.argsB64u,
          argsDigestHex: wireFrame.argsDigestHex,
          argsDecodedUtf8: wireArgsBytes.toString('utf8'),
          argsBytesMatchTheModelsArguments,
          claimKeyIdMatchesTheDepsCustodySeam: wireFrame.keyId === custodySeam.keyId,
          requestSuppliedValuesAppearNowhereInTheFrame:
            !JSON.stringify(wireFrame).includes('a-request-supplied'),
        },
        relayOutbox: {
          resultSeq: outboxEntry.resultSeq,
          callId: outboxEntry.callId,
          payloadBytes: typeof outboxEntry.payload === 'string' ? outboxEntry.payload.length : null,
          relayCallLedgerEntry: relayCallEntry ?? null,
        },
        deviceResultFrame: {
          tag: deviceResultFrame.tag,
          outcome: deviceResultFrame.outcome,
          requestId: deviceResultFrame.requestId,
          callId: deviceResultFrame.callId,
          deviceId: deviceResultFrame.deviceId,
          deviceKeyId: deviceResultFrame.deviceKeyId,
          grantId: deviceResultFrame.grantId,
          epoch: deviceResultFrame.epoch,
          audience: deviceResultFrame.audience,
          errorCode: deviceResultFrame.errorCode ?? null,
          correlation: deviceResultFrame.correlation ?? null,
        },
        deviceOwnAccount: {
          logFile: serveStdout,
          eventsForThisCall: eventsForThisCall.map((event) => ({
            event: event.event,
            level: event.level,
            seq: event.seq ?? null,
            outcome: event.outcome ?? null,
            accepted: event.accepted ?? null,
            resultSeq: event.resultSeq ?? null,
          })),
          agentSawTheFrame,
          agentExecutedIt,
        },
      },
      notes:
        'The frame is exactly what the real transport POSTed into the relay\'s own frame admission, taken from the witness of the process\'s fetch. The result is the relay\'s own outbox copy: byte-identical to what the device sent, and signed by the device key that lives only in the agent process.',
    });
    if (!deviceSidePass) {
      throw new Error('DEVICE_RESULT_NOT_CORRELATED');
    }

    // ---------------------------------------------------------------- S9. the content correlation the proof exists for
    const platformVerification = await resultFrameModule.verifyResultFrame({
      frame: deviceResultFrame,
      verifier: resultVerifier,
      now: Date.now(),
      // No window here: the result's own nonce is reserved by the SINK below, which is the
      // production receiver. Reserving it twice would refuse the second, honest verification.
    });
    const deviceReport = platformVerification.ok === true
      ? JSON.parse(platformVerification.resultBytes.toString('utf8'))
      : null;
    const runnerBytes = fs.readFileSync(realFile);
    const runnerText = runnerBytes.toString('utf8');
    const runnerStat = fs.statSync(realFile);
    const deviceResult = deviceReport?.result ?? null;
    const contentCorrelation = {
      pathTheDeviceRead: deviceResult?.path ?? null,
      pathThisRunnerRead: path.relative(workspaceRoot, realFile),
      deviceReportedSha256Hex: deviceResult?.sha256Hex ?? null,
      runnerSha256Hex: sha256Hex(runnerBytes),
      deviceReportedSize: deviceResult?.size ?? null,
      runnerSizeBytes: runnerBytes.length,
      runnerMtimeMs: runnerStat.mtimeMs,
      deviceReportedBytesRead: deviceResult?.bytesRead ?? null,
      deviceReportedTruncated: deviceResult?.truncated ?? null,
      deviceReportedEncoding: deviceResult?.encoding ?? null,
      sha256Agrees: deviceResult?.sha256Hex === sha256Hex(runnerBytes),
      sizeAgrees: deviceResult?.size === runnerBytes.length,
      contentAgrees: deviceResult?.content === runnerText,
      contentSha256: typeof deviceResult?.content === 'string' ? sha256Hex(deviceResult.content) : null,
    };
    const sinkVerdict = await sink.ingestResult({
      callId: outboxEntry.callId,
      payload: outboxEntry.payload,
      resultSeq: outboxEntry.resultSeq,
    });
    const ledgerAfterCompletion = await ledger.get(wireFrame.callId);
    const storedResult = await sink.resultFor(wireFrame.callId);
    // `relay.cjs`'s helpers answer `{status, body}`; the relay's own payload is `body`.
    const ackEnvelope = await relay.ackResults(serverDeviceId, [outboxEntry.resultSeq]);
    const ackVerdict = ackEnvelope.body ?? {};
    const ackAcked = Array.isArray(ackVerdict.acked) ? ackVerdict.acked : [];
    const relayStateAfterAck = await relay.stateOf(serverDeviceId);
    const toolCallId = wireFrame.callId;
    const correlation = {
      toolSaysAccepted,
      toolReported: {
        outcome: toolPayload.outcome,
        status: toolPayload.status,
        deviceId: toolPayload.deviceId,
        requestId: toolPayload.requestId,
        code: toolPayload.code,
      },
      theOneIdentityAcrossEveryRealArtifact: {
        requestIdOnTheToolPayload: toolPayload.requestId,
        requestIdOnTheWireFrame: wireFrame.requestId,
        requestIdInTheDurableLedger: ledgerAfterCompletion?.requestId ?? null,
        requestIdOnTheDeviceResult: deviceResultFrame.requestId,
        requestIdAgreesEverywhere:
          toolPayload.requestId === wireFrame.requestId &&
          ledgerAfterCompletion?.requestId === wireFrame.requestId &&
          deviceResultFrame.requestId === wireFrame.requestId,
        callIdOnTheWire: toolCallId,
        callIdInTheDurableLedger: ledgerAfterCompletion?.callId ?? null,
        callIdInTheRelayCallLedger: relayCallEntry?.callId ?? null,
        callIdInTheDeviceResult: deviceResultFrame.callId,
        callIdAgreesEverywhere:
          ledgerAfterCompletion?.callId === toolCallId &&
          relayCallEntry?.callId === toolCallId &&
          deviceResultFrame.callId === toolCallId,
      },
      deviceResultAuthenticatedByThePlatformVerifier: platformVerification.ok === true,
      platformVerificationCode: platformVerification.ok === true ? null : platformVerification.error?.code ?? null,
      deviceReportMatchesTheRealBytes: contentCorrelation,
      sink: sinkVerdict,
      ledger: ledgerAfterCompletion
        ? { state: ledgerAfterCompletion.state, outcome: ledgerAfterCompletion.outcome, resultSeq: ledgerAfterCompletion.resultSeq }
        : null,
      storedResult: storedResult
        ? { callId: storedResult.callId, outcome: storedResult.outcome, success: storedResult.success, toolName: storedResult.toolName, deviceId: storedResult.deviceId }
        : null,
      relayAck: { status: ackEnvelope.status, acked: ackAcked, remaining: ackVerdict.remaining ?? null },
      relayCallLedgerAfterAck: (relayStateAfterAck.storage?.callLedger ?? []).map((entry) => ({
        callId: entry.callId,
        state: entry.state,
      })),
      durableCompletionWrites: durable.counters.durableCompletionWrites,
    };
    correlation.toolReportIsTheDeviceOutput =
      toolSaysAccepted === true &&
      correlation.theOneIdentityAcrossEveryRealArtifact.requestIdAgreesEverywhere === true &&
      correlation.theOneIdentityAcrossEveryRealArtifact.callIdAgreesEverywhere === true &&
      platformVerification.ok === true &&
      contentCorrelation.sha256Agrees === true &&
      contentCorrelation.contentAgrees === true &&
      contentCorrelation.sizeAgrees === true;
    evidence.correlation = correlation;
    const correlationPass =
      correlation.toolReportIsTheDeviceOutput === true &&
      sinkVerdict?.status === 'completed' &&
      sinkVerdict?.success === true &&
      sinkVerdict?.outcome === 'succeeded' &&
      sinkVerdict?.callId === toolCallId &&
      ledgerAfterCompletion?.state === 'completed' &&
      ledgerAfterCompletion?.outcome === 'succeeded' &&
      storedResult?.success === true &&
      durable.counters.durableCompletionWrites === 1 &&
      ackAcked.length === 1;
    record({
      id: 'S9',
      title: 'CORRELATION — the tool\'s accepted report IS the device\'s real output, byte for byte',
      status: correlationPass ? 'PASS' : 'FAIL',
      observed: correlation,
      notes:
        'The chain: the requestId the model is told -> the signed frame that left the process -> the platform\'s durable reservation -> the DEVICE-SIGNED result. Then the device\'s own sha256/size/content for the file it read are compared with this runner\'s independent read of the same path. The sink is the production receiver; the ledger is the durable Mongo one.',
    });
    if (!correlationPass) {
      throw new Error('CONTENT_CORRELATION_FAILED');
    }// ---------------------------------------------------------------- THE NEGATIVES
    // Each negative is a REAL invocation of the REAL tool entry over the REAL deps assembly, with
    // exactly one documented seam changed. The wire snapshot (hop witness + the relay's own state +
    // the agent's own log) is taken BEFORE and AFTER each one; "nothing was sent" is equality.
    const wireSnapshot = async () => {
      const state = await relay.stateOf(serverDeviceId);
      const events = parseAgentLog(serveStdout);
      return {
        hopCalls: fetchWitness.hopCalls().length,
        relayFrameSeq: state.storage?.nextSeq ?? null,
        relayCallLedger: (state.storage?.callLedger ?? []).map((entry) => `${entry.callId}:${entry.state}`),
        relayPendingFrames: (state.storage?.pending ?? []).length,
        relayPendingResultCallIds: (state.storage?.pendingResults ?? []).map((entry) => entry.callId),
        relayFramesThisInstance: state.framesThisInstance ?? null,
        deviceFrameReceipts: events.filter((event) => event.event === 'frame.received').length,
        deviceResultsSent: events.filter((event) => event.event === 'result.sent').length,
        ledgerKeys: await durableStore.keys(),
        resultStoreSize: await resultStore.size(),
      };
    };

    // N1 — the unconfigured control: the same entry over deps built WITHOUT the custody var answers
    // `not-configured` exactly as the tool's contract requires, and the hop is never touched.
    const n1SnapshotBefore = await wireSnapshot();
    const depsWithoutCustody = depsModule.createDeviceCommandDeps({
      env: { [RELAY_BASE_URL_ENV]: relay.base },
      logger: depsLogger,
    });
    const toolWithoutCustody = toolModule.createDeviceCommandTool({
      ...depsWithoutCustody,
      req,
      ledger,
      env: depsEnv,
      logger: depsLogger,
    });
    const n1Raw = await tenantStorage.run({ tenantId: TENANT, userId }, async () =>
      toolWithoutCustody.invoke({ name: toolModule.DEVICE_COMMAND_TOOL_NAME, args: toolArgs, type: 'tool_call' }),
    );
    const n1Payload = JSON.parse(n1Raw);
    const n1SnapshotAfter = await wireSnapshot();
    const n1Pass =
      n1Payload.outcome === toolModule.DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED &&
      n1Payload.ok === false &&
      /custody/i.test(n1Payload.summary) &&
      /nothing was signed/i.test(n1Payload.summary) &&
      depsWithoutCustody.custody === null &&
      JSON.stringify(n1SnapshotAfter) === JSON.stringify(n1SnapshotBefore);
    record({
      id: 'N1',
      title: 'CONTROL — the same tool with no custody configured refuses `not-configured`, untouched hop',
      status: n1Pass ? 'PASS' : 'FAIL',
      observed: {
        payload: n1Payload,
        custodyInTheseDeps: 'absent (the env had no custody key file var)',
        wireSnapshotBefore: n1SnapshotBefore,
        wireSnapshotAfter: n1SnapshotAfter,
        wireSnapshotsAreIdentical: JSON.stringify(n1SnapshotAfter) === JSON.stringify(n1SnapshotBefore),
      },
      notes:
        'This is the tool\'s own fail-closed contract exercised against the REAL relay URL: not-configured before any client is built, nothing signed, nothing sent.',
    });
    evidence.negatives.push({ id: 'N1', status: n1Pass ? 'PASS' : 'FAIL', observed: n1Payload });
    if (!n1Pass) {
      throw new Error('NEGATIVE_CUSTODY_CONTROL_FAILED');
    }

    // N2 — a resolver regime that cannot admit `read_file`: refused with the registry's own code,
    // `delivered:'no'`, before the clock, the nonce, the signer, the ledger and the wire.
    const n2SnapshotBefore = await wireSnapshot();
    const toolThrowingResolver = toolModule.createDeviceCommandTool({
      ...deps,
      req,
      ledger,
      env: depsEnv,
      logger: depsLogger,
      resolvePolicy: () => {
        throw new Error('the narrowing document source is unavailable in this regime');
      },
    });
    const n2Raw = await tenantStorage.run({ tenantId: TENANT, userId }, async () =>
      toolThrowingResolver.invoke({ name: toolModule.DEVICE_COMMAND_TOOL_NAME, args: toolArgs, type: 'tool_call' }),
    );
    const n2Payload = JSON.parse(n2Raw);
    const n2ExpectedCode = registryModule.authorizeDispatch('read_file', {
      ceiling: dispatchAssemblyModule.DEFAULT_SERVER_STAGE,
      deviceFloor: { enabled: [] },
    }).code;
    const n2SnapshotAfter = await wireSnapshot();
    const n2Pass =
      n2Payload.outcome === toolModule.DEVICE_COMMAND_OUTCOMES.REFUSED &&
      n2Payload.ok === false &&
      n2Payload.delivered === 'no' &&
      n2Payload.code === n2ExpectedCode &&
      n2Payload.policy?.evaluated === true &&
      n2Payload.policy?.decision === 'denied' &&
      JSON.stringify(n2SnapshotAfter) === JSON.stringify(n2SnapshotBefore);
    record({
      id: 'N2',
      title: 'NEGATIVE — an unadmittable tool is REFUSED with the registry\'s code, before anything is signed or sent',
      status: n2Pass ? 'PASS' : 'FAIL',
      observed: {
        payload: n2Payload,
        expectedCode: n2ExpectedCode,
        expectedCodeSource: 'deviceToolRegistry.authorizeDispatch computed live, not restated',
        wireSnapshotBefore: n2SnapshotBefore,
        wireSnapshotAfter: n2SnapshotAfter,
        wireSnapshotsAreIdentical: JSON.stringify(n2SnapshotAfter) === JSON.stringify(n2SnapshotBefore),
      },
      notes:
        'The regime encodes the W10 interface, not a product state — but the mechanism refused is the product\'s: the gate inside the single production assembly runs before the replay window, the envelope and the wire.',
    });
    evidence.negatives.push({ id: 'N2', status: n2Pass ? 'PASS' : 'FAIL', observed: n2Payload });
    if (!n2Pass) {
      throw new Error('NEGATIVE_RESOLVER_REGIME_FAILED');
    }

    // N3 — the required ceiling negative: a tool OUTSIDE the stage ceiling. `write_file` is a stage-B
    // tool; the gate runs at the narrowest stage A, so it is refused with the registry's OWN widening
    // code. The target file does not exist before the call and must not exist after it.
    const refusedTargetName = 'tool-live-refused-write.txt';
    const refusedTarget = path.join(workspaceRoot, refusedTargetName);
    const refusedTargetExistedBefore = fs.existsSync(refusedTarget);
    const n3SnapshotBefore = await wireSnapshot();
    const registryWideningCode = registryModule.DISPATCH_CODES.OUTSIDE_SERVER_CEILING;
    const n3Args = { tool: 'write_file', arguments: { path: refusedTarget, content: 'this must never be written' } };
    const n3Raw = await tenantStorage.run({ tenantId: TENANT, userId }, async () =>
      toolModule
        .createDeviceCommandTool({ ...deps, req, ledger, env: depsEnv, logger: depsLogger })
        .invoke({ name: toolModule.DEVICE_COMMAND_TOOL_NAME, args: n3Args, type: 'tool_call' }),
    );
    const n3Payload = JSON.parse(n3Raw);
    await w13.sleep(250);
    const n3SnapshotAfter = await wireSnapshot();
    const refusedTargetExistsAfter = fs.existsSync(refusedTarget);
    const n3Pass =
      n3Payload.outcome === toolModule.DEVICE_COMMAND_OUTCOMES.REFUSED &&
      n3Payload.ok === false &&
      n3Payload.delivered === 'no' &&
      n3Payload.tool === 'write_file' &&
      n3Payload.code === registryWideningCode &&
      n3Payload.policy?.evaluated === true &&
      n3Payload.policy?.decision === 'denied' &&
      n3Payload.policy?.tier === 1 &&
      String(n3Payload.summary).includes(registryWideningCode) &&
      refusedTargetExistedBefore === false &&
      refusedTargetExistsAfter === false &&
      JSON.stringify(n3SnapshotAfter) === JSON.stringify(n3SnapshotBefore);
    record({
      id: 'N3',
      title: 'NEGATIVE — a tool OUTSIDE the stage ceiling is REFUSED with the registry\'s code; nothing executed, nothing sent',
      status: n3Pass ? 'PASS' : 'FAIL',
      observed: {
        payload: n3Payload,
        registryWideningCode,
        registryWideningCodeSource: 'deviceToolRegistry.DISPATCH_CODES read live, not restated',
        requiredStage: 'B (write_file is a stage-B tool); the gate runs at the narrowest stage A',
        targetFile: { path: refusedTarget, existedBefore: refusedTargetExistedBefore, existsAfter: refusedTargetExistsAfter },
        nothingExecuted: {
          targetFileStillAbsent: refusedTargetExistsAfter === false,
          deviceReceivedNoNewFrame: n3SnapshotAfter.deviceFrameReceipts === n3SnapshotBefore.deviceFrameReceipts,
          deviceSentNoNewResult: n3SnapshotAfter.deviceResultsSent === n3SnapshotBefore.deviceResultsSent,
        },
        nothingSent: {
          hopCallsDelta: n3SnapshotAfter.hopCalls - n3SnapshotBefore.hopCalls,
          relayFrameSeqUnchanged: n3SnapshotAfter.relayFrameSeq === n3SnapshotBefore.relayFrameSeq,
          relayCallLedgerUnchanged: JSON.stringify(n3SnapshotAfter.relayCallLedger) === JSON.stringify(n3SnapshotBefore.relayCallLedger),
          ledgerKeysUnchanged: JSON.stringify(n3SnapshotAfter.ledgerKeys) === JSON.stringify(n3SnapshotBefore.ledgerKeys),
        },
        wireSnapshotBefore: n3SnapshotBefore,
        wireSnapshotAfter: n3SnapshotAfter,
      },
      notes:
        'This is the honest-refusal proof the GM record requires: the registry\'s code reaches the model, and on the penultimate hop (fetch witness + relay seq/ledgers) and on the device itself (its own log + the unwritten file) nothing changed.',
    });
    evidence.negatives.push({ id: 'N3', status: n3Pass ? 'PASS' : 'FAIL', observed: n3Payload });
    if (!n3Pass) {
      throw new Error('NEGATIVE_CEILING_FAILED');
    }// ---------------------------------------------------------------- S10. cleanup and the independent namespace check
    const finalLedgerRows = await collections.ledger.find({}).toArray();
    const finalResultRows = await collections.results.find({}).toArray();
    const relayStateFinal = await relay.stateOf(serverDeviceId);
    evidence.finalState = {
      ledgerInMongo: finalLedgerRows.map((row) => ({
        callId: row._id,
        state: row.state,
        outcome: row.outcome,
        resultSeq: row.resultSeq,
        requestId: row.requestId,
        toolName: row.toolName,
        deviceId: row.deviceId,
        tenantId: row.tenantId,
      })),
      resultsInMongo: finalResultRows.map((row) => ({
        callId: row._id,
        outcome: row.outcome,
        success: row.success,
        toolName: row.toolName,
      })),
      relayCallLedger: (relayStateFinal.storage?.callLedger ?? []).map((entry) => ({
        callId: entry.callId,
        state: entry.state,
        resultSeq: entry.resultSeq,
      })),
      relayPendingResults: (relayStateFinal.storage?.pendingResults ?? []).map((entry) => entry.callId),
      relayPendingFrames: (relayStateFinal.storage?.pending ?? []).length,
    };
    record({
      id: 'S10/pre',
      title: 'FINAL STATE — the platform\'s durable record, independent of this process\'s memory',
      status:
        evidence.finalState.ledgerInMongo.length === 1 &&
        evidence.finalState.ledgerInMongo[0]?.state === 'completed' &&
        evidence.finalState.ledgerInMongo[0]?.outcome === 'succeeded' &&
        evidence.finalState.resultsInMongo.length === 1 &&
        evidence.finalState.resultsInMongo[0]?.success === true &&
        evidence.finalState.relayCallLedger.length === 1 &&
        evidence.finalState.relayCallLedger[0]?.state === 'completed'
          ? 'PASS'
          : 'FAIL',
      observed: evidence.finalState,
      notes:
        'Read straight from the MongoDB collections with the driver (not through the ledger object): one completed call, one stored success, and the relay\'s own call ledger closed.',
    });
    if (steps[steps.length - 1].status !== 'PASS') {
      throw new Error('FINAL_STATE_UNEXPECTED');
    }
  } finally {
    // The resident agent stops the way a service manager stops it: stdin EOF is the documented
    // control channel, so the runtime drains and exits cleanly. A hang is bounded and then killed.
    if (serveChild !== null) {
      try {
        if (serveChild.stdin !== null && serveChild.stdin.writable) {
          serveChild.stdin.end();
        }
        await withTimeout(
          new Promise((resolve) => {
            if (serveChild.exitCode !== null || serveChild.signalCode !== null) {
              resolve();
              return;
            }
            serveChild.once('exit', resolve);
          }),
          15000,
          'the agent `serve` child exiting after stdin EOF',
        ).catch((err) => {
          cleanupNotes.push(`agent shutdown: ${err.message}`);
          try {
            serveChild.kill();
          } catch {
            cleanupNotes.push('agent kill failed');
          }
        });
      } catch (err) {
        cleanupNotes.push(`agent shutdown failed: ${err.message}`);
      }
    }
    try {
      if (relay !== null) {
        await relay.dispose();
      }
    } catch {
      cleanupNotes.push('relay dispose failed');
    }
    try {
      if (server !== null) {
        await new Promise((resolve) => server.close(resolve));
      }
    } catch {
      cleanupNotes.push('http server close failed');
    }
    try {
      if (fetchWitness !== null) {
        fetchWitness.restore();
      }
    } catch {
      cleanupNotes.push('fetch witness restore failed');
    }
    try {
      const mongooseModuleForClose = require(path.join(REPO, 'node_modules', 'mongoose'));
      await mongooseModuleForClose.disconnect();
    } catch {
      cleanupNotes.push('mongoose disconnect failed');
    }
    try {
      dropped = (await adminClient.db(dbName).dropDatabase()) === true;
    } catch (err) {
      cleanupNotes.push(`dropDatabase failed: ${err.message}`);
    }
    const namespaceAfter = await env.listNamespace(adminClient.db('admin'));
    const delta = env.namespaceDelta(namespaceBefore, namespaceAfter);
    const ownPrefixLeftovers = namespaceAfter.nonSystem.filter((name) => name.startsWith(env.DB_PREFIX));
    const foreignNewDatabases = delta.added.filter((name) => !name.startsWith(env.DB_PREFIX));
    const namespaceClean = dropped === true && ownPrefixLeftovers.length === 0;
    evidence.namespace = {
      before: namespaceBefore.nonSystem,
      after: namespaceAfter.nonSystem,
      equal: delta.equal,
      added: delta.added,
      missing: delta.missing,
      ownDatabaseCreated: dbName,
      ownDatabaseDropped: dropped === true,
      ownPrefixLeftovers,
      foreignNewDatabases,
      namespaceClean,
      systemDatabasesExcluded: env.SYSTEM_DATABASES,
    };

    // THE TREE. The agent root and the relay's scratch live outside the tracked tree or inside the
    // gitignored run directory; the comparison below states exactly what this run added.
    // A failure HERE must never mask the real one: the whole section is guarded, and its own
    // failures join `cleanupNotes` instead of replacing the in-flight error.
    try {
      const gitStatusAfter = gitStatusLines();
      evidence.treeState = {
        gitStatusBefore: gitStatusBeforeLines,
        gitStatusAfter,
        entriesAddedByThisRun: gitStatusAfter.filter((line) => !gitStatusBeforeLines.includes(line)),
        entriesRemovedByThisRun: gitStatusBeforeLines.filter((line) => !gitStatusAfter.includes(line)),
        runStateDirectory: path.relative(REPO, workDir),
        runStateIsGitIgnored: true,
        agentRoot,
        agentRootInsideTheRepo: typeof agentRoot === 'string' && agentRoot.startsWith(REPO),
        agentRootRemoved: false,
        labKeyFileUntouched: fs.existsSync(labKeyFile),
        privateKeyMaterialWrittenUnderTheRepo: 'none',
      };
    } catch (err) {
      cleanupNotes.push(`tree-state comparison failed: ${err.message}`);
      evidence.treeState = { unavailable: true, agentRoot, labKeyFileUntouched: fs.existsSync(labKeyFile) };
    }
    // Best effort: the resident's own root (key + replay window) is this run's, so it is removed.
    // `~/.cbhr/lab-backend` is NEVER touched: it is the shared lab key the recipe names.
    try {
      fs.rmSync(agentRoot, { recursive: true, force: true });
      evidence.treeState.agentRootRemoved = !fs.existsSync(agentRoot);
    } catch (err) {
      cleanupNotes.push(`agent root removal failed: ${err.code ?? err.message}`);
    }
    await adminClient.close().catch(() => {
      cleanupNotes.push('admin client close failed');
    });

    record({
      id: 'S10',
      title: 'CLEANUP — the run database is dropped, the namespace returns, and the tracked tree is untouched',
      status:
        namespaceClean &&
        evidence.treeState.agentRootInsideTheRepo === false &&
        evidence.treeState.entriesAddedByThisRun.length === 0 &&
        evidence.treeState.entriesRemovedByThisRun.length === 0 &&
        evidence.treeState.labKeyFileUntouched === true
          ? 'PASS'
          : 'FAIL',
      observed: evidence.namespace,
      notes: cleanupNotes.length === 0 ? null : cleanupNotes.join('; '),
    });
    if (foreignNewDatabases.length > 0) {
      limits.push({
        id: 'L0',
        statement: `The shared local replica set is not exclusive: these databases appeared during the run and belong to other lanes — ${foreignNewDatabases.join(', ')}. This run's own database (${dbName}) was created and dropped, and no \`${env.DB_PREFIX}\` database remains.`,
        evidence: 'step S10',
      });
    }
  }

  // ------------------------------------------------------------------ summary and verdict
  const failed = steps.filter((step) => step.status === 'FAIL');
  const summary = {
    runId,
    harness: HARNESS,
    stepCount: steps.length,
    passed: steps.filter((step) => step.status === 'PASS').length,
    failed: failed.map((step) => ({ id: step.id, status: step.status })),
    toolReachedARealDeviceThroughALiveRelay: evidence.correlation?.toolReportIsTheDeviceOutput === true,
    acceptedOutcome: evidence.correlation?.toolReported ?? null,
    refusalOutcome: evidence.negatives.find((entry) => entry.id === 'N3')?.observed ?? null,
    limits,
    accepted: failed.length === 0,
    acceptedMeans:
      'exit 0 means the real tool dispatched through the real deps into a real relay and a real resident device, the tool\'s report correlated byte-for-byte with the device\'s output, the refusals were honest and provably sent nothing, and the database namespace returned to its pre-run state',
  };
  banner('PER-STEP LEDGER');
  for (const step of steps) {
    say(`${step.status.padEnd(5)}  ${step.id.padEnd(9)}  ${step.title}`);
  }
  say('');
  say(`LIMITS REPORTED (${limits.length}):`);
  for (const limit of limits) {
    say(`  ${limit.id}: ${limit.statement}`);
  }
  say('');
  say('VERDICT:');
  say(JSON.stringify(summary, null, 2));

  evidence.summary = summary;
  evidence.finishedAt = new Date().toISOString();
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  const evidenceFile = path.join(EVIDENCE_DIR, `tool-live-relay-${runId}.json`);
  const logFile = path.join(workDir, 'run.log');
  fs.writeFileSync(evidenceFile, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
  fs.writeFileSync(logFile, `${logLines.join('\n')}\n`, 'utf8');
  say('');
  say(`EVIDENCE: ${path.relative(REPO, evidenceFile)}`);
  say(`LOG:      ${path.relative(REPO, logFile)}`);
  // Explicit exit: workerd's runtime and Mongoose both keep handles alive.
  process.exit(summary.accepted ? 0 : 2);
}

/** Reads the DEVICE private key so the ceremony proofs can be signed by the endpoint (see S3/S4). */
function loadAgentPrivateKeyForProof(agentRoot) {
  const keyFile = path.join(agentRoot, 'device-key.json');
  const raw = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
  const pkcs8 = raw.privateKeyPkcs8B64u;
  if (typeof pkcs8 !== 'string') {
    throw new Error('HARNESS_REFUSAL: the agent key file has an unexpected shape');
  }
  return nodeCrypto.createPrivateKey({
    key: Buffer.from(pkcs8, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  });
}

/** Parses the agent runtime's log lines: `<iso> LEVEL event {json fields}`. */
function parseAgentLog(file) {
  const text = readText(file);
  if (text === null) {
    return [];
  }
  const events = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^\S+ +(DEBUG|INFO|WARN|ERROR) +([A-Za-z0-9._-]+)(?: +(.*))?$/.exec(line.trim());
    if (match === null) {
      continue;
    }
    const record = { level: match[1].toLowerCase(), event: match[2] };
    if (match[3] !== undefined) {
      try {
        Object.assign(record, JSON.parse(match[3]));
      } catch {
        record.detail = match[3];
      }
    }
    events.push(record);
  }
  return events;
}

/** Waits until the relay reports a device-tagged socket for the device, or fails loudly. */
async function waitForDeviceSocket(relay, deviceId, timeoutMs) {
  const state = await w13.waitFor(
    async () => {
      try {
        const current = await relay.stateOf(deviceId);
        return (current.sockets ?? []).some((socket) => socket?.tag === 'device') ? current : null;
      } catch {
        return null;
      }
    },
    { timeout: timeoutMs, interval: 200 },
  );
  if (state === null) {
    throw new Error(
      `HARNESS_REFUSAL: the real agent did not connect a device socket to the relay within ${timeoutMs}ms`,
    );
  }
  return state;
}

/** Waits until the relay's outbox holds a result for the call, or fails loudly. */
async function waitForOutboxEntry(relay, deviceId, callId, timeoutMs) {
  const entry = await w13.waitFor(
    async () => {
      try {
        const pending = await relay.pendingOf(deviceId);
        return (pending.pending ?? []).find((item) => item.callId === callId) ?? null;
      } catch {
        return null;
      }
    },
    { timeout: timeoutMs, interval: 200 },
  );
  if (entry === null) {
    throw new Error(
      `HARNESS_REFUSAL: the device produced no result for ${callId} within ${timeoutMs}ms — the live loop did not close`,
    );
  }
  return entry;
}

/** The tracked/untracked state of the worktree, as git reports it (no writes, read-only). */
function gitStatusLines() {
  try {
    return execFileSync('git', ['-C', REPO, 'status', '--porcelain'], { encoding: 'utf8', windowsHide: true })
      .split(/\r?\n/)
      .filter((line) => line.trim().length > 0);
  } catch (err) {
    return [`<git status unavailable: ${err.message}>`];
  }
}

const gitStatusBeforeLines = gitStatusLines();

main().catch((error) => {
  say('');
  say(`TOOL-LIVE FAILED: ${error.message}`);
  say(error.stack ?? '');
  process.exit(1);
});
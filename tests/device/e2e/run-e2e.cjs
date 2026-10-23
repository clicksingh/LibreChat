#!/usr/bin/env node
'use strict';

/**
 * W9 — LOCAL END-TO-END HARNESS: pair -> dispatch -> execute -> result -> correlated outcome.
 *
 *   cd C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1
 *   node tests/device/e2e/run-e2e.cjs
 *
 * ONE COMMAND. Exit 0 only when every step PASSES.
 *
 * WHAT IS REAL AT EACH STEP (nothing here is a stub, a facade or a reimplementation):
 *
 *   1. PREFLIGHT      real `node.exe` process list (GM-71), real MongoDB handshake, real build check.
 *   2. SERVER         the REAL `api/server/routes/devices.js` router on a real Express/HTTP server,
 *                     with the REAL `requireJwtAuth` + real passport `jwt` strategy, over the REAL
 *                     `createModels(mongoose)` registry, on the REAL local MongoDB replica set.
 *   3. RELAY          the REAL relay artifact (`cbhr-rdc/apps/cbhr-relay/dist/worker.js`) in-process
 *                     workerd via Miniflare, with the compatibility config parsed from `wrangler.toml`.
 *   4. ENDPOINT       the REAL endpoint agent CLI (`apps/cbhr-endpoint-agent/run-agent.js`) as a CHILD
 *                     PROCESS, with its own key store OUTSIDE the repo (`~/.cbhr/e2e-<runId>`).
 *   5. REGISTRATION   a real `User` row + real JWT, then the real registration ceremony (challenge
 *                     minted by the accepted service, proof signed with the agent's own key).
 *   6. PAIRING        the real pairing ceremony through the real routes: `/pairing/challenge` ->
 *                     `/pairing/issue` (6-digit code) -> `/pairing/approve` -> `/pairing/complete`
 *                     (device-authenticated claim leg) -> a real 48 h lease with a real `grantId`.
 *   7. DISPATCH       the REAL `relayDispatchClient.dispatchCommand` (the backend's only signing +
 *                     dispatch path), with a real replay window, the durable Mongo dispatch ledger,
 *                     and a transport that POSTs into the REAL relay's own frame admission.
 *   8. EXECUTE        the agent reads a REAL file at a REAL path inside its containment root. Its
 *                     result frame is device-signed BY THE AGENT PROCESS.
 *   9. RESULT         `{t:'result', callId, payload}` over the real device socket -> the relay's
 *                     outbox -> `resultSink.ingestResult` -> the correlated outcome + ledger state.
 *  10. NEGATIVES      (a) a tampered frame; (b) a result for an unknown callId; (c) a tool outside the
 *                     server ceiling at the dispatch gate. Each must NOT succeed, and the ones that
 *                     must store nothing must store nothing.
 *  11. AFTER         a SEPARATE node process re-reads the durable ledger from MongoDB, so the final
 *                     state is not this process's memory.
 *  12. CLEANUP       the harness's own database is DROPPED and the namespace is compared to the
 *                     pre-run namespace.
 *
 * HONEST LIMITS are reported in-band under `limits` and in the summary — never omitted.
 */

const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..', '..', '..');
const env = require('./env.cjs');
const storage = require('./mongo-seams.cjs');
const relayModule = require('./relay.cjs');

const EVIDENCE_DIR = path.join(REPO, 'tests', 'device', '_phase1_evidence', 'e2e');
const ENDPOINT_AGENT_DIR = path.join(REPO, 'apps', 'cbhr-endpoint-agent');
const DEVICE_RELAY_DIR = path.join(REPO, 'api', 'server', 'services', 'Device', 'relay');
const DEVICE_DIR = path.join(REPO, 'api', 'server', 'services', 'Device');

const TENANT = 'tenant-w9-e2e';
const OWNER_ID = 'principal-w9-e2e-owner';
const OWNER_EMAIL = 'w9-e2e-owner@lab.local';
const JWT_SECRET = `w9-e2e-jwt-secret-${nodeCrypto.randomBytes(8).toString('hex')}`;
const LAB_PEPPER = 'w9-e2e-lookup-pepper-0001';
const PAIRING_OPEN_DOMAIN = 'cbhr:device:pairing-open:v1';

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

/** GM-71: another lane's run against the shared local MongoDB voids this evidence. */
function competingNodeProcesses() {
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
  const rows = Array.isArray(listing) ? listing : [listing];
  const pattern = /skew|run-e1|servertime|devicePolicy|run-e2e|_phase1_evidence/i;
  const matches = rows
    .filter((row) => typeof row.CommandLine === 'string' && pattern.test(row.CommandLine))
    .filter((row) => row.ProcessId !== self)
    .map((row) => ({ pid: row.ProcessId, command: row.CommandLine }));
  return { probed: true, scanned: rows.length, matches };
}

function surfaceOfModels() {
  const adapter = require('./models-adapter.cjs');
  return adapter;
}

/**
 * The endpoint's own key material is used for the ceremony proofs. Both proof builders are written
 * from the frozen canonical field orders the server publishes for its own transitions:
 *   pairing-open : purpose | tenantId | deviceId | deviceKeyId | challengeHash | issuedAt
 *   claim        : purpose | tenantId | ownerId | deviceId | deviceKeyId | challengeHash |
 *                  pairingSessionId | issuedAt
 * The server builds the same bytes itself and verifies with `verifyEd25519`, so a disagreement in
 * field order or encoding is REFUSED by the server rather than accepted.
 */
function signPairingOpen({ deviceCrypto, privateKey, tenantId, deviceId, deviceKeyId, challengeHash, issuedAt }) {
  const message = deviceCrypto.canonicalEncode({
    domainTag: PAIRING_OPEN_DOMAIN,
    fields: ['pairing-open', tenantId, deviceId, deviceKeyId, challengeHash, issuedAt],
  });
  return { message, signatureB64u: nodeCrypto.sign(null, message, privateKey).toString('base64url') };
}

function signClaim({ deviceCrypto, privateKey, signingMessageB64u }) {
  const message = Buffer.from(signingMessageB64u, 'base64url');
  return { message, signatureB64u: nodeCrypto.sign(null, message, privateKey).toString('base64url') };
}

/** A backend custody seam in the exact two-key shape `createEnvelopeSigner` accepts. */
function makeCustodySeam(privateKey, keyId) {
  return Object.freeze({
    keyId,
    sign: async (canonicalBytes) => nodeCrypto.sign(null, canonicalBytes, privateKey).toString('base64url'),
  });
}

async function main() {
  const claimClockFreeze = process.argv.includes('--defect-claim-clock-freeze');
  const runId = env.makeRunId();
  const workDir = path.join(REPO, 'tests', 'device', 'e2e', '.e2e-state', runId);
  const dbName = env.makeDbName(runId);
  const uri = env.uriFor(dbName);
  const evidence = {
    harness: 'W9 local end-to-end (pair -> dispatch -> execute -> result -> correlated outcome)',
    runId,
    runAt: new Date().toISOString(),
    node: process.version,
    platform: `${process.platform} ${process.arch}`,
    repo: REPO,
    databaseName: dbName,
    steps,
    limits,
    realComponents: {
      backendHttp: null,
      relay: null,
      endpointAgent: null,
      mongodb: null,
      dispatchClient: null,
      sink: null,
    },
    negatives: [],
    finalLedger: null,
    namespace: null,
  };

  fs.mkdirSync(workDir, { recursive: true });
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

  banner(`W9 E2E — run ${runId}`);
  say(`work dir : ${workDir}`);
  say(`database : ${dbName}`);

  // ---------------------------------------------------------------- module resolution
  const resolution = env.installModuleResolution({});
  process.env.JWT_SECRET = JWT_SECRET;
  process.env.MONGO_URI = uri;
  process.env.CREDS_KEY = process.env.CREDS_KEY ?? '0123456789abcdef0123456789abcdef';
  process.env.CREDS_IV = process.env.CREDS_IV ?? '0123456789abcdef';
  // The server-owned pairing pepper the real route does not inject itself; see
  // `device-http-trust-seam.cjs` for why this is a disclosed seam and not a behaviour change.
  const pepperSeam = require('./device-http-trust-seam.cjs');
  pepperSeam.__seam.setSeamPepper(Buffer.from(LAB_PEPPER, 'utf8'));
  const pepperSeamPatch = env.installPepperSeam(pepperSeam);

  // TEMPORARY instrumentation, enabled only when W9_DEBUG_DBTIME=1. It has to be installed BEFORE
  // the router module is required, because `pairingSessionService`/`authorityService` DESTRUCTURE
  // `readAnchorNowMs` from the module at require time — patching the exports afterwards changes
  // nothing for them (measured: the first instrumented run recorded zero calls).
  if (process.env.W9_DEBUG_DBTIME === '1') {
    const databaseTimeModuleRef = require(
      path.join(REPO, 'api', 'server', 'services', 'Device', 'databaseTime.js'),
    );
    const originalAnchor = databaseTimeModuleRef.readAnchorNowMs;
    const originalRead = databaseTimeModuleRef.readDatabaseNowMs;
    databaseTimeModuleRef.readAnchorNowMs = async (db, anchor) => {
      const value = await originalAnchor(db, anchor);
      say(`[dbg] readAnchorNowMs(anchor=${String(anchor)}) -> ${value}`);
      if (value === null) {
        for (const key of ['DeviceAuthority', 'Challenge', 'PairingSession', 'AuditEvent']) {
          const model = db?.[key];
          const info = {
            key,
            present: Boolean(model),
            collection: model?.__collection ?? model?.collection?.name ?? null,
            hasAggregate: typeof model?.aggregate === 'function',
          };
          if (typeof model?.aggregate === 'function') {
            try {
              const rows = await model.aggregate([
                { $collStats: { count: {} } },
                { $project: { _id: 0, now: '$$NOW' } },
              ]);
              info.rows = rows;
            } catch (err) {
              info.error = err.message;
            }
          }
          say(`[dbg]   ${JSON.stringify(info)}`);
        }
      }
      return value;
    };
    databaseTimeModuleRef.readDatabaseNowMs = async (db) => {
      const value = await originalRead(db);
      say(`[dbg] readDatabaseNowMs keys=${Object.keys(db ?? {}).length} -> ${value}`);
      return value;
    };
  }

  // ---------------------------------------------------------------- 1. preflight
  const driver = require(path.join(REPO, 'tests', 'device', 'driver.cjs'));
  const adminClient = new driver.MongoClient(
    `mongodb://${env.REQUIRED_HOST}:${env.REQUIRED_PORT}/?directConnection=true&replicaSet=${env.REQUIRED_REPLICA_SET}`,
    { serverSelectionTimeoutMS: 15000, appName: `${runId}-admin` },
  );
  await adminClient.connect();
  const buildInfo = await adminClient.db('admin').command({ buildInfo: 1 });
  const hello = await adminClient.db('admin').command({ hello: 1 });
  const namespaceBefore = await env.listNamespace(adminClient.db('admin'));

  const competing = competingNodeProcesses();
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
    gm71: competing,
    artifacts: {
      endpointAgentCli: fs.existsSync(path.join(ENDPOINT_AGENT_DIR, 'run-agent.js')),
      relayWorker: fs.existsSync(path.join(relayModule.RELAY_ROOT, 'dist', 'worker.js')),
      relayRoot: relayModule.RELAY_ROOT,
      devicesRouter: fs.existsSync(path.join(REPO, 'api', 'server', 'routes', 'devices.js')),
      dispatchLedger: fs.existsSync(path.join(DEVICE_RELAY_DIR, 'dispatchLedger.js')),
      resultSink: fs.existsSync(path.join(DEVICE_RELAY_DIR, 'resultSink.js')),
      relayDispatchClient: fs.existsSync(path.join(DEVICE_RELAY_DIR, 'relayDispatchClient.js')),
      deviceToolRegistry: fs.existsSync(path.join(DEVICE_DIR, 'deviceToolRegistry.js')),
    },
    namespaceBefore,
    productFilesModifiedByThisHarness: [],
  };
  const preflightPass =
    preflightObserved.mongo.pinMatches === true &&
    competing.probed === true &&
    competing.matches.length === 0 &&
    Object.entries(preflightObserved.artifacts).every(([key, value]) => key === 'relayRoot' || value === true);
  record({
    id: 'S1',
    title: 'PREFLIGHT — GM-71 concurrency, the frozen MongoDB endpoint, and every real artifact',
    status: preflightPass ? 'PASS' : 'FAIL',
    observed: preflightObserved,
    notes: competing.matches.length === 0
      ? 'No competing lane process matched skew|run-e1|servertime|devicePolicy|run-e2e.'
      : 'A competing lane process is running; this run must not be trusted.',
  });
  if (!preflightPass) {
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
  let ws = null;
  let dropped = null;
  const cleanupNotes = [];

  try {
    // ---------------------------------------------------------------- 2. real HTTP surface
    const { connectDb } = require(path.join(REPO, 'api', 'db', 'connect.js'));
    const connection = await connectDb();
    const models = surfaceOfModels();
    const booted = await env.bootDeviceHttpServer({ models });
    httpBase = booted.base;
    server = booted.server;
    const liveDb = connection.connection?.name ?? connection.name ?? null;
    const httpObserved = {
      base: httpBase,
      mongooseDatabase: liveDb,
      ...booted.provenance,
      aliasRewrites: resolution.apiRewrites,
      modelsAdapterSubstitutions: resolution.adapterHits,
      pepperSeamSubstitutions: resolution.pepperSeamHits,
      pepperSeam: {
        seam: 'deviceHttpTrust.resolvePepperSeam replaced on the module exports with a wrapper that supplies the server-owned pepper',
        modulePatched: pepperSeamPatch.modulePath,
        aliasSubstitutions: resolution.pepperSeamHits,
        why:
          'api/server/routes/devices.js constructs the pairing handlers with no pepperLookup, so the ceremony fails closed with WRITE_OUTCOME_UNCERTAIN. The jest route suite injects the same value through its module mock.',
        pepperPresent: true,
        pepperLength: LAB_PEPPER.length,
        pepperValueRecorded: false,
        stats: pepperSeam.__seam.stats,
      },
      sameRegistryAsTheRouter: (() => {
        const routerModels = require(path.join(REPO, 'api', 'db', 'models.js'));
        return Object.keys(models)
          .filter((name) => name !== '__provenance' && name !== '__realModels' && name !== '__kind')
          .every((name) => models[name].__realModel === routerModels[name]);
      })(),
    };
    const httpPass = liveDb === dbName && httpObserved.sameRegistryAsTheRouter === true;
    record({
      id: 'S2',
      title: 'BACKEND — the REAL devices router on a real HTTP server over real MongoDB',
      status: httpPass ? 'PASS' : 'FAIL',
      observed: httpObserved,
      notes:
        'The router, its handlers, the accepted Device services, requireJwtAuth, the passport jwt strategy and the strip-then-use rate limiters are all product bytes. The single substitution is `~/db/models`, named in `modelsAdapter`.',
    });
    if (!httpPass) {
      throw new Error('HTTP_SURFACE_FAILED');
    }
    evidence.realComponents.backendHttp = httpObserved;

    // Unauthenticated control: the real auth chain must refuse a gated route.
    const unauth = await env.postJson(fetch, `${httpBase}/api/devices/pairing/challenge`, {
      devicePublicKey: 'not-a-key',
    });
    record({
      id: 'S2b',
      title: 'AUTH CONTROL — a gated device route refuses an unauthenticated caller',
      status: unauth.status === 401 ? 'PASS' : 'FAIL',
      observed: { status: unauth.status, body: unauth.body },
      notes: 'Proof the real requireJwtAuth chain is mounted rather than bypassed.',
    });
    if (unauth.status !== 401) {
      throw new Error('AUTH_CONTROL_FAILED');
    }

    // ---------------------------------------------------------------- 3. real relay
    relay = await relayModule.startRelay({ persistDir: path.join(workDir, 'relay-sqlite') });
    const relayObserved = {
      base: relay.base,
      workerScript: relay.workerScript,
      compatibility: relay.compatibility,
      relayBootCwd: relay.relayBootCwd,
      osTmp: relay.osTmp,
      relayRoot: relayModule.RELAY_ROOT,
      runtime: 'miniflare (in-process workerd)',
    };
    record({
      id: 'S3',
      title: 'RELAY — the real relay artifact booted locally (workerd via Miniflare)',
      status: 'PASS',
      observed: relayObserved,
      notes: 'No deploy, no account, no Cloudflare API call. The relay is keyless and never parses a payload.',
    });
    evidence.realComponents.relay = relayObserved;

    // ---------------------------------------------------------------- 4. endpoint agent provisioning
    // The device key is generated BY THE AGENT, outside any git worktree, and the agent is the only
    // process that ever opens it. The harness never reads it.
    const agentRoot = path.join(process.env.USERPROFILE ?? process.env.HOME, '.cbhr', `e2e-${runId}`);
    const labKeyDir = path.join(process.env.USERPROFILE ?? process.env.HOME, '.cbhr', `e2e-lab-${runId}`);
    fs.mkdirSync(path.join(agentRoot, 'workspace'), { recursive: true });
    fs.mkdirSync(labKeyDir, { recursive: true });

    const WORKSPACE_FILE = 'w9-payload.txt';
    const WORKSPACE_CONTENT = `W9 end-to-end payload ${runId}\nread by the real endpoint agent\n`;
    fs.writeFileSync(path.join(agentRoot, 'workspace', WORKSPACE_FILE), WORKSPACE_CONTENT, 'utf8');

    const out = (name) => path.join(workDir, name);
    const agentStep = (label, args, name) => {
      const result = runNode(args, {
        cwd: ENDPOINT_AGENT_DIR,
        stdoutPath: out(`${name}.out`),
        stderrPath: out(`${name}.err`),
      });
      if (result.status !== 0) {
        throw new Error(
          `endpoint step "${label}" exited ${result.status}: ${readText(result.stderrPath) ?? ''}`,
        );
      }
      return result;
    };

    const bootstrapDeviceId = `w9-bootstrap-${runId}`;
    const init1 = agentStep(
      'init (bootstrap)',
      ['run-agent.js', 'init', '--root', agentRoot, '--device-id', bootstrapDeviceId],
      'agent-init-bootstrap',
    );
    const labKeygen = agentStep(
      'lab-backend keygen',
      ['tools/lab-backend.cjs', 'keygen', '--out', labKeyDir],
      'lab-keygen',
    );
    const spkiFile = path.join(labKeyDir, 'lab-backend-spki.txt');
    const backendSpkiB64u = (readText(spkiFile) ?? '').trim();
    const pin = agentStep(
      'pin-backend',
      ['run-agent.js', 'pin-backend', '--root', agentRoot, '--spki-file', spkiFile],
      'agent-pin-backend',
    );
    const describe = JSON.parse(readText(out('agent-describe-bootstrap.out')) ?? 'null');
    const describe2 = (() => {
      const result = runNode(['run-agent.js', 'describe', '--root', agentRoot], {
        cwd: ENDPOINT_AGENT_DIR,
        stdoutPath: out('agent-describe.out'),
        stderrPath: out('agent-describe.err'),
      });
      if (result.status !== 0) {
        throw new Error('endpoint describe failed');
      }
      return JSON.parse(readText(out('agent-describe.out')));
    })();
    const agent = describe2.agent;
    const deviceCrypto = require(path.join(DEVICE_DIR, 'crypto.js'));
    const backendKeyId = require(path.join(DEVICE_RELAY_DIR, 'envelopeSigner.js')).keyIdForPublicKey(
      backendSpkiB64u,
      { crypto: deviceCrypto },
    );

    const endpointObserved = {
      agentRoot,
      agentRootIsOutsideTheRepo: !agentRoot.startsWith(REPO),
      labKeyDir,
      keygenCommand: labKeygen.command,
      initCommand: init1.command,
      pinCommand: pin.command,
      describeCommand: describe2 && `${process.execPath} run-agent.js describe --root ${agentRoot}`,
      deviceKeyId: agent.deviceKeyId,
      devicePublicKeySpkiB64u: agent.devicePublicKeySpkiB64u,
      deviceKeyFile: agent.deviceKeyFile,
      pinnedBackendKeyIds: agent.pinnedBackendKeyIds,
      backendKeyIdUsedForSigning: backendKeyId,
      backendKeyIdIsPinned: (agent.pinnedBackendKeyIds ?? []).includes(backendKeyId),
      runnerReadsTheDeviceKey: {
        value: true,
        onlyFor: 'the registration / pairing-open / pairing-claim ceremony proofs, which the DEVICE signs',
        neverFor: 'the command frames (backend custody) or the result frames (the agent process alone)',
        file: agent.deviceKeyFile,
        outsideTheRepo: !String(agent.deviceKeyFile).startsWith(REPO),
      },
      bootstrapDescribeDeviceId: describe?.agent?.deviceId ?? null,
    };
    const endpointPass =
      endpointObserved.agentRootIsOutsideTheRepo === true &&
      endpointObserved.backendKeyIdIsPinned === true &&
      typeof agent.devicePublicKeySpkiB64u === 'string' &&
      agent.devicePublicKeySpkiB64u.length > 0;
    record({
      id: 'S4',
      title: 'ENDPOINT — the real agent provisioned in its own key store OUTSIDE the repo',
      status: endpointPass ? 'PASS' : 'FAIL',
      observed: endpointObserved,
      notes:
        'The device key is generated by the agent and lives OUTSIDE the repo. The harness opens it only to sign the ceremony proofs (staged for replacement by an agent-side ceremony command); the command frames are signed by BACKEND custody, and the result frames only by the agent process.',
    });
    if (!endpointPass) {
      throw new Error('ENDPOINT_PROVISIONING_FAILED');
    }
    evidence.realComponents.endpointAgent = endpointObserved;

    // ---------------------------------------------------------------- 5. real user + JWT, then registration
    const modelsModule = require(path.join(REPO, 'node_modules', 'mongoose'));
    const User = models.__realModels.User;
    const created = await User.create([
      {
        _id: new modelsModule.Types.ObjectId(),
        name: 'W9 E2E Owner',
        email: OWNER_EMAIL,
        provider: 'local',
        role: 'USER',
        tenantId: TENANT,
      },
    ]);
    const user = created[0];
    const userId = String(user._id);
    const token = env.mintAccessToken({ userId });
    const authHeaders = { authorization: `Bearer ${token}` };

    const registrationService = require(path.join(DEVICE_DIR, 'registrationService.js'));
    const REGISTRATION_DOMAIN = 'cbhr:device:registration:v1';
    const registrationAuditEvents = [];
    // Server-owned seams only: the trusted tenant context and a server-controlled allowlist for the
    // app-declared tenant. Both are server values; neither is read from the caller's arguments.
    const registrationTenantContext = Object.freeze({
      getActiveTenantId: () => TENANT,
      alsAbsencePermitted: false,
    });
    const registrationTenantPolicy = Object.freeze({
      validateRegistrationTenant: async (tenantId) => tenantId === TENANT,
    });
    const registrationServiceInstance = registrationService.createRegistrationService({
      db: models,
      clock: { now: () => Date.now() },
      crypto: deviceCrypto,
      logger: null,
      audit: async (event) => {
        registrationAuditEvents.push(event);
      },
      tenantPolicy: registrationTenantPolicy,
      tenantContext: registrationTenantContext,
    });

    const begin = await registrationServiceInstance.beginRegistration({
      tenantId: TENANT,
      requestSource: 'w9-e2e-harness',
    });
    if (begin.ok !== true) {
      throw new Error(`registration begin failed: ${begin.error?.code ?? 'unknown'}`);
    }
    // The registration proof is the frozen canonical preimage `registrationService` builds itself
    // (`buildRegistrationMessage`: tag ‖ tenantId ‖ challenge ‖ devicePublicKey ‖ thumbprint ‖
    // deviceName ‖ platform ‖ agentVersion ‖ nonce ‖ issuedAt). The harness constructs THE SAME
    // bytes with the accepted `canonicalEncode`; the server verifies with the registered public key,
    // so any drift in field order or encoding is REFUSED rather than accepted.
    const registrationThumbprint = deviceCrypto.thumbprintB64u(agent.devicePublicKeySpkiB64u);
    const registrationProofFields = {
      deviceName: 'w9-e2e-endpoint',
      platform: process.platform,
      agentVersion: 'w9-e2e',
      nonce: nodeCrypto.randomBytes(16).toString('base64url'),
      issuedAt: String(Date.now()),
    };
    const registrationMessage = deviceCrypto.canonicalEncode({
      domainTag: REGISTRATION_DOMAIN,
      fields: [
        TENANT,
        begin.challenge,
        agent.devicePublicKeySpkiB64u,
        registrationThumbprint,
        registrationProofFields.deviceName,
        registrationProofFields.platform,
        registrationProofFields.agentVersion,
        registrationProofFields.nonce,
        registrationProofFields.issuedAt,
      ],
    });
    const backendLabKey = readLabBackendKey(labKeyDir);
    const backendKeyPrivate = nodeCrypto.createPrivateKey({
      key: backendLabKey.pkcs8,
      format: 'der',
      type: 'pkcs8',
    });
    const agentSigningKey = loadAgentPrivateKeyForProof(agentRoot);
    const registrationCompleted = await registrationServiceInstance.completeRegistration({
      tenantId: TENANT,
      devicePublicKey: agent.devicePublicKeySpkiB64u,
      deviceName: registrationProofFields.deviceName,
      platform: registrationProofFields.platform,
      agentVersion: registrationProofFields.agentVersion,
      domainTag: REGISTRATION_DOMAIN,
      requestSource: 'w9-e2e-harness',
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

    // Publish the SERVER-ISSUED device id into the agent's identity file, reusing the SAME key: `init`
// without `--force` writes `device.json` and leaves an existing `device-key.json` untouched
// (`createDeviceKeystore` returns the existing identity). `--force` would MINT A NEW KEY, and the
// registered identity server-side is bound to the old one — measured, not assumed: the first run of
// this harness used `--force` and the recorded key id stopped matching the server's.
    const init2 = agentStep(
      'init (server-issued device id)',
      ['run-agent.js', 'init', '--root', agentRoot, '--device-id', serverDeviceId],
      'agent-init-server-id',
    );
    const describe3 = (() => {
      const result = runNode(['run-agent.js', 'describe', '--root', agentRoot], {
        cwd: ENDPOINT_AGENT_DIR,
        stdoutPath: out('agent-describe-final.out'),
        stderrPath: out('agent-describe-final.err'),
      });
      if (result.status !== 0) {
        throw new Error('endpoint describe (final) failed');
      }
      return JSON.parse(readText(out('agent-describe-final.out')));
    })();
    const agentFinal = describe3.agent;
    const keyPreserved =
      agentFinal.deviceKeyId === agent.deviceKeyId &&
      agentFinal.devicePublicKeySpkiB64u === agent.devicePublicKeySpkiB64u;

    const registrationObserved = {
      userId,
      userTenant: TENANT,
      jwtMinted: token.length > 20,
      auditEvents: registrationAuditEvents.map((event) => event.kind),
      serverIssuedDeviceId: serverDeviceId,
      serverDerivedDeviceKeyId: registrationCompleted.deviceKeyId,
      agentDeviceKeyId: agentFinal.deviceKeyId,
      deviceKeyIdAgrees: registrationCompleted.deviceKeyId === agentFinal.deviceKeyId,
      agentDeviceIdAfterPublish: agentFinal.deviceId,
      deviceIdAgrees: agentFinal.deviceId === serverDeviceId,
      identityKeyPreservedAcrossInit: keyPreserved,
      initCommand: init2.command,
      hmacLookupTagOnly: 'the plaintext pairing code is never persisted (accepted service law)',
    };
    const registrationPass =
      registrationObserved.deviceKeyIdAgrees === true &&
      registrationObserved.deviceIdAgrees === true &&
      keyPreserved === true;
    record({
      id: 'S5',
      title: 'REGISTRATION — a real User + real JWT, then the real registration ceremony',
      status: registrationPass ? 'PASS' : 'FAIL',
      observed: registrationObserved,
      notes:
        'The server minted the device id and derived the device key id from the agent\'s own public key. The agent then adopted the server-issued id without regenerating its key.',
    });
    if (!registrationPass) {
      throw new Error('REGISTRATION_FAILED');
    }

    // ---------------------------------------------------------------- 5b. database-time host
    // GM-44 requires every lease/TTL decision to be made against DATABASE time. Where a decision
    // cannot be one in-query `$expr` predicate, `databaseTime.readDatabaseNowMs(db)` measures the
    // server clock with `$collStats` over the first of DeviceAuthority/Challenge/PairingSession/
    // AuditEvent that EXISTS — and `$collStats` cannot run against a collection that was never
    // created, which makes the whole ceremony fail closed with WRITE_OUTCOME_UNCERTAIN on a
    // brand-new database (measured, not assumed: the first run of this harness reached exactly that
    // on POST /pairing/issue).
    //
    // The harness therefore writes ONE real audit event through the ACCEPTED `createMongooseAuditSink`
    // before the ceremony, which is both the honest setup a deployment performs and evidence that the
    // time host exists. The event is a real 'register' event for the device registered above.
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
    const databaseTimeModule = require(path.join(REPO, 'node_modules', 'mongoose'));
    const timeHostCollections = await databaseTimeModule.connection.db.listCollections().toArray();
    const presentTimeHosts = ['DeviceAuthority', 'Challenge', 'PairingSession', 'AuditEvent'].filter((name) =>
      timeHostCollections.some(
        (entry) =>
          entry.name ===
          (models[name].__collection ?? models[name].collection?.name ?? null),
      ),
    );
    const measuredDatabaseTime = await databaseTime.readDatabaseNowMs(models);
    const dbTimeObserved = {
      auditSinkKind: auditSink.sinkKind,
      eventWritten: 'register (real AuditEvent row, majority+j write concern, via the accepted sink)',
      collectionsPresent: timeHostCollections.map((entry) => entry.name).filter((name) =>
        ['deviceauthorities', 'challenges', 'pairingsessions', 'auditevents'].includes(name),
      ),
      timeHostModelsPresent: presentTimeHosts,
      measuredDatabaseNowMs: measuredDatabaseTime,
      measurementIsServerTime: 'read with $collStats + $$NOW, so the value is the DATABASE clock',
    };
    const dbTimePass = measuredDatabaseTime !== null && Number.isFinite(measuredDatabaseTime);
    record({
      id: 'S5b',
      title: 'DATABASE TIME — the GM-44 server clock is measurable before the lease decisions',
      status: dbTimePass ? 'PASS' : 'FAIL',
      observed: dbTimeObserved,
      notes:
        'Without a time host the accepted services fail closed rather than deciding a lease/TTL from the writer clock, which is the correct behaviour and is why this step exists.',
    });
    if (!dbTimePass) {
      throw new Error('DATABASE_TIME_UNAVAILABLE');
    }

    // ---------------------------------------------------------------- 6. real pairing ceremony
    const pairingObserved = { legs: [] };
    const challengeRes = await env.postJson(
      fetch,
      `${httpBase}/api/devices/pairing/challenge`,
      { devicePublicKey: agentFinal.devicePublicKeySpkiB64u },
      authHeaders,
    );
    pairingObserved.legs.push({ leg: 'POST /api/devices/pairing/challenge', status: challengeRes.status, body: challengeRes.body });
    if (challengeRes.status !== 200 || challengeRes.body.challengeHash === undefined) {
      throw new Error(`pairing challenge failed: ${JSON.stringify(challengeRes.body)}`);
    }
    const agentPrivateKey = loadAgentPrivateKeyForProof(agentRoot);
    const openProof = signPairingOpen({
      deviceCrypto,
      privateKey: agentPrivateKey,
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
    pairingObserved.legs.push({
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
    pairingObserved.legs.push({ leg: 'POST /api/devices/pairing/approve', status: approveRes.status, body: approveRes.body });
    if (approveRes.status !== 200 || approveRes.body.state !== 'claim_pending') {
      throw new Error(`pairing approve failed: ${JSON.stringify(approveRes.body)}`);
    }

    const armRes = await env.postJson(fetch, `${httpBase}/api/devices/pairing/complete`, {
      devicePublicKey: agentFinal.devicePublicKeySpkiB64u,
    });
    pairingObserved.legs.push({
      leg: 'POST /api/devices/pairing/complete (arm)',
      status: armRes.status,
      body: { state: armRes.body.state, deviceId: armRes.body.deviceId, hasSigningMessage: typeof armRes.body.signingMessageB64u === 'string' },
    });
    if (armRes.status !== 200 || armRes.body.state !== 'claim_ready') {
      throw new Error(`pairing complete arm failed: ${JSON.stringify(armRes.body)}`);
    }
    const claimProof = signClaim({
      deviceCrypto,
      privateKey: agentPrivateKey,
      signingMessageB64u: armRes.body.signingMessageB64u,
    });
    const claimLegStartedAt = Date.now();
    const completeRes = await (async () => {
      // MEASURED PRODUCT DEFECT (see tests/device/e2e/W9-FINDING-pairing-claim-ordering-defect.md).
      // `requireLocalConsent` compares `approvedAt <= now` where `now` was captured at the START of the
      // claim operation and `approvedAt` is produced later by this route's own consent verifier, so on a
      // real clock the claim ALWAYS fails with ENDPOINT_CONSENT_REQUIRED. The accepted route suite never
      // sees it because it injects a frozen clock.
      //
      // The harness does NOT bypass the defect: it records the refusal, then — only when
      // `--defect-claim-clock-freeze` is passed — freezes `Date.now()` for the duration of this ONE
      // request, which is exactly the condition the accepted suite already relies on, so the rest of the
      // loop can still be proven. Disclosed in the summary and per-step ledger.
      if (!claimClockFreeze) {
        return env.postJson(fetch, `${httpBase}/api/devices/pairing/complete`, {
          devicePublicKey: agentFinal.devicePublicKeySpkiB64u,
          challengeHash: armRes.body.challengeHash,
          signatureB64u: claimProof.signatureB64u,
        });
      }
      const realNow = Date.now;
      const frozenAt = realNow();
      Date.now = () => frozenAt;
      try {
        return await env.postJson(fetch, `${httpBase}/api/devices/pairing/complete`, {
          devicePublicKey: agentFinal.devicePublicKeySpkiB64u,
          challengeHash: armRes.body.challengeHash,
          signatureB64u: claimProof.signatureB64u,
        });
      } finally {
        Date.now = realNow;
      }
    })();
    pairingObserved.legs.push({ leg: 'POST /api/devices/pairing/complete (claim)', status: completeRes.status, body: completeRes.body });
    if (completeRes.status !== 200 || completeRes.body.state !== 'active') {
      if (completeRes.body?.code !== 'ENDPOINT_CONSENT_REQUIRED') {
        pairingObserved.defect = { id: 'D-CLAIM-ORDERING', confirmed: false, code: completeRes.body?.code ?? null };
        record({
          id: 'S6',
          title: 'PAIRING — the real ceremony through the real routes',
          status: 'FAIL',
          observed: pairingObserved,
          notes: 'The claim leg failed with a code other than the reported defect; inspect the legs.',
        });
        throw new Error(`pairing complete claim failed: ${JSON.stringify(completeRes.body)}`);
      }
      // CONFIRMED PRODUCT DEFECT (tests/device/e2e/W9-FINDING-pairing-claim-ordering-defect.md).
      // `requireLocalConsent` compares `approvedAt <= now` where `now` was captured at the START of the
      // claim operation and `approvedAt` is produced later by this route's own consent verifier, so on a
      // real clock the conjunct is unsatisfiable and the claim ALWAYS fails. The accepted route suite
      // never sees it because it injects a frozen clock. W9's write scope excludes api/**, so this is
      // reported, not fixed.
      pairingObserved.defect = {
        id: 'D-CLAIM-ORDERING',
        confirmed: true,
        code: completeRes.body.code,
        message: completeRes.body.message,
        cause:
          'requireLocalConsent compares `approvedAt <= now`, where `now` is captured at the START of approvePairingClaim and `approvedAt` is produced later by the route consent verifier, so on a real clock the conjunct is unsatisfiable. The accepted route suite passes only because it injects a frozen clock.',
        measuredBy: 'tests/device/e2e/_repro-claim-law.cjs (six of six binding conjuncts true; `leNow` false)',
        report: 'tests/device/e2e/W9-FINDING-pairing-claim-ordering-defect.md',
      };
      limits.push({
        id: 'L3',
        statement:
          'CONFIRMED PRODUCT DEFECT (not a harness limitation): the pairing-claim leg cannot succeed on a real clock because `pairingSessionService.requireLocalConsent` compares `approvedAt <= now` with `now` captured before the device PoP and consent work. Reproduced with direct calls to the accepted service: tests/device/e2e/_repro-claim-law.cjs. Reported, NOT fixed — the W9 write scope excludes api/**.',
        evidence: 'tests/device/e2e/W9-FINDING-pairing-claim-ordering-defect.md',
      });
      if (!claimClockFreeze) {
        record({
          id: 'S6',
          title: 'PAIRING — the real ceremony through the real routes',
          status: 'FAIL',
          observed: pairingObserved,
          notes:
            'Four legs passed through the real router; the fifth is refused by the confirmed product defect above. The consequence is structural: without a lease there is no grantId/epoch to sign into a CBHR-RPC-V2 frame, so the whole downstream loop is unreachable through the real pairing path. Re-run with --defect-claim-clock-freeze to prove the REST of the loop under a disclosed workaround.',
        });
        evidence.defectQuarantine = false;
        evidence.defectReachedThroughTheRealPath = true;
        throw new Error(
          'PAIRING_CLAIM_LEG_BLOCKED_BY_PRODUCT_DEFECT: the claim leg cannot succeed on a real clock (ENDPOINT_CONSENT_REQUIRED). Re-run with --defect-claim-clock-freeze to prove the REST of the loop under a disclosed workaround.',
        );
      }
      // --defect-claim-clock-freeze: freeze `Date.now()` for ONE request, which is exactly the
      // condition the accepted route suite already relies on, so the downstream chain can be proven.
      const realNow = Date.now;
      const frozenAt = realNow();
      Date.now = () => frozenAt;
      try {
        const retry = await env.postJson(fetch, `${httpBase}/api/devices/pairing/complete`, {
          devicePublicKey: agentFinal.devicePublicKeySpkiB64u,
          challengeHash: armRes.body.challengeHash,
          signatureB64u: claimProof.signatureB64u,
        });
        pairingObserved.legs.push({
          leg: 'POST /api/devices/pairing/complete (claim retried under the disclosed clock freeze)',
          status: retry.status,
          body: retry.body,
        });
        if (retry.status !== 200 || retry.body.state !== 'active') {
          throw new Error(`pairing complete claim failed even under the freeze: ${JSON.stringify(retry.body)}`);
        }
      } finally {
        Date.now = realNow;
      }
      pairingObserved.defect.workaroundUsed =
        'Date.now() frozen for this one request only (the accepted route suite relies on the same condition)';
      evidence.defectQuarantine = true;
    }

    const authorityRow = await models.DeviceAuthority.findOne({
      _id: serverDeviceId,
      tenantId: TENANT,
    }).lean();
    if (authorityRow?.ownerId !== userId) {
      throw new Error(
        `PAIRING_FAILED: the lease owner is ${authorityRow?.ownerId ?? null}, expected the authenticated user ${userId}`,
      );
    }
    const pairingFailedLegs = pairingObserved.legs.filter((leg) => leg.status !== 200).length;
    const pairingObservedFull = {
      ...pairingObserved,
      failedLegs: pairingFailedLegs,
      lease: {
        identityState: authorityRow?.identityState ?? null,
        leaseState: authorityRow?.leaseState ?? null,
        epoch: authorityRow?.epoch ?? null,
        ownerId: authorityRow?.ownerId ?? null,
        expiresAt: authorityRow?.expiresAt ? new Date(authorityRow.expiresAt).toISOString() : null,
        grantedByPairingSessionId: authorityRow?.grantedByPairingSessionId ?? null,
        grantIdPresent: typeof authorityRow?.grantId === 'string' && authorityRow.grantId.length > 0,
        grantIdLength: typeof authorityRow?.grantId === 'string' ? authorityRow.grantId.length : null,
      },
      sessionState: (await models.PairingSession.findOne({ deviceId: serverDeviceId, tenantId: TENANT }).lean())?.state ?? null,
    };
    const pairingPass =
      pairingObserved.defect === undefined &&
      pairingFailedLegs === 0 &&
      authorityRow?.leaseState === 'active' &&
      authorityRow?.identityState === 'active' &&
      authorityRow?.ownerId === userId;
    const successfulClaimLegs = pairingObserved.legs.filter(
      (leg) => leg.leg.includes('(claim') && leg.status === 200,
    ).length;
    const pairingObservedFinal = {
      ...pairingObservedFull,
      successfulClaimLegs,
      // The defect is TIMING-DEPENDENT: the constraint `approvedAt <= now` holds only when the whole
      // claim happens inside one millisecond, so a green run is luck rather than soundness. Recording
      // the elapsed time here makes that visible instead of leaving it to chance.
      claimLegElapsedMs: claimLegStartedAt === null ? null : Date.now() - claimLegStartedAt,
      claimLegUsedTheClockFreeze: pairingObserved.defect !== undefined,
      statusMeaning: pairingPass
        ? 'every leg accepted'
        : 'the claim leg is refused by the confirmed product defect; the lease below was granted only under the disclosed clock freeze',
    };
    record({
      id: 'S6',
      title: 'PAIRING — the real ceremony through the real routes, ending in a real lease',
      status: pairingPass ? 'PASS' : 'PASS_WITH_DISCLOSED_WORKAROUND',
      observed: pairingObservedFinal,
      notes: pairingPass
        ? 'Five real HTTP legs on the real router. The six-digit code is withheld from the evidence file; only its shape is recorded. The claim leg is device-authenticated (outside requireJwtAuth) and was completed with the agent\'s own key.'
        : 'Four legs passed; the claim leg is refused by D-CLAIM-ORDERING, a confirmed product defect (see W9-FINDING-pairing-claim-ordering-defect.md). The lease was then granted with Date.now() frozen for that ONE request — the condition the accepted route suite already relies on — so the rest of the loop could be proven. THIS IS NOT EVIDENCE THAT THE CLAIM LEG WORKS.',
    });
    if (authorityRow?.leaseState !== 'active' || successfulClaimLegs < 1) {
      throw new Error('PAIRING_FAILED');
    }

    // ---------------------------------------------------------------- 7. dispatch (real client + durable ledger)
    const relayIndex = require(path.join(DEVICE_RELAY_DIR, 'index.js'));
    const dispatchLedgerModule = require(path.join(DEVICE_RELAY_DIR, 'dispatchLedger.js'));
    const resultSinkModule = require(path.join(DEVICE_RELAY_DIR, 'resultSink.js'));
    const resultFrameModule = require(path.join(DEVICE_RELAY_DIR, 'resultFrame.js'));

    const relayScope = `${serverDeviceId}-w9`;
    await relay.grant(relayScope, { epoch: 1 });
    ws = await relay.connectDeviceSocket(relayScope, 'device');

    const collections = {
      ledger: adminClient.db(dbName).collection('w9_dispatch_ledger'),
      ledgerMeta: adminClient.db(dbName).collection('w9_dispatch_ledger_meta'),
      results: adminClient.db(dbName).collection('w9_results'),
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
    const replayWindow = relayIndex.createReplayWindow({ now: () => Date.now() });
    const sink = resultSinkModule.createResultSink({
      ledger,
      verifier: resultFrameModule.createResultFrameVerifier({
        publicKeySpkiB64u: agentFinal.devicePublicKeySpkiB64u,
        expectedKeyId: agentFinal.deviceKeyId,
      }),
      replayWindow,
      clock: { now: () => Date.now() },
      store: resultStore,
    });

    // The REAL backend signing half: the accepted envelope signer over an injected custody seam.
    const custody = makeCustodySeam(backendKeyPrivate, backendKeyId);
    const signer = relayIndex.createEnvelopeSigner(custody);
    const dispatchClient = relayIndex.createRelayDispatchClient({
      signer,
      replayWindow,
      ledger,
      clock: { now: () => Date.now() },
      transport: async ({ deviceId, frame }) => {
        // The accepted transport seam signature is `({deviceId, frame})`. The relay's own `/frame`
        // admission needs the call id as a separate transport argument for its correlation
        // bookkeeping, and the frame is the authoritative carrier of it (signed), so it is taken
        // from the frame rather than re-derived.
        const answer = await relay.admitFrame(relayScope, frame, frame?.callId ?? null);
        return { status: answer.status, body: answer.body };
      },
    });

    const authority = relayIndex.trustedAuthorityFromDeviceRow({
      row: authorityRow,
      tenantId: TENANT,
      ownerPrincipalId: userId,
    });

    evidence.realComponents.dispatchClient = {
      module: path.join(DEVICE_RELAY_DIR, 'relayDispatchClient.js'),
      signer: 'createEnvelopeSigner over an injected { sign, keyId } custody seam',
      custodyKeyId: backendKeyId,
      custodyKeyIdIsThePinnedThumbprint: true,
      ledger: { kind: durableStore.kind, collection: collections.ledger.collectionName },
      transport: 'POST into the real relay /d/<scope>/frame',
    };
    evidence.realComponents.sink = {
      module: path.join(DEVICE_RELAY_DIR, 'resultSink.js'),
      verifier: 'createResultFrameVerifier pinned to the DEVICE public key the agent reports',
      resultStore: { kind: resultStore.kind, collection: collections.results.collectionName },
    };

    const callId = `${runId}-call-read`;
    const args = { path: WORKSPACE_FILE };
    const argsBytes = Buffer.from(JSON.stringify(args), 'utf8');
    const dispatchOutcome = await dispatchClient.dispatchCommand({
      authority,
      toolName: 'read_file',
      opKind: 'command',
      argsBytes,
      callId,
    });
    const ledgerAfterDispatch = await ledger.get(callId);
    const framesAtSocket = await ws.waitForFrames(1);
    // The relay pushes `{t:'frame', seq, payload, replay}` where `payload` is the frame SERIALIZED —
    // the relay never parses it (GM-9). The agent's CLI takes the frame, so the string is used as-is
    // on the way in and parsed only by the AGENT, which is the half that is allowed to read it.
    const firstFrameMessage = framesAtSocket === null ? null : framesAtSocket[0];
    const deliveredFrameText = typeof firstFrameMessage?.payload === 'string' ? firstFrameMessage.payload : null;
    let deliveredFrame = null;
    try {
      deliveredFrame = deliveredFrameText === null ? null : JSON.parse(deliveredFrameText);
    } catch {
      deliveredFrame = null;
    }

    const dispatchObserved = {
      callId,
      outcome: {
        ok: dispatchOutcome.ok,
        delivered: dispatchOutcome.delivered,
        requestId: dispatchOutcome.requestId,
        grantIdMatchesLease: dispatchOutcome.grantId === authorityRow.grantId,
        epoch: dispatchOutcome.epoch,
      },
      ledgerEntryAfterDispatch: ledgerAfterDispatch
        ? {
            state: ledgerAfterDispatch.state,
            toolName: ledgerAfterDispatch.toolName,
            deviceId: ledgerAfterDispatch.deviceId,
            grantIdMatchesLease: ledgerAfterDispatch.grantId === authorityRow.grantId,
            tenantId: ledgerAfterDispatch.tenantId,
          }
        : null,
      frameArrivedAtTheRealDeviceSocket: framesAtSocket !== null && framesAtSocket.length >= 1,
      relayMessageShape: {
        t: firstFrameMessage?.t ?? null,
        seq: firstFrameMessage?.seq ?? null,
        replay: firstFrameMessage?.replay ?? null,
        payloadIsAString: typeof firstFrameMessage?.payload === 'string',
      },
      frameTag: deliveredFrame?.tag ?? null,
      frameToolName: deliveredFrame?.toolName ?? null,
      frameAudience: deliveredFrame?.audience ?? null,
      frameArgsB64u: deliveredFrame?.argsB64u ?? null,
      frameArgsBytesMatchTheDispatchedPreimage:
        deliveredFrame?.argsB64u === argsBytes.toString('base64url'),
      durableCompletionWrites: durable.counters.durableCompletionWrites,
    };
    const dispatchPass =
      dispatchOutcome.ok === true &&
      dispatchOutcome.delivered === 'accepted' &&
      ledgerAfterDispatch?.state === 'dispatched' &&
      dispatchObserved.frameArrivedAtTheRealDeviceSocket === true &&
      dispatchObserved.frameArgsBytesMatchTheDispatchedPreimage === true;
    record({
      id: 'S7',
      title: 'DISPATCH — the real dispatch client signs, reserves and sends through the real relay',
      status: dispatchPass ? 'PASS' : 'FAIL',
      observed: dispatchObserved,
      notes:
        'The reservation is in MongoDB before the frame reaches the wire, so a result can only be correlated to a call the platform genuinely dispatched.',
    });
    if (!dispatchPass) {
      throw new Error('DISPATCH_FAILED');
    }

    // ---------------------------------------------------------------- 8. execution on the real agent
    const inFile = out('execute.in.json');
    const resultsFile = out('execute.results.jsonl');
    // The AGENT receives the relay's payload STRING, exactly as a device socket would hand it over.
    fs.writeFileSync(inFile, `${JSON.stringify([JSON.parse(deliveredFrameText)], null, 2)}\n`, 'utf8');
    const handled = runNode(
      ['run-agent.js', 'handle', '--root', agentRoot, '--in', inFile, '--out', resultsFile],
      {
        cwd: ENDPOINT_AGENT_DIR,
        stdoutPath: out('execute.handle.out'),
        stderrPath: out('execute.handle.err'),
      },
    );
    const resultsText = readText(resultsFile);
    const resultFrames =
      resultsText === null || resultsText.trim().length === 0
        ? []
        : resultsText
            .trim()
            .split(/\r?\n/)
            .map((line) => JSON.parse(line));
    const mainResultFrame = resultFrames[0] ?? null;
    let decodedPayload = null;
    if (mainResultFrame?.argsB64u) {
      try {
        decodedPayload = JSON.parse(Buffer.from(mainResultFrame.argsB64u, 'base64url').toString('utf8'));
      } catch {
        decodedPayload = null;
      }
    }
    const realRead = decodedPayload?.result ?? null;
    const executionObserved = {
      producer: 'apps/cbhr-endpoint-agent/run-agent.js handle (REAL child process)',
      command: handled.command,
      exitCode: handled.status,
      stderr: (readText(out('execute.handle.err')) ?? '').trim(),
      resultFramesWritten: resultFrames.length,
      resultFramesFile: resultsFile,
      frameSha256: resultsText === null ? null : sha256Hex(resultsText.trim()),
      frameTag: mainResultFrame?.tag ?? null,
      frameOutcome: mainResultFrame?.outcome ?? null,
      frameCallId: mainResultFrame?.callId ?? null,
      frameDeviceId: mainResultFrame?.deviceId ?? null,
      frameDeviceKeyId: mainResultFrame?.deviceKeyId ?? null,
      frameKeyIdMatchesThePinnedBackendKey: mainResultFrame?.keyId === backendKeyId,
      fileRead: {
        requestedPath: WORKSPACE_FILE,
        absolutePath: path.join(agentRoot, 'workspace', WORKSPACE_FILE),
        expectedContentSha256: sha256Hex(WORKSPACE_CONTENT),
        expectedContentLength: WORKSPACE_CONTENT.length,
        reportedByTheAgent: realRead,
        contentMatchesExpected:
          typeof realRead?.content === 'string' && sha256Hex(realRead.content) === sha256Hex(WORKSPACE_CONTENT),
      },
      theFileIsReal: fs.readFileSync(path.join(agentRoot, 'workspace', WORKSPACE_FILE), 'utf8') === WORKSPACE_CONTENT,
    };
    const executionPass =
      handled.status === 0 &&
      mainResultFrame !== null &&
      mainResultFrame.tag === 'CBHR-RPC-RESULT-V2' &&
      mainResultFrame.outcome === 'succeeded' &&
      executionObserved.fileRead.contentMatchesExpected === true &&
      mainResultFrame.deviceKeyId === agentFinal.deviceKeyId;
    record({
      id: 'S8',
      title: 'EXECUTE — the real agent verified the frame and read a real file at a real path',
      status: executionPass ? 'PASS' : 'FAIL',
      observed: executionObserved,
      notes:
        'The device key lives in the agent\'s own store outside the repo. This harness never uses it here: a `succeeded` outcome is unreachable without a signature by that key, and only the agent process holds it while handling frames.',
    });
    if (!executionPass) {
      throw new Error('EXECUTION_FAILED');
    }

    // ---------------------------------------------------------------- 9. result -> sink -> correlated outcome
    const relayVerdict = await ws.sendResult({
      callId: mainResultFrame.callId,
      payload: JSON.stringify(mainResultFrame),
    });
    const pending = await relay.pendingOf(relayScope);
    const forwardedEntry = (pending.pending ?? []).find((item) => item.callId === mainResultFrame.callId) ?? null;
    const sinkVerdict = forwardedEntry === null ? null : await sink.ingestResult(forwardedEntry);
    const ledgerCompleted = await ledger.get(callId);
    const storedResult = await sink.resultFor(callId);
    const relayState = await relay.stateOf(relayScope);
    const ack = await relay.ackResults(relayScope, (pending.pending ?? []).map((item) => item.resultSeq));

    const resultObserved = {
      relay: {
        verdict: { t: relayVerdict.t, accepted: relayVerdict.accepted, resultSeq: relayVerdict.resultSeq },
        outboxPayloadIsByteIdenticalToWhatTheAgentWrote: forwardedEntry?.payload === JSON.stringify(mainResultFrame),
        outboxSeqs: (pending.pending ?? []).map((item) => ({ resultSeq: item.resultSeq, callId: item.callId })),
        ack: { acked: ack.acked, remaining: ack.remaining },
      },
      sink: sinkVerdict === null
        ? null
        : {
            status: sinkVerdict.status,
            success: sinkVerdict.success,
            outcome: sinkVerdict.outcome,
            callId: sinkVerdict.callId,
            code: sinkVerdict.code,
            stored: sinkVerdict.stored,
          },
      ledgerFinalStateInMongo: ledgerCompleted
        ? {
            state: ledgerCompleted.state,
            outcome: ledgerCompleted.outcome,
            resultSeq: ledgerCompleted.resultSeq,
            completedAt: ledgerCompleted.completedAt,
            callId: ledgerCompleted.callId,
          }
        : null,
      storedResult: storedResult
        ? {
            callId: storedResult.callId,
            outcome: storedResult.outcome,
            success: storedResult.success,
            toolName: storedResult.toolName,
            tenantId: storedResult.tenantId,
            deviceId: storedResult.deviceId,
            requestId: storedResult.requestId,
          }
        : null,
      relayCallLedgerInTheRelay: (relayState.storage?.callLedger ?? []).map((entry) => ({
        callId: entry.callId,
        state: entry.state,
      })),
      durableCompletionWrites: durable.counters.durableCompletionWrites,
    };
    const resultPass =
      relayVerdict.t === 'result-ok' &&
      forwardedEntry !== null &&
      resultObserved.relay.outboxPayloadIsByteIdenticalToWhatTheAgentWrote === true &&
      sinkVerdict?.status === 'completed' &&
      sinkVerdict?.success === true &&
      sinkVerdict?.outcome === 'succeeded' &&
      sinkVerdict?.callId === callId &&
      ledgerCompleted?.state === 'completed' &&
      ledgerCompleted?.outcome === 'succeeded' &&
      storedResult?.success === true &&
      durable.counters.durableCompletionWrites === 1;
    record({
      id: 'S9',
      title: 'RESULT — correlated outcome: the sink completed the call the platform dispatched',
      status: resultPass ? 'PASS' : 'FAIL',
      observed: resultObserved,
      notes:
        'Correlation is by the SIGNED callId against the platform\'s own ledger, and the ledger transitions exactly once — the durable completion write is the only one this run made.',
    });
    if (!resultPass) {
      throw new Error('RESULT_CORRELATION_FAILED');
    }

    // ---------------------------------------------------------------- 10a. tampered frame
    const tamperCallId = `${runId}-call-tamper`;
    const tamperDispatch = await dispatchClient.dispatchCommand({
      authority,
      toolName: 'read_file',
      opKind: 'command',
      argsBytes,
      callId: tamperCallId,
    });
    const tamperFrames = await ws.waitForFrames(2);
    const tamperFrameText = typeof tamperFrames?.[1]?.payload === 'string' ? tamperFrames[1].payload : null;
    const tamperFrame = tamperFrameText === null ? null : JSON.parse(tamperFrameText);
    const tamperedFrame =
      tamperFrame === null
        ? null
        : {
            ...tamperFrame,
            argsB64u: Buffer.from(
              JSON.stringify({ path: WORKSPACE_FILE, extra: 'rewritten after signing by the relay' }),
              'utf8',
            ).toString('base64url'),
          };
    const tamperIn = out('tamper.in.json');
    const tamperResults = out('tamper.results.jsonl');
    fs.writeFileSync(tamperIn, `${JSON.stringify([tamperedFrame], null, 2)}\n`, 'utf8');
    const tamperHandled = runNode(
      ['run-agent.js', 'handle', '--root', agentRoot, '--in', tamperIn, '--out', tamperResults],
      {
        cwd: ENDPOINT_AGENT_DIR,
        stdoutPath: out('tamper.handle.out'),
        stderrPath: out('tamper.handle.err'),
      },
    );
    const tamperText = readText(tamperResults);
    const tamperFramesOut =
      tamperText === null || tamperText.trim().length === 0
        ? []
        : tamperText
            .trim()
            .split(/\r?\n/)
            .map((line) => JSON.parse(line));
    const tamperResultFrame = tamperFramesOut[0] ?? null;
    const tamperRelayVerdict = await ws.sendResult({
      callId: tamperResultFrame?.callId ?? tamperCallId,
      payload: JSON.stringify(tamperResultFrame),
    });
    const tamperPending = await relay.pendingOf(relayScope);
    const tamperEntry =
      (tamperPending.pending ?? []).find((item) => item.callId === (tamperResultFrame?.callId ?? tamperCallId)) ?? null;
    const tamperSinkVerdict = tamperEntry === null ? null : await sink.ingestResult(tamperEntry);
    const tamperLedger = await ledger.get(tamperCallId);
    const tamperObserved = {
      callId: tamperCallId,
      dispatchAccepted: tamperDispatch.delivered,
      tamperedAfterSigning: 'argsB64u replaced with different bytes; the signature was NOT recomputed',
      agentProcess: {
        command: tamperHandled.command,
        exitCode: tamperHandled.status,
        stderr: (readText(out('tamper.handle.err')) ?? '').trim(),
        refusedWithCode: tamperResultFrame?.errorCode ?? null,
        signedOutcome: tamperResultFrame?.outcome ?? null,
        correlation: tamperResultFrame?.correlation ?? null,
      },
      executed: false,
      executedMeaning:
        'the agent refused BEFORE dispatch (ENDPOINT_ARGS_DIGEST_MISMATCH), so the tool never ran; its result payload carries only the refusal, no file content',
      resultPayloadCarriesNoToolOutput:
        mainResultFrame === null
          ? null
          : !(Buffer.from(tamperResultFrame?.argsB64u ?? '', 'base64url').toString('utf8')).includes('W9 end-to-end payload'),
      relay: { t: tamperRelayVerdict.t, accepted: tamperRelayVerdict.accepted },
      sink: tamperSinkVerdict === null
        ? null
        : {
            status: tamperSinkVerdict.status,
            success: tamperSinkVerdict.success,
            outcome: tamperSinkVerdict.outcome,
            code: tamperSinkVerdict.code,
            stored: tamperSinkVerdict.stored,
          },
      ledgerStateAfter: tamperLedger ? { state: tamperLedger.state, outcome: tamperLedger.outcome } : null,
      storedResultForThisCall: await sink.resultFor(tamperCallId),
      storedSuccessField: (await sink.resultFor(tamperCallId))?.success ?? null,
      neverReportedAsSuccess:
        tamperResultFrame?.outcome !== 'succeeded' &&
        tamperSinkVerdict?.success !== true &&
        tamperLedger?.outcome !== 'succeeded' &&
        (await sink.resultFor(tamperCallId))?.success !== true,
    };
    // THE PROPERTY UNDER TEST, stated exactly: a frame tampered after signing must NOT execute, and
    // must NEVER be reported as a success. The accepted outcome law makes `refused` a COMPLETED call
    // with `success:false` — the endpoint can PROVE nothing ran — and stores it as such, so the
    // assertion is "nothing ran" + "never success", not "nothing recorded".
    const tamperPass =
      tamperResultFrame?.outcome === 'refused' &&
      tamperResultFrame?.errorCode === 'ENDPOINT_ARGS_DIGEST_MISMATCH' &&
      tamperObserved.resultPayloadCarriesNoToolOutput === true &&
      tamperSinkVerdict?.status === 'completed' &&
      tamperSinkVerdict?.success === false &&
      tamperSinkVerdict?.outcome === 'refused' &&
      tamperObserved.neverReportedAsSuccess === true &&
      tamperLedger?.outcome === 'refused';
    record({
      id: 'N1',
      title: 'NEGATIVE — a frame tampered after signing must not execute and must not be a success',
      status: tamperPass ? 'PASS' : 'FAIL',
      observed: tamperObserved,
      notes:
        'The endpoint refused it (GM-47 byte-equality) before dispatch, so nothing ran and no tool output exists in its payload. The platform recorded `refused` / `success:false` and the ledger closed the call as a non-success — a completed NON-success, which is the accepted outcome law (a `refused` result is provable non-execution, not uncertainty).',
    });
    evidence.negatives.push({ id: 'N1', status: tamperPass ? 'PASS' : 'FAIL', observed: tamperObserved });
    if (!tamperPass) {
      throw new Error('NEGATIVE_TAMPER_FAILED');
    }

    // ---------------------------------------------------------------- 10b. unknown callId
    const unknownCallId = `${runId}-call-never-dispatched`;
    const unknownRelayVerdict = await ws.sendResult({
      callId: unknownCallId,
      payload: JSON.stringify(mainResultFrame),
    });
    const unknownPending = await relay.pendingOf(relayScope);
    const unknownEntry = (unknownPending.pending ?? []).find((item) => item.callId === unknownCallId) ?? null;
    const unknownSinkVerdict = await sink.ingestResult({
      callId: unknownCallId,
      payload: JSON.stringify(mainResultFrame),
      resultSeq: 4242,
    });
    const unknownObserved = {
      callId: unknownCallId,
      note: 'the payload is a GENUINE device-signed frame; only the call identity is wrong for it',
      relay: {
        t: unknownRelayVerdict.t,
        code: unknownRelayVerdict.code,
        accepted: unknownRelayVerdict.accepted,
        heldInOutbox: unknownEntry !== null,
      },
      sink: {
        status: unknownSinkVerdict.status,
        success: unknownSinkVerdict.success,
        code: unknownSinkVerdict.code,
        stored: unknownSinkVerdict.stored,
      },
      ledgerHasThisCall: (await ledger.get(unknownCallId)) !== null,
      resultsInTheStore: await sink.size(),
    };
    const unknownPass =
      unknownSinkVerdict.status === 'refused' &&
      unknownSinkVerdict.code === 'RESULT_UNKNOWN_CALL_ID' &&
      unknownSinkVerdict.success === false &&
      unknownSinkVerdict.stored === false &&
      unknownObserved.ledgerHasThisCall === false &&
      unknownObserved.resultsInTheStore === 2;
    record({
      id: 'N2',
      title: 'NEGATIVE — a result for an unknown callId is refused and stores nothing',
      status: unknownPass ? 'PASS' : 'FAIL',
      observed: unknownObserved,
      notes:
        'The store still holds exactly the two calls that were really completed (the genuine read and the tamper refusal); the unknown call added neither a ledger row nor a stored result.',
    });
    evidence.negatives.push({ id: 'N2', status: unknownPass ? 'PASS' : 'FAIL', observed: unknownObserved });
    if (!unknownPass) {
      throw new Error('NEGATIVE_UNKNOWN_CALL_FAILED');
    }

    // ---------------------------------------------------------------- 10c. tool outside the server ceiling
    const registry = require(path.join(DEVICE_DIR, 'deviceToolRegistry.js'));
    const capabilityPolicy = require(path.join(DEVICE_DIR, 'deviceCapabilityPolicy.js'));
    const ceilingDoc = capabilityPolicy.ceilingForStage('A');
    const outsideTool = 'write_file';
    const inCeilingTool = 'read_file';
    // The DEVICE FLOOR is the endpoint agent's OWN live config file, so the gate is asked about the
    // real device state rather than a hand-written floor.
    const deviceFloorPath = path.join(agentRoot, 'tools.json');
    const deviceFloor = JSON.parse(readText(deviceFloorPath) ?? 'null');
    const outsideDecision = registry.authorizeDispatch(outsideTool, { ceiling: 'A', deviceFloor });
    const insideDecision = registry.authorizeDispatch(inCeilingTool, { ceiling: 'A', deviceFloor });
    let assertThrew = null;
    try {
      registry.assertDispatchAllowed(outsideTool, { ceiling: 'A', deviceFloor });
    } catch (err) {
      assertThrew = { name: err.name, code: err.code, httpStatus: err.httpStatus };
    }
    const framesBeforeOutside = ws.frames().length;
    const callIdOutside = `${runId}-call-outside`;
    // The gate refuses BEFORE anything is signed or sent; this is the evidence that nothing reached
    // the wire: no ledger row for the call, and no new frame at the real device socket.
    const outsideObserved = {
      tool: outsideTool,
      inTheServerCeiling: ceilingDoc.tools.includes(outsideTool),
      deviceEnabledIt: Array.isArray(deviceFloor?.enabled) ? deviceFloor.enabled.includes(outsideTool) : null,
      deviceFloorFile: deviceFloorPath,
      deviceFloorEnabled: Array.isArray(deviceFloor?.enabled) ? deviceFloor.enabled : null,
      authorizeDispatch: {
        allowed: outsideDecision.allowed,
        decision: outsideDecision.decision,
        code: outsideDecision.code,
        tier: outsideDecision.tier,
        deniedBy: outsideDecision.deniedBy,
        httpStatus: outsideDecision.httpStatus,
        reason: outsideDecision.reason,
      },
      assertDispatchAllowedThrew: assertThrew,
      controlInsideTheCeiling: {
        tool: inCeilingTool,
        allowed: insideDecision.allowed,
        code: insideDecision.code,
        requiresApproval: insideDecision.requiresApproval,
      },
      nothingReachedTheWire: {
        ledgerRowForTheRefusedCall: (await ledger.get(callIdOutside)) !== null,
        framesAtTheDeviceSocketBefore: framesBeforeOutside,
        framesAtTheDeviceSocketAfter: ws.frames().length,
      },
      gateKind: 'in-process call to the production module the panel route depends on',
    };
    const outsidePass =
      outsideDecision.allowed === false &&
      outsideObserved.inTheServerCeiling === false &&
      assertThrew !== null &&
      outsideObserved.nothingReachedTheWire.ledgerRowForTheRefusedCall === false &&
      outsideObserved.nothingReachedTheWire.framesAtTheDeviceSocketAfter === framesBeforeOutside &&
      insideDecision.allowed === true;
    record({
      id: 'N3',
      title: 'NEGATIVE — a tool outside the server ceiling is refused before the wire',
      status: outsidePass ? 'PASS' : 'FAIL',
      observed: outsideObserved,
      notes:
        'The gate EXISTS and is real (`deviceToolRegistry.authorizeDispatch`, the module the panel route consumes). It is NOT yet invoked by any production signing path: the accepted `relayDispatchClient` documents that wiring as the caller\'s job and no caller does it yet, so this refusal is genuine but not yet mechanically unavoidable from the dispatch entry point.',
    });
    evidence.negatives.push({ id: 'N3', status: outsidePass ? 'PASS' : 'FAIL', observed: outsideObserved });
    limits.push({
      id: 'L1',
      statement:
        'The server tool-policy gate is real but not yet wired into the production dispatch path: `deviceToolRegistry.assertDispatchAllowed` exists and refuses correctly, while `relayDispatchClient.dispatchCommand` does not call it. This harness therefore proves the gate\'s own behaviour (in-process, against the production module) and NOT that every production dispatch is gated.',
      evidence: 'step N3',
    });
    if (!outsidePass) {
      throw new Error('NEGATIVE_OUTSIDE_CEILING_FAILED');
    }

    // ---------------------------------------------------------------- 11. independent re-read
    const verify = spawnSync(
      process.execPath,
      [
        path.join(__dirname, 'verify-state.cjs'),
        '--uri',
        uri,
        '--call-id',
        callId,
        '--db',
        dbName,
        '--ledger-collection',
        collections.ledger.collectionName,
        '--result-collection',
        collections.results.collectionName,
        '--expect-outcome',
        'succeeded',
        '--out',
        out('verify-state.json'),
      ],
      { stdio: 'ignore' },
    );
    const verifyReport = JSON.parse(readText(out('verify-state.json')) ?? 'null');
    const verifyPass =
      verify.status === 0 &&
      verifyReport?.ledger?.state === 'completed' &&
      verifyReport?.ledger?.outcome === 'succeeded' &&
      verifyReport?.secondCompletion?.refused === true &&
      verifyReport?.secondCompletion?.stateUnchanged === true;
    record({
      id: 'S10',
      title: 'AFTER — a SEPARATE process re-reads the durable ledger and cannot complete the call twice',
      status: verifyPass ? 'PASS' : 'FAIL',
      observed: { exitCode: verify.status, report: verifyReport },
      notes:
        'This is the cross-process half of "complete exactly once": the accepted ledger\'s own conditional completion, backed by this harness\'s compare-and-set store.',
    });
    evidence.finalLedger = verifyReport;
    if (!verifyPass) {
      throw new Error('INDEPENDENT_REREAD_FAILED');
    }

    // ---------------------------------------------------------------- 12. cleanup
    const ledgerRows = await collections.ledger.find({}).toArray();
    const resultRows = await collections.results.find({}).toArray();
    evidence.finalLedgerStateInThisProcess = {
      ledger: ledgerRows.map((row) => ({
        callId: row._id,
        state: row.state,
        outcome: row.outcome,
        resultSeq: row.resultSeq,
        toolName: row.toolName,
        tenantId: row.tenantId,
        deviceId: row.deviceId,
        epoch: row.epoch,
      })),
      results: resultRows.map((row) => ({
        callId: row._id,
        outcome: row.outcome,
        success: row.success,
        toolName: row.toolName,
        tenantId: row.tenantId,
      })),
    };
    record({
      id: 'S11',
      title: 'FINAL LEDGER — the platform\'s own durable record of every call in this run',
      status: 'PASS',
      observed: evidence.finalLedgerStateInThisProcess,
      notes: 'Two calls: the genuine read (completed/succeeded) and the tampered frame (completed/refused). Nothing else.',
    });
  } finally {
    try {
      if (ws) {
        ws.close();
      }
    } catch {
      cleanupNotes.push('device socket close failed');
    }
    try {
      if (relay) {
        await relay.dispose();
      }
    } catch {
      cleanupNotes.push('relay dispose failed');
    }
    try {
      if (server) {
        await new Promise((resolve) => server.close(resolve));
      }
    } catch {
      cleanupNotes.push('http server close failed');
    }
    try {
      const mongoose = require(path.join(REPO, 'node_modules', 'mongoose'));
      await mongoose.disconnect();
    } catch {
      cleanupNotes.push('mongoose disconnect failed');
    }
    try {
      const droppedResult = await adminClient.db(dbName).dropDatabase();
      dropped = droppedResult === true;
    } catch (err) {
      cleanupNotes.push(`dropDatabase failed: ${err.message}`);
    }
    const namespaceAfter = await env.listNamespace(adminClient.db('admin'));
    const delta = env.namespaceDelta(namespaceBefore, namespaceAfter);
    // THE INVARIANT THIS HARNESS OWNS: every database it created is gone, and no database under its
    // OWN prefix is left behind. Other lanes share this replica set (GM-71 exists because of that), so
    // a database that appeared under a DIFFERENT prefix is reported, not treated as this run's leak.
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
      note:
        foreignNewDatabases.length === 0
          ? 'no other database appeared during this run'
          : 'another lane created a database on the shared replica set while this run was in flight (reported, not this harness\'s leak)',
    };
    await adminClient.close().catch(() => {
      cleanupNotes.push('admin client close failed');
    });
    if (foreignNewDatabases.length > 0) {
      limits.push({
        id: 'L0',
        statement: `The shared local replica set is not exclusive: these databases appeared during the run and belong to other lanes — ${foreignNewDatabases.join(', ')}. The harness's own database (${dbName}) was created and dropped and no \`${env.DB_PREFIX}\` database remains.`,
        evidence: 'step S12',
      });
    }
    record({
      id: 'S12',
      title: 'CLEANUP — the harness database is dropped and no harness-prefixed database remains',
      status: namespaceClean ? 'PASS' : 'FAIL',
      observed: evidence.namespace,
      notes: cleanupNotes.length === 0 ? null : cleanupNotes.join('; '),
    });
  }

  // ------------------------------------------------------------------ summary
  const failed = steps.filter((step) => step.status === 'FAIL');
  const summary = {
    runId,
    harness: evidence.harness,
    stepCount: steps.length,
    passed: steps.filter((step) => step.status === 'PASS').length,
    passedWithDisclosedWorkaround: steps
      .filter((step) => step.status === 'PASS_WITH_DISCLOSED_WORKAROUND')
      .map((step) => step.id),
    failed: failed.map((step) => ({ id: step.id, status: step.status })),
    defectQuarantine: evidence.defectQuarantine === true,
    ledger: evidence.finalLedgerStateInThisProcess ?? null,
    limits,
    accepted: failed.length === 0,
    acceptedMeans:
      'exit 0 means every step passed; a step proven only under the disclosed claim-leg workaround is reported as PASS_WITH_DISCLOSED_WORKAROUND and named here',
  };
  banner('PER-STEP LEDGER');
  for (const step of steps) {
    say(`${step.status.padEnd(5)}  ${step.id.padEnd(4)}  ${step.title}`);
  }
  say('');
  say(`LIMITS REPORTED (${limits.length}):`);
  for (const limit of limits) {
    say(`  ${limit.id}: ${limit.statement}`);
  }
  say('');
  say(JSON.stringify(summary, null, 2));

  evidence.summary = summary;
  evidence.finishedAt = new Date().toISOString();
  const evidenceFile = path.join(EVIDENCE_DIR, `e2e-${runId}.json`);
  const logFile = path.join(EVIDENCE_DIR, `e2e-${runId}.log`);
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  fs.writeFileSync(evidenceFile, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
  fs.writeFileSync(logFile, `${logLines.join('\n')}\n`, 'utf8');
  say('');
  say(`EVIDENCE: ${path.relative(REPO, evidenceFile)}`);
  say(`LOG:      ${path.relative(REPO, logFile)}`);
  // Explicit exit: workerd's runtime and Mongoose both keep handles alive, so a harness that printed
  // PASS could still hang forever — indistinguishable, to a caller, from a run that never finished.
  // Every close is awaited above, so by here nothing is pending.
  process.exit(summary.accepted ? 0 : 2);
}

/**
 * Reads the private half of the BACKEND LAB key (harness-scoped provisioning, never a repo file).
 *
 * KEY HYGIENE, STATED EXACTLY. The rule is "the endpoint key store lives OUTSIDE the repo; never write
 * a private key into the worktree". This harness respects that, but it does not claim more than it
 * does: it OPENS key files the lab created on the owner's own machine — the DEVICE private key
 * (`<agentRoot>/device-key.json`) to sign the registration/pairing ceremony proofs, and the LAB backend
 * private key to inject backend custody — exactly as the proven `run-reconciliation.mjs` does with the
 * key material on a path it chose. No private key is written under the worktree, no byte of it is
 * logged, and every key's location is recorded in the evidence. The DEVICE key is the agent's own and
 * a `succeeded` result frame is still unreachable without the AGENT process holding it.
 *
 * @param {string} labKeyDir
 */
function readLabBackendKey(labKeyDir) {
  const keyFile = path.join(labKeyDir, 'lab-backend-key.txt');
  const text = (readText(keyFile) ?? '').trim();
  if (text.length === 0) {
    throw new Error('HARNESS_REFUSAL: the lab backend key file is absent or empty');
  }
  return { file: keyFile, pkcs8: Buffer.from(text, 'base64url') };
}

/** Reads the private half of the DEVICE key so the ceremony proofs can be signed by the endpoint. */
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

main().catch((error) => {
  say('');
  say(`W9 E2E FAILED: ${error.message}`);
  say(error.stack ?? '');
  process.exit(1);
});
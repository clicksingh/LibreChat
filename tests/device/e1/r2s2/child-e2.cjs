'use strict';

/**
 * W3-B R2 S2-T E2 child process (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * One real independent OS process. It fences and opens its own guarded connection to the shared
 * fixture database, publishes per-phase readiness files, waits for its peer's readiness file (file
 * barrier), then performs genuine `claimAuthority` / `revokeLease` calls against two seeded authority
 * rows at one frozen generation g = 0.
 *
 * stdio is inherited/redirected to files on purpose: this sandbox cannot open named pipes for piped
 * child stdio, so every observation is exchanged through files.
 */

const fs = require('node:fs');
const path = require('node:path');

const fence = require('./fence.cjs');
const ledger = require('./ledger.cjs');

// eslint-disable-next-line global-require, import/no-dynamic-require
const env = require(path.resolve(__dirname, '..', 'r2', 'env.cjs'));

const w3a = env.w3a;

const ROW_X = 's2t-03-race-row-x';
const ROW_Y = 's2t-03-race-row-y';
const FROZEN_GENERATION = 0;

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      out[token.slice(2)] = argv[i + 1];
      i += 1;
    }
  }
  return out;
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function waitForPeer(barrierDir, phase, peerRole, timeoutMs) {
  const peerFile = path.join(barrierDir, `ready-${peerRole}-p${phase}.json`);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(peerFile)) return true;
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return false;
}

function envelopeView(envelope) {
  if (envelope === null || typeof envelope !== 'object') return { raw: envelope ?? null };
  return {
    ok: envelope.ok === true,
    matched: typeof envelope.matched === 'number' ? envelope.matched : (envelope.matched ?? null),
    errorCode: envelope.error ? (envelope.error.code ?? null) : null,
    httpStatus: envelope.error ? (envelope.error.httpStatus ?? null) : null,
    errorMessage: envelope.error ? (envelope.error.message ?? null) : null,
    epoch: envelope.authority ? (envelope.authority.epoch ?? null) : null,
    leaseState: envelope.authority ? (envelope.authority.leaseState ?? null) : null,
    ownerId: envelope.authority ? (envelope.authority.ownerId ?? null) : null,
    grantId: envelope.authority ? (envelope.authority.grantId ?? null) : null,
  };
}

function progress(line) {
  process.stdout.write(`[s2t-03] ${line}\n`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const role = args.role === 'B' ? 'B' : 'A';
  const peerRole = role === 'A' ? 'B' : 'A';
  const dbName = args.db;
  const barrierDir = args.barrier;
  const outFile = args.out;
  const claimsPhaseA = Number(args.claimsA ?? 16);
  const claimsPhaseC = Number(args.claimsC ?? 9);
  const barrierTimeoutMs = Number(args.barrierTimeoutMs ?? 30000);

  const report = {
    kind: 's2t-03-e2-child',
    role,
    pid: process.pid,
    ppid: process.ppid,
    nodeVersion: process.version,
    startedAt: new Date().toISOString(),
    dbName,
    frozenGeneration: FROZEN_GENERATION,
    claimsPhaseA,
    claimsPhaseC,
    attempts: [],
    barrierReached: {},
    peerReady: {},
    compositionPrecondition: null,
    registryShape: null,
    finalRows: null,
    fatal: null,
    fenceProblems: null,
  };

  let client = null;
  try {
    report.fenceProblems = fence.checkDbName(dbName);
    if (report.fenceProblems.length > 0) {
      throw new fence.S2TFenceViolation(report.fenceProblems, { dbName, phase: 'child-pre-connect' });
    }
    const connected = await fence.connectGuarded({ dbName, appName: `cbhr-r2-s2t-e2-${role}` });
    client = connected.client;
    report.topology = connected.topology;

    const loaded = env.loadRegistry();
    report.registryShape = Object.fromEntries(
      Object.entries(loaded.shape).map(([key, value]) => [key, value.typeofModel]),
    );
    await env.connectMongoose({ uri: fence.FROZEN_URI, dbName, appName: `cbhr-r2-s2t-e2-${role}` });
    const clock = w3a.makeClock();
    const cryptoSurface = w3a.makeCrypto();
    const audit = env.makeRealAuditSink(loaded.registry, clock);
    const consent = w3a.makeLocalConsent();

    report.compositionPrecondition = env.attemptComposition(loaded.registry, {
      clock,
      cryptoSurface,
      audit,
      tenantPolicy: w3a.makeTenantPolicy(),
      consent: consent.verify.bind(consent),
      pepperLookup: w3a.LAB_PEPPER,
    });
    if (report.compositionPrecondition.some((attempt) => attempt.accepted !== true)) {
      throw new Error('HARNESS_FAIL: factory composition rejected genuine model constructors');
    }

    const authority = w3a.product.createAuthorityService({
      db: loaded.registry,
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      verifyRenewalProof: async () => ({ ok: false }),
    });

    let attemptIndex = 0;
    const record = (phase, op, view, extra = {}) => {
      report.attempts.push({
        seq: attemptIndex,
        phase,
        role,
        op,
        expectedEpochSupplied: FROZEN_GENERATION,
        ...extra,
        ...view,
      });
      attemptIndex += 1;
    };

    async function barrier(phase) {
      fs.mkdirSync(barrierDir, { recursive: true });
      writeJson(path.join(barrierDir, `ready-${role}-p${phase}.json`), {
        role,
        phase,
        pid: process.pid,
        at: new Date().toISOString(),
      });
      report.barrierReached[`p${phase}`] = true;
      const ready = await waitForPeer(barrierDir, phase, peerRole, barrierTimeoutMs);
      report.peerReady[`p${phase}`] = ready;
      if (!ready) {
        throw new Error(`BARRIER_TIMEOUT: peer readiness for phase ${phase} never appeared`);
      }
      progress(`barrier p${phase} passed (pid ${process.pid})`);
    }

    // Phase A: same-generation claims against a LIVE active row X.
    await barrier(1);
    for (let i = 0; i < claimsPhaseA; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const envelope = await authority.claimAuthority({
        deviceId: ROW_X,
        tenantId: w3a.TENANT,
        ownerId: w3a.OWNER_A,
        sessionId: `s2t-03-x-${role}-${i}`,
        expectedEpoch: FROZEN_GENERATION,
        grantProof: {
          ownerConfirmedAt: new Date(clock.now()),
          endpointSignatureVerifiedAt: new Date(clock.now()),
          verifiedKeyId: `key-${ROW_X}`,
          localApprovalNonceHash: `s2t-03-nonce-${role}-${i}`,
        },
      });
      record('A_pre_revoke_live_lease', 'claimAuthority', envelopeView(envelope), { row: ROW_X, i });
    }
    progress(`phase A complete (${claimsPhaseA} claims, pid ${process.pid})`);

    // Phase B1: the only legitimate generation-changing operation at g.
    await barrier(2);
    {
      const envelope = await authority.revokeLease({
        deviceId: ROW_X,
        tenantId: w3a.TENANT,
        ownerId: w3a.OWNER_A,
        epoch: FROZEN_GENERATION,
      });
      record('B1_revoke_at_g', 'revokeLease', envelopeView(envelope), { row: ROW_X });
    }
    progress(`phase B1 complete (revoke at g, pid ${process.pid})`);

    // Phase B2: stale g-pinned ceremonies against the now g+1 revoked row.
    await barrier(3);
    {
      const envelope = await authority.claimAuthority({
        deviceId: ROW_X,
        tenantId: w3a.TENANT,
        ownerId: w3a.OWNER_A,
        sessionId: `s2t-03-x-stale-${role}`,
        expectedEpoch: FROZEN_GENERATION,
        grantProof: {
          ownerConfirmedAt: new Date(clock.now()),
          endpointSignatureVerifiedAt: new Date(clock.now()),
          verifiedKeyId: `key-${ROW_X}`,
          localApprovalNonceHash: `s2t-03-stale-nonce-${role}`,
        },
      });
      record('B2_stale_g_claim_after_revoke', 'claimAuthority', envelopeView(envelope), { row: ROW_X });
    }
    progress(`phase B2 complete (stale ceremony, pid ${process.pid})`);

    // Phase C: pure same-generation claim race against a claimable row Y.
    await barrier(4);
    for (let i = 0; i < claimsPhaseC; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const envelope = await authority.claimAuthority({
        deviceId: ROW_Y,
        tenantId: w3a.TENANT,
        ownerId: w3a.OWNER_B,
        sessionId: `s2t-03-y-${role}-${i}`,
        expectedEpoch: FROZEN_GENERATION,
        grantProof: {
          ownerConfirmedAt: new Date(clock.now()),
          endpointSignatureVerifiedAt: new Date(clock.now()),
          verifiedKeyId: `key-${ROW_Y}`,
          localApprovalNonceHash: `s2t-03-y-nonce-${role}-${i}`,
        },
      });
      record('C_pure_same_generation_claim_race', 'claimAuthority', envelopeView(envelope), {
        row: ROW_Y,
        i,
      });
    }
    progress(`phase C complete (${claimsPhaseC} claims, pid ${process.pid})`);

    report.finalRows = {
      x: await client
        .db(dbName)
        .collection(loaded.registry.DeviceAuthority.collection.name)
        .findOne({ _id: ROW_X }),
      y: await client
        .db(dbName)
        .collection(loaded.registry.DeviceAuthority.collection.name)
        .findOne({ _id: ROW_Y }),
    };
    report.finishedAt = new Date().toISOString();
    progress(`all phases complete (pid ${process.pid}, ${report.attempts.length} attempts)`);
  } catch (err) {
    report.fatal = report.fatal ?? `${err.name}: ${err.message}`;
    report.fatalStack = err.stack ?? null;
    progress(`FATAL ${report.fatal}`);
  } finally {
    try {
      await w3a.mongoose.disconnect();
    } catch {
      /* the child never owns the fixture database lifetime */
    }
    if (client !== null) await client.close().catch(() => {});
    writeJson(outFile, report);
  }
}

main().catch((err) => {
  const args = parseArgs(process.argv.slice(2));
  if (args.out) {
    writeJson(args.out, {
      kind: 's2t-03-e2-child',
      role: args.role ?? null,
      pid: process.pid,
      fatal: `UNHANDLED: ${err.name}: ${err.message}`,
      stack: err.stack ?? null,
    });
  }
  process.exitCode = 1;
});
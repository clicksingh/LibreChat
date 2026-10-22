'use strict';

/**
 * W3-B R2-T0A E2 child process (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * One real independent OS process for the T0A-01 sessionVersion issue-vs-approve ABA race.
 * It fences and opens its own guarded connection to the shared fixture database, publishes a
 * readiness file, waits for its peer's readiness file (file barrier), re-reads the observed
 * `claim_pending` session with the GENUINE PairingSession model, then performs N genuine
 * composition attempts (role A: issuance/supersede, role B: approval/consume) against that
 * observed session.
 *
 * stdio is ignored on purpose: this sandbox cannot open named pipes for piped child stdio, so
 * every observation is exchanged through files.
 */

const fs = require('node:fs');
const path = require('node:path');

const fence = require('./fence.cjs');
const env = require('./env.cjs');

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

async function waitForPeer(barrierDir, peerRole, timeoutMs) {
  const peerFile = path.join(barrierDir, `ready-${peerRole}.json`);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(peerFile)) return true;
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return false;
}

/** Attempts each frozen factory with the RAW genuine registry; returns the service or the guard error. */
function composeServices(registry, { clock, cryptoSurface, audit, consent }) {
  const results = [];
  const attempts = [
    {
      factory: 'createAuthorityService',
      call: () =>
        env.w3a.product.createAuthorityService({
          db: registry,
          clock,
          crypto: cryptoSurface,
          logger: null,
          audit: audit.audit,
          verifyRenewalProof: async () => ({ ok: false }),
        }),
    },
    {
      factory: 'createRegistrationService',
      call: () =>
        env.w3a.product.createRegistrationService({
          db: registry,
          clock,
          crypto: cryptoSurface,
          logger: null,
          audit: audit.audit,
          tenantPolicy: env.w3a.makeTenantPolicy(),
        }),
    },
    {
      factory: 'createPairingSessionService',
      call: () =>
        env.w3a.product.createPairingSessionService({
          db: registry,
          clock,
          crypto: cryptoSurface,
          logger: null,
          audit: audit.audit,
          authorityService: {
            readAuthority: async () => null,
            releaseLapsedLease: async () => ({ ok: false, matched: 0, authority: null, error: null }),
            spendChallenge: async () => ({ ok: false, matched: 0, authority: null, error: null }),
            claimAuthority: async () => ({ ok: false, matched: 0, authority: null, error: null }),
          },
          tenantPolicy: env.w3a.makeTenantPolicy(),
          verifyLocalConsent: consent,
          pepperLookup: env.w3a.LAB_PEPPER,
        }),
    },
  ];
  const services = {};
  for (const attempt of attempts) {
    try {
      services[attempt.factory] = attempt.call();
      results.push({ factory: attempt.factory, accepted: true, error: null });
    } catch (err) {
      results.push({ factory: attempt.factory, accepted: false, error: { name: err.name, message: err.message } });
    }
  }
  return { results, services };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const role = args.role === 'B' ? 'B' : 'A';
  const peerRole = role === 'A' ? 'B' : 'A';
  const dbName = args.db;
  const barrierDir = args.barrier;
  const outFile = args.out;
  const iterations = Number(args.iterations ?? 25);
  const scenario = args.scenario ?? 'session-aba-issue-vs-approve';
  const tag = args.tag ?? 't0a01aba';
  const sessionId = args.session ?? null;
  const tenantId = args.tenant ?? env.w3a.TENANT;
  const deviceId = args.device ?? null;
  const deviceKeyId = args.deviceKey ?? null;
  const ownerId = args.owner ?? env.w3a.OWNER_A;

  const report = {
    kind: 'r2-t0a-e2-child',
    role,
    roleFunction: role === 'A' ? 'issuance/supersede' : 'approval/consume',
    scenario,
    tag,
    pid: process.pid,
    ppid: process.ppid,
    nodeVersion: process.version,
    startedAt: new Date().toISOString(),
    dbName,
    sessionId,
    tenantId,
    iterationsTarget: iterations,
    attempts: 0,
    compositionFailures: 0,
    composedInSomeFactory: 0,
    productCallsAttempted: 0,
    barrierReached: false,
    peerReady: false,
    barrierTimeoutMs: Number(args.barrierTimeoutMs ?? 30000),
    observedSession: null,
    registryShape: null,
    attemptsDetail: [],
    fatal: null,
    fenceProblems: null,
  };

  let client = null;
  try {
    report.fenceProblems = fence.checkDbName(dbName);
    if (report.fenceProblems.length > 0) {
      throw new fence.R2aFenceViolation(report.fenceProblems, { dbName, phase: 'child-pre-connect' });
    }
    const connected = await fence.connectGuarded({ dbName, appName: `cbhr-r2-t0a-e2-${role}` });
    client = connected.client;
    report.topology = connected.topology;

    const loaded = env.loadRegistry();
    report.registryShape = env.registryModelTypeof(loaded.registry);
    await env.connectMongoose({ uri: fence.FROZEN_URI, dbName }).catch(() => null);
    report.mongooseReadyState = env.w3a.mongoose.connection.readyState;
    const clock = env.w3a.makeClock();
    const audit = env.makeRealAuditSink(loaded.registry, clock);
    report.auditSinkKind = audit.kind;

    fs.mkdirSync(barrierDir, { recursive: true });
    writeJson(path.join(barrierDir, `ready-${role}.json`), {
      role,
      pid: process.pid,
      at: new Date().toISOString(),
      dbName,
    });
    report.barrierReached = true;

    report.peerReady = await waitForPeer(barrierDir, peerRole, report.barrierTimeoutMs);
    if (!report.peerReady) {
      report.fatal = 'BARRIER_TIMEOUT: peer readiness file never appeared';
    }

    // Observed session: a genuine Mongoose read of the shared claim_pending row.
    const observedDoc = sessionId
      ? await loaded.registry.PairingSession.findOne({ _id: sessionId, tenantId }).lean()
      : null;
    report.observedSession = observedDoc
      ? {
          found: true,
          _id: String(observedDoc._id),
          state: observedDoc.state,
          pendingOwnerId: observedDoc.pendingOwnerId,
          deviceId: observedDoc.deviceId,
          deviceKeyId: observedDoc.deviceKeyId,
          sessionVersion: Object.prototype.hasOwnProperty.call(observedDoc, 'sessionVersion')
            ? observedDoc.sessionVersion
            : null,
          sessionVersionFieldPresent: Object.prototype.hasOwnProperty.call(observedDoc, 'sessionVersion'),
          expectedSessionVersionFieldPresent: Object.prototype.hasOwnProperty.call(observedDoc, 'expectedSessionVersion'),
          claimFields: observedDoc.claim ? Object.keys(observedDoc.claim) : null,
        }
      : { found: false, _id: sessionId, state: null, sessionVersion: null, sessionVersionFieldPresent: false };

    const startAt = Date.now();
    for (let i = 0; i < iterations; i += 1) {
      const consent = env.w3a.makeLocalConsent();
      const composed = composeServices(loaded.registry, {
        clock: env.w3a.makeClock(),
        cryptoSurface: env.w3a.makeCrypto(),
        audit,
        consent: consent.verify.bind(consent),
      });
      report.attempts += 1;
      const rejected = composed.results.filter((c) => c.accepted === false);
      if (rejected.length === composed.results.length) {
        report.compositionFailures += 1;
      } else {
        report.composedInSomeFactory += 1;
      }

      let productCall = null;
      if (composed.results.every((c) => c.accepted === true)) {
        // Post-repair path only: the intended F13 product call. Unreachable against pre-repair
        // bytes, and deliberately not simulated with any facade.
        report.productCallsAttempted += 1;
        const service = composed.services.createPairingSessionService;
        try {
          if (role === 'A') {
            productCall = await service.issuePairingSession({
              tenantId,
              deviceId,
              deviceKeyId,
              expectedSessionVersion: report.observedSession ? report.observedSession.sessionVersion : null,
              domainTag: env.w3a.constants.PAIRING_OPEN_DOMAIN,
              proof: { nonce: `t0a01-${i}`, issuedAt: String(clock.now()), signatureB64u: null },
            });
          } else {
            productCall = await service.approvePairingClaim({
              tenantId,
              ownerId,
              pairingSessionId: sessionId,
              expectedSessionVersion: report.observedSession ? report.observedSession.sessionVersion : null,
              localConsent: { nonce: `t0a01-consent-${i}` },
              proof: { challenge: null, nonce: `t0a01-${i}`, issuedAt: String(clock.now()) },
            });
          }
          productCall = { ok: productCall.ok === true, code: productCall.error ? productCall.error.code : null };
        } catch (err) {
          productCall = { ok: false, code: err.code ?? null, error: `${err.name}: ${err.message}` };
        }
      }

      if (report.attemptsDetail.length < 3) {
        report.attemptsDetail.push({
          i,
          attemptedAtOffsetMs: Date.now() - startAt,
          acceptedFactories: composed.results.filter((c) => c.accepted).map((c) => c.factory),
          rejectedFactories: rejected.map((c) => ({ factory: c.factory, error: c.error })),
          productCall,
        });
      }
    }
    report.finishedAt = new Date().toISOString();
    report.durationMs = Date.now() - startAt;
  } catch (err) {
    report.fatal = report.fatal ?? `${err.name}: ${err.message}`;
    report.fatalStack = err.stack ?? null;
  } finally {
    try {
      await env.w3a.mongoose.disconnect();
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
      kind: 'r2-t0a-e2-child',
      role: args.role ?? null,
      pid: process.pid,
      fatal: `UNHANDLED: ${err.name}: ${err.message}`,
      stack: err.stack ?? null,
    });
  }
  process.exitCode = 1;
});
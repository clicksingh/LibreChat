'use strict';

/**
 * W3-B R2-T0 E2 child process (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * One real independent OS process. It fences and opens its own guarded connection to the shared
 * fixture database, publishes a readiness file, waits for its peer's readiness file (file barrier),
 * then performs N genuine composition attempts against the same authority generation.
 *
 * stdio is inherited/ignored on purpose: this sandbox cannot open named pipes for piped child stdio,
 * so every observation is exchanged through files.
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const role = args.role === 'B' ? 'B' : 'A';
  const peerRole = role === 'A' ? 'B' : 'A';
  const dbName = args.db;
  const barrierDir = args.barrier;
  const outFile = args.out;
  const attemptsTarget = Number(args.attempts ?? 25);
  const scenario = args.scenario ?? 'race';
  const tag = args.tag ?? 'e2';

  const report = {
    kind: 'r2-t0-e2-child',
    role,
    scenario,
    tag,
    pid: process.pid,
    ppid: process.ppid,
    nodeVersion: process.version,
    startedAt: new Date().toISOString(),
    dbName,
    attemptsTarget,
    attempts: 0,
    compositionFailures: 0,
    winners: 0,
    losers: 0,
    epochDelta: null,
    barrierReached: false,
    peerReady: false,
    barrierTimeoutMs: Number(args.barrierTimeoutMs ?? 30000),
    attemptsDetail: [],
    fatal: null,
    fenceProblems: null,
  };

  let client = null;
  try {
    report.fenceProblems = fence.checkDbName(dbName);
    if (report.fenceProblems.length > 0) {
      throw new fence.R2FenceViolation(report.fenceProblems, { dbName, phase: 'child-pre-connect' });
    }
    const connected = await fence.connectGuarded({ dbName, appName: `cbhr-r2-t0-e2-${role}` });
    client = connected.client;
    report.topology = connected.topology;

    const loaded = env.loadRegistry();
    report.registryShape = Object.fromEntries(Object.entries(loaded.shape).map(([k, v]) => [k, v.typeofModel]));
    const audit = env.makeRealAuditSink(loaded.registry, env.w3a.makeClock());

    fs.mkdirSync(barrierDir, { recursive: true });
    writeJson(path.join(barrierDir, `ready-${role}.json`), { role, pid: process.pid, at: new Date().toISOString() });
    report.barrierReached = true;

    report.peerReady = await waitForPeer(barrierDir, peerRole, report.barrierTimeoutMs);
    if (!report.peerReady) {
      report.fatal = 'BARRIER_TIMEOUT: peer readiness file never appeared';
    }

    const startAt = Date.now();
    for (let i = 0; i < attemptsTarget; i += 1) {
      const consent = env.w3a.makeLocalConsent();
      const composition = env.attemptComposition(loaded.registry, {
        clock: env.w3a.makeClock(),
        cryptoSurface: env.w3a.makeCrypto(),
        audit,
        tenantPolicy: env.w3a.makeTenantPolicy(),
        consent: consent.verify.bind(consent),
        pepperLookup: env.w3a.LAB_PEPPER,
      });
      report.attempts += 1;
      const rejected = composition.filter((c) => c.accepted === false);
      if (rejected.length === composition.length) {
        report.compositionFailures += 1;
        report.losers += 1;
      } else {
        report.winners += 1;
      }
      if (report.attemptsDetail.length < 3) {
        report.attemptsDetail.push({
          i,
          attemptedAtOffsetMs: Date.now() - startAt,
          accepted: composition.filter((c) => c.accepted).map((c) => c.factory),
          rejected: rejected.map((c) => ({ factory: c.factory, error: c.error, guardAnchor: c.guardAnchor })),
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
  // Never leave the parent without an observation.
  const args = parseArgs(process.argv.slice(2));
  if (args.out) {
    writeJson(args.out, {
      kind: 'r2-t0-e2-child',
      role: args.role ?? null,
      pid: process.pid,
      fatal: `UNHANDLED: ${err.name}: ${err.message}`,
      stack: err.stack ?? null,
    });
  }
  process.exitCode = 1;
});
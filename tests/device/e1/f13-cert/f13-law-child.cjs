'use strict';

/**
 * F13 sessionVersion ABA — two-OS-process child (test-only, NEW FILE).
 *
 *   node f13-law-child.cjs --role=A|B --db=<w3 db> --rundir=<dir> --rounds=25 --clock=<ms> --prepared=<file>
 *
 * Role A = issuance/supersede (mint an open challenge, then `issuePairingSession` for the SAME
 * device whose `claim_pending` session is armed).
 * Role B = approval/consume (`approvePairingClaim` with the real claim proof the parent armed).
 *
 * Both roles are REAL product calls over the frozen `createModels(mongoose)` registry. Every
 * observation travels through files (stdio is 'ignore': piped child stdio is EPERM here).
 * No minted pairing code, private key, pepper or signature is written to any file.
 */

const fs = require('node:fs');
const path = require('node:path');

const support = require('../w3a/support.cjs');
const env = require('../w3a/env.cjs');

const TENANT = env.TENANT;

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const [flag, inline] = token.includes('=') ? token.split(/=(.*)/s, 2) : [token, null];
    const value = inline !== null ? inline : argv[i + 1];
    out[flag.slice(2)] = value === undefined ? true : value;
    if (inline === null) i += 1;
  }
  return out;
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  fs.renameSync(tmp, file);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

async function waitFor(file, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) {
      try {
        return readJson(file);
      } catch {
        /* the peer may still be publishing */
      }
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`BARRIER_TIMEOUT waiting for ${file}`);
}

function errorCode(result) {
  return result && result.error ? result.error.code ?? null : null;
}

async function sessionView(ctx, sessionId) {
  const row = await ctx.models.PairingSession.findOne({ _id: sessionId, tenantId: TENANT }).lean();
  if (row === null) return null;
  return {
    state: row.state ?? null,
    sessionVersion: Number.isInteger(row.sessionVersion) ? row.sessionVersion : null,
    pendingOwnerId: row.pendingOwnerId ?? null,
    consumedAt: row.consumedAt ? new Date(row.consumedAt).toISOString() : null,
    claimExpectedEpoch: row.claim ? row.claim.expectedEpoch ?? null : null,
    claimChallengeRefPresent: Boolean(row.claim && row.claim.challengeRef),
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const role = args.role === 'B' ? 'B' : 'A';
  const rounds = Number(args.rounds ?? 25);
  const clockMs = Number(args.clock);
  const rundir = args.rundir;
  const prepared = readJson(args.prepared);

  const report = {
    kind: 'f13-law-child',
    role,
    pid: process.pid,
    ppid: process.ppid,
    dbName: args.db,
    rounds,
    clockNowMs: clockMs,
    startedAt: new Date().toISOString(),
    attempts: 0,
    results: [],
    fatal: null,
  };

  let ctx = null;
  try {
    ctx = await support.makeContext({
      tag: `f13law-${role}`,
      dbName: args.db,
      syncIndexes: false,
      dropOnTeardown: false,
      mode: 'raw-registry',
      principalId: env.OWNER_A,
    });
    ctx.clock.set(clockMs);
    const pairing = ctx.pairingService({ verifyLocalConsent: ctx.consent.verify.bind(ctx.consent) });

    for (let round = 0; round < rounds; round += 1) {
      const planned = prepared.rounds[round];
      const key = env.makeDeviceKey(planned.deviceTag);
      const observedAtBarrier = await sessionView(ctx, planned.sessionId);
      writeJson(path.join(rundir, `f13law-ready-${round}-${role}.json`), {
        round,
        role,
        pid: process.pid,
        observedAtBarrier,
      });
      await waitFor(path.join(rundir, `f13law-go-${round}.json`));

      report.attempts += 1;
      let record;
      if (role === 'A') {
        const openChallenge = await pairing.mintPairingOpenChallenge({
          tenantId: TENANT,
          deviceId: planned.deviceId,
          deviceKeyId: planned.deviceKeyId,
        });
        let issue = { ok: false, code: null, error: { code: 'MINT_OPEN_CHALLENGE_FAILED' } };
        if (openChallenge.ok) {
          issue = await pairing.issuePairingSession({
            tenantId: TENANT,
            deviceId: planned.deviceId,
            deviceKeyId: planned.deviceKeyId,
            domainTag: env.constants.PAIRING_OPEN_DOMAIN,
            requestSource: 'f13-law-fixture',
            challengeHash: openChallenge.challengeHash,
            proof: support.pairingOpenProof(ctx, {
              deviceId: planned.deviceId,
              deviceKeyId: planned.deviceKeyId,
              key,
              challengeHash: openChallenge.challengeHash,
              issuedAt: openChallenge.issuedAt,
            }),
          });
        }
        record = {
          action: 'issuePairingSession',
          round,
          deviceId: planned.deviceId,
          ok: issue.ok === true,
          errorCode: errorCode(issue),
          codeIssued: typeof issue.code === 'string' && /^[0-9]{6}$/.test(issue.code),
          issuedSessionId: issue.ok && issue.pairingSession ? String(issue.pairingSession._id) : null,
        };
      } else {
        const approve = await pairing.approvePairingClaim({
          pairingSessionId: planned.sessionId,
          tenantId: TENANT,
          ownerId: planned.ownerId,
          domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
          localConsent: { nonce: `f13-law-consent-${round}` },
          proof: support.pairingClaimProof(ctx, {
            session: {
              _id: planned.sessionId,
              deviceId: planned.deviceId,
              deviceKeyId: planned.deviceKeyId,
            },
            ownerId: planned.ownerId,
            challengeHash: planned.claimChallengeHash,
            key,
            issuedAt: planned.claimChallengeIssuedAt,
          }),
        });
        record = {
          action: 'approvePairingClaim',
          round,
          deviceId: planned.deviceId,
          ok: approve.ok === true,
          errorCode: errorCode(approve),
          grantedEpoch:
            approve.ok && approve.authority && Number.isInteger(approve.authority.epoch)
              ? approve.authority.epoch
              : null,
          grantedOwnerId: approve.ok && approve.authority ? approve.authority.ownerId ?? null : null,
        };
      }

      record.sessionAfter = await sessionView(ctx, planned.sessionId);
      record.pid = process.pid;
      writeJson(path.join(rundir, `f13law-res-${round}-${role}.json`), record);
      report.results.push(record);
    }

    report.duplicateKeyObservations = ctx.recorder.duplicateErrors();
    report.writeConcernSummary = ctx.recorder.summary();
    report.finishedAt = new Date().toISOString();
  } catch (err) {
    report.fatal = `${err.name}: ${err.message}`;
    report.fatalStack = String(err.stack ?? '').split('\n').slice(0, 8);
  } finally {
    if (ctx !== null) await ctx.teardown().catch(() => {});
    writeJson(path.join(rundir, `f13law-results-${role}.json`), report);
  }
  return report;
}

main().then(
  (report) => {
    process.exitCode = report.fatal === null ? 0 : 4;
  },
  (err) => {
    const args = parseArgs(process.argv.slice(2));
    if (args.rundir) {
      writeJson(path.join(args.rundir, `f13law-results-${args.role ?? 'A'}.json`), {
        kind: 'f13-law-child',
        role: args.role ?? null,
        pid: process.pid,
        fatal: `UNHANDLED: ${err.name}: ${err.message}`,
      });
    }
    process.exitCode = 4;
  },
);
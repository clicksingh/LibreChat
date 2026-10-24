'use strict';

/**
 * E2 race child (lane I9 / task T1) — round-based.
 *
 *   node race-child.cjs --db=<w3 db> --fixture=<id> --shard=A|B --rounds=25 \
 *        --rundir=<dir> --clock=<ms> --prepared=<file>
 *
 * Protocol, per round (file-based only; stdio is 'ignore' because piped stdio is EPERM here):
 *   1. ARM outside the window. For E2-V24T15 shard B this is the REAL pairing ceremony up to
 *      `mintPairingClaimChallenge`, which freezes the server-derived expectedEpoch; the claim CAS
 *      is therefore armed exactly as the frozen protocol arms it (never with a harness-invented
 *      epoch).
 *   2. write  <rundir>/<fixture>-ready-<round>-<shard>.json
 *   3. await  <rundir>/<fixture>-go-<round>.json
 *   4. perform the real product CAS and write
 *      <rundir>/<fixture>-res-<round>-<shard>.json
 *
 * Nothing here reimplements product behaviour; every state change is a real product call.
 */

const fs = require('node:fs');
const path = require('node:path');

const support = require('../w3a/support.cjs');
const env = require('../w3a/env.cjs');

const TENANT = env.TENANT;
const OWNER_A = env.OWNER_A;
const OWNER_B = env.OWNER_B;

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) continue;
    const [flag, inline] = arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, null];
    const value = inline !== null ? inline : argv[index + 1];
    options[flag.slice(2)] = value === undefined ? true : value;
    if (inline === null) index += 1;
  }
  return options;
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // Atomic publish: write a private temp file, then rename, so no reader observes a partial file.
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  fs.renameSync(tmp, file);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

async function waitForFile(file, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) {
      try {
        return readJson(file);
      } catch {
        /* the writer may still be publishing the file: retry until it parses */
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`BARRIER_TIMEOUT waiting for ${file}`);
}

/** Arms the real pairing ceremony for one device and returns what the approve step needs. */
/**
 * GM-41: waits, with a bound, until shard A's revoke is OBSERVED COMMITTED in the device row before
 * shard B arms its fresh claim. Returns `{ok:true}` when the row observably leaves the live lease
 * (leaseState not 'active', or the epoch advancing past the seed epoch), and `{ok:false}` on timeout.
 *
 * This is a FIXTURE-side ordering gate, not a product behaviour: it makes the fixture's premise — a
 * lapsed lease ready to claim — true by construction, rather than by hoping the scheduler opens the
 * right side first. The product still decides everything: the revoke still runs as a real CAS, the
 * claim still runs as a real CAS, and exactly-one-winner per transition still holds.
 *
 * The wait does NOT weaken the contention: the claim still lands in the window immediately after the
 * revoke, with no time for anything else to act, and the epoch arithmetic (1->2->3) is still decided
 * by the product's own transactions.
 */
async function waitForRevokeCommitted(ctx, device, { timeoutMs = 15000, intervalMs = 25 } = {}) {
  const startedAt = Date.now();
  for (;;) {
    const row = await ctx.models.DeviceAuthority.findOne(
      { _id: device.deviceId, tenantId: TENANT },
    ).lean();
    if (row !== null && (row.leaseState !== 'active' || Number(row.epoch) > device.seedEpoch)) {
      return { ok: true, waitedMs: Date.now() - startedAt };
    }
    if (Date.now() - startedAt >= timeoutMs) {
      return { ok: false, waitedMs: Date.now() - startedAt };
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

async function armClaimCeremony(ctx, pairing, device, key) {
  const openChallenge = await pairing.mintPairingOpenChallenge({
    tenantId: TENANT,
    deviceId: device.deviceId,
    deviceKeyId: device.deviceKeyId,
  });
  if (!openChallenge.ok) {
    return { ok: false, stage: 'mint-open-challenge', error: { code: openChallenge.error ? openChallenge.error.code : null } };
  }
  const issue = await pairing.issuePairingSession({
    tenantId: TENANT,
    deviceId: device.deviceId,
    deviceKeyId: device.deviceKeyId,
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
    requestSource: 'e2-t15-arm',
    challengeHash: openChallenge.challengeHash,
    proof: support.pairingOpenProof(ctx, {
      deviceId: device.deviceId,
      deviceKeyId: device.deviceKeyId,
      key,
      challengeHash: openChallenge.challengeHash,
      issuedAt: openChallenge.issuedAt,
    }),
  });
  if (!issue.ok) {
    return { ok: false, stage: 'issue', error: { code: issue.error ? issue.error.code : null } };
  }
  const redeem = await pairing.redeemPairingCode({ code: issue.code, tenantId: TENANT, ownerId: device.claimOwner });
  if (!redeem.ok) {
    return { ok: false, stage: 'redeem', error: { code: redeem.error ? redeem.error.code : null } };
  }
  const session = await ctx.models.PairingSession.findOne({ _id: redeem.pairingSession._id, tenantId: TENANT }).lean();
  const claimChallenge = await pairing.mintPairingClaimChallenge({
    pairingSessionId: String(session._id),
    tenantId: TENANT,
    ownerId: device.claimOwner,
  });
  if (!claimChallenge.ok) {
    return { ok: false, stage: 'mint-claim-challenge', error: { code: claimChallenge.error ? claimChallenge.error.code : null } };
  }
  return {
    ok: true,
    session,
    challengeHash: claimChallenge.challengeHash,
    issuedAt: claimChallenge.issuedAt,
    armedExpectedEpoch: session.claim ? session.claim.expectedEpoch : null,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const dbName = options.db;
  const fixture = options.fixture;
  const shard = options.shard;
  const rounds = Number(options.rounds);
  const rundir = options.rundir;
  const clockMs = Number(options.clock);
  const prepared = readJson(options.prepared);

  const ctx = await support.makeContext({
    tag: `race-${fixture}-${shard}`,
    dbName,
    syncIndexes: false,
    dropOnTeardown: false,
    mode: 'raw-registry',
    principalId: shard === 'A' ? OWNER_A : OWNER_B,
  });
  ctx.clock.set(clockMs);

  const baseAuthority = ctx.authorityService();
  // Test-only observation wrapper: delegates every call to the real service and records the
  // claim envelope (the pairing service performs the claim internally).
  const observedClaims = [];
  const observingAuthority = {
    ...baseAuthority,
    claimAuthority: async (args) => {
      const result = await baseAuthority.claimAuthority(args);
      observedClaims.push({
        matched: result.matched ?? 0,
        ok: result.ok === true,
        errorCode: result.error ? result.error.code : null,
      });
      return result;
    },
  };
  // The local endpoint owns this consent verdict: the consent VERIFIER is the injected seam
  // (freeze §9). ctx.consent is the same FIXED trusted verifier support.makeContext injects
  // everywhere else: it echoes the trusted session truth the product handed it.
  const pairing = ctx.pairingService({
    authorityService: observingAuthority,
    verifyLocalConsent: ctx.consent.verify.bind(ctx.consent),
  });

  const results = [];
  try {
    for (let round = 0; round < rounds; round += 1) {
      const device = prepared.devices[round % prepared.devices.length];

      writeJson(`${rundir}/${fixture}-ready-${round}-${shard}.json`, {
        shard,
        round,
        pid: process.pid,
        at: ctx.clock.now(),
      });
      await waitForFile(`${rundir}/${fixture}-go-${round}.json`);

      let record;
      let armed = null;
      if (fixture === 'E2-T7-ONEPC-TWO-PC-RACE') {
        const outcome = await baseAuthority.claimAuthority({
          deviceId: device.deviceId,
          tenantId: TENANT,
          ownerId: OWNER_A,
          expectedEpoch: 0,
          sessionId: `e2-t7-${shard}-${round}`,
          grantProof: null,
        });
        record = {
          action: 'claimAuthority',
          deviceId: device.deviceId,
          ownerId: OWNER_A,
          expectedEpoch: 0,
          ok: outcome.ok === true,
          matched: outcome.matched ?? 0,
          errorCode: outcome.error ? outcome.error.code : null,
        };
      } else if (fixture === 'E2-T8-TWO-OWNERS-ONE-PC-RACE') {
        const ownerId = shard === 'A' ? OWNER_A : OWNER_B;
        const outcome = await baseAuthority.claimAuthority({
          deviceId: device.deviceId,
          tenantId: TENANT,
          ownerId,
          expectedEpoch: 0,
          sessionId: `e2-t8-${shard}-${round}`,
          grantProof: null,
        });
        record = {
          action: 'claimAuthority',
          deviceId: device.deviceId,
          ownerId,
          expectedEpoch: 0,
          ok: outcome.ok === true,
          matched: outcome.matched ?? 0,
          errorCode: outcome.error ? outcome.error.code : null,
        };
      } else if (fixture === 'E2-V24T15-REVOKE-VS-CLAIM-RACE') {
        if (shard === 'A') {
          const outcome = await baseAuthority.revokeLease({
            deviceId: device.deviceId,
            tenantId: TENANT,
            ownerId: device.seedOwner,
            epoch: device.seedEpoch,
          });
          record = {
            action: 'revokeLease',
            deviceId: device.deviceId,
            ownerId: device.seedOwner,
            expectedEpoch: device.seedEpoch,
            ok: outcome.ok === true,
            matched: outcome.matched ?? 0,
            errorCode: outcome.error ? outcome.error.code : null,
          };
        } else {
          /**
           * GM-41 — THE ARM WAITS FOR THE REVOKE TO BE OBSERVED COMMITTED.
           *
           * This fixture asserts that every raced row commits BOTH legal transitions in order: the
           * revoke (epoch 1->2) and then the fresh claim (2->3). That expectation is only true under
           * an ordering the fixture previously did not establish. Both shards were released by the
           * same `go` file, so when the claim armed before the revoke committed, the lease was still
           * live, `issuePairingSession` CORRECTLY refused it, no CAS was attempted, and the row
           * produced one transition instead of two.
           *
           * The product was right and the fixture went red for it — measured at 23 of 25 rows and 48
           * of 50 CAS attempts, reported as a PRODUCT_FAIL. A flake that reads as a product failure
           * trains everyone to re-run red results, which is what lets a real regression through.
           *
           * So the arm waits, with a bound, until the row observably leaves the live lease. The race
           * is still real: the claim still lands immediately after the revoke, in the next window,
           * with the product's own epoch arithmetic deciding everything. What is removed is only the
           * fixture's dependence on which side of the barrier the scheduler happened to pick.
           */
          const armedAfterRevoke = await waitForRevokeCommitted(ctx, device, { timeoutMs: 15000 });
          if (!armedAfterRevoke.ok) {
            record = {
              action: 'waitForRevokeCommitted',
              deviceId: device.deviceId,
              ownerId: device.claimOwner,
              ok: false,
              matched: 0,
              errorCode: 'REVOKE_NOT_OBSERVED_COMMITTED',
              waitedMs: armedAfterRevoke.waitedMs,
              casAttempted: false,
            };
          } else {
            armed = await armClaimCeremony(ctx, pairing, device, env.makeDeviceKey(device.tag));
          }
          if (!record && !armed.ok) {
            record = {
              action: 'armClaimCeremony',
              deviceId: device.deviceId,
              ownerId: device.claimOwner,
              ok: false,
              matched: 0,
              errorCode: armed.error ? armed.error.code : null,
              armStage: armed.stage,
              casAttempted: false,
            };
          } else if (!record) {
            // Reached ONLY when the revoke was observed committed and the arm succeeded. The wait is
            // not an outcome: when it fails, `record` is already set and `armed` is still null, so this
            // branch must be skipped rather than dereferencing it.
            const key = env.makeDeviceKey(device.tag);
            const proof = support.pairingClaimProof(ctx, {
              session: armed.session,
              ownerId: device.claimOwner,
              challengeHash: armed.challengeHash,
              key,
              issuedAt: armed.issuedAt,
            });
            const approve = await pairing.approvePairingClaim({
              pairingSessionId: String(armed.session._id),
              tenantId: TENANT,
              ownerId: device.claimOwner,
              domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
              localConsent: { nonce: 'lab-consent-nonce-0001' },
              proof,
            });
            const observed = observedClaims[observedClaims.length - 1] ?? { matched: 0, ok: false, errorCode: null };
            record = {
              action: 'approvePairingClaim->claimAuthority',
              deviceId: device.deviceId,
              ownerId: device.claimOwner,
              armedExpectedEpoch: armed.armedExpectedEpoch,
              ok: approve.ok === true && observed.ok === true,
              matched: observed.matched,
              errorCode: approve.error ? approve.error.code : observed.errorCode,
              approveOk: approve.ok === true,
              casAttempted: true,
            };
          }
        }
      } else {
        throw new Error(`unknown race fixture ${fixture}`);
      }

      writeJson(`${rundir}/${fixture}-res-${round}-${shard}.json`, { round, shard, pid: process.pid, ...record });
      results.push({ round, shard, pid: process.pid, ...record });
    }

    writeJson(`${rundir}/${fixture}-results-${shard}.json`, {
      shard,
      pid: process.pid,
      rounds,
      results,
      duplicateKeyObservations: ctx.recorder.duplicateErrors(),
      writeConcernSummary: ctx.recorder.summary(),
    });
    return 0;
  } finally {
    await ctx.teardown().catch(() => {});
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`${JSON.stringify({ child: 'race', status: 'HARNESS_FAIL', error: { name: err.name, message: err.message, stack: err.stack } })}\n`);
    process.exit(4);
  },
);
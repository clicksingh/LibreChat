'use strict';

/**
 * E1-T20-CRASH-AFTER-SPEND crash child (lane I9 / task T1).
 *
 *   node crash-child.cjs --db=<w3 db> --point=c2|c3|c4|c5|c6 --rundir=<dir> --clock=<ms> \
 *        --owner=<principalId>
 *
 * The child performs the REAL product writes for its crash point and then calls `process.exit(7)`
 * from a test-only observation wrapper, i.e. after the target product write and before the next
 * product step. Every wrapper awaits the real product method and only observes its envelope; no
 * product behaviour is reimplemented. A witness file records the durable facts the parent
 * verifier needs (the parent is a separate OS process and never trusts the child's memory).
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const support = require('../w3a/support.cjs');
const env = require('../w3a/env.cjs');

const TENANT = env.TENANT;
const SENTINEL = 7;

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

/**
 * Drives the REAL pairing ceremony up to (and including) approvePairingClaim with the supplied
 * pairing service, so a crash wrapper on any underlying product call can fire.
 * Returns the approve envelope plus the pieces the parent verifier needs.
 */
async function drivePairingUntilApprove(ctx, pairing, { deviceId, deviceKeyId, ownerId, key, rundir, point }) {
  const openChallenge = await pairing.mintPairingOpenChallenge({ tenantId: TENANT, deviceId, deviceKeyId });
  if (!openChallenge.ok) return { approve: null, stage: 'mint-open-challenge' };
  const issue = await pairing.issuePairingSession({
    tenantId: TENANT,
    deviceId,
    deviceKeyId,
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
    requestSource: 'e1-crash',
    challengeHash: openChallenge.challengeHash,
    proof: support.pairingOpenProof(ctx, {
      deviceId,
      deviceKeyId,
      key,
      challengeHash: openChallenge.challengeHash,
      issuedAt: openChallenge.issuedAt,
    }),
  });
  if (!issue.ok) return { approve: null, stage: 'issue', error: issue.error };
  const redeem = await pairing.redeemPairingCode({ code: issue.code, tenantId: TENANT, ownerId });
  if (!redeem.ok) return { approve: null, stage: 'redeem', error: redeem.error };
  const session = await ctx.models.PairingSession.findOne({ _id: redeem.pairingSession._id, tenantId: TENANT }).lean();
  const claimChallenge = await pairing.mintPairingClaimChallenge({
    pairingSessionId: String(session._id),
    tenantId: TENANT,
    ownerId,
  });
  if (!claimChallenge.ok) return { approve: null, stage: 'mint-claim-challenge', error: claimChallenge.error };
  writeJson(`${rundir}/${point}-armed.json`, {
    deviceId,
    deviceKeyId,
    sessionId: String(session._id),
    claimChallengeHash: claimChallenge.challengeHash,
    claimChallengeIssuedAt: claimChallenge.issuedAt,
    deviceTag: key.tag ?? null,
  });
  const proof = support.pairingClaimProof(ctx, {
    session,
    ownerId,
    challengeHash: claimChallenge.challengeHash,
    key,
    issuedAt: claimChallenge.issuedAt,
  });
  const approve = await pairing.approvePairingClaim({
    pairingSessionId: String(session._id),
    tenantId: TENANT,
    ownerId,
    domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
    localConsent: { nonce: 'lab-consent-nonce-0001' },
    proof,
  });
  return { approve, session, claimChallenge, stage: approve.ok ? 'done' : 'approve' };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const dbName = options.db;
  const point = options.point;
  const rundir = options.rundir;
  const clockMs = Number(options.clock);
  const ownerId = options.owner ?? env.OWNER_A;

  const ctx = await support.makeContext({
    tag: `crash-${point}`,
    dbName,
    syncIndexes: false,
    dropOnTeardown: false,
    mode: 'raw-registry',
    principalId: ownerId,
  });
  ctx.clock.set(clockMs);

  // Bind the trusted consent seam to this process's injected clock so the structured verifier
  // emits approvedAt from the lab epoch, not the wall clock (see env.makeLocalConsent).
  const consent = env.makeLocalConsent({ clock: ctx.clock });
  ctx.consent = consent;

  const pairingServiceFor = (extra = {}) =>
    ctx.pairingService({ verifyLocalConsent: consent.verify.bind(consent), ...extra });

  const tag = `e1-crash-${point}`;
  const key = env.makeDeviceKey(tag);
  let witnessWritten = false;
  const crash = (payload) => {
    witnessWritten = true;
    writeJson(`${rundir}/${point}-witness.json`, {
      point,
      pid: process.pid,
      tenantId: TENANT,
      ownerId,
      clockMs: ctx.clock.now(),
      reachedPostStep: false,
      witnessCount: witnessWritten ? 0 : 1,
      deviceTag: tag,
      ...payload,
    });
    process.exit(SENTINEL);
  };

  // Real registration: the device identity and its deviceKeyId come from the product itself.
  const registration = await support.registerDevice(ctx, { deviceName: tag, key });
  if (!registration.ok) {
    writeJson(`${rundir}/${point}-registration-failed.json`, {
      error: registration.error && registration.error.code ? registration.error.code : null,
    });
    await ctx.teardown();
    process.exit(4);
  }
  const deviceId = registration.deviceId;
  const deviceKeyId = registration.deviceKeyId;
  const durable = { deviceId, deviceKeyId };
  ctx.bindTrust({ deviceId, principalId: ownerId });

'use strict';

/* Region c2..c4 for crash-child.cjs (kept as a separate authoring file, then spliced in). */

/* ---- c2: crash immediately after the pairing-claim challenge spend ------------- */
if (point === 'c2') {
  const baseAuthority = ctx.authorityService();
  const observingAuthority = {
    ...baseAuthority,
    spendChallenge: async (args) => {
      const result = await baseAuthority.spendChallenge(args);
      if (result.ok === true && args.purpose === 'pairing-claim') {
        crash({
          crashPoint: 'c2-after-challenge-spend',
          after: 'authorityService.spendChallenge',
          ...durable,
          challengeHash: args.challengeHash,
          spendMatched: result.matched,
        });
      }
      return result;
    },
  };
  const pairing = pairingServiceFor({ authorityService: observingAuthority });
  const ceremony = await drivePairingUntilApprove(ctx, pairing, { deviceId, deviceKeyId, ownerId, key, rundir, point });
  writeJson(`${rundir}/${point}-unexpected.json`, { approveOk: ceremony.approve ? ceremony.approve.ok === true : false });
  await ctx.teardown();
  process.exit(0);
}

/* ---- c3: crash immediately after the session claim_pending -> consumed CAS ----- */
if (point === 'c3') {
  // A pass-through Proxy over the genuine model registry: every property/method is the real one
  // except PairingSession.findOneAndUpdate, which delegates to the real model and observes.
  const observingDb = new Proxy(ctx.db, {
    get(target, property, receiver) {
      if (property !== 'PairingSession') {
        return Reflect.get(target, property, receiver);
      }
      const realModel = target.PairingSession;
      return new Proxy(realModel, {
        get(modelTarget, modelProperty, modelReceiver) {
          if (modelProperty !== 'findOneAndUpdate') {
            return Reflect.get(modelTarget, modelProperty, modelReceiver);
          }
          return async (...args) => {
            const result = await realModel.findOneAndUpdate(...args);
            if (result && result.state === 'consumed' && (result.grantedGrantId ?? null) === null) {
              crash({
                crashPoint: 'c3-after-session-consume',
                after: 'PairingSession.findOneAndUpdate claim_pending->consumed',
                ...durable,
                sessionId: String(result._id),
                grantedGrantIdAfterConsume: result.grantedGrantId ?? null,
              });
            }
            return result;
          };
        },
      });
    },
  });
  const pairing = pairingServiceFor({ db: observingDb });
  const ceremony = await drivePairingUntilApprove(ctx, pairing, { deviceId, deviceKeyId, ownerId, key, rundir, point });
  writeJson(`${rundir}/${point}-unexpected.json`, { approveOk: ceremony.approve ? ceremony.approve.ok === true : false });
  await ctx.teardown();
  process.exit(0);
}

/* ---- c4: crash immediately after the LP-4 authority claim CAS ------------------ */
if (point === 'c4') {
  const baseAuthority = ctx.authorityService();
  const observingAuthority = {
    ...baseAuthority,
    claimAuthority: async (args) => {
      const result = await baseAuthority.claimAuthority(args);
      if (result.ok === true && result.matched === 1) {
        crash({
          crashPoint: 'c4-after-authority-claim',
          after: 'authorityService.claimAuthority',
          ...durable,
          sessionId: args.sessionId,
          claimMatched: result.matched,
          claimEpoch: result.authority ? result.authority.epoch : null,
          grantIdLength: result.authority && typeof result.authority.grantId === 'string' ? result.authority.grantId.length : 0,
        });
      }
      return result;
    },
  };
  const pairing = pairingServiceFor({ authorityService: observingAuthority });
  const ceremony = await drivePairingUntilApprove(ctx, pairing, { deviceId, deviceKeyId, ownerId, key, rundir, point });
  writeJson(`${rundir}/${point}-unexpected.json`, { approveOk: ceremony.approve ? ceremony.approve.ok === true : false });
  await ctx.teardown();
  process.exit(0);
}

  /* ---- c5 / c6 need a complete committed ceremony first -------------------------- */
  const ceremony = await support.runPairingCeremony(ctx, { deviceId, deviceKeyId, ownerId, key });
  if (!ceremony.ok) {
    writeJson(`${rundir}/${point}-ceremony-failed.json`, {
      stage: ceremony.stage,
      errorCode: ceremony.approve && ceremony.approve.error ? ceremony.approve.error.code : null,
    });
    await ctx.teardown();
    process.exit(4);
  }
  const granted = ceremony.approve.authority;

  if (point === 'c5') {
    const baseAuthority = ctx.authorityService();
    const observingAuthority = {
      ...baseAuthority,
      revokeLease: async (args) => {
        const result = await baseAuthority.revokeLease(args);
        if (result.ok === true && result.matched === 1) {
          crash({
            crashPoint: 'c5-after-revoke',
            after: 'authorityService.revokeLease',
            ...durable,
            sessionId: ceremony.sessionId,
            grantIdBeforeRevoke: granted ? granted.grantId : null,
            revokeEpoch: result.authority ? result.authority.epoch : null,
            prevEpoch: result.authority ? result.authority.prevEpoch : null,
          });
        }
        return result;
      },
    };
    await observingAuthority.revokeLease({ deviceId, tenantId: TENANT, ownerId, epoch: granted ? granted.epoch : 1 });
    writeJson(`${rundir}/${point}-unexpected.json`, { note: 'revoke returned without crashing' });
    await ctx.teardown();
    process.exit(0);
  }

  if (point === 'c6') {
    const baseAuthority = ctx.authorityService();
    const observingAuthority = {
      ...baseAuthority,
      retireIdentity: async (args) => {
        const result = await baseAuthority.retireIdentity(args);
        if (result.ok === true && result.matched === 1) {
          crash({
            crashPoint: 'c6-after-retire',
            after: 'authorityService.retireIdentity',
            ...durable,
            sessionId: ceremony.sessionId,
            retireMatched: result.matched,
            retireEpoch: result.authority ? result.authority.epoch : null,
          });
        }
        return result;
      },
    };
    await observingAuthority.retireIdentity({ deviceId, tenantId: TENANT });
    writeJson(`${rundir}/${point}-unexpected.json`, { note: 'retire returned without crashing' });
    await ctx.teardown();
    process.exit(0);
  }

  throw new Error(`unknown crash point ${point}`);
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`${JSON.stringify({ child: 'crash', status: 'HARNESS_FAIL', error: { name: err.name, message: err.message } })}\n`);
    process.exit(4);
  },
);
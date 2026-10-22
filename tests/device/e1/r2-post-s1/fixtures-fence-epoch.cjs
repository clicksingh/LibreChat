'use strict';

/**
 * R2-FENCE-EPOCH — hostile rows H-01..H-10 (epoch/generation law, claim ceremony fence).
 *
 * Tier discipline: every E1 row below attempts the genuine composition (raw
 * `createModels(mongoose)` registry + real `AuditEvent` sink) as its FIRST step. When that step
 * throws the frozen factory guard, the row is recorded EXPECTED_RED / FACTORY_COMPOSITION_FAIL and
 * the downstream frozen oracle is preserved as `pendingOracle`. No fixture here substitutes a
 * facade, a plain-object db, or a raw-driver audit sink to reach the downstream red.
 *
 * E0 components are labelled `tier:'E0'` and are static/pure observations only; a row can never be
 * PASS_CURRENT on E0 components alone when its oracle is E1.
 */

const { runFixture, compositionBlocked, seedAuthority } = require('./ctx.cjs');
const { STATUS } = require('./results.cjs');
const env = require('./env.cjs');

const fs = require('node:fs');
const path = require('node:path');

const AUTHORITY = 'authorityService.js';

function sliceSource(absolute, from, to) {
  if (!fs.existsSync(absolute)) return null;
  return fs
    .readFileSync(absolute, 'utf8')
    .split('\n')
    .slice(from - 1, to)
    .map((line, index) => `${from + index}: ${line.trim()}`)
    .join('\n');
}

function src(relative, from, to) {
  return sliceSource(path.join(env.DEVICE_DIR, relative), from, to);
}

function srcWorktree(relative, from, to) {
  return sliceSource(path.join(env.WORKTREE, relative), from, to);
}

const ANCHORS = {
  retirePipeline: 'api/server/services/Device/authorityService.js:158-172',
  retireImpl: 'api/server/services/Device/authorityService.js:882-950',
  claimFilter: 'api/server/services/Device/authorityService.js:106-118',
  auditEmit: 'api/server/services/Device/authorityService.js:320-334',
  casLaw: 'api/server/services/Device/authorityService.js:247-264',
  spendBoundTenant: 'api/server/services/Device/authorityService.js:958-990',
  guardAuthority: 'api/server/services/Device/authorityService.js:174-189',
  guardRegistration: 'api/server/services/Device/registrationService.js:166-189',
  guardPairing: 'api/server/services/Device/pairingSessionService.js:182-230',
  retireRoleReason: 'api/server/services/Device/authorityService.js:947',
  retireAdminNull: 'api/server/services/Device/authorityService.js:937',
  rejoinAttempts: 'api/server/services/Device/pairingSessionService.js:940-942',
  maxAttempts: 'api/server/services/Device/pairingSessionService.js:39',
  schemaChallenge: 'packages/data-schemas/src/schema/challenge.ts:17-63',
  schemaPairingClaim: 'packages/data-schemas/src/schema/pairingSession.ts:93-99',
  schemaAuthorityEpoch: 'packages/data-schemas/src/schema/deviceAuthority.ts:78-83',
};

function absenceEvidence(names) {
  const found = env.staticSurfaceAbsence(names);
  return names.map((name) => ({
    name,
    oracle: `${name} exists in the Device service bytes and the Phase-1 schema/model bytes`,
    actual: found[name].present
      ? `present in ${found[name].hits.join(', ')}`
      : 'absent from the Device service bytes and the Phase-1 schema/model bytes',
    met: found[name].present,
    tier: 'E0',
  }));
}

function fixtures() {
  return [
    {
      id: 'R2-H01-RETIRE-EPOCH',
      hostileRows: ['H-01'],
      tier: 'E1',
      group: 'R2-FENCE-EPOCH',
      expectedOracle: 'PASS iff readAuthority(deviceId,tenantId).epoch after retiring a pending/never row === g+1; FAIL if === g',
      options: { syncIndexes: true },
      build: async (ctx) => {
        const blocked = compositionBlocked(ctx, {
          pendingOracle: 'retireIdentity on a pending/never row returns matched===1 and readAuthority epoch === g+1',
          extraActual: {
            scenario: 'mint ceremony at g, retire pending/never row before the claim CAS',
            staticRetirePipeline: src(AUTHORITY, 158, 172),
          },
          components: [
            {
              name: 'retire_epoch_unconditional',
              oracle: 'retire advances epoch by exactly +1 regardless of prior leaseState',
              actual: 'buildRetirePipeline adds +1 only when leaseState === "active", so a pending/never row advances +0',
              met: false,
              tier: 'E0',
            },
          ],
        });
        return { ...blocked, attempts: 1, notes: 'first truthful failure is factory construction; oracle preserved as pending' };
      },
    },
    {
      id: 'R2-H02-RETIRED-RECOVERY',
      hostileRows: ['H-02'],
      tier: 'E1',
      group: 'R2-FENCE-EPOCH',
      expectedOracle: 'PASS iff recovery classification for a retired row is DEVICE_IDENTITY_REVOKED; FAIL if any bounded "re-attempt safe" result',
      build: async (ctx) => {
        const blocked = compositionBlocked(ctx, {
          pendingOracle: 'RECOVER_AFTER_UNCERTAIN(deviceId, tenantId, ownerId, g, grantId) on a retired row => DEVICE_IDENTITY_REVOKED',
          extraActual: { scenario: 'retired row then recovery classification' },
          components: absenceEvidence(['recoverAfterUncertain', 'RECOVER_AFTER_UNCERTAIN']),
        });
        return blocked;
      },
    },
    {
      id: 'R2-H03-EXPECTED-EPOCH-REQUIRED',
      hostileRows: ['H-03'],
      tier: 'E1',
      group: 'R2-FENCE-EPOCH',
      expectedOracle: 'PASS iff claimAuthority without expectedEpoch returns PAIRING_CEREMONY_REQUIRED (400) and performs 0 writes',
      build: async (ctx) => {
        const blocked = compositionBlocked(ctx, {
          pendingOracle: 'claimAuthority({deviceId,tenantId,ownerId,sessionId,grantProof}) with no expectedEpoch => { ok:false, error.code:"PAIRING_CEREMONY_REQUIRED" (400) }, writes 0',
          extraActual: {
            scenario: 'call claimAuthority without expectedEpoch',
            claimFilterSource: src(AUTHORITY, 106, 118),
            claimArgsSource: src(AUTHORITY, 516, 537),
          },
          components: absenceEvidence(['expectedEpoch', 'PAIRING_CEREMONY_REQUIRED']),
        });
        return blocked;
      },
    },
    {
      id: 'R2-H04-REQUEST-IDENTITY-REJECTED',
      hostileRows: ['H-04'],
      tier: 'E1',
      group: 'R2-FENCE-EPOCH',
      expectedOracle: 'PASS iff an adapter-forwarded body field (expectedEpoch | ceremonyId | generation) yields REQUEST_SUPPLIED_IDENTITY_REJECTED (400) with 0 writes',
      build: async (ctx) => {
        const constructed = env.scanConstructedErrorCodes().find((entry) => entry.code === 'REQUEST_SUPPLIED_IDENTITY_REJECTED') ?? null;
        const blocked = compositionBlocked(ctx, {
          pendingOracle: 'request-supplied expectedEpoch/ceremonyId/generation => REQUEST_SUPPLIED_IDENTITY_REJECTED (400), 0 writes, 0 model calls',
          extraActual: {
            scenario: 'adapter forwards request body fields expectedEpoch/ceremonyId/generation',
            constructedSitesForCode: constructed,
          },
          components: [
            {
              name: 'request_identity_rejection_emitted',
              oracle: 'at least one product site constructs REQUEST_SUPPLIED_IDENTITY_REJECTED before a model call',
              actual: constructed === null ? 'code exists in the error map but no product site constructs it' : `constructed at ${constructed.sites.join(', ')}`,
              met: constructed !== null,
              tier: 'E0',
            },
            (() => {
              const containers = env.staticSurfaceAbsence(['args.body', 'args.query', 'args.params']);
              const readBy = Object.entries(containers)
                .filter(([, value]) => value.present)
                .map(([key, value]) => `${key} -> ${value.hits.join(', ')}`);
              return {
                name: 'device_service_never_reads_request_containers',
                oracle: 'no Device service byte reads args.body/args.query/args.params',
                actual: readBy.length === 0 ? 'no request container is read by any Device service byte' : `read by ${readBy.join(' | ')}`,
                met: readBy.length === 0,
                tier: 'E0',
              };
            })(),
          ],
        });
        return blocked;
      },
    },
    {
      id: 'R2-H05-SUPERSEDED-CEREMONY',
      hostileRows: ['H-05'],
      tier: 'E1',
      group: 'R2-FENCE-EPOCH',
      expectedOracle: "PASS iff a superseded ceremony's proof spends 0-match and session.state is unchanged at 'claim_pending'",
      build: async (ctx) => {
        const blocked = compositionBlocked(ctx, {
          pendingOracle: "ceremony-1 proof after ceremony-2 arming => spend 0-match, session.state === 'claim_pending'",
          extraActual: {
            scenario: "present ceremony 1's proof after ceremony 2 was armed for the same session",
            challengeSchemaSource: srcWorktree('packages/data-schemas/src/schema/challenge.ts', 17, 63),
            pairingClaimSubdocSource: srcWorktree('packages/data-schemas/src/schema/pairingSession.ts', 93, 99),
          },
          components: [
            {
              name: 'boundEpoch_persisted',
              oracle: 'Challenge.boundEpoch exists and is mandatory in schema + spend CAS (F2)',
              actual: 'challenge schema has no boundEpoch field; spend whitelist has no boundEpoch conjunct',
              met: false,
              tier: 'E0',
            },
            {
              name: 'claim_expectedEpoch_persisted',
              oracle: 'PairingSession.claim.expectedEpoch exists (F2)',
              actual: 'PairingSession.claim subdocument exposes challengeRef + openedAt only',
              met: false,
              tier: 'E0',
            },
          ],
        });
        return blocked;
      },
    },
    {
      id: 'R2-H06-ONE-WINNER-PER-GENERATION',
      hostileRows: ['H-06'],
      tier: 'E1',
      group: 'R2-FENCE-EPOCH',
      expectedOracle: 'PASS iff exactly one of N>=50 competing ceremonies at generation g reports matched===1, every loser reports matched===0, and epochDelta===1 (one winner PER GENERATION)',
      options: { syncIndexes: false },
      build: async (ctx) => {
        const N = 50;
        let winners = 0;
        let losers = 0;
        let compositionFailures = 0;
        const firstErrors = [];
        for (let i = 0; i < N; i += 1) {
          const attempts = ctx.compose();
          const rejected = attempts.filter((a) => a.accepted === false);
          if (rejected.length === attempts.length) {
            compositionFailures += 1;
            if (firstErrors.length < 1) firstErrors.push(rejected[0].error);
          } else {
            winners += 1;
          }
        }
        losers = 0; // no attempt reached a CAS, so no attempt can be called a loser of the race
        return {
          status: STATUS.EXPECTED_RED,
          attempts: N,
          actual: {
            kind: 'FACTORY_COMPOSITION_FAIL',
            scenario: 'two competing claim ceremonies minted at the same generation g, N=50',
            n: N,
            compositionFailures,
            notExecuted: compositionFailures,
            winners,
            losers,
            epochDelta: null,
            firstCompositionError: firstErrors[0] ?? null,
            pendingOracle: 'exactly one attempt reports matched===1 per generation g; every loser reports matched===0; epochDelta===1',
            pendingAfterFirstFix: true,
            oneWinnerPerGenerationOnly: true,
          },
          components: [
            {
              name: 'one_winner_per_generation',
              oracle: 'exactly one winner per generation g (never two)',
              actual: `${winners} winners observed among ${N} attempts; all ${compositionFailures} attempts stopped at factory construction`,
              met: false,
              tier: 'E1',
            },
          ],
          sourceAnchors: [ANCHORS.guardAuthority, ANCHORS.casLaw],
          notes: 'V24-T15 fence: this row asserts one winner PER GENERATION only; the legitimate sequential regrant in a NEW generation is asserted separately by R2-H07 (never both in one fixture).',
        };
      },
    },
    {
      id: 'R2-H08-MATCHEDCOUNT-UNCERTAIN',
      hostileRows: ['H-08'],
      tier: 'E1',
      group: 'R2-FENCE-EPOCH',
      expectedOracle: 'PASS iff a DeviceAuthority.updateOne reporting matchedCount:2 yields WRITE_OUTCOME_UNCERTAIN and emits 0 audit rows',
      build: async (ctx) => {
        const blocked = compositionBlocked(ctx, {
          pendingOracle: 'matchedCount:2 => { ok:false, error.code:"WRITE_OUTCOME_UNCERTAIN" } and audit recorder length 0',
          extraActual: { scenario: 'force DeviceAuthority.updateOne to report matchedCount:2', casLawSource: src(AUTHORITY, 247, 290) },
          components: [
            {
              name: 'matchedCount_gt_one_classified',
              oracle: 'non-finite/unacknowledged/matchedCount>1 => WRITE_OUTCOME_UNCERTAIN with no success audit',
              actual: 'performUpdate only rejects non-numeric/non-acknowledged results; no matchedCount>1 branch is observable without composition',
              met: false,
              tier: 'E1',
            },
          ],
        });
        return blocked;
      },
    },
    {
      id: 'R2-H09-BENIGN-RENEWAL-STALENESS',
      hostileRows: ['H-09'],
      tier: 'E1',
      group: 'R2-FENCE-EPOCH',
      expectedOracle: 'PASS iff a benign epoch advance between mint and claim fires a documented terminal code AND a fresh ceremony can be minted afterwards',
      build: async (ctx) => {
        const blocked = compositionBlocked(ctx, {
          pendingOracle: 'PAIRING_CEREMONY_STALE with a documented re-issue path, plus successful fresh-session mint',
          extraActual: { scenario: 'renew (benign epoch advance) between ceremony mint and claim' },
          components: absenceEvidence(['PAIRING_CEREMONY_STALE', 'PAIRING_CEREMONY_REQUIRED']),
        });
        return blocked;
      },
    },
    {
      id: 'R2-H10-EPOCH-NO-DECREMENT',
      hostileRows: ['H-10'],
      tier: 'E1',
      group: 'R2-FENCE-EPOCH',
      expectedOracle: 'PASS iff a write that sets epoch at or below the committed prevEpoch fails hard; never a silent decrement',
      build: async (ctx) => {
        const deviceId = `r2-t0-h10-${Date.now().toString(36)}`;
        const authorityRow = await seedAuthority(ctx, { _id: deviceId, epoch: 5, leaseState: 'expired', identityState: 'active', ownerId: env.w3a.OWNER_A });
        const before = await ctx.models.DeviceAuthority.findOne({ _id: deviceId }).lean();

        let decrementResult = null;
        let decrementError = null;
        try {
          const res = await ctx.models.DeviceAuthority.updateOne({ _id: deviceId }, { $set: { epoch: 3, prevEpoch: 5 } });
          decrementResult = { acknowledged: res.acknowledged === true, matchedCount: res.matchedCount, modifiedCount: res.modifiedCount };
        } catch (err) {
          decrementError = { name: err.name, message: err.message, paths: Object.keys(err.errors ?? {}) };
        }
        const after = await ctx.models.DeviceAuthority.findOne({ _id: deviceId }).lean();

        let validatorResult = null;
        let validatorError = null;
        try {
          const res = await ctx.models.DeviceAuthority.updateOne(
            { _id: deviceId },
            { $set: { epoch: -1 } },
            { runValidators: true },
          );
          validatorResult = { acknowledged: res.acknowledged === true, matchedCount: res.matchedCount };
        } catch (err) {
          validatorError = { name: err.name, message: err.message, paths: Object.keys(err.errors ?? {}) };
        }

        const silentDecrement = decrementError === null && after !== null && after.epoch < before.epoch;
        return {
          status: STATUS.EXPECTED_RED,
          actual: {
            scenario: 'write epoch at or below the committed prevEpoch (5) on the real DeviceAuthority model',
            seededEpoch: before ? before.epoch : null,
            decrementWrite: decrementResult,
            decrementError,
            epochAfterDecrement: after ? after.epoch : null,
            silentDecrement,
            negativeEpochWithRunValidators: validatorResult,
            negativeEpochError: validatorError,
            pendingOracle: 'a write of epoch <= prevEpoch must fail hard (schema/CAS level), never silently decrement',
            pendingAfterFirstFix: true,
          },
          components: [
            {
              name: 'no_epoch_decrement',
              oracle: 'epoch is strictly non-decreasing per _id: hard failure on a decrement',
              actual:
                decrementError !== null
                  ? `hard failure: ${decrementError.name}: ${decrementError.message}`
                  : `silent decrement accepted: epoch 5 -> ${after ? after.epoch : 'n/a'} (matchedCount ${decrementResult ? decrementResult.matchedCount : 'n/a'})`,
              met: decrementError !== null,
              tier: 'E1',
            },
            {
              name: 'negative_epoch_blocked',
              oracle: 'min:0 blocks a negative epoch',
              actual:
                validatorError !== null
                  ? `blocked by runValidators: ${validatorError.message}`
                  : `accepted with runValidators (matchedCount ${validatorResult ? validatorResult.matchedCount : 'n/a'})`,
              met: validatorError !== null,
              tier: 'E1',
            },
          ],
          sourceAnchors: [ANCHORS.schemaAuthorityEpoch],
          attempts: 2,
          notes: 'No service composition is needed for this row: the fence value is schema/model-level, so the row executes genuinely.',
        };
      },
    },
  ];
}

module.exports = { id: 'R2-FENCE-EPOCH', fixtures };

async function main(record) {
  for (const def of fixtures()) {
    // eslint-disable-next-line no-await-in-loop
    record(await runFixture(def));
  }
}
module.exports.main = main;
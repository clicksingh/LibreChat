'use strict';

/**
 * R2-COMPOSITION-ERRORS — hostile rows H-30..H-39 (real-model composition, audit projector,
 * error-map completeness, write-result provability, G16 ledger, invariant citations).
 *
 * Rows whose first truthful failure is factory construction are EXPECTED_RED /
 * FACTORY_COMPOSITION_FAIL with the frozen oracle preserved. Rows that are genuinely executable
 * without product composition (H-30 construction gate, H-32 pure error map, H-33 static map
 * completeness, H-37 effective write concern, H-38 ledger, H-39 citations) execute for real.
 */

const fs = require('node:fs');
const path = require('node:path');

const { runFixture, compositionBlocked } = require('./ctx.cjs');
const { STATUS } = require('./results.cjs');
const env = require('./env.cjs');
const preflight = require('./preflight.cjs');
const ctxState = require('./ctx.cjs').state;

function fixtures() {
  return [
    {
      id: 'R2-H30-REAL-MODEL-COMPOSITION',
      hostileRows: ['H-30'],
      tier: 'E1',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff all three services construct directly from createModels(mongoose) with no facade and no facade provenance',
      build: async (ctx) => {
        const composition = ctx.compose();
        const allAccepted = composition.every((c) => c.accepted === true);
        const registryShape = ctx.shape;
        const anyFacade = Object.values(registryShape).some((s) => s.typeofModel !== 'function');
        return {
          status: allAccepted && !anyFacade ? STATUS.PASS_CURRENT : STATUS.EXPECTED_RED,
          attempts: composition.length,
          actual: {
            kind: allAccepted ? 'COMPOSITION_OK' : 'FACTORY_COMPOSITION_FAIL',
            scenario: 'construct each service with createModels(mongoose), no facade',
            composition,
            registryModelTypeof: Object.fromEntries(Object.entries(registryShape).map(([k, v]) => [k, v.typeofModel])),
            facadeProvenancePresent: anyFacade,
            dbArgument: 'raw createModels(mongoose) registry (no makeDbFacade, no plain-object model surface)',
            pendingOracle: 'all three frozen factories accept genuine Mongoose Model constructors and the services round-trip against real Mongo',
            pendingAfterFirstFix: !allAccepted,
          },
          components: composition.map((c) => ({
            name: `factory__${c.factory}`,
            oracle: 'factory accepts genuine Mongoose model constructors',
            actual: c.accepted ? 'accepted' : `${c.error.name}: ${c.error.message}`,
            met: c.accepted,
            tier: 'E1',
          })),
          sourceAnchors: composition.filter((c) => !c.accepted).map((c) => c.guardAnchor),
          productClaim: false,
          notes: 'This is the frozen D-04 / G12 defect row: the guard rejects `typeof model === "function"`, so no genuine composition is possible today.',
        };
      },
    },
    {
      id: 'R2-H31-AUDIT-SHAPE-PROJECTOR',
      hostileRows: ['H-31'],
      tier: 'E1',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff each missing projected key throws AUDIT_EVENT_SHAPE_INVALID before persistence and writes nothing',
      build: async (ctx) => {
        const required = ['tenantId', 'deviceId', 'epoch', 'kind', 'ts', 'actor', 'reasonCode'];
        const base = {
          tenantId: env.w3a.TENANT,
          deviceId: 'r2-t0-h31-device',
          ownerId: null,
          grantId: null,
          epoch: 0,
          seq: 0,
          kind: 'register',
          ts: new Date(ctx.clock.now()),
          actor: 'r2-t0-h31-actor',
          reasonCode: 'r2-t0-h31-reason',
        };
        const missingKeyResults = [];
        for (const key of required) {
          const doc = { ...base };
          delete doc[key];
          let outcome;
          try {
            // eslint-disable-next-line no-await-in-loop
            await ctx.models.AuditEvent.create([doc], { writeConcern: env.WRITE_CONCERN });
            outcome = { threw: false, error: null };
          } catch (err) {
            outcome = { threw: true, error: { name: err.name, message: err.message, paths: Object.keys(err.errors ?? {}) } };
          }
          missingKeyResults.push({ key, ...outcome });
        }
        let nullablePresence = null;
        try {
          const docs = await ctx.models.AuditEvent.create(
            [{ ...base, ownerId: null, grantId: null, seq: null }],
            { writeConcern: env.WRITE_CONCERN },
          );
          nullablePresence = { inserted: true, id: String(docs[0]._id) };
        } catch (err) {
          nullablePresence = { inserted: false, error: { name: err.name, message: err.message } };
        }

        const projector = env.staticSurfaceAbsence(['projectAuditEvent', 'AUDIT_EVENT_SHAPE_INVALID']);
        const everyMissingThrows = missingKeyResults.every((r) => r.threw === true);
        return {
          status: STATUS.EXPECTED_RED,
          attempts: required.length + 1,
          actual: {
            kind: 'PARTIAL_E1_MODEL_SHAPE_ONLY',
            scenario: 'reconstitute the frozen shape of every audit kind',
            missingRequiredKeyResults: missingKeyResults,
            everySchemaRequiredKeyThrows: everyMissingThrows,
            nullablePresenceWrite: nullablePresence,
            projectorAbsence: projector,
            pendingOracle: 'a projector validates kind-specific nullability and rejects invalid shapes with AUDIT_EVENT_SHAPE_INVALID before persistence',
            pendingAfterFirstFix: true,
          },
          components: [
            {
              name: 'schema_required_keys_enforced',
              oracle: 'a missing mandatory projected key throws before persistence',
              actual: everyMissingThrows ? `all ${required.length} mandatory keys throw a Mongoose ValidationError` : 'at least one mandatory key was accepted',
              met: everyMissingThrows,
              tier: 'E1',
            },
            {
              name: 'projector_exists',
              oracle: 'projectAuditEvent validates kind-specific nullability',
              actual: 'projectAuditEvent absent; AUDIT_EVENT_SHAPE_INVALID absent from the error vocabulary',
              met: false,
              tier: 'E0',
            },
          ],
          sourceAnchors: ['packages/data-schemas/src/schema/auditEvent.ts:24-66'],
          notes: 'The schema-level half is genuine E1 evidence; the frozen oracle additionally requires the kind-specific projector that does not exist, so the row stays EXPECTED_RED.',
        };
      },
    },
    {
      id: 'R2-H32-NEW-ERROR-STATUSES',
      hostileRows: ['H-32'],
      tier: 'E1',
      executedTier: 'E0',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff DeviceError(PAIRING_CEREMONY_STALE).httpStatus === 409 and DeviceError(PAIRING_CEREMONY_REQUIRED).httpStatus === 400',
      options: { dropOnTeardown: true },
      build: async (ctx) => {
        const errors = env.w3a.product.errors;
        const stale = new errors.DeviceError('PAIRING_CEREMONY_STALE');
        const required = new errors.DeviceError('PAIRING_CEREMONY_REQUIRED');
        const shapeInvalid = new errors.DeviceError('AUDIT_EVENT_SHAPE_INVALID');
        const inMap = {
          PAIRING_CEREMONY_STALE: Object.prototype.hasOwnProperty.call(errors.DEVICE_ERROR_CODES, 'PAIRING_CEREMONY_STALE'),
          PAIRING_CEREMONY_REQUIRED: Object.prototype.hasOwnProperty.call(errors.DEVICE_ERROR_CODES, 'PAIRING_CEREMONY_REQUIRED'),
          AUDIT_EVENT_SHAPE_INVALID: Object.prototype.hasOwnProperty.call(errors.DEVICE_ERROR_CODES, 'AUDIT_EVENT_SHAPE_INVALID'),
        };
        const met = stale.httpStatus === 409 && required.httpStatus === 400;
        return {
          status: met ? STATUS.PASS_CURRENT : STATUS.EXPECTED_RED,
          executedTier: 'E0',
          actual: {
            scenario: "construct DeviceError('PAIRING_CEREMONY_STALE') and DeviceError('PAIRING_CEREMONY_REQUIRED')",
            PAIRING_CEREMONY_STALE: { httpStatus: stale.httpStatus, inMap: inMap.PAIRING_CEREMONY_STALE, expected: 409 },
            PAIRING_CEREMONY_REQUIRED: { httpStatus: required.httpStatus, inMap: inMap.PAIRING_CEREMONY_REQUIRED, expected: 400 },
            AUDIT_EVENT_SHAPE_INVALID: { httpStatus: shapeInvalid.httpStatus, inMap: inMap.AUDIT_EVENT_SHAPE_INVALID, expected: 500 },
            pendingOracle: 'the three F9 error-map entries exist with statuses 409 / 400 / 500',
            pendingAfterFirstFix: !met,
          },
          components: [
            { name: 'PAIRING_CEREMONY_STALE_409', oracle: 'httpStatus 409 from a real map entry', actual: `httpStatus ${stale.httpStatus}, inMap ${inMap.PAIRING_CEREMONY_STALE}`, met: stale.httpStatus === 409 && inMap.PAIRING_CEREMONY_STALE === true, tier: 'E0' },
            { name: 'PAIRING_CEREMONY_REQUIRED_400', oracle: 'httpStatus 400 from a real map entry', actual: `httpStatus ${required.httpStatus}, inMap ${inMap.PAIRING_CEREMONY_REQUIRED}`, met: required.httpStatus === 400 && inMap.PAIRING_CEREMONY_REQUIRED === true, tier: 'E0' },
            { name: 'AUDIT_EVENT_SHAPE_INVALID_500', oracle: 'httpStatus 500 from a real map entry (a 500 produced by the unmapped-code fallback does not count)', actual: `httpStatus ${shapeInvalid.httpStatus}, inMap ${inMap.AUDIT_EVENT_SHAPE_INVALID}`, met: shapeInvalid.httpStatus === 500 && inMap.AUDIT_EVENT_SHAPE_INVALID === true, tier: 'E0' },
          ],
          sourceAnchors: ['api/server/services/Device/errors.js:1-20', 'api/server/services/Device/errors.js:159'],
          productClaim: false,
          notes: 'Pure E0 row (no I/O): the matrix marks it E1, but the oracle is a pure in-memory map lookup, so it is executed and labelled E0. Unmapped codes fall back to HTTP 500.',
        };
      },
    },
    {
      id: 'R2-H33-ERROR-MAP-COMPLETENESS',
      hostileRows: ['H-33'],
      tier: 'E1',
      executedTier: 'E0',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff every constructed `new DeviceError("<CODE>")` literal has an entry in the error map',
      build: async () => {
        const errors = env.w3a.product.errors;
        const constructed = env.scanConstructedErrorCodes();
        const rows = constructed.map((entry) => ({
          code: entry.code,
          sites: entry.sites,
          inMap: Object.prototype.hasOwnProperty.call(errors.DEVICE_ERROR_CODES, entry.code),
        }));
        const unmapped = rows.filter((r) => !r.inMap);
        return {
          status: unmapped.length === 0 ? STATUS.PASS_CURRENT : STATUS.EXPECTED_RED,
          executedTier: 'E0',
          attempts: rows.length,
          actual: {
            scenario: 'inspect every `new DeviceError("<CODE>")` site statically',
            constructedCodeCount: rows.length,
            constructedCodes: rows,
            unmapped,
            mapSize: Object.keys(errors.DEVICE_ERROR_CODES).length,
          },
          components: [
            {
              name: 'every_constructed_code_is_mapped',
              oracle: 'mapping completeness: no unmapped constructed code',
              actual: unmapped.length === 0 ? `all ${rows.length} constructed codes are mapped` : `unmapped: ${unmapped.map((u) => u.code).join(', ')}`,
              met: unmapped.length === 0,
              tier: 'E0',
            },
          ],
          sourceAnchors: ['api/server/services/Device/errors.js:1-20'],
          productClaim: false,
          notes: 'Pure E0 row: static scan of the frozen Device service bytes against the frozen error map. F9 adds three new codes; this row does not assert them (H-32 does).',
        };
      },
    },
    {
      id: 'R2-H34-ZERO-MATCH-NOT-STALE',
      hostileRows: ['H-34'],
      tier: 'E1',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff a same-value $set reported as matchedCount:0 by an instrumented model yields the documented code for that state, never a fabricated PAIRING_CEREMONY_STALE',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'matchedCount:0 on a same-value $set => the documented state code, never a fabricated staleness classification',
          extraActual: { scenario: 'replay a same-value $set reported as matchedCount:0 by an instrumented model' },
          components: [
            {
              name: 'no_fabricated_stale_classification',
              oracle: 'the classifier never fabricates a stale-ceremony classification for a live-state 0-match',
              actual: 'not observable: no service can be constructed; PAIRING_CEREMONY_STALE does not exist in the vocabulary at all today',
              met: false,
              tier: 'E1',
            },
          ],
        }),
    },
    {
      id: 'R2-H35-DEAD-ZONE-DETERMINISTIC',
      hostileRows: ['H-35'],
      tier: 'E1',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff the 5 s dead zone (now = expiresAt + 2500) emits exactly the frozen code and never the other candidate',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'now = expiresAt + 2500 => exactly one deterministic frozen code (PAIRING_WINDOW_TOO_EARLY), the other candidate never emitted',
          extraActual: { scenario: 'exercise the 5 s dead zone at now = expiresAt + 2500' },
          components: [
            {
              name: 'margin_code_present',
              oracle: 'PAIRING_WINDOW_TOO_EARLY exists with a frozen status for the 5 s margin',
              actual: `PAIRING_WINDOW_TOO_EARLY -> ${env.w3a.product.errors.DEVICE_ERROR_CODES.PAIRING_WINDOW_TOO_EARLY}`,
              met: env.w3a.product.errors.DEVICE_ERROR_CODES.PAIRING_WINDOW_TOO_EARLY === 409,
              tier: 'E0',
            },
          ],
        }),
    },
    {
      id: 'R2-H36-REJOIN-BUDGET',
      hostileRows: ['H-36'],
      tier: 'E1',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff the frozen rejoin/attempt provenance holds and any block of a legitimate same-owner rejoin is audited',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'same-owner legitimate rejoin x5 then redeem: the frozen budget behaviour holds and any block is audited',
          extraActual: {
            scenario: 'same-owner legitimate rejoin x5 then redeem',
            rejoinAttemptsSource: env.readProduct('pairingSessionService.js').source
              ? env.readProduct('pairingSessionService.js').source.split('\n').slice(936, 950).map((l, i) => `${937 + i}: ${l.trim()}`).join('\n')
              : null,
          },
          components: [
            {
              name: 'rejoin_consumes_zero_guess_attempts',
              oracle: 'a successful authenticated same-owner rejoin does not consume the code-guess attempt budget (F10)',
              actual: 'rejoinPendingPairing increments attemptsUsed via `$inc: { attemptsUsed: 1 }` (pairingSessionService.js:940-942), i.e. rejoin consumes the guess budget',
              met: false,
              tier: 'E0',
            },
          ],
        }),
    },
    {
      id: 'R2-H37-EFFECTIVE-WRITE-CONCERN',
      hostileRows: ['H-37'],
      tier: 'E1',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff a pinned write reports non-zero opTime, no writeConcernError and a non-null replica-set name; never a vacuous pass',
      build: async (ctx) => {
        const hello = await ctx.client.db(ctx.dbName).command({ hello: 1 });
        const reply = await ctx.client
          .db(ctx.dbName)
          .command({ insert: 'r2t0_write_probe', documents: [{ probe: 'h37', at: new Date(ctx.clock.now()) }], writeConcern: { w: 'majority', j: true } });
        const opTime = reply.opTime ?? null;
        const opTimeRaw = opTime !== null && typeof opTime === 'object' && opTime.ts !== undefined ? opTime.ts : opTime;
        const opTimeCandidate =
          opTimeRaw !== null && typeof opTimeRaw === 'object' && opTimeRaw.$timestamp !== undefined ? opTimeRaw.$timestamp : opTimeRaw;
        let opTimeSeconds = null;
        try {
          opTimeSeconds = opTimeCandidate === null || opTimeCandidate === undefined ? null : Number(BigInt(opTimeCandidate));
        } catch {
          opTimeSeconds = null;
        }
        const nonZeroOpTime = opTimeSeconds !== null && opTimeSeconds > 0;
        const writeConcernError = reply.writeConcernError ?? null;
        const setName = hello.setName ?? null;
        const modelWrite = await ctx.models.DeviceAuthority.create(
          [
            {
              _id: 'r2-t0-h37-model-write',
              tenantId: env.w3a.TENANT,
              deviceKeyId: 'r2-t0-h37-key',
              devicePublicKey: env.w3a.labKey.spkiB64u,
              identityState: 'pending',
              leaseState: 'never',
              epoch: 0,
            },
          ],
          { writeConcern: env.WRITE_CONCERN },
        );
        const met = nonZeroOpTime && writeConcernError === null && setName !== null;
        return {
          status: met ? STATUS.PASS_CURRENT : STATUS.UNEXPECTED_RED,
          attempts: 2,
          actual: {
            scenario: 'hello() + write-result inspection on a pinned majority+journal write',
            setName,
            opTime,
            opTimeSecondsText: opTimeSeconds === null ? null : `${opTimeSeconds}`,
            opTimeRawTypeof: typeof opTimeRaw,
            nonZeroOpTime,
            writeConcernError,
            writeConcernRequested: { w: 'majority', j: true },
            modelWriteInserted: modelWrite.length === 1,
            pendingOracle: 'every product authority-critical write proves effective majority+journal topology',
            pendingAfterFirstFix: false,
          },
          components: [
            { name: 'non_zero_opTime', oracle: 'opTime present and non-zero', actual: JSON.stringify(opTime), met: nonZeroOpTime, tier: 'E1' },
            { name: 'no_writeConcernError', oracle: 'writeConcernError absent', actual: JSON.stringify(writeConcernError), met: writeConcernError === null, tier: 'E1' },
            { name: 'replica_set_name', oracle: 'setName non-null', actual: String(setName), met: setName !== null, tier: 'E1' },
          ],
          sourceAnchors: ['api/server/services/Device/authorityService.js:34', 'api/server/services/Device/authorityService.js:253'],
          productClaim: false,
          notes: 'This row certifies that effective majority+journal durability is provable on the frozen topology for harness writes. It is NOT a product claim: whether each product write site pins the concern is H-29, which is blocked at factory composition.',
        };
      },
    },
    {
      id: 'R2-H38-G16-LEDGER-BEFORE-AFTER',
      hostileRows: ['H-38'],
      tier: 'E0',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff every G16 ledger path reproduces its SHA-256 and the path set is identical before and after the suite',
      build: async () => {
        const after = preflight.verifyLedger();
        const before = ctxState.g16Before ?? null;
        const stable =
          before !== null &&
          before.ok === true &&
          after.ok === true &&
          preflight.preimageFingerprint(before) === preflight.preimageFingerprint(after);
        const freezeMatches = after.freeze.ok === true;
        return {
          status: stable && freezeMatches ? STATUS.PASS_CURRENT : STATUS.UNEXPECTED_RED,
          executedTier: 'E0',
          attempts: after.itemCount,
          actual: {
            scenario: 'recompute every hash in the G16 ledger before and after R2/T0',
            ledgerPath: after.ledgerPath,
            governanceRoot: after.governanceRoot,
            itemCount: after.itemCount,
            declaredCount: after.declaredCount,
            verified: after.verified,
            mismatches: after.mismatches,
            missing: after.missing,
            duplicatePaths: after.duplicatePaths,
            pathSetDrift: after.pathSetDrift,
            aggregateDeclared: after.aggregateSha256Declared,
            before: before === null ? null : { ok: before.ok, verified: before.verified, fingerprint: preflight.preimageFingerprint(before), freezeActual: before.freeze.actual },
            afterOk: after.ok,
            afterFingerprint: preflight.preimageFingerprint(after),
            stableAcrossSuite: stable,
            newlyAuthorizedOutsideLedger: ['tests/device/e1/r2/**', 'tests/device/_phase1_evidence/w3b-r2/t0/**'],
          },
          components: [
            {
              name: 'all_preimages_reproduce',
              oracle: '51/51 ledger preimages reproduce their SHA-256',
              actual: `${after.verified}/${after.itemCount} verified; missing ${after.missing.length}; mismatches ${after.mismatches.length}`,
              met: after.verified === after.itemCount && after.missing.length === 0 && after.mismatches.length === 0,
              tier: 'E0',
            },
            {
              name: 'freeze_sha_unchanged',
              oracle: 'R1 final design freeze SHA-256 unchanged',
              actual: after.freeze.actual,
              met: freezeMatches,
              tier: 'E0',
            },
            {
              name: 'unchanged_across_suite',
              oracle: 'no ledger preimage changed across the T0 suite',
              actual: stable ? 'before and after fingerprints identical' : 'before/after fingerprints differ or before-run verification missing',
              met: stable,
              tier: 'E0',
            },
          ],
          sourceAnchors: ['evidence/w3b-r1/G16-PREIMAGE-LEDGER-20261015.json', 'docs/GOVERNOR-W3B-R1-DESIGN-FREEZE-20261015.md'],
          productClaim: false,
          notes: 'Only newly authorized r2/t0 paths are added by this wave; they are outside the old ledger by construction.',
        };
      },
    },
    {
      id: 'R2-H39-INVARIANT-CITATIONS',
      hostileRows: ['H-39'],
      tier: 'E0',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff the operative gate family is cited as W3-B R0 G10-G16 (no hyphen) and the implementation-law family as W2 G-1-G-9 (hyphen), as published',
      build: async () => {
        const resolved = preflight.resolveGovernanceRoot();
        const read = (relative) => {
          const file = path.join(resolved.root ?? '', relative);
          return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
        };
        const freezeText = read(preflight.FREEZE_DOC);
        const r2AuthText = read('docs/GOVERNOR-W3B-R2-T0-TEST-AUTHORIZATION-20261015.md');
        const r0Text = read('docs/GOVERNOR-W3B-R0-EVIDENCE-DISPOSITION-20261015.md');
        const w2Text = read('docs/GOVERNOR-PHASE1-W2-RULINGS-20261011.md');
        const checks = {
          freezeCitesGateFamilyWithoutHyphen: freezeText !== null && /W3-B\s+G10\.\.G16/.test(freezeText),
          freezeCitesImplementationFamilyWithHyphen: freezeText !== null && /W2\s+G-1\.\.G-9/.test(freezeText),
          freezeAvoidsHyphenatedGateFamily: freezeText !== null && !/G-10/.test(freezeText),
          r0DefinesG10ToG16: r0Text !== null && Array.from({ length: 7 }, (_, i) => `G${i + 10}`).every((g) => r0Text.includes(g)),
          w2DefinesHyphenatedFamily: w2Text !== null && Array.from({ length: 9 }, (_, i) => `G-${i + 1}:`).every((g) => w2Text.includes(g)),
        };
        const met = Object.values(checks).every(Boolean);
        return {
          status: met ? STATUS.PASS_CURRENT : STATUS.EXPECTED_RED,
          executedTier: 'E0',
          attempts: Object.keys(checks).length,
          actual: {
            scenario: "audit the freeze text's invariant citations",
            governanceRoot: resolved.root,
            checks,
            informational: { r2AuthorizationMentionsGateFamily: r2AuthText !== null && /G16/.test(r2AuthText) },
          },
          components: Object.entries(checks).map(([name, value]) => ({
            name,
            oracle: 'citation family present exactly as published',
            actual: String(value),
            met: value,
            tier: 'E0',
          })),
          sourceAnchors: ['docs/GOVERNOR-W3B-R1-DESIGN-FREEZE-20261015.md:6', 'docs/GOVERNOR-W3B-R0-EVIDENCE-DISPOSITION-20261015.md:10-16', 'docs/GOVERNOR-PHASE1-W2-RULINGS-20261011.md:5-27'],
          productClaim: false,
        };
      },
    },
  ];
}

module.exports = { id: 'R2-COMPOSITION-ERRORS', fixtures, STATUS };

async function main(record) {
  for (const def of fixtures()) {
    // eslint-disable-next-line no-await-in-loop
    record(await runFixture(def));
  }
}
module.exports.main = main;
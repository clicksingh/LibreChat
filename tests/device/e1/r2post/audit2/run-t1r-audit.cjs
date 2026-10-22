'use strict';

/**
 * W3-B R2 T1R AUDIT TEST-FIRST RECOVERY runner (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 *   node tests/device/e1/r2post/audit2/run-t1r-audit.cjs
 *
 * Executes EXACTLY the nine authorized T1R rows from
 *   docs/GOVERNOR-W3B-R2-T1R-AUDIT-TEST-AUTHORIZATION-20261015.md
 *   (governance root copy: C:\Users\Aryan\Desktop\codellm\cbhr-rdc\docs\...)
 *
 * Substrate: the real I10 TypeScript bridge -> `createModels(mongoose).AuditEvent` (genuine
 * Mongoose model, no stub/mock), the frozen lab Mongo URI at 127.0.0.1:27027 / cbhrRdcP1.
 *
 * DB law: every owned database is `cbhr_rdc_phase1_r2_t1r_<unique>`, fenced before any
 * MongoClient is constructed, and dropped on success and failure.
 *
 * This runner writes ONLY under:
 *   tests/device/e1/r2post/audit2/**                                  (the runner + its fence)
 *   tests/device/_phase1_evidence/w3b-r2/t1r-audit/run-<id>/**        (artifacts)
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/** r2post/audit2 -> r2post -> e1 -> device -> tests -> worktree */
const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..', '..');

// eslint-disable-next-line global-require, import/no-dynamic-require
const fence = require('./fence.cjs');
// eslint-disable-next-line global-require, import/no-dynamic-require
const w3a = require(path.resolve(WORKTREE, 'tests', 'device', 'e1', 'w3a', 'env.cjs'));

const EVIDENCE_ROOT = path.join(WORKTREE, 'tests', 'device', '_phase1_evidence', 'w3b-r2', 't1r-audit');
const RUNNER_REL = 'tests/device/e1/r2post/audit2/run-t1r-audit.cjs';
const COMMAND = `node ${RUNNER_REL}`;
const FROZEN_HEAD = 'a3fb9754bce5a940cb0f78161985b93c20d74727';
const COMMISSION = 'PHASE1-LOCAL-AUTHORITY-001';
const AUTHORIZATION_DOC = 'docs/GOVERNOR-W3B-R2-T1R-AUDIT-TEST-AUTHORIZATION-20261015.md';

const DEVICE_DIR = path.join(WORKTREE, 'api', 'server', 'services', 'Device');
const SCHEMA_DIR = path.join(WORKTREE, 'packages', 'data-schemas', 'src', 'schema');
const MODELS_DIR = path.join(WORKTREE, 'packages', 'data-schemas', 'src', 'models');
const AUDIT_SINK_REL = 'api/server/services/Device/auditSink.js';
const AUDIT_SINK_ABS = path.join(WORKTREE, 'api', 'server', 'services', 'Device', 'auditSink.js');

const WC = Object.freeze({ w: 'majority', j: true });

const PREIMAGES = [
  { name: 'schema/auditEvent.ts', rel: 'packages/data-schemas/src/schema/auditEvent.ts', expected: '7B54D7590CE6A8E3213CC054A276B32727F83D753B1848F461763E34AE5D369E' },
  { name: 'models/auditEvent.ts', rel: 'packages/data-schemas/src/models/auditEvent.ts', expected: 'BBD4A070F1453D360ABCADDC50A95B3A7B52CB0A2BA548ED17A34D2579E376FF' },
  { name: 'Device/errors.js', rel: 'api/server/services/Device/errors.js', expected: '7C084A33BF392CF0FC0FBCC8B8E1280382073FEC839860EC0DD51F2AEC727039' },
  { name: 'Device/authorityService.js', rel: 'api/server/services/Device/authorityService.js', expected: 'B51B3CEC5A02935A0CC7486F0A91B0883F33C7C0FE0F3A58C35E659AD9E9C0CF' },
  { name: 'Device/registrationService.js', rel: 'api/server/services/Device/registrationService.js', expected: '9DB81E9ACDB79DCE45456E6C38EC463A80B9911A24AFB54C690D5CD1C8157EA9' },
  { name: 'Device/pairingSessionService.js', rel: 'api/server/services/Device/pairingSessionService.js', expected: 'D1644F00C1B67CC9712D540B04D2FF39D3118D40FAA0BB091C0DF0C424046D6F' },
];

/** Authorized pre-repair states (binding). */
const EXPECTED_STATES = {
  'T1R-01': 'PASS_CURRENT',
  'T1R-02': 'EXPECTED_RED',
  'T1R-03': 'PASS_CURRENT',
  'T1R-04': 'EXPECTED_RED',
  'T1R-05': 'EXPECTED_RED',
  'T1R-06': 'EXPECTED_RED',
  'T1R-07': 'PASS_CURRENT',
  'T1R-08': 'PASS_CURRENT',
  'T1R-09': 'PASS_CURRENT',
};

/** F6 / R1-B frozen contract (read-only design truth source). */
const AUDIT_EVENT_KEYS = Object.freeze([
  'tenantId', 'deviceId', 'ownerId', 'grantId', 'epoch', 'seq', 'kind', 'ts', 'actor', 'reasonCode',
]);
const AUDIT_KINDS = Object.freeze([
  'register', 'grant', 'renew', 'revoke', 'expire', 'retire', 'release', 'claim-refused',
]);
/** R1-B §4.1:711-717 MUST_BE_NULL(kind, field). */
const MUST_BE_NULL = Object.freeze({
  register: Object.freeze(['actor', 'reasonCode']),
  grant: Object.freeze(['reasonCode']),
  renew: Object.freeze(['reasonCode']),
  revoke: Object.freeze(['reasonCode']),
  expire: Object.freeze(['actor', 'reasonCode']),
  retire: Object.freeze([]),
  release: Object.freeze(['reasonCode']),
  'claim-refused': Object.freeze(['epoch', 'seq']),
});
/** R1-B §3.1 / §2.4 fields whose value MAY be null for that kind (R/N). */
const NULLABLE_BY_KIND = Object.freeze({
  register: Object.freeze(['ownerId', 'grantId', 'actor', 'reasonCode']),
  grant: Object.freeze(['reasonCode']),
  renew: Object.freeze(['reasonCode']),
  revoke: Object.freeze(['reasonCode']),
  expire: Object.freeze(['actor', 'reasonCode']),
  retire: Object.freeze([]),
  release: Object.freeze(['deviceId', 'ownerId', 'grantId', 'epoch', 'seq', 'reasonCode']),
  'claim-refused': Object.freeze(['ownerId', 'grantId', 'epoch', 'seq', 'actor', 'reasonCode']),
});
/** R1-B §3.4:506-511 forbidden keys (the ones this lane probes). */
const FORBIDDEN_PROBE_KEYS = Object.freeze(['lookupTag', 'code', 'ip']);

const TEN = 'tenant-t1r-audit-fixed';
const DEV = 'device-t1r-audit-0001';
const OWNER = 'principal-t1r-owner-a';
const GRANT = 'grant-t1r-audit-0001';
const TS_MS = 1791000000000;
const SYNTH_TEN = 'tenant-t1r-synthetic';
const SYNTH_DEV = 'device-t1r-synthetic-0001';

// ---------------------------------------------------------------------------
// small utilities
// ---------------------------------------------------------------------------

function sha256File(abs) {
  return crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex').toUpperCase();
}

function sha256Of(abs) {
  if (!fs.existsSync(abs)) {
    return { exists: false, actual: null };
  }
  return { exists: true, actual: sha256File(abs) };
}

function walkSourceFiles(dir, out = []) {
  if (!fs.existsSync(dir)) {
    return out;
  }
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
      walkSourceFiles(full, out);
    } else if (/\.(js|ts)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

/** Static absence scan over the product Device service bytes + Phase-1 schema/model bytes. */
function scanProductSurface(names) {
  const files = [...walkSourceFiles(DEVICE_DIR), ...walkSourceFiles(SCHEMA_DIR), ...walkSourceFiles(MODELS_DIR)];
  const out = {};
  for (const name of names) {
    const hits = [];
    for (const file of files) {
      const source = fs.readFileSync(file, 'utf8');
      if (source.includes(name)) {
        hits.push({
          file: path.relative(WORKTREE, file).replace(/\\/g, '/'),
          lines: source.split('\n').reduce((acc, line, i) => (line.includes(name) ? acc.concat(i + 1) : acc), []),
        });
      }
    }
    out[name] = { present: hits.length > 0, hits };
  }
  return out;
}

/** Static fabrication-sentinel scan of the three frozen emitters. */
function scanFabricationSentinels() {
  const files = ['authorityService.js', 'registrationService.js', 'pairingSessionService.js'];
  const re = /(actor|reasonCode)\s*:\s*'(system|unknown|unspecified)'/g;
  const hits = [];
  for (const file of files) {
    const abs = path.join(DEVICE_DIR, file);
    if (!fs.existsSync(abs)) continue;
    const lines = fs.readFileSync(abs, 'utf8').split('\n');
    lines.forEach((line, index) => {
      re.lastIndex = 0;
      if (re.test(line)) {
        hits.push({ file, line: index + 1, text: line.trim() });
      }
    });
  }
  return hits;
}

function describeError(err) {
  if (err === null || err === undefined) {
    return { name: null, code: null, message: null, paths: [] };
  }
  return {
    name: err.name ?? null,
    code: err.code ?? null,
    message: err.message ?? null,
    paths: Object.keys(err.errors ?? {}),
  };
}

// ---------------------------------------------------------------------------
// F6 event literals (frozen truth source: R1-B §2.4 / §3.1)
// ---------------------------------------------------------------------------

function buildF6Events() {
  const ts = () => new Date(TS_MS);
  return {
    register: { tenantId: TEN, deviceId: DEV, ownerId: null, grantId: null, epoch: 0, seq: 0, kind: 'register', ts: ts(), actor: null, reasonCode: null },
    grant: { tenantId: TEN, deviceId: DEV, ownerId: OWNER, grantId: GRANT, epoch: 4, seq: 4, kind: 'grant', ts: ts(), actor: OWNER, reasonCode: null },
    renew: { tenantId: TEN, deviceId: DEV, ownerId: OWNER, grantId: GRANT, epoch: 5, seq: 5, kind: 'renew', ts: ts(), actor: OWNER, reasonCode: null },
    revoke: { tenantId: TEN, deviceId: DEV, ownerId: OWNER, grantId: GRANT, epoch: 6, seq: 6, kind: 'revoke', ts: ts(), actor: OWNER, reasonCode: null },
    expire: { tenantId: TEN, deviceId: DEV, ownerId: OWNER, grantId: GRANT, epoch: 7, seq: 7, kind: 'expire', ts: ts(), actor: null, reasonCode: null },
    retire: { tenantId: TEN, deviceId: DEV, ownerId: OWNER, grantId: GRANT, epoch: 8, seq: 8, kind: 'retire', ts: ts(), actor: OWNER, reasonCode: 'owner' },
    release: { tenantId: TEN, deviceId: null, ownerId: null, grantId: null, epoch: null, seq: null, kind: 'release', ts: ts(), actor: OWNER, reasonCode: null },
    'claim-refused': { tenantId: TEN, deviceId: DEV, ownerId: null, grantId: null, epoch: null, seq: null, kind: 'claim-refused', ts: ts(), actor: null, reasonCode: 'attempts-exhausted' },
  };
}

/** Fully non-null synthetic event (every one of the 10 keys carries a value). */
function fullyNonNullEvent() {
  return {
    tenantId: SYNTH_TEN,
    deviceId: SYNTH_DEV,
    ownerId: OWNER,
    grantId: GRANT,
    epoch: 3,
    seq: 3,
    kind: 'grant',
    ts: new Date(TS_MS),
    actor: OWNER,
    reasonCode: 'SYNTHETIC_NON_NULL',
  };
}

function readBackDiff(event, doc) {
  const diffs = [];
  for (const key of AUDIT_EVENT_KEYS) {
    const want = event[key];
    const got = doc ? doc[key] : undefined;
    if (want === null || want === undefined) {
      if (got !== null && got !== undefined) diffs.push({ key, expected: want, actual: got });
      continue;
    }
    if (key === 'ts') {
      const wantMs = want instanceof Date ? want.getTime() : NaN;
      const gotMs = got instanceof Date ? got.getTime() : NaN;
      if (wantMs !== gotMs) diffs.push({ key, expected: new Date(wantMs).toISOString(), actual: got instanceof Date ? got.toISOString() : String(got) });
      continue;
    }
    if (want !== got) diffs.push({ key, expected: want, actual: got });
  }
  return diffs;
}

// ---------------------------------------------------------------------------
// safety net: every owned DB is dropped on success and on fatal failure
// ---------------------------------------------------------------------------

const ownedDbs = new Set();
let driverClient = null;
let dropsDone = false;
let dropRecords = [];
let safetyNetRunning = false;
const lifecycle = { mongooseClosed: false, clientClosed: false };

async function dropAllOwned(reason) {
  const records = [];
  for (const dbName of ownedDbs) {
    if (!fence.isOwnedDb(dbName)) {
      records.push({ dbName, dropped: false, error: 'FENCE_VIOLATION: refusing to drop a non-r2/t1r database' });
      continue;
    }
    let client = driverClient;
    if (client === null && w3a.mongoose.connection.readyState === 1 && w3a.mongoose.connection.db) {
      // fall back to the mongoose connection's own driver handle
      try {
        await w3a.mongoose.connection.db.dropDatabase();
        records.push({ dbName, dropped: true, via: 'mongoose-connection', reason });
        continue;
      } catch (err) {
        records.push({ dbName, dropped: false, error: `${err.name}: ${err.message}` });
        continue;
      }
    }
    if (client === null) {
      records.push({ dbName, dropped: false, error: 'no fenced client available for drop' });
      continue;
    }
    // eslint-disable-next-line no-await-in-loop
    const result = await fence.dropOwnDatabase(client, dbName);
    records.push({ ...result, reason });
  }
  return records;
}

/**
 * Closes the mongoose connection before any drop. A still-in-flight Mongoose index build
 * (triggered lazily by the model factories) can otherwise re-create the collection — and
 * therefore the database — immediately after a successful `dropDatabase()`.
 */
async function closeMongoose() {
  try {
    if (w3a.mongoose.connection.readyState !== 0) {
      await w3a.mongoose.connection.close();
    }
  } catch {
    /* ignore */
  }
  lifecycle.mongooseClosed = true;
}

function installSafetyNet() {
  const onFatal = (err) => {
    if (safetyNetRunning) return;
    safetyNetRunning = true;
    try {
      process.stderr.write(`[t1r-audit] FATAL: ${err && err.stack ? err.stack : String(err)}\n`);
    } catch {
      /* ignore */
    }
    closeMongoose()
      .then(() => dropAllOwned('fatal'))
      .catch(() => {})
      .finally(() => {
        try {
          if (driverClient) driverClient.close().catch(() => {});
        } catch {
          /* ignore */
        }
        process.exit(1);
      });
  };
  process.on('uncaughtException', onFatal);
  process.on('unhandledRejection', onFatal);
}

// ---------------------------------------------------------------------------
// row builders
// ---------------------------------------------------------------------------

function check(name, oracle, met, actual, tier) {
  return { name, oracle, met: met === true, actual, tier };
}

function modelGenuineness(model) {
  const schemaKeys = model && model.schema ? Object.keys(model.schema.paths) : [];
  return {
    typeofModel: typeof model,
    isFunction: typeof model === 'function',
    modelName: model ? model.modelName : null,
    collection: model && model.collection ? model.collection.name : null,
    baseIsMongoose: model ? model.base === w3a.mongoose : false,
    schemaIsMongooseSchema: model && model.schema ? model.schema instanceof w3a.mongoose.Schema : false,
    prototypeInstanceOfMongooseModel:
      typeof w3a.mongoose.Model === 'function' && model ? model.prototype instanceof w3a.mongoose.Model : null,
    hasCreate: !!(model && typeof model.create === 'function'),
    schemaKeys,
    auditEventKeysPresent: AUDIT_EVENT_KEYS.every((k) => schemaKeys.includes(k)),
    requiredPaths: model && model.schema ? Object.entries(model.schema.paths).filter(([, p]) => p.isRequired).map(([k]) => k).sort() : [],
  };
}

async function row01(ctx) {
  const model = ctx.AuditEvent;
  const genuineness = modelGenuineness(model);
  const event = fullyNonNullEvent();
  const validation = new model({ ...event }).validateSync();
  const created = await model.create([{ ...event }], { writeConcern: WC });
  const insertedId = created[0]._id;
  const readBack = await ctx.client.db(ctx.dbName).collection('deviceauthorityevents').findOne({ _id: insertedId });
  const diffs = readBackDiff(event, readBack);
  const opTime = created[0].$__ && created[0].$__.opTime ? String(created[0].$__.opTime) : null;

  const checks = [
    check('genuine_model_constructor', 'createModels(mongoose).AuditEvent is a genuine Mongoose model constructor', genuineness.isFunction && genuineness.baseIsMongoose && genuineness.schemaIsMongooseSchema && genuineness.hasCreate, genuineness, 'E1'),
    check('real_model_identity', 'modelName AuditEvent, collection deviceauthorityevents, all 10 F6 keys are schema paths', genuineness.modelName === 'AuditEvent' && genuineness.collection === 'deviceauthorityevents' && genuineness.auditEventKeysPresent, { modelName: genuineness.modelName, collection: genuineness.collection, schemaKeys: genuineness.schemaKeys }, 'E1'),
    check('real_substrate_topology', 'real Mongo 7.0.43 on replica set cbhrRdcP1, writable primary', ctx.topology.serverVersion === '7.0.43' && ctx.topology.setName === 'cbhrRdcP1' && ctx.topology.isWritablePrimary === true, ctx.topology, 'E1'),
    check('fully_non_null_event_validates', 'a fully non-null event passes real schema validation', validation === undefined, { validateSync: validation === undefined ? null : describeError(validation) }, 'E1'),
    check('majority_j_explicit', "persistence requested with explicit writeConcern { w:'majority', j:true }", WC.w === 'majority' && WC.j === true && created.length === 1, { writeConcernRequested: WC, createdCount: created.length, insertedId: String(insertedId), opTime }, 'E1'),
    check('durable_readback_via_real_driver', 'the written event reads back from the real collection with all 10 keys equal', readBack !== null && diffs.length === 0, { readBackFound: readBack !== null, diffs, readBack }, 'E1'),
  ];

  return {
    id: 'T1R-01',
    title: 'REAL-SUBSTRATE-CONTROL',
    tier: 'E1',
    expectedOracle: 'genuine createModels(mongoose).AuditEvent typeof function; real Mongo 7.0.43/cbhrRdcP1; a fully non-null valid event persists with explicit majority+j, reads back, owned DB drops.',
    checks,
    evidence: { genuineness, event, writeConcern: WC, insertedId: String(insertedId), readBack, diffs },
  };
}

async function row02(ctx) {
  const model = ctx.AuditEvent;
  const events = buildF6Events();
  const perKind = [];

  for (const kind of AUDIT_KINDS) {
    const event = events[kind];
    const nullTruthDiffs = MUST_BE_NULL[kind].filter((field) => event[field] !== null);
    let validateError = null;
    let validationPassed = false;
    try {
      const err = new model({ ...event }).validateSync();
      validationPassed = err === undefined || err === null;
      if (!validationPassed) validateError = describeError(err);
    } catch (err) {
      validateError = describeError(err);
    }

    let persisted = false;
    let insertedId = null;
    let readBack = null;
    let persistenceError = null;
    let readBackDiffs = null;
    if (validationPassed) {
      try {
        const docs = await model.create([{ ...event }], { writeConcern: WC });
        insertedId = String(docs[0]._id);
        persisted = true;
        readBack = await ctx.client.db(ctx.dbName).collection('deviceauthorityevents').findOne({ _id: docs[0]._id });
        readBackDiffs = readBackDiff(event, readBack);
      } catch (err) {
        persistenceError = describeError(err);
      }
    }

    perKind.push({
      kind,
      event,
      mustBeNull: [...MUST_BE_NULL[kind]],
      nullableByKind: [...NULLABLE_BY_KIND[kind]],
      mustBeNullViolations: nullTruthDiffs,
      validationPassed,
      validateErrorPaths: validateError ? validateError.paths : [],
      validateErrorMessage: validateError ? validateError.message : null,
      persisted,
      insertedId,
      persistenceError,
      readBackFound: readBack !== null,
      readBackDiffs,
      met: validationPassed && persisted && readBack !== null && Array.isArray(readBackDiffs) && readBackDiffs.length === 0,
    });
  }

  const metKinds = perKind.filter((k) => k.met).map((k) => k.kind);
  const rejectedKinds = perKind.filter((k) => !k.validationPassed).map((k) => ({ kind: k.kind, paths: k.validateErrorPaths }));

  const checks = [
    check('all_eight_kinds_executed', 'one exact F6 event per authorized kind is validated against the genuine model', perKind.length === 8 && AUDIT_KINDS.every((k) => perKind.some((row) => row.kind === k)), { executed: perKind.map((k) => k.kind) }, 'E1'),
    ...perKind.map((row) =>
      check(
        `kind_${row.kind}_persists_and_reads_back`,
        `the exact F6 ${row.kind} event validates, persists with majority+j, and reads back equal`,
        row.met,
        {
          validationPassed: row.validationPassed,
          validateErrorPaths: row.validateErrorPaths,
          persisted: row.persisted,
          readBackFound: row.readBackFound,
          readBackDiffs: row.readBackDiffs,
        },
        'E1',
      ),
    ),
  ];

  return {
    id: 'T1R-02',
    title: 'F6-SHAPE-8-KINDS',
    tier: 'E1',
    expectedOracle: 'PER KIND: the exact F6 literal for register/grant/renew/revoke/expire/retire/release/claim-refused validates against the genuine model, persists with explicit majority+j, and reads back. PASS only when all 8 do.',
    checks,
    evidence: {
      designRef: 'R1-B §3.1 kind table + §4.1 MUST_BE_NULL + §2.4 emitted shapes',
      perKind,
      metKinds,
      unmetKinds: AUDIT_KINDS.filter((k) => !metKinds.includes(k)),
      rejectedKinds,
      currentSchemaRejectingPaths: perKind.reduce((acc, row) => acc.concat(row.validateErrorPaths.map((p) => ({ kind: row.kind, path: p }))), []),
    },
  };
}

function row03() {
  const events = buildF6Events();
  const forbiddenValues = ['system', 'unknown', 'unspecified'];
  const literalViolations = [];
  for (const kind of AUDIT_KINDS) {
    for (const field of AUDIT_EVENT_KEYS) {
      const value = events[kind][field];
      if (MUST_BE_NULL[kind].includes(field) && value !== null) {
        literalViolations.push({ kind, field, value, why: 'MUST_BE_NULL field is not literally null' });
      }
      if (typeof value === 'string' && forbiddenValues.includes(value)) {
        literalViolations.push({ kind, field, value, why: 'sentinel fabrication' });
      }
    }
  }
  const productSentinels = scanFabricationSentinels();

  const checks = [
    check('f6_must_be_null_is_literal_null', 'every MUST_BE_NULL(kind, field) position in the F6 literals is literally null', literalViolations.length === 0, { violations: literalViolations }, 'E0'),
    check('no_sentinel_in_f6_literals', "no F6 literal uses the fabricated sentinels 'system'/'unknown'/'unspecified'", !Object.values(events).some((ev) => AUDIT_EVENT_KEYS.some((k) => typeof ev[k] === 'string' && forbiddenValues.includes(ev[k]))), { forbiddenValues }, 'E0'),
    check('no_fabrication_sentinel_in_product_emitters', "the frozen emitters never assign actor/reasonCode to 'system'/'unknown'/'unspecified'", productSentinels.length === 0, { hits: productSentinels, scannedFiles: ['authorityService.js', 'registrationService.js', 'pairingSessionService.js'] }, 'E0'),
    check('must_be_null_set_matches_r1b', 'the MUST_BE_NULL map used here equals R1-B §4.1:711-717', JSON.stringify(MUST_BE_NULL) === JSON.stringify({ register: ['actor', 'reasonCode'], grant: ['reasonCode'], renew: ['reasonCode'], revoke: ['reasonCode'], expire: ['actor', 'reasonCode'], retire: [], release: ['reasonCode'], 'claim-refused': ['epoch', 'seq'] }), { mustBeNull: MUST_BE_NULL }, 'E0'),
  ];

  return {
    id: 'T1R-03',
    title: 'NULL-TRUTH-NO-FABRICATION',
    tier: 'E0',
    expectedOracle: 'MUST_BE_NULL fields are literally null and no fabricated system/unknown/unspecified sentinel exists in the F6 literals or the frozen product emitters.',
    checks,
    evidence: { f6Events: events, mustBeNull: MUST_BE_NULL, forbiddenValues, literalViolations, productSentinels },
  };
}

function probeAuditSinkModule() {
  const exists = fs.existsSync(AUDIT_SINK_ABS);
  const requireOutcome = { attempted: true, ok: false, error: null, exports: null };
  if (exists) {
    try {
      // eslint-disable-next-line global-require, import/no-dynamic-require
      const mod = require(AUDIT_SINK_ABS);
      requireOutcome.ok = true;
      requireOutcome.exports = Object.keys(mod);
    } catch (err) {
      requireOutcome.error = describeError(err);
    }
  } else {
    try {
      // eslint-disable-next-line global-require, import/no-dynamic-require
      require(AUDIT_SINK_ABS);
    } catch (err) {
      requireOutcome.error = describeError(err);
    }
  }
  const surface = scanProductSurface(['projectAuditEvent', 'AUDIT_EVENT_KEYS', 'createMongooseAuditSink', 'AUDIT_WRITE_CONCERN']);
  return { exists, requireOutcome, surface };
}

function row04(probe) {
  const checks = [
    check('product_audit_sink_exists', 'api/server/services/Device/auditSink.js exists', probe.exists === true, { path: AUDIT_SINK_REL, exists: probe.exists }, 'E0'),
    check('require_succeeds', 'requiring the product audit sink resolves a module', probe.requireOutcome.ok === true, probe.requireOutcome, 'E0'),
    check('projectAuditEvent_exported', 'projectAuditEvent is exported/declared by the product audit sink', probe.surface.projectAuditEvent.present === true, { present: probe.surface.projectAuditEvent.present, hits: probe.surface.projectAuditEvent.hits, absentObservation: probe.surface.projectAuditEvent.present === false ? 'absent from the Device service bytes and the Phase-1 schema/model bytes' : null }, 'E0'),
    check('AUDIT_EVENT_KEYS_exported', 'AUDIT_EVENT_KEYS is exported/declared by the product audit sink', probe.surface.AUDIT_EVENT_KEYS.present === true, { present: probe.surface.AUDIT_EVENT_KEYS.present, hits: probe.surface.AUDIT_EVENT_KEYS.hits }, 'E0'),
  ];
  return {
    id: 'T1R-04',
    title: 'PROJECTOR-PRESENCE',
    tier: 'E0',
    expectedOracle: 'product auditSink.js exists and exports projectAuditEvent + AUDIT_EVENT_KEYS.',
    checks,
    evidence: { expectedExports: ['projectAuditEvent', 'AUDIT_EVENT_KEYS'], probe, futureModuleAbsent: probe.exists === false },
  };
}

function row05(probe, errorsSurface) {
  const projectorPresent = probe.exists && probe.surface.projectAuditEvent.present;
  const keyDeletionExecutions = [];
  const checks = [
    check('projector_present', 'projectAuditEvent exists in the product audit sink so the key-presence negative can execute', projectorPresent === true, { status: projectorPresent ? 'PROJECTOR_PRESENT' : 'PROJECTOR_ABSENT', auditSinkExists: probe.exists }, 'E0'),
    check('ten_key_deletion_rejections_executed', 'for each of the 10 exact F6 keys: deleting it makes projectAuditEvent throw AUDIT_EVENT_SHAPE_INVALID before persistence', false, { executed: 0, expected: 10, status: 'PROJECTOR_ABSENT', keyDeletionExecutions, reason: 'no projector exists, so no deletion can be executed and none is fabricated' }, 'E0'),
    check('forbidden_lookupTag_rejection_executed', 'a payload carrying the forbidden key lookupTag is rejected', false, { executed: false, status: 'PROJECTOR_ABSENT', forbiddenProbeKeys: FORBIDDEN_PROBE_KEYS }, 'E0'),
    check('extra_benign_key_rejection_or_projection_executed', 'a payload carrying a benign extra key is rejected/projected per R1-B', false, { executed: false, status: 'PROJECTOR_ABSENT' }, 'E0'),
    check('no_fabricated_execution', 'no key-deletion result was invented while the projector is absent', keyDeletionExecutions.length === 0 && projectorPresent !== true, { fabricated: false, executedCount: keyDeletionExecutions.length }, 'E0'),
  ];
  return {
    id: 'T1R-05',
    title: 'KEY-PRESENCE-NEGATIVE',
    tier: 'E0',
    expectedOracle: 'with the projector present: each of the 10 exact F6 keys deleted ⇒ AUDIT_EVENT_SHAPE_INVALID before persistence, plus lookupTag and a benign extra key handled per R1-B. Until then: EXPECTED_RED/PROJECTOR_ABSENT with no fabricated execution.',
    checks,
    evidence: {
      status: projectorPresent ? 'PROJECTOR_PRESENT' : 'PROJECTOR_ABSENT',
      auditSinkExists: probe.exists,
      keyDeletionExecutions,
      forbiddenProbeKeys: FORBIDDEN_PROBE_KEYS,
      informational: {
        note: 'informational only — does NOT satisfy this row, which is about projector behaviour, not the error-code map',
        AUDIT_EVENT_SHAPE_INVALID_in_device_error_map: errorsSurface,
      },
    },
  };
}

function row06(probe) {
  const checks = [
    check('createMongooseAuditSink_present', 'the product exports createMongooseAuditSink', probe.surface.createMongooseAuditSink.present === true, { present: probe.surface.createMongooseAuditSink.present, status: probe.exists ? 'MODULE_PRESENT_NO_EXPORT' : 'MODULE_ABSENT' }, 'E0'),
    check('sink_factory_invoked_with_genuine_model', 'createMongooseAuditSink({ AuditEvent: createModels(mongoose).AuditEvent }) constructs a sink', false, { invoked: false, reason: 'createMongooseAuditSink absent from product bytes' }, 'E0'),
    check('sinkKind_mongoose_AuditEvent', "the constructed sink reports sinkKind 'mongoose-AuditEvent'", false, { sinkKind: null }, 'E0'),
    check('explicit_majority_j_at_sink_write', "the sink writes with explicit { w:'majority', j:true }", false, { writeConcern: null }, 'E0'),
    check('durable_readback_through_sink', 'an event written through the sink reads back durably', false, { readBack: false }, 'E0'),
  ];
  return {
    id: 'T1R-06',
    title: 'REAL-MONGOOSE-SINK',
    tier: 'E0',
    expectedOracle: "createMongooseAuditSink exists: genuine model constructor accepted, sinkKind 'mongoose-AuditEvent', explicit majority+j, durable read-back. Current absence is expected red.",
    checks,
    evidence: { probe: probe.surface.createMongooseAuditSink, moduleAbsent: probe.exists === false },
  };
}

async function row07(ctx) {
  const model = ctx.AuditEvent;
  const declared = model.schema.indexes().map((entry) => ({ key: entry[0], options: entry[1] ?? {} }));
  const syncResult = await w3a.syncDeclaredIndexes({ AuditEvent: model });
  const live = await ctx.client.db(ctx.dbName).collection('deviceauthorityevents').listIndexes().toArray();

  const normalize = (key) => JSON.stringify(Object.keys(key).sort().reduce((acc, k) => ({ ...acc, [k]: key[k] }), {}));
  const declaredKeys = declared.map((d) => normalize(d.key)).sort();
  const liveCompound = live.filter((ix) => ix.name !== '_id_').map((ix) => normalize(ix.key)).sort();
  const uniqueIndexes = live.filter((ix) => ix.name !== '_id_' && ix.unique === true);
  const suspiciousIndexes = live.filter((ix) => Object.keys(ix.key ?? {}).some((k) => /seq|eventId/i.test(k)));

  const checks = [
    check('collection_is_deviceauthorityevents', 'the real model writes to collection deviceauthorityevents', model.collection.name === 'deviceauthorityevents', { collection: model.collection.name }, 'E1'),
    check('declared_indexes_exactly_two_compound', 'the schema declares exactly the two frozen compound indexes', declared.length === 2 && declaredKeys.length === 2, { declared }, 'E1'),
    check('live_indexes_match_declared_plus_id', 'the live collection indexes are exactly the two declared compound indexes plus _id_', live.length === 3 && JSON.stringify(liveCompound) === JSON.stringify(declaredKeys), { live: live.map((ix) => ({ name: ix.name, key: ix.key, unique: ix.unique ?? false })), liveCompound, declaredKeys, syncResult }, 'E1'),
    check('no_unique_seq_or_eventId_index', 'no index is unique and no index key mentions seq or eventId', uniqueIndexes.length === 0 && suspiciousIndexes.length === 0, { uniqueIndexes: uniqueIndexes.map((ix) => ix.name), suspiciousIndexes: suspiciousIndexes.map((ix) => ix.name) }, 'E1'),
  ];

  return {
    id: 'T1R-07',
    title: 'SCHEMA-INDEX-COLLECTION-CONTROL',
    tier: 'E1',
    expectedOracle: "collection deviceauthorityevents and exactly the two existing compound indexes are preserved; no new unique seq/eventId index.",
    checks,
    evidence: { declared, live: live.map((ix) => ({ name: ix.name, key: ix.key, unique: ix.unique ?? false })), syncResult, aggregateReadback: live },
  };
}

async function row08(ctx) {
  const model = ctx.AuditEvent;
  const synthetic = fullyNonNullEvent();
  const validation = new model({ ...synthetic }).validateSync();
  const created = await model.create([{ ...synthetic }], { writeConcern: WC });
  const readBack = await ctx.client.db(ctx.dbName).collection('deviceauthorityevents').findOne({ _id: created[0]._id });
  const diffs = readBackDiff(synthetic, readBack);

  const frozenNullEvent = buildF6Events().register;
  const countBefore = await ctx.client.db(ctx.dbName).collection('deviceauthorityevents').countDocuments({ tenantId: frozenNullEvent.tenantId });
  let frozenNullRejected = false;
  let frozenNullError = null;
  try {
    const err = new model({ ...frozenNullEvent }).validateSync();
    frozenNullRejected = err !== undefined && err !== null;
    frozenNullError = frozenNullRejected ? describeError(err) : null;
  } catch (err) {
    frozenNullRejected = true;
    frozenNullError = describeError(err);
  }
  let frozenNullPersisted = false;
  if (!frozenNullRejected) {
    try {
      await model.create([{ ...frozenNullEvent }], { writeConcern: WC });
      frozenNullPersisted = true;
    } catch (err) {
      frozenNullError = describeError(err);
    }
  }
  const countAfter = await ctx.client.db(ctx.dbName).collection('deviceauthorityevents').countDocuments({ tenantId: frozenNullEvent.tenantId });

  const checks = [
    check('fully_non_null_synthetic_persists', 'a fully non-null synthetic event validates and persists durably', validation === undefined && created.length === 1 && readBack !== null && diffs.length === 0, { validateSync: validation === undefined ? null : describeError(validation), insertedId: String(created[0]._id), readBackFound: readBack !== null, diffs }, 'E1'),
    check('frozen_truthful_null_event_rejects', 'at least one frozen truthful-null F6 event (register) is rejected by the current schema', frozenNullRejected === true, { rejected: frozenNullRejected, error: frozenNullError, frozenEvent: frozenNullEvent }, 'E1'),
    check('rejected_event_writes_nothing', 'the rejected frozen event leaves the collection count unchanged for its tenant', frozenNullPersisted === false && countBefore === countAfter, { countBefore, countAfter, persisted: frozenNullPersisted }, 'E1'),
  ];

  return {
    id: 'T1R-08',
    title: 'PRE-REPAIR-FAILURE-CONTROL',
    tier: 'E1',
    expectedOracle: 'a fully non-null synthetic event persists while at least one frozen truthful-null event rejects (nothing written).',
    checks,
    evidence: { synthetic, diffs, frozenNullEvent, frozenNullError, countBefore, countAfter },
  };
}

function preimageManifest() {
  const items = PREIMAGES.map((item) => {
    const abs = path.join(WORKTREE, item.rel);
    const observed = sha256Of(abs);
    return { name: item.name, rel: item.rel, expected: item.expected, actual: observed.actual, exists: observed.exists, match: observed.exists && observed.actual === item.expected, kind: 'preimage' };
  });
  const sink = sha256Of(AUDIT_SINK_ABS);
  items.push({ name: 'Device/auditSink.js', rel: AUDIT_SINK_REL, expected: 'ABSENT', actual: sink.exists ? sink.actual : 'ABSENT', exists: sink.exists, match: sink.exists === false, kind: 'absence' });
  return { generatedAt: new Date().toISOString(), items, allMatch: items.every((i) => i.match === true), sinkAbsent: sink.exists === false };
}

/**
 * Read-only HEAD resolution. Handles a plain `.git` directory, a `.git` gitfile (linked
 * worktree, as in this commission) and the worktree `commondir`/packed-refs indirection.
 */
function readGitHead() {
  const dotGit = path.join(WORKTREE, '.git');
  try {
    let gitDir = dotGit;
    if (fs.statSync(dotGit).isFile()) {
      const content = fs.readFileSync(dotGit, 'utf8').trim();
      const match = /^gitdir:\s*(.+)$/.exec(content);
      if (!match) {
        return { head: null, ref: null, sha: null, source: 'unreadable-gitfile' };
      }
      const resolved = match[1].trim();
      gitDir = path.isAbsolute(resolved) ? resolved : path.resolve(WORKTREE, resolved);
    }
    const head = fs.readFileSync(path.join(gitDir, 'HEAD'), 'utf8').trim();
    if (!head.startsWith('ref: ')) {
      return { head, ref: null, sha: head, source: 'detached', gitDir };
    }
    const ref = head.slice(5).trim();
    const gitDirRef = path.join(gitDir, ref);
    if (fs.existsSync(gitDirRef)) {
      return { head, ref, sha: fs.readFileSync(gitDirRef, 'utf8').trim(), source: 'worktree-ref', gitDir };
    }
    let commonDir = null;
    const commonDirFile = path.join(gitDir, 'commondir');
    if (fs.existsSync(commonDirFile)) {
      const rel = fs.readFileSync(commonDirFile, 'utf8').trim();
      commonDir = path.isAbsolute(rel) ? rel : path.resolve(gitDir, rel);
      const commonRef = path.join(commonDir, ref);
      if (fs.existsSync(commonRef)) {
        return { head, ref, sha: fs.readFileSync(commonRef, 'utf8').trim(), source: 'commondir-ref', gitDir, commonDir };
      }
      const packed = path.join(commonDir, 'packed-refs');
      if (fs.existsSync(packed)) {
        const line = fs.readFileSync(packed, 'utf8').split('\n').find((l) => l.endsWith(` ${ref}`));
        if (line) return { head, ref, sha: line.split(' ')[0], source: 'packed-refs', gitDir, commonDir };
      }
    }
    return { head, ref, sha: null, source: 'unresolved', gitDir, commonDir };
  } catch (err) {
    return { head: null, ref: null, sha: null, source: `unreadable: ${err.message}` };
  }
}

function row09(hashManifest, probe, gitHead) {
  const checks = [
    ...hashManifest.items.map((item) =>
      check(
        `preimage_unchanged__${item.name}`,
        item.kind === 'preimage' ? `SHA-256 equals the binding preimage ${item.expected}` : 'the file is absent',
        item.match === true,
        { expected: item.expected, actual: item.actual, exists: item.exists },
        'E0',
      ),
    ),
    check('audit_sink_still_absent', 'api/server/services/Device/auditSink.js is still absent at the end of the run', probe.exists === false, { exists: probe.exists, actual: hashManifest.items[hashManifest.items.length - 1].actual }, 'E0'),
    check(
      'frozen_head_corroboration',
      `when the worktree git dir is readable, git HEAD still resolves to ${FROZEN_HEAD} (corroboration; criterion (c) itself is the six source hashes)`,
      gitHead.sha === null ? true : gitHead.sha === FROZEN_HEAD,
      { ...gitHead, blocking: gitHead.sha !== null, note: gitHead.sha === null ? 'HEAD not resolvable read-only; this corroborating check is non-blocking' : 'HEAD resolved and compared' },
      'E0',
    ),
  ];
  return {
    id: 'T1R-09',
    title: 'CANONICAL-INTEGRITY',
    tier: 'E0',
    expectedOracle: 'all six binding files are unchanged and auditSink.js is absent throughout.',
    checks,
    evidence: { hashManifest, gitHead },
  };
}

// ---------------------------------------------------------------------------
// fence negative control (proves the DB-name fence refuses foreign names)
// ---------------------------------------------------------------------------

function fenceNegativeControl() {
  const candidates = [
    'cbhr_rdc_phase1_r2_t1r_work_deadbeef_20261015120000',
    'cbhr_rdc_phase1_r2_t0_work_deadbeef',
    'cbhr_rdc_phase1_r2_post_s1_work',
    'cbhr_rdc_phase1_w3_e1_onepc',
    'cbhr_rdc_phase1_preflight_20261010',
    'cbhr_rdc_phase1_governor_nullgrant_probe_20261010',
    'devices_prod',
    'deviceauthorities',
    'librechat',
    'admin',
    'local',
    'config',
    'cbhr_rdc_phase1_r2_t1r_',
    'cbhr_rdc_phase1_r2_t1X_work',
  ];
  return candidates.map((name) => {
    const problems = fence.checkDbName(name);
    return { name, problems, verdict: problems.length === 0 ? 'ACCEPT' : 'REFUSE' };
  });
}

// ---------------------------------------------------------------------------
// artifact writers
// ---------------------------------------------------------------------------

function writeJson(abs, value) {
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function writeText(abs, value) {
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, value, 'utf8');
}

function markdownReport(meta, rows, hashManifest, namespaceAudit, fenceControl, criteria, exitCode) {
  const lines = [];
  lines.push(`# T1R-AUDIT RUN REPORT — ${meta.runId}`);
  lines.push('');
  lines.push(`- Commission: ${COMMISSION}`);
  lines.push(`- Authorization: \`${AUTHORIZATION_DOC}\``);
  lines.push(`- Command: \`${COMMAND}\``);
  lines.push(`- Frozen HEAD: \`${FROZEN_HEAD}\` (observed \`${meta.gitHead.sha ?? 'unreadable'}\` via ${meta.gitHead.source})`);
  lines.push(`- Started: ${meta.startedAt} — finished: ${meta.finishedAt}`);
  lines.push(`- Node: ${process.version} on ${process.platform}/${process.arch} (pid ${process.pid})`);
  lines.push(`- Exit code: ${exitCode}`);
  lines.push('');
  lines.push('## Rows');
  lines.push('');
  lines.push('| row | expected | actual | tier | met | headline |');
  lines.push('|---|---|---|---|---|---|');
  for (const row of rows) {
    const headline = row.checks.filter((c) => c.met !== true).map((c) => c.name).slice(0, 4).join(', ') || 'all checks met';
    lines.push(`| ${row.id} ${row.title} | ${row.expected} | ${row.actual} | ${row.tier} | ${row.met} | ${headline.replace(/\|/g, '\\|')} |`);
  }
  lines.push('');
  lines.push('## Exit-code criteria');
  lines.push('');
  for (const [key, value] of Object.entries(criteria)) {
    lines.push(`- ${key}: ${value}`);
  }
  lines.push('');
  lines.push('## Source-hash manifest');
  lines.push('');
  lines.push('| file | expected | actual | match |');
  lines.push('|---|---|---|---|');
  for (const item of hashManifest.items) {
    lines.push(`| ${item.rel} | ${item.expected} | ${item.actual} | ${item.match} |`);
  }
  lines.push('');
  lines.push('## Namespace audit');
  lines.push('');
  lines.push(`- owned DBs created/used: ${JSON.stringify(namespaceAudit.ownedDbs)}`);
  lines.push(`- drops: ${JSON.stringify(namespaceAudit.drops)}`);
  lines.push(`- before: ${JSON.stringify(namespaceAudit.before)}`);
  lines.push(`- after drops: ${JSON.stringify(namespaceAudit.after)}`);
  lines.push(`- foreign created: ${JSON.stringify(namespaceAudit.foreignCreated)}`);
  lines.push(`- foreign removed: ${JSON.stringify(namespaceAudit.foreignRemoved)}`);
  lines.push(`- leftover owned: ${JSON.stringify(namespaceAudit.leftoverOwned)}`);
  lines.push(`- ok: ${namespaceAudit.ok}`);
  lines.push('');
  lines.push('### Fence negative control (DB-name refusals)');
  lines.push('');
  lines.push('| name | verdict | problems |');
  lines.push('|---|---|---|');
  for (const entry of fenceControl) {
    lines.push(`| ${entry.name} | ${entry.verdict} | ${entry.problems.join('; ').replace(/\|/g, '\\|')} |`);
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  const startedAt = new Date().toISOString();
  const runId = `w3b-r2-t1r-audit-${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)}-${crypto.randomBytes(3).toString('hex')}`;
  const runDir = path.join(EVIDENCE_ROOT, `run-${runId}`);
  const artifactsDir = path.join(runDir, 'artifacts');
  fs.mkdirSync(artifactsDir, { recursive: true });

  installSafetyNet();

  // 1. fence the DB name BEFORE any MongoClient exists
  const dbName = fence.createDbName('work', crypto);
  const fenceChecks = {
    dbName,
    pattern: String(fence.DB_NAME_PATTERN),
    problems: fence.checkDbName(dbName),
    uri: fence.FROZEN_URI,
    uriProblems: fence.checkUri(fence.FROZEN_URI),
    clientCreatedBeforeFence: false,
  };
  fence.assertDbName(dbName, { phase: 'pre-client', runId });
  fenceChecks.accepted = true;
  ownedDbs.add(dbName);

  const probe = probeAuditSinkModule();
  const surfaceScan = scanProductSurface(['AUDIT_EVENT_SHAPE_INVALID']);
  const errorsSurface = {
    AUDIT_EVENT_SHAPE_INVALID_in_device_error_map: surfaceScan.AUDIT_EVENT_SHAPE_INVALID.present,
    hits: surfaceScan.AUDIT_EVENT_SHAPE_INVALID.hits,
  };

  const rows = [];
  let beforeSnapshot = null;
  let namespaceAudit = null;
  let hashManifest = preimageManifest();
  let gitHead = readGitHead();
  let criteria = {};
  let exitCode = 1;
  let fatal = null;

  try {
    // 2. guarded driver client (fenced), then inventory BEFORE
    const guarded = await fence.connectGuarded({ dbName, appName: `cbhr-phase1-r2-t1r-audit-${runId}`.slice(0, 60) });
    driverClient = guarded.client;
    const topology = guarded.topology;
    const databaseNamesBefore = await fence.listDatabases(driverClient);
    beforeSnapshot = databaseNamesBefore;

    // 3. real mongoose + genuine createModels(mongoose) registry
    const connected = await w3a.connectMongoose({ uri: fence.FROZEN_URI, dbName });
    const loaded = w3a.loadModels();
    const AuditEvent = loaded.registry.AuditEvent;
    const ctx = { client: driverClient, dbName, AuditEvent, topology, bridge: loaded };

    // 4. the nine authorized rows, in order
    rows.push(await row01(ctx));
    rows.push(await row02(ctx));
    rows.push(row03());
    rows.push(row04(probe));
    rows.push(row05(probe, errorsSurface));
    rows.push(row06(probe));
    rows.push(await row07(ctx));
    rows.push(await row08(ctx));

    // 5. namespace audit AFTER all writes; close mongoose first so no in-flight index build
    //    can re-create the database after the drop; drop every owned DB; then verify and retry.
    const databaseNamesAfterWrites = await fence.listDatabases(driverClient);
    await closeMongoose();
    dropRecords = await dropAllOwned('normal');
    dropsDone = true;
    let databaseNamesAfter = await fence.listDatabases(driverClient);
    const stillOwnedAfterDrop = databaseNamesAfter.filter((name) => fence.isOwnedDb(name));
    const verifyRetry = { attempted: stillOwnedAfterDrop.length > 0, stillOwnedBefore: stillOwnedAfterDrop, drops: [] };
    if (stillOwnedAfterDrop.length > 0) {
      verifyRetry.drops = await dropAllOwned('verify-retry');
      dropRecords = dropRecords.concat(verifyRetry.drops);
      databaseNamesAfter = await fence.listDatabases(driverClient);
    }
    verifyRetry.stillOwnedAfter = databaseNamesAfter.filter((name) => fence.isOwnedDb(name));

    const sets = fence.auditDatabaseSets(databaseNamesBefore, databaseNamesAfter);
    const ownedList = [...ownedDbs];
    namespaceAudit = {
      ownedDbs: ownedList,
      ownedPrefix: fence.DB_PREFIX,
      drops: dropRecords,
      verifyRetry,
      allOwnedDropped: ownedList.every((name) => dropRecords.some((d) => d.dbName === name && d.dropped === true)),
      afterWritesSnapshot: databaseNamesAfterWrites,
      before: sets.before,
      after: sets.after,
      created: sets.created,
      removed: sets.removed,
      foreignCreated: sets.foreignCreated,
      foreignRemoved: sets.foreignRemoved,
      leftoverOwned: sets.leftoverOwned,
      protectedChanged: sets.protectedChanged,
      foreignTouched: sets.foreignCreated.length > 0 || sets.foreignRemoved.length > 0,
      ok: sets.ok,
    };

    // 6. integrity row last (after drops)
    hashManifest = preimageManifest();
    gitHead = readGitHead();
    rows.push(row09(hashManifest, probe, gitHead));
  } catch (err) {
    fatal = describeError(err);
    await closeMongoose();
    try {
      if (!dropsDone) {
        dropRecords = await dropAllOwned('failure');
        dropsDone = true;
      }
    } catch (dropErr) {
      dropRecords = [{ dbName: null, dropped: false, error: `drop after failure failed: ${dropErr.message}` }];
    }
    if (namespaceAudit === null) {
      let afterFailure = null;
      let leftoverAfterFailure = [];
      let foreignCreatedAfterFailure = [];
      let foreignRemovedAfterFailure = [];
      let auditError = 'namespace audit could not be completed';
      try {
        if (driverClient) {
          afterFailure = await fence.listDatabases(driverClient);
          const setsAfterFailure = fence.auditDatabaseSets(beforeSnapshot ?? afterFailure, afterFailure);
          leftoverAfterFailure = setsAfterFailure.leftoverOwned;
          foreignCreatedAfterFailure = setsAfterFailure.foreignCreated;
          foreignRemovedAfterFailure = setsAfterFailure.foreignRemoved;
          auditError = null;
        }
      } catch (auditErr) {
        auditError = `namespace audit after failure unavailable: ${auditErr.message}`;
      }
      namespaceAudit = {
        ownedDbs: [...ownedDbs],
        ownedPrefix: fence.DB_PREFIX,
        drops: dropRecords,
        allOwnedDropped: dropRecords.every((d) => d.dropped === true) && leftoverAfterFailure.length === 0,
        before: beforeSnapshot,
        after: afterFailure,
        created: [],
        removed: [],
        foreignCreated: foreignCreatedAfterFailure,
        foreignRemoved: foreignRemovedAfterFailure,
        leftoverOwned: leftoverAfterFailure,
        protectedChanged: null,
        foreignTouched: foreignCreatedAfterFailure.length > 0 || foreignRemovedAfterFailure.length > 0,
        ok: false,
        error: auditError,
      };
    }
  } finally {
    await closeMongoose();
    try {
      if (driverClient) {
        await driverClient.close();
      }
    } catch {
      /* ignore */
    }
    lifecycle.clientClosed = true;
  }

  // 7. classify every row against the authorized pre-repair state
  const finalized = rows.map((row) => {
    const expected = EXPECTED_STATES[row.id];
    const met = row.checks.every((c) => c.met === true);
    let actual;
    if (expected === 'PASS_CURRENT') {
      actual = met ? 'PASS_CURRENT' : 'HARNESS_FAIL';
    } else {
      actual = met ? 'UNEXPECTED_GREEN' : 'EXPECTED_RED';
    }
    const evidenceRefs = [`artifacts/${row.id}.json`];
    return {
      id: row.id,
      title: row.title,
      expected,
      actual,
      tier: row.tier,
      met,
      expectedOracle: row.expectedOracle,
      checks: row.checks,
      evidence: row.evidence,
      evidenceRefs,
      notes:
        expected === 'PASS_CURRENT' && !met
          ? 'PASS_CURRENT row unsatisfied: pre-repair regression or harness/substrate defect — reported as HARNESS_FAIL, never as red.'
          : actual === 'UNEXPECTED_GREEN'
            ? 'expected red but the row currently satisfies — reported explicitly as UNEXPECTED_GREEN, never reinterpreted as a pass.'
            : null,
    };
  });

  const idOrder = ['T1R-01', 'T1R-02', 'T1R-03', 'T1R-04', 'T1R-05', 'T1R-06', 'T1R-07', 'T1R-08', 'T1R-09'];
  finalized.sort((a, b) => idOrder.indexOf(a.id) - idOrder.indexOf(b.id));

  criteria = {
    a_all_nine_states_match_authorized: finalized.every((row) => row.actual === row.expected) && finalized.length === 9,
    b_namespace_clean: namespaceAudit.ok === true && namespaceAudit.allOwnedDropped === true,
    c_six_preimages_unchanged: hashManifest.items.filter((i) => i.kind === 'preimage').every((i) => i.match === true),
    d_audit_sink_absent: hashManifest.sinkAbsent === true && probe.exists === false,
  };
  exitCode = Object.values(criteria).every((v) => v === true) ? 0 : 1;

  const finishedAt = new Date().toISOString();
  const meta = {
    runId,
    commission: COMMISSION,
    authorizationDoc: AUTHORIZATION_DOC,
    command: COMMAND,
    frozenHead: FROZEN_HEAD,
    gitHead,
    startedAt,
    finishedAt,
    node: process.version,
    platform: `${process.platform}/${process.arch}`,
    pid: process.pid,
    exitCode,
    fatal,
    mongooseVersion: (() => {
      try {
        return w3a.mongoose.version;
      } catch {
        return null;
      }
    })(),
  };

  const fenceControl = fenceNegativeControl();
  const ledger = {
    runId,
    commission: COMMISSION,
    authorizationDoc: AUTHORIZATION_DOC,
    command: COMMAND,
    frozenHead: FROZEN_HEAD,
    observedGitHead: gitHead,
    startedAt,
    finishedAt,
    exitCode,
    criteria,
    fatal,
    rows: finalized.map((row) => ({
      id: row.id,
      title: row.title,
      expected: row.expected,
      actual: row.actual,
      tier: row.tier,
      met: row.met,
      expectedOracle: row.expectedOracle,
      evidenceRefs: row.evidenceRefs,
      checks: row.checks,
      notes: row.notes,
    })),
    sourceHashes: hashManifest,
    namespaceAudit,
    fenceControl,
  };

  writeJson(path.join(runDir, 'T1R-RESULTS.json'), ledger);
  writeJson(path.join(runDir, 'T1R-SOURCE-HASH-MANIFEST.json'), { runId, manifest: hashManifest, auditSink: { rel: AUDIT_SINK_REL, expected: 'ABSENT', exists: probe.exists, absent: !probe.exists } });
  writeJson(path.join(runDir, 'T1R-NAMESPACE-AUDIT.json'), { runId, fenceChecks, namespaceAudit, fenceControl });
  writeJson(path.join(runDir, 'T1R-RUN-META.json'), meta);
  for (const row of finalized) {
    writeJson(path.join(artifactsDir, `${row.id}.json`), row);
  }
  writeText(path.join(runDir, 'T1R-REPORT.md'), markdownReport(meta, finalized, hashManifest, namespaceAudit, fenceControl, criteria, exitCode));

  const summary = {
    runId,
    runDir: path.relative(WORKTREE, runDir).replace(/\\/g, '/'),
    exitCode,
    criteria,
    rows: finalized.map((row) => ({ id: row.id, expected: row.expected, actual: row.actual, tier: row.tier, met: row.met })),
    namespace: { ownedDbs: namespaceAudit.ownedDbs, drops: namespaceAudit.drops, leftoverOwned: namespaceAudit.leftoverOwned, foreignCreated: namespaceAudit.foreignCreated, foreignRemoved: namespaceAudit.foreignRemoved, ok: namespaceAudit.ok },
    sourceHashes: hashManifest.items.map((i) => ({ rel: i.rel, expected: i.expected, actual: i.actual, match: i.match })),
    fatal,
  };

  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  process.stdout.write(`\n[t1r-audit] ${COMMAND}\n[t1r-audit] verdict rows: ${finalized.map((r) => `${r.id}=${r.actual}`).join(' ')}\n[t1r-audit] exit ${exitCode}\n`);
  process.exitCode = exitCode;
  return ledger;
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`[t1r-audit] HARNESS_FAIL: ${err && err.stack ? err.stack : String(err)}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  AUDIT_EVENT_KEYS,
  AUDIT_KINDS,
  MUST_BE_NULL,
  NULLABLE_BY_KIND,
  EXPECTED_STATES,
  PREIMAGES,
  buildF6Events,
  fullyNonNullEvent,
  scanFabricationSentinels,
};

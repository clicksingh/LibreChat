'use strict';

/**
 * W3-B R2 S4T environment (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Reuses the proven R2 primitives read-only (`../../r2/env.cjs` -> `../../w3a/env.cjs`):
 *   - genuine `createModels(mongoose)` from `packages/data-schemas/src/models/index.ts`, executed
 *     through the disclosed I10 TS bridge;
 *   - the frozen `api/server/services/Device/*.js` product services, crypto surface and error map.
 *
 * Adds only what S4T needs:
 *   - the genuine product audit adapter `api/server/services/Device/auditSink.js`
 *     (`createMongooseAuditSink`) so the real `AuditEvent` create path is exercised, not a test sink;
 *   - raw-driver read-back helpers and a bounded dependency-surface hasher.
 *
 * No plain-object model facade exists anywhere in this lane: the raw registry is handed to the frozen
 * factories directly.
 */

const fs = require('node:fs');
const path = require('node:path');

// eslint-disable-next-line global-require, import/no-dynamic-require
const baseEnv = require(path.resolve(__dirname, '..', '..', 'r2', 'env.cjs'));

const w3a = baseEnv.w3a;

const WORKTREE = baseEnv.WORKTREE;
const DEVICE_DIR = baseEnv.DEVICE_DIR;
const WRITE_CONCERN = baseEnv.WRITE_CONCERN;

/** The genuine product audit adapter (S3-B accepted byte). */
const auditSinkPath = path.join(DEVICE_DIR, 'auditSink.js');
// eslint-disable-next-line global-require, import/no-dynamic-require
const auditSink = require(auditSinkPath);

const DEVICE_MODELS = Object.freeze(['DeviceAuthority', 'PairingSession', 'Challenge', 'AuditEvent']);

/** Real frozen registry: genuine Mongoose Model constructors (identity-checkable). */
function loadRegistry() {
  const info = w3a.loadModels();
  const registry = info.registry;
  const shape = {};
  for (const key of Object.keys(registry)) {
    const model = registry[key];
    shape[key] = {
      typeofModel: typeof model,
      modelName: model.modelName,
      collection: model.collection ? model.collection.name : null,
      hasCreate: typeof model.create === 'function',
      hasUpdateOne: typeof model.updateOne === 'function',
      hasFindOne: typeof model.findOne === 'function',
      hasFindOneAndUpdate: typeof model.findOneAndUpdate === 'function',
    };
  }
  return { registry, shape, info };
}

/**
 * The only audit sink used by this lane: the genuine product Mongoose `AuditEvent` adapter, which
 * projects first and then writes with the explicit frozen `{w:'majority', j:true}` concern.
 */
function makeProductAuditSink({ AuditEvent, logger = null }) {
  const built = auditSink.createMongooseAuditSink({ AuditEvent, logger });
  const outcomes = [];
  const events = [];
  return {
    kind: `product-adapter:${built.sinkKind}`,
    collection: AuditEvent.collection.name,
    modelName: AuditEvent.modelName,
    events,
    outcomes,
    async audit(event) {
      events.push(event);
      try {
        await built.audit(event);
        outcomes.push({ ok: true });
      } catch (err) {
        outcomes.push({ ok: false, error: { name: err.name, code: err.code ?? null, message: err.message } });
        throw err;
      }
    },
  };
}

/** Raw-driver read of the exact collection/document the genuine model wrote. */
async function readRawDoc(client, dbName, collection, filter) {
  return client.db(dbName).collection(collection).findOne(filter);
}

/** Genuine-model lean read of the exact document the product returned. */
async function readLean(model, filter) {
  return model.findOne(filter).lean();
}

async function countCollection(client, dbName, collection) {
  return client.db(dbName).collection(collection).countDocuments({});
}

/** True when the on-disk bytes of a file are unchanged (bounded read-only check). */
function fileDigest(absolute) {
  if (!fs.existsSync(absolute)) {
    return null;
  }
  return require('node:crypto').createHash('sha256').update(fs.readFileSync(absolute)).digest('hex');
}

module.exports = {
  baseEnv,
  w3a,
  mongoose: w3a.mongoose,
  WORKTREE,
  DEVICE_DIR,
  WRITE_CONCERN,
  DEVICE_MODELS,
  auditSink,
  auditSinkPath,
  loadRegistry,
  makeProductAuditSink,
  readRawDoc,
  readLean,
  countCollection,
  fileDigest,
  connectMongoose: w3a.connectMongoose,
  constants: w3a.constants,
  TENANT: w3a.TENANT,
  OTHER_TENANT: w3a.OTHER_TENANT,
  OWNER_A: w3a.OWNER_A,
  OWNER_B: w3a.OWNER_B,
  OWNER_C: w3a.OWNER_C,
  labKey: w3a.labKey,
  makeDeviceKey: w3a.makeDeviceKey,
  makeClock: w3a.makeClock,
  makeCrypto: w3a.makeCrypto,
  makeTenantPolicy: w3a.makeTenantPolicy,
  makeLocalConsent: w3a.makeLocalConsent,
  sign: w3a.sign,
  LAB_PEPPER: w3a.LAB_PEPPER,
  product: w3a.product,
  attemptComposition: baseEnv.attemptComposition,
  collectionCounts: baseEnv.collectionCounts,
};

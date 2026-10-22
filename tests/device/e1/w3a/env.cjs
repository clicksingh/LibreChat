'use strict';

/**
 * W3-A / I11 environment loader (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Loads the REAL frozen product bytes and hands them to the fixtures:
 *   - `packages/data-schemas/src/models/index.ts` (I4 barrel) executed through the I10
 *     in-memory TypeScript bridge, so every model/schema byte is the frozen product byte and
 *     `applyTenantIsolation` is the real plugin;
 *   - `api/server/services/Device/authorityService.js` (I6) and
 *     `api/server/services/Device/{registrationService,pairingSessionService}.js` (I5);
 *   - `api/server/services/Device/{crypto,errors}.js` (I7).
 *
 * This module owns no product behaviour. It only supplies:
 *   - an injected deterministic clock;
 *   - a FIXED trusted tenant principal, a server-controlled tenant allowlist and a fixed local
 *     consent verdict (G-3/G-9 seams) — never a request-supplied identity;
 *   - a lab-only deterministic Ed25519 device key so several OS processes can sign the same
 *     canonical messages without shipping key files around;
 *   - a RECORDING proxy around the Mongoose models that delegates every call to the real model
 *     and records the exact filter/update/options actually passed by the product bytes.
 */

const path = require('node:path');
const nodeCrypto = require('node:crypto');

const BRIDGE_PATH = path.resolve(
  __dirname,
  '..',
  '..',
  '_phase1_evidence',
  'w2-runtime',
  'w2c-integration',
  'bridge',
  'register.cjs',
);

// eslint-disable-next-line global-require, import/no-dynamic-require
const bridge = require(BRIDGE_PATH);
bridge.setProfile('track2');

const mongoose = require(bridge.mongoosePath);

/** w3a -> e1 -> device -> tests -> worktree */
const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..');
const DEVICE_DIR = path.join(WORKTREE, 'api', 'server', 'services', 'Device');

function requireProduct(relative) {
  const absolute = path.join(DEVICE_DIR, relative);
  // eslint-disable-next-line global-require, import/no-dynamic-require
  return { absolute, exports: require(absolute) };
}

const i6 = requireProduct('authorityService.js');
const i5registration = requireProduct('registrationService.js');
const i5pairing = requireProduct('pairingSessionService.js');
const i7crypto = requireProduct('crypto.js');
const i7errors = requireProduct('errors.js');

const PRODUCT_FILES = {
  authorityService: i6.absolute,
  registrationService: i5registration.absolute,
  pairingSessionService: i5pairing.absolute,
  crypto: i7crypto.absolute,
  errors: i7errors.absolute,
};

/** FIXED trusted test principal/tenant. Injected by the harness only — never from a request. */
const TENANT = 'tenant-w3a-i11-fixed';
const OTHER_TENANT = 'tenant-w3a-i11-foreign';
const OWNER_A = 'principal-w3a-i11-owner-a';
const OWNER_B = 'principal-w3a-i11-owner-b';
const OWNER_C = 'principal-w3a-i11-owner-c';

const LEASE_TTL_MS = 172800000;
const SKEW_MARGIN_MS = 5000;
const CODE_TTL_MS = 300000;
const REGISTRATION_CHALLENGE_TTL_MS = 120000;
const MAX_ATTEMPTS = 5;
const MAX_CODE_REGENERATIONS = 3;
const REGISTRATION_DOMAIN = 'cbhr:device:registration:v1';
const PAIRING_OPEN_DOMAIN = 'cbhr:device:pairing-open:v1';
const PAIRING_CLAIM_DOMAIN = 'cbhr:device:pairing-claim:v1';
const PAIRING_DENY_DOMAIN = 'cbhr:device:pairing-deny:v1';

/** Lab-only pepper; never written to a report or a log. */
const LAB_PEPPER = Buffer.from('w3a-i11-lab-only-lookup-pepper-0001', 'utf8');

/** Fixed deterministic epoch base so every assertion body is wall-clock free. */
const EPOCH_BASE_MS = 1791000000000;

/** Deterministic Ed25519 seed for the lab device key (test-only, not a production secret). */
const LAB_KEY_SEED = Buffer.from('cbhr-w3a-i11-lab-device-key-seed', 'utf8').subarray(0, 32);
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function loadModels() {
  const barrel = require(bridge.MODELS_BARREL);
  const registry = barrel.createModels(mongoose);
  return {
    registry,
    keys: Object.keys(registry).sort(),
    barrelPath: bridge.MODELS_BARREL,
    schemaBarrelPath: bridge.SCHEMA_BARREL,
    createModelsSource: barrel.createModels.toString().slice(0, 200),
  };
}

function makeClock(startMs = EPOCH_BASE_MS) {
  let current = startMs;
  return {
    kind: 'injected-deterministic',
    now: () => current,
    set: (value) => {
      current = value;
      return current;
    },
    advance: (delta) => {
      current += delta;
      return current;
    },
    get: () => current,
  };
}

function makeLabKeyPair() {
  const privateKey = nodeCrypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, LAB_KEY_SEED]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = nodeCrypto.createPublicKey(privateKey);
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return {
    privateKey,
    publicKey,
    spkiB64u: spki.toString('base64url'),
  };
}

/**
 * Deterministic per-device Ed25519 lab key. Test-only: the seed is derived from a label so
 * several OS processes can regenerate the same key without exchanging key files. Never a
 * production key material and never written to a report.
 */
function makeDeviceKey(tag) {
  const seed = nodeCrypto
    .createHash('sha256')
    .update(`cbhr-w3a-i11-device-key:${String(tag)}`)
    .digest()
    .subarray(0, 32);
  const privateKey = nodeCrypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = nodeCrypto.createPublicKey(privateKey);
  return {
    tag: String(tag),
    privateKey,
    publicKey,
    spkiB64u: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
  };
}

function sign(keyPair, message) {
  return nodeCrypto.sign(null, message, keyPair.privateKey).toString('base64url');
}

/** Wraps the frozen crypto surface; `overrides` are disclosed fault-injection seams. */
function makeCrypto(overrides = {}) {
  return { ...i7crypto.exports, ...overrides };
}

/**
 * Recording proxy around `createModels(mongoose)`.
 *
 * Delegates every call to the real Mongoose model. Promise-returning helpers are re-wrapped in
 * a Promise with a recording side effect; `find`/`findOne` keep the real Query object (the
 * product chains `.lean()`), and the recorder observes after `.lean()` resolves.
 */
const PROMISE_METHODS = new Set([
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'findOneAndUpdate',
  'findOneAndDelete',
  'replaceOne',
  'create',
  'insertMany',
  'bulkWrite',
  'save',
]);
const QUERY_METHODS = new Set(['findOne', 'find', 'countDocuments', 'distinct', 'aggregate']);

function describeError(err) {
  if (err === null || typeof err !== 'object') {
    return { name: null, code: null, keyPattern: null, keyValue: null, message: String(err) };
  }
  return {
    name: err.name ?? null,
    code: err.code ?? null,
    keyPattern: err.keyPattern ?? null,
    keyValue: err.keyValue ?? null,
    message: err.message ?? null,
  };
}

function instrumentModel(name, model, recorder) {
  return new Proxy(model, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== 'function' || typeof property !== 'string') {
        return value;
      }
      if (PROMISE_METHODS.has(property)) {
        return function recordedPromiseCall(...args) {
          const documentMethod = property === 'create' || property === 'insertMany';
          const optionsIndex = documentMethod || property === 'deleteOne' || property === 'deleteMany' || property === 'findOneAndDelete' ? 1 : 2;
          const record = {
            model: name,
            method: property,
            filter: documentMethod ? null : args[0] ?? null,
            options: args.length > optionsIndex ? args[optionsIndex] ?? null : null,
            payloadKind: documentMethod ? 'document' : Array.isArray(args[1]) ? 'pipeline' : 'update',
            seq: recorder.length,
            ok: null,
            error: null,
          };
          let outcome;
          try {
            outcome = value.apply(target, args);
          } catch (err) {
            record.ok = false;
            record.error = describeError(err);
            recorder.push(record);
            throw err;
          }
          return Promise.resolve(outcome).then(
            (result) => {
              record.ok = true;
              record.result = {
                matchedCount: result && typeof result.matchedCount === 'number' ? result.matchedCount : null,
                modifiedCount: result && typeof result.modifiedCount === 'number' ? result.modifiedCount : null,
                acknowledged: result && typeof result.acknowledged === 'boolean' ? result.acknowledged : null,
                upsertedCount: result && typeof result.upsertedCount === 'number' ? result.upsertedCount : null,
              };
              recorder.push(record);
              return result;
            },
            (err) => {
              record.ok = false;
              record.error = describeError(err);
              recorder.push(record);
              throw err;
            },
          );
        };
      }
      if (QUERY_METHODS.has(property)) {
        return function recordedQueryCall(...args) {
          const record = {
            model: name,
            method: property,
            filter: args[0] ?? null,
            options: null,
            payloadKind: 'query',
            seq: recorder.length,
            ok: null,
            error: null,
          };
          const query = value.apply(target, args);
          if (query !== null && typeof query === 'object' && typeof query.lean === 'function') {
            const originalLean = query.lean.bind(query);
            query.lean = (...leanArgs) => {
              return Promise.resolve(originalLean(...leanArgs)).then(
                (doc) => {
                  record.ok = true;
                  record.result = { docFound: doc !== null && doc !== undefined };
                  recorder.push(record);
                  return doc;
                },
                (err) => {
                  record.ok = false;
                  record.error = describeError(err);
                  recorder.push(record);
                  throw err;
                },
              );
            };
          } else {
            record.ok = null;
            recorder.push(record);
          }
          return query;
        };
      }
      return value.bind(target);
    },
  });
}

function instrumentModels(models, recorder) {
  const instrumented = {};
  for (const key of Object.keys(models)) {
    instrumented[key] = instrumentModel(key, models[key], recorder);
  }
  return instrumented;
}

const FORWARDED_METHODS = [
  'findOne',
  'find',
  'findOneAndUpdate',
  'findOneAndDelete',
  'findOneAndReplace',
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'replaceOne',
  'countDocuments',
  'distinct',
  'aggregate',
  'create',
  'insertMany',
  'bulkWrite',
];

/**
 * DISCLOSED test-only adapter.
 *
 * The real `createModels(mongoose)` registry exposes genuine Mongoose Model *constructors*
 * (`typeof === 'function'`), while I6/I5 `assertDependencies` require `typeof db.<Model> === 'object'`.
 * This adapter is a behaviour-free plain-object facade: every forwarded method applies the
 * genuine instrumented model method to the genuine model. It exists solely to let the real
 * product bytes execute; it adds no logic and no fallback. The recorded provenance is reported
 * with every fixture.
 */
function makeDbFacade(models, recorder) {
  const instrumented = instrumentModels(models, recorder);
  const db = {};
  const provenance = {};
  for (const key of Object.keys(models)) {
    const real = models[key];
    const proxy = instrumented[key];
    const surface = {};
    const forwarded = [];
    for (const method of FORWARDED_METHODS) {
      if (typeof real[method] === 'function') {
        surface[method] = (...args) => proxy[method](...args);
        forwarded.push(method);
      }
    }
    Object.defineProperty(surface, '__provenance', {
      value: { modelName: real.modelName, collection: real.collection.name, forwarded },
      enumerable: false,
    });
    db[key] = surface;
    provenance[key] = {
      modelName: real.modelName,
      collection: real.collection.name,
      realModelTypeof: typeof real,
      facadeTypeof: typeof surface,
      forwarded,
    };
  }
  return { db, instrumented, provenance, kind: 'plain-object-model-facade-delegating-to-real-mongoose-models' };
}

/** Records the exact raw-registry rejection produced by the frozen factory shape checks. */
function probeFactoryShapeAgainstRawRegistry(registry, clock, cryptoSurface) {
  const marker = 'PROBE';
  const attempts = [
    {
      factory: 'createAuthorityService',
      call: () =>
        i6.exports.createAuthorityService({
          db: registry,
          clock,
          crypto: cryptoSurface,
          logger: null,
          audit: async () => {},
          verifyRenewalProof: async () => ({ ok: false }),
        }),
    },
    {
      factory: 'createRegistrationService',
      call: () =>
        i5registration.exports.createRegistrationService({
          db: registry,
          clock,
          crypto: cryptoSurface,
          logger: null,
          audit: async () => {},
          tenantPolicy: { validateRegistrationTenant: () => true },
        }),
    },
    {
      factory: 'createPairingSessionService',
      call: () =>
        i5pairing.exports.createPairingSessionService({
          db: registry,
          clock,
          crypto: cryptoSurface,
          logger: null,
          audit: async () => {},
          authorityService: {
            readAuthority: async () => null,
            releaseLapsedLease: async () => ({ ok: false, matched: 0, authority: null, error: null }),
            spendChallenge: async () => ({ ok: false, matched: 0, authority: null, error: null }),
            claimAuthority: async () => ({ ok: false, matched: 0, authority: null, error: null }),
          },
          tenantPolicy: { validateRegistrationTenant: () => true },
          verifyLocalConsent: () => true,
          pepperLookup: LAB_PEPPER,
        }),
    },
  ];
  return attempts.map((attempt) => {
    try {
      attempt.call();
      return { factory: attempt.factory, marker, accepted: true, error: null };
    } catch (err) {
      return {
        factory: attempt.factory,
        marker,
        accepted: false,
        error: { name: err.name, message: err.message },
      };
    }
  });
}

function makeRecorder() {
  const entries = [];
  const pushes = (record) => entries.push(record);
  return {
    entries,
    push: pushes,
    writeConcernOf: (model, method) =>
      entries
        .filter((entry) => entry.model === model && entry.method === method)
        .map((entry) => entry.options),
    duplicateErrors: () =>
      entries
        .filter((entry) => entry.ok === false && entry.error && entry.error.code === 11000)
        .map((entry) => ({ model: entry.model, method: entry.method, keyPattern: entry.error.keyPattern, keyValue: entry.error.keyValue })),
    summary: () => {
      const byMethod = {};
      for (const entry of entries) {
        const key = `${entry.model}.${entry.method}`;
        byMethod[key] = byMethod[key] ?? { calls: 0, failures: 0, writeConcernPinned: 0, writeConcernMissing: 0 };
        byMethod[key].calls += 1;
        if (entry.ok === false) byMethod[key].failures += 1;
        if (entry.payloadKind === 'document' || entry.payloadKind === 'update' || entry.payloadKind === 'pipeline') {
          const wc = entry.options && entry.options.writeConcern;
          if (wc && wc.w === 'majority' && wc.j === true) byMethod[key].writeConcernPinned += 1;
          else byMethod[key].writeConcernMissing += 1;
        }
      }
      return byMethod;
    },
  };
}

/** FIXED trusted tenant allowlist (G-3). Never request-supplied. */
function makeTenantPolicy(allowed = [TENANT]) {
  return {
    kind: 'fixed-server-controlled-allowlist',
    allowed: [...allowed],
    calls: [],
    validateRegistrationTenant(tenantId, requestSource) {
      this.calls.push({ tenantId, requestSource: requestSource ?? null });
      return allowed.includes(tenantId);
    },
  };
}

/** FIXED trusted local-endpoint consent seam (endpoint-host consent only). */
function makeLocalConsent({ granted = true, nonce = 'lab-consent-nonce-0001' } = {}) {
  return {
    kind: 'fixed-trusted-local-consent',
    granted,
    calls: [],
    verify(input) {
      this.calls.push({ tenantId: input.tenantId, ownerId: input.ownerId, pairingSessionId: input.pairingSessionId });
      if (!granted) {
        return false;
      }
      return { ok: true, nonceHash: i7crypto.exports.sha256B64u(nonce) };
    },
  };
}

/** Real product audit sink that persists through the real AuditEvent model. */
function makeAuditSink(models, recorder) {
  const events = [];
  return {
    kind: 'real-AuditEvent-model',
    events,
    async audit(event) {
      events.push({ ...event });
      await models.AuditEvent.create(event);
    },
  };
}

/** Audit sink that fails after the CAS has committed (G-5 uncertainty probe). */
function makeFailingAuditSink() {
  const events = [];
  return {
    kind: 'throwing-sink-after-commit',
    events,
    async audit(event) {
      events.push({ ...event });
      throw new Error('LAB_INJECTED_AUDIT_SINK_FAILURE');
    },
  };
}

/** A verifier that always accepts, used only as the injected renewal-proof seam. */
function makeRenewalProof(expected) {
  const calls = [];
  const fn = async (input) => {
    calls.push(input ?? null);
    if (input === null || typeof input !== 'object' || input.__accept === false) {
      return { ok: false };
    }
    return {
      ok: true,
      binding: {
        tenantId: expected.tenantId,
        ownerPrincipalId: expected.ownerId,
        deviceId: expected.deviceId,
        deviceKeyId: expected.deviceKeyId ?? null,
        grantId: expected.grantId,
        epoch: expected.epoch,
      },
    };
  };
  fn.calls = calls;
  return fn;
}

async function connectMongoose({ uri, dbName }) {
  await mongoose.connect(uri, { dbName, autoIndex: false });
  const connection = mongoose.connection;
  return {
    databaseName: connection.db.databaseName,
    host: connection.host,
    port: connection.port,
    models: Object.keys(connection.models).sort(),
  };
}

async function syncDeclaredIndexes(models) {
  const applied = {};
  for (const key of Object.keys(models)) {
    applied[key] = { collection: models[key].collection.name, dropped: await models[key].syncIndexes() };
  }
  return applied;
}

/** Real Mongoose live-index read-back: listIndexes(), never the schema. */
async function listLiveIndexes(client, dbName, collections) {
  const out = {};
  for (const collection of collections) {
    out[collection] = await client.db(dbName).collection(collection).listIndexes().toArray();
  }
  return out;
}

function productHasRequestContainersRead() {
  const fs = require('node:fs');
  const forbidden = /args\.(body|query|params|headers|req|request|res)\b/;
  const out = {};
  for (const [name, file] of Object.entries(PRODUCT_FILES)) {
    const source = fs.readFileSync(file, 'utf8');
    out[name] = { file, readsRequestContainer: forbidden.test(source) };
  }
  return out;
}

module.exports = {
  bridge,
  mongoose,
  WORKTREE,
  DEVICE_DIR,
  PRODUCT_FILES,
  bridgePath: BRIDGE_PATH,
  product: {
    createAuthorityService: i6.exports.createAuthorityService,
    createRegistrationService: i5registration.exports.createRegistrationService,
    createPairingSessionService: i5pairing.exports.createPairingSessionService,
    crypto: i7crypto.exports,
    errors: i7errors.exports,
  },
  constants: {
    LEASE_TTL_MS,
    SKEW_MARGIN_MS,
    CODE_TTL_MS,
    REGISTRATION_CHALLENGE_TTL_MS,
    MAX_ATTEMPTS,
    MAX_CODE_REGENERATIONS,
    REGISTRATION_DOMAIN,
    PAIRING_OPEN_DOMAIN,
    PAIRING_CLAIM_DOMAIN,
    PAIRING_DENY_DOMAIN,
    LAB_PEPPER_LENGTH: LAB_PEPPER.length,
    EPOCH_BASE_MS,
  },
  TENANT,
  OTHER_TENANT,
  OWNER_A,
  OWNER_B,
  OWNER_C,
  LAB_PEPPER,
  labKey: makeLabKeyPair(),
  makeDeviceKey,
  loadModels,
  makeClock,
  makeCrypto,
  makeRecorder,
  instrumentModels,
  makeDbFacade,
  probeFactoryShapeAgainstRawRegistry,
  FORWARDED_METHODS,
  makeTenantPolicy,
  makeLocalConsent,
  makeAuditSink,
  makeFailingAuditSink,
  makeRenewalProof,
  sign,
  connectMongoose,
  syncDeclaredIndexes,
  listLiveIndexes,
  productHasRequestContainersRead,
};
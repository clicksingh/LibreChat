'use strict';

/**
 * W3-B R2-T0 environment (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Loads the REAL frozen product bytes through the disclosed I10 bridge that W3-A already proved:
 *   - `packages/data-schemas/src/models/index.ts` -> `createModels(mongoose)` (frozen product byte);
 *   - `api/server/services/Device/*.js` product services and the frozen errors/crypto surfaces.
 *
 * Tier discipline (F7):
 *   - `registry` is handed to product factories DIRECTLY. There is no `makeDbFacade` here and no
 *     plain-object model facade anywhere in this lane. `typeof registry.<Model> === 'function'`
 *     is asserted, and that is the only `db` argument any r2 fixture uses for E1/E2 rows.
 *   - the audit sink is the REAL `AuditEvent` Mongoose model (`registry.AuditEvent.create`). No
 *     raw-driver audit sink exists in this lane, so no fixture can accidentally certify E1/E2
 *     against a driver insert.
 *
 * This module owns no product behaviour: it injects a deterministic clock, fixed trusted tenant
 * principals, a server-controlled tenant allowlist, a fixed local-consent verdict and a lab-only
 * deterministic device key.
 */

const fs = require('node:fs');
const path = require('node:path');

// eslint-disable-next-line global-require, import/no-dynamic-require
const w3a = require(path.resolve(__dirname, '..', 'w3a', 'env.cjs'));

/** r2 -> e1 -> device -> tests -> worktree */
const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..');
const DEVICE_DIR = path.join(WORKTREE, 'api', 'server', 'services', 'Device');
const DATA_SCHEMAS_DIR = path.join(WORKTREE, 'packages', 'data-schemas', 'src');

const WRITE_CONCERN = Object.freeze({ w: 'majority', j: true });

const AUTHORITY_CRITICAL_WRITE_SITES = [
  { service: 'authorityService', anchor: 'api/server/services/Device/authorityService.js', kind: 'authority CAS / registration create' },
  { service: 'registrationService', anchor: 'api/server/services/Device/registrationService.js', kind: 'DeviceAuthority registration create' },
  { service: 'pairingSessionService', anchor: 'api/server/services/Device/pairingSessionService.js', kind: 'PairingSession create/update/consume' },
  { service: 'AuditEvent', anchor: 'api/server/services/Device/authorityService.js', kind: 'real AuditEvent create' },
];

function readProduct(relative) {
  const absolute = path.join(DEVICE_DIR, relative);
  return { absolute, source: fs.existsSync(absolute) ? fs.readFileSync(absolute, 'utf8') : null };
}

/** Real frozen registry: genuine Mongoose Model constructors. */
function loadRegistry() {
  const info = w3a.loadModels();
  const registry = info.registry;
  const shape = {};
  for (const key of Object.keys(registry)) {
    shape[key] = {
      typeofModel: typeof registry[key],
      modelName: registry[key].modelName,
      collection: registry[key].collection.name,
      hasCreate: typeof registry[key].create === 'function',
      hasUpdateOne: typeof registry[key].updateOne === 'function',
      hasFindOne: typeof registry[key].findOne === 'function',
    };
  }
  return { registry, shape, info };
}

/**
 * The only audit sink in this lane: the real AuditEvent Mongoose model, written with the frozen
 * majority+journal concern using the unambiguous array-form `create` overload.
 */
function makeRealAuditSink(registry, clock) {
  const events = [];
  const outcomes = [];
  return {
    kind: 'real-AuditEvent-model-sink',
    modelName: registry.AuditEvent.modelName,
    collection: registry.AuditEvent.collection.name,
    events,
    outcomes,
    async audit(event) {
      events.push({ ...event });
      const ts = event && event.ts ? event.ts : new Date(clock.now());
      try {
        const docs = await registry.AuditEvent.create([{ ...event, ts }], { writeConcern: WRITE_CONCERN });
        outcomes.push({
          ok: true,
          insertedId: String(docs[0]._id),
          writeConcernRequested: WRITE_CONCERN,
          opTime: docs[0].$__?.opTime ? String(docs[0].$__?.opTime) : null,
        });
        return docs[0];
      } catch (err) {
        outcomes.push({
          ok: false,
          error: { name: err.name, message: err.message, paths: Object.keys(err.errors ?? {}) },
        });
        throw err;
      }
    },
  };
}

/** Disclosed fault-injection sink used only where a frozen row requires an after-commit failure. */
function makeThrowingAuditSink() {
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

/**
 * Attempts the three frozen factories with the RAW real registry (no facade, no shim, no retry)
 * and records the truthful composition outcome per factory.
 */
function attemptComposition(registry, { clock, cryptoSurface, audit, tenantPolicy, consent, verifyRenewalProof, pepperLookup }) {
  const attempts = [
    {
      factory: 'createAuthorityService',
      guardAnchor: 'api/server/services/Device/authorityService.js:174-189',
      call: () =>
        w3a.product.createAuthorityService({
          db: registry,
          clock,
          crypto: cryptoSurface,
          logger: null,
          audit: audit.audit,
          verifyRenewalProof: verifyRenewalProof ?? (async () => ({ ok: false })),
        }),
    },
    {
      factory: 'createRegistrationService',
      guardAnchor: 'api/server/services/Device/registrationService.js:166-189',
      call: () =>
        w3a.product.createRegistrationService({
          db: registry,
          clock,
          crypto: cryptoSurface,
          logger: null,
          audit: audit.audit,
          tenantPolicy,
        }),
    },
    {
      factory: 'createPairingSessionService',
      guardAnchor: 'api/server/services/Device/pairingSessionService.js:182-230',
      call: () =>
        w3a.product.createPairingSessionService({
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
          tenantPolicy,
          verifyLocalConsent: consent,
          pepperLookup,
        }),
    },
  ];
  return attempts.map((attempt) => {
    try {
      const service = attempt.call();
      return {
        factory: attempt.factory,
        guardAnchor: attempt.guardAnchor,
        accepted: true,
        error: null,
        serviceKind: service && typeof service === 'object' ? 'object' : typeof service,
      };
    } catch (err) {
      return {
        factory: attempt.factory,
        guardAnchor: attempt.guardAnchor,
        accepted: false,
        error: { name: err.name, message: err.message },
        serviceKind: null,
      };
    }
  });
}

/**
 * FACTORY_COMPOSITION_FAIL view: the first truthful failure of every composition-gated row.
 * `pendingOracle` preserves the downstream frozen oracle so it is not lost.
 */
function compositionFailView(attempts, pendingOracle, extra = {}) {
  const firstRejected = attempts.find((a) => a.accepted === false) ?? null;
  return {
    kind: 'FACTORY_COMPOSITION_FAIL',
    reason: 'current factory dependency guards reject genuine Mongoose model constructors',
    attempts,
    firstRejectedFactory: firstRejected ? firstRejected.factory : null,
    guardAnchor: firstRejected ? firstRejected.guardAnchor : null,
    error: firstRejected ? firstRejected.error : null,
    pendingOracle,
    pendingAfterFirstFix: true,
    ...extra,
  };
}

/** Real collection counts for the four Phase-1 collections (DB read-back, not schema guesses). */
async function collectionCounts(client, dbName) {
  const out = {};
  for (const name of ['deviceauthorities', 'pairingsessions', 'challenges', 'deviceauthorityevents']) {
    // eslint-disable-next-line no-await-in-loop
    out[name] = await client.db(dbName).collection(name).countDocuments({});
  }
  return out;
}

/** Real read-back of every authority row in the fixture database. */
async function readAuthorityRows(client, dbName) {
  return client
    .db(dbName)
    .collection('deviceauthorities')
    .find({}, { projection: { _id: 1, tenantId: 1, epoch: 1, leaseState: 1, identityState: 1, ownerId: 1, grantId: 1, prevEpoch: 1 } })
    .toArray();
}

/** Static scan: every `new DeviceError('<CODE>')` literal in the frozen Device service bytes. */
function scanConstructedErrorCodes() {
  const found = new Map();
  for (const file of fs.readdirSync(DEVICE_DIR).filter((f) => f.endsWith('.js'))) {
    const source = fs.readFileSync(path.join(DEVICE_DIR, file), 'utf8');
    const re = /new DeviceError\(\s*'([A-Z0-9_]+)'/g;
    let match = re.exec(source);
    while (match !== null) {
      const entry = found.get(match[1]) ?? { code: match[1], sites: [] };
      entry.sites.push(`${file}:${source.slice(0, match.index).split('\n').length}`);
      found.set(match[1], entry);
      match = re.exec(source);
    }
  }
  return Array.from(found.values()).sort((a, b) => a.code.localeCompare(b.code));
}

/** Static scan: write-concern pinning at the product write sites (E0 supplementary evidence only). */
function scanWriteConcernSites() {
  const files = ['authorityService.js', 'registrationService.js', 'pairingSessionService.js'];
  const result = {};
  for (const file of files) {
    const source = fs.readFileSync(path.join(DEVICE_DIR, file), 'utf8');
    const lines = source.split('\n');
    const sites = [];
    lines.forEach((line, index) => {
      if (/writeConcern/.test(line)) {
        sites.push({ line: index + 1, text: line.trim(), body: lines.slice(Math.max(0, index - 4), index + 5).join('\n') });
      }
    });
    const constant = /WRITE_CONCERN\s*=\s*Object\.freeze\(\{\s*w:\s*'majority',\s*j:\s*true\s*\}\)/.test(source)
      || /writeConcern:\s*\{\s*w:\s*'majority',\s*j:\s*true\s*\}/.test(source);
    result[file] = { writeConcernPinnedConstant: constant, occurrenceCount: sites.length, sites: sites.map((s) => ({ line: s.line, text: s.text })) };
  }
  return result;
}

/** Static absence probe for design surfaces that the freeze requires and no product byte provides. */
function staticSurfaceAbsence(names) {
  const files = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
        walk(full);
      } else if (/\.(js|ts)$/.test(entry.name)) {
        files.push(full);
      }
    }
  };
  walk(DEVICE_DIR);
  walk(path.join(DATA_SCHEMAS_DIR, 'schema'));
  walk(path.join(DATA_SCHEMAS_DIR, 'models'));
  const out = {};
  for (const name of names) {
    const hits = [];
    for (const file of files) {
      const source = fs.readFileSync(file, 'utf8');
      if (source.includes(name)) {
        hits.push(path.relative(WORKTREE, file).replace(/\\/g, '/'));
      }
    }
    out[name] = { present: hits.length > 0, hits };
  }
  return out;
}

function makeContextEnv({ clock } = {}) {
  const loaded = loadRegistry();
  const effectiveClock = clock ?? w3a.makeClock();
  return {
    loaded,
    registry: loaded.registry,
    shape: loaded.shape,
    clock: effectiveClock,
    cryptoSurface: w3a.makeCrypto(),
    tenantPolicy: w3a.makeTenantPolicy(),
    consent: w3a.makeLocalConsent(),
    pepperLookup: w3a.LAB_PEPPER,
    product: w3a.product,
    constants: w3a.constants,
    TENANT: w3a.TENANT,
    OTHER_TENANT: w3a.OTHER_TENANT,
    OWNER_A: w3a.OWNER_A,
    OWNER_B: w3a.OWNER_B,
    OWNER_C: w3a.OWNER_C,
    mongoose: w3a.mongoose,
    bridgePath: w3a.bridgePath,
    labKey: w3a.labKey,
    sign: w3a.sign,
    makeDeviceKey: w3a.makeDeviceKey,
    makeRealAuditSink,
    makeThrowingAuditSink,
    attemptComposition,
  };
}

module.exports = {
  WORKTREE,
  DEVICE_DIR,
  DATA_SCHEMAS_DIR,
  WRITE_CONCERN,
  AUTHORITY_CRITICAL_WRITE_SITES,
  w3a,
  readProduct,
  loadRegistry,
  makeRealAuditSink,
  makeThrowingAuditSink,
  attemptComposition,
  compositionFailView,
  collectionCounts,
  readAuthorityRows,
  scanConstructedErrorCodes,
  scanWriteConcernSites,
  staticSurfaceAbsence,
  makeContextEnv,
  connectMongoose: w3a.connectMongoose,
  syncDeclaredIndexes: w3a.syncDeclaredIndexes,
};
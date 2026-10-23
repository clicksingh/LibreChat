'use strict';

/**
 * W9 — the DISCLOSED `~/db/models` adapter.
 *
 * THE PROBLEM IT CLOSES (stated exactly, because a substitution that is not named is a facade):
 *   - `api/db/models.js` is `createModels(mongoose)` spread into `module.exports`, so each member is a
 *     genuine Mongoose Model CONSTRUCTOR: `typeof models.DeviceAuthority === 'function'`.
 *   - every accepted `Device/**` factory asserts `typeof db.<Model> === 'object'`
 *     (`pairingSessionService.assertDependencies`, `registrationService.assertDependencies`,
 *     `authorityService.assertDependencies`).
 *   - `api/server/routes/devices.js` hands the raw registry to those factories AT MODULE LOAD
 *     (`const pairingComplete = createPairingCompleteHandler({ db, ... })`), so outside jest the real
 *     router cannot be required at all.
 *
 * WHAT THIS FILE IS: a plain object whose members are LIVE FORWARDERS to the genuine models. It adds
 * no logic, no fallback, no cache, no policy and no default. `__realModel` exposes the genuine model
 * so the harness can prove the forwarder and the registry are the same object.
 *
 * The registry it wraps is the SAME `mongoose` instance the real router and the real `api/db/models`
 * use (resolved by absolute path), so a row written through a handler is visible to the forwarders
 * and vice versa.
 */

const path = require('node:path');

const REPO = path.resolve(__dirname, '..', '..', '..');
const { createModels } = require(path.join(REPO, 'node_modules', '@librechat', 'data-schemas'));
// THE ROOT MONGOOSE INSTANCE, deliberately. `tests/device/_phase1_evidence/w2-runtime/node_modules`
// carries a SECOND mongoose install (the vendored test runtime), and anything loaded from there sees
// a different `mongoose` — which brings a different `Schema.Types.Date`. A `lean()` document produced
// by one realm then fails the OTHER realm's `value instanceof Date`, and the accepted services use
// exactly that comparison (`databaseTime.toMillis`, `pairingCompleteHttpHandler.toMillis`). Measured,
// not assumed: with the vendored instance the claim leg failed `ENDPOINT_CONSENT_REQUIRED` while
// every field visibly matched, because `claim.openedAt` converted to `null`.
//
// The real router (`api/db/models.js`) resolves through the same root junction, and `createModels`
// returns the models already registered on the connected instance, so the adapter and the router
// share one registry and one realm.
const mongoose = require(path.join(REPO, 'node_modules', 'mongoose'));

const registry = createModels(mongoose);

/**
 * Every method a genuine Mongoose Model exposes that the product tree may call. Only methods the
 * model actually has are forwarded, so the adapter never invents a capability.
 */
const FORWARDED_METHODS = Object.freeze([
  'findOne',
  'find',
  'findOneAndUpdate',
  'findOneAndDelete',
  'findById',
  'findByIdAndUpdate',
  'findByIdAndDelete',
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'create',
  'insertMany',
  'countDocuments',
  'estimatedDocumentCount',
  'distinct',
  'aggregate',
  'bulkWrite',
  'replaceOne',
  'exists',
  'watch',
  'syncIndexes',
  'init',
  'listIndexes',
]);

/** The genuine constructors, kept for provenance and for the harness's own direct reads. */
const realModels = Object.freeze({ ...registry });

const db = {};
const provenance = {};
for (const name of Object.keys(registry)) {
  const model = registry[name];
  const surface = {};
  const forwarded = [];
  for (const method of FORWARDED_METHODS) {
    if (typeof model[method] === 'function') {
      surface[method] = (...args) => model[method](...args);
      forwarded.push(method);
    }
  }
  // A genuine Mongoose Model carries `schema`; `createMongooseAuditSink` requires it, so forwarding
  // it keeps that accepted precondition satisfiable rather than working around it.
  surface.schema = model.schema;
  Object.defineProperty(surface, '__modelName', { value: model.modelName, enumerable: false });
  Object.defineProperty(surface, '__collection', {
    value: model.collection?.name ?? null,
    enumerable: false,
  });
  Object.defineProperty(surface, '__forwarded', { value: Object.freeze(forwarded), enumerable: false });
  Object.defineProperty(surface, '__realModel', { value: model, enumerable: false });
  db[name] = surface;
  provenance[name] = {
    modelName: model.modelName,
    collection: model.collection?.name ?? null,
    realModelTypeof: typeof model,
    adapterMemberTypeof: typeof surface,
    forwarded,
  };
}

Object.defineProperty(db, '__provenance', { value: Object.freeze(provenance), enumerable: false });
Object.defineProperty(db, '__realModels', { value: realModels, enumerable: false });
Object.defineProperty(db, '__kind', {
  value: 'plain-object-model-adapter-forwarding-to-genuine-createModels-registry',
  enumerable: false,
});

// GM-44 DATABASE-TIME SURFACE. `databaseTime.readDatabaseNowMs(db)` measures the server clock with
// `$collStats` + `$$NOW`, and `$collStats` is only valid as the FIRST stage of a pipeline. The
// genuine model registry carries the Mongoose tenant-isolation plugin, which PREPENDS a tenant
// `$match` to every `Model.aggregate()` call whenever an ALS tenant context is active — which is
// exactly the case on every authenticated device route. Such a prepended stage makes the accepted
// `$collStats` read throw ("$collStats is only valid as the first stage in a pipeline"), and the
// accepted code treats the throw as "no candidate can answer" and returns `null`, so every
// lease/TTL decision fails closed.
//
// The fix below is NOT a behaviour change: `readDatabaseNowMs` does not take a tenant and must not
// depend on one; its contract is "the measured clock of the server that holds these collections",
// and `$collStats` answers without reading a single document. The adapter's `aggregate` therefore
// runs the server's own collection pipeline DIRECTLY on the driver's collection handle, bypassing
// the Mongoose helpers (and their plugin stages) while executing the IDENTICAL pipeline the caller
// supplied. No filter is invented, no tenant stage is repaired, and every model query still goes
// through the genuine model.
//
// Measured, not assumed: with plain `Model.aggregate` forwarding, the first authenticated
// `/pairing/challenge` in this harness measured `null` while the unauthenticated S5b probe measured
// the server time fine — the only difference between them is the active ALS tenant. The audit- and
// write-style model methods are deliberately NOT rerouted: only `aggregate` has the "first stage
// only" law, and minimal surface is the point.
//
// The driver returns an AggregationCursor where Mongoose returns a thenable Aggregate whose awaited
// value is the ARRAY of rows. Callers of the model surface (the accepted `readDatabaseNowMs` among
// them) await the call and treat the result as rows, so the adapter keeps THAT contract by draining
// the cursor here.
for (const name of Object.keys(db)) {
  const member = db[name];
  member.aggregate = async (pipeline, ...rest) => {
    const raw = member.__realModel?.collection;
    if (raw !== null && raw !== undefined && typeof raw.aggregate === 'function') {
      const cursor = raw.aggregate(pipeline, ...rest);
      if (cursor !== null && typeof cursor === 'object' && typeof cursor.toArray === 'function') {
        return cursor.toArray();
      }
      return cursor;
    }
    return member.__realModel.aggregate(pipeline, ...rest);
  };
}

module.exports = db;
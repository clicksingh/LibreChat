'use strict';

/**
 * W3-B R2-T0A environment (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Read-only reuse of the accepted R2-T0 environment primitives (r2/env.cjs, itself built on the
 * disclosed I10/I11 bridge). Nothing under r2/** is written. This module adds only:
 *   - the runtime version read-back used by the result payload;
 *   - a genuine-registry shape projection (`typeof model === 'function'` evidence);
 *   - the t0a evidence path constants.
 *
 * Tier discipline (F7): the `registry` handed to the product factories is the RAW
 * `createModels(mongoose)` object. There is no facade, no shim, no retry in this lane. The audit
 * sink is the REAL AuditEvent Mongoose model.
 */

const fs = require('node:fs');
const path = require('node:path');

// eslint-disable-next-line global-require, import/no-dynamic-require
const r2env = require(path.resolve(__dirname, '..', 'r2', 'env.cjs'));

const WORKTREE = r2env.WORKTREE;
const DEVICE_DIR = r2env.DEVICE_DIR;
const DATA_SCHEMAS_DIR = r2env.DATA_SCHEMAS_DIR;
const WRITE_CONCERN = r2env.WRITE_CONCERN;

const T0A_DIR = path.resolve(__dirname, '..', '..', '_phase1_evidence', 'w3b-r2', 't0a');
const ARTIFACTS_DIR = path.join(T0A_DIR, 'artifacts');
const T0_DIR = path.resolve(__dirname, '..', '..', '_phase1_evidence', 'w3b-r2', 't0');
const R2_DIR = path.resolve(__dirname, '..', 'r2');
const R2A_DIR = __dirname;
const STDOUT_LOG = path.join(T0A_DIR, 'run-r2a-stdout.log');

function runtimeVersions() {
  const runtimeRoot = path.join(WORKTREE, 'tests', 'device', '_phase1_evidence', 'w2-runtime', 'node_modules');
  const read = (name) => {
    const manifest = path.join(runtimeRoot, name, 'package.json');
    return fs.existsSync(manifest) ? JSON.parse(fs.readFileSync(manifest, 'utf8')).version : null;
  };
  return { mongoose: read('mongoose'), mongodb: read('mongodb'), node: process.version };
}

/** `typeof registry.<Model>` projection: the E1/E2 genuine-constructor evidence. */
function registryModelTypeof(registry) {
  const out = {};
  for (const key of Object.keys(registry)) {
    out[key] = { typeofModel: typeof registry[key], modelName: registry[key].modelName ?? null };
  }
  return out;
}

/** The four Phase-1 collections, read back with the real driver. */
async function collectionCounts(client, dbName) {
  return r2env.collectionCounts(client, dbName);
}

async function readAuthorityRows(client, dbName) {
  return r2env.readAuthorityRows(client, dbName);
}

/** Server/user database inventory for the namespace audit (true for the vendored driver). */
module.exports = {
  WORKTREE,
  DEVICE_DIR,
  DATA_SCHEMAS_DIR,
  WRITE_CONCERN,
  T0A_DIR,
  T0_DIR,
  R2_DIR,
  R2A_DIR,
  ARTIFACTS_DIR,
  STDOUT_LOG,
  w3a: r2env.w3a,
  r2env,
  loadRegistry: r2env.loadRegistry,
  makeRealAuditSink: r2env.makeRealAuditSink,
  makeThrowingAuditSink: r2env.makeThrowingAuditSink,
  attemptComposition: r2env.attemptComposition,
  compositionFailView: r2env.compositionFailView,
  scanConstructedErrorCodes: r2env.scanConstructedErrorCodes,
  connectMongoose: r2env.connectMongoose,
  syncDeclaredIndexes: r2env.syncDeclaredIndexes,
  collectionCounts,
  readAuthorityRows,
  runtimeVersions,
  registryModelTypeof,
};
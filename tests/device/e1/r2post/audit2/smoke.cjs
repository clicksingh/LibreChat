'use strict';

/**
 * Read-only harness dry-run for the T1R audit lane (test-only).
 *
 *   node tests/device/e1/r2post/audit2/smoke.cjs
 *
 * Proves module resolution, the I10 bridge, the genuine createModels(mongoose).AuditEvent
 * model, the frozen Mongo topology and the DB-name fence — WITHOUT writing to any database
 * and without creating any database (a connection alone creates nothing).
 */

const path = require('node:path');
const fence = require('./fence.cjs');

const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..', '..');
// eslint-disable-next-line global-require, import/no-dynamic-require
const w3a = require(path.join(WORKTREE, 'tests', 'device', 'e1', 'w3a', 'env.cjs'));

async function main() {
  const out = { ok: false };
  const dbName = fence.createDbName('smoke', require('node:crypto'));
  out.fence = {
    dbName,
    problems: fence.checkDbName(dbName),
    uriProblems: fence.checkUri(fence.FROZEN_URI),
    refusesForeign: ['cbhr_rdc_phase1_r2_t0_x', 'devices_prod', 'admin', 'cbhr_rdc_phase1_r2_t1r_'].map((n) => ({
      n,
      problems: fence.checkDbName(n),
    })),
  };
  fence.assertDbName(dbName);

  const guarded = await fence.connectGuarded({ dbName, appName: 'cbhr-phase1-r2-t1r-smoke' });
  out.topology = guarded.topology;
  try {
    const loaded = w3a.loadModels();
    const model = loaded.registry.AuditEvent;
    out.bridge = {
      barrelPath: loaded.barrelPath,
      schemaBarrelPath: loaded.schemaBarrelPath,
      createModelsSource: loaded.createModelsSource,
      registryKeys: loaded.keys.length,
      mongooseVersion: w3a.mongoose.version,
    };
    out.model = {
      typeofModel: typeof model,
      modelName: model.modelName,
      collection: model.collection.name,
      baseIsMongoose: model.base === w3a.mongoose,
      schemaIsMongooseSchema: model.schema instanceof w3a.mongoose.Schema,
      prototypeInstanceOfMongooseModel: model.prototype instanceof w3a.mongoose.Model,
      hasCreate: typeof model.create === 'function',
      schemaPaths: Object.keys(model.schema.paths),
      requiredPaths: Object.entries(model.schema.paths).filter(([, p]) => p.isRequired).map(([k]) => k).sort(),
      declaredIndexes: model.schema.indexes().map((entry) => ({ key: entry[0], options: entry[1] ?? {} })),
    };
    out.ok = true;
  } finally {
    await guarded.client.close();
  }
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
}

main().catch((err) => {
  process.stderr.write(`SMOKE_FAIL: ${err && err.stack ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});

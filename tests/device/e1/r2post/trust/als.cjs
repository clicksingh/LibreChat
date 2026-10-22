'use strict';

/**
 * W3-B R2 T2-F4 real AsyncLocalStorage loader (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Loads the ACTUAL frozen `packages/data-schemas/src/config/tenantContext.ts` product bytes through
 * the existing pinned I10 TypeScript bridge (the same in-memory `require.extensions['.ts']` path the
 * W3-A/W2-C runtime already proved). No package is installed, no ALS stub and no re-implementation
 * exists anywhere in this lane: `tenantStorage` below IS the frozen module's singleton, and the
 * T2-F4 rows enter tenant contexts through `tenantStorage.run()`.
 *
 * `node:async_hooks` is imported only to assert that the singleton really is a native
 * `AsyncLocalStorage` instance.
 */

const fs = require('node:fs');
const path = require('node:path');
const { AsyncLocalStorage } = require('node:async_hooks');

// Requiring the durability env installs the pinned I10 bridge (require.extensions['.ts']) and
// resolves `mongoose`/`mongodb`/`typescript` to the scoped lab runtime. It must load BEFORE the
// `.ts` require below. Nothing in that module is written by this lane.
// eslint-disable-next-line global-require, import/no-dynamic-require
const durabilityEnv = require(path.resolve(__dirname, '..', 'durability', 'env.cjs'));

const WORKTREE = durabilityEnv.WORKTREE;
const DATA_SCHEMAS_SRC = path.join(WORKTREE, 'packages', 'data-schemas', 'src');
const TENANT_CONTEXT_TS = path.join(DATA_SCHEMAS_SRC, 'config', 'tenantContext.ts');
const TENANT_ISOLATION_TS = path.join(DATA_SCHEMAS_SRC, 'models', 'plugins', 'tenantIsolation.ts');

function sha256FileUpper(absolute) {
  return require('node:crypto')
    .createHash('sha256')
    .update(fs.readFileSync(absolute))
    .digest('hex')
    .toUpperCase();
}

// The REAL frozen product TypeScript module, compiled in memory and executed from disk by the
// bridge. This is the module the tenantIsolation plugin also consumes, so it is a singleton.
// eslint-disable-next-line global-require, import/no-dynamic-require
const tenantContextModule = require(TENANT_CONTEXT_TS);

module.exports = {
  WORKTREE,
  DATA_SCHEMAS_SRC,
  TENANT_CONTEXT_TS,
  TENANT_ISOLATION_TS,
  tenantContextSha256: sha256FileUpper(TENANT_CONTEXT_TS),
  tenantIsolationSha256: sha256FileUpper(TENANT_ISOLATION_TS),
  tenantStorage: tenantContextModule.tenantStorage,
  getTenantId: tenantContextModule.getTenantId,
  getUserId: tenantContextModule.getUserId,
  getRequestId: tenantContextModule.getRequestId,
  runAsSystem: tenantContextModule.runAsSystem,
  scopedCacheKey: tenantContextModule.scopedCacheKey,
  SYSTEM_TENANT_ID: tenantContextModule.SYSTEM_TENANT_ID,
  storageIsNativeAsyncLocalStorage: tenantContextModule.tenantStorage instanceof AsyncLocalStorage,
  moduleKind: 'real-frozen-tenantContext.ts-executed-through-pinned-I10-bridge',
  /** Fresh resolution of the same frozen path: used to prove the rows used the module singleton. */
  resolveTenantStorageIdentity() {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    const fresh = require(TENANT_CONTEXT_TS);
    return {
      sameModuleInstance: fresh === tenantContextModule,
      sameStorageInstance: fresh.tenantStorage === tenantContextModule.tenantStorage,
    };
  },
  /** The frozen F4 trusted dependency shape, bound to the REAL getTenantId. */
  makeTenantContextDependency(alsAbsencePermitted) {
    return {
      getActiveTenantId: tenantContextModule.getTenantId,
      alsAbsencePermitted: alsAbsencePermitted === true,
    };
  },
};
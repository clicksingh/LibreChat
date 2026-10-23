'use strict';

/**
 * W10b — THE PERSISTENCE LAYER, AGAINST A REAL MONGODB (and the 503 that stops being one).
 *
 * `docs/GM-RULING-ABSOLUTE-ADMIN-POLICY-AND-AUDIT-SEAM-20261023.md` (GM-81: the audit seam is
 * injected and fails closed), `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3/§6
 * (GM-76/GM-78/GM-79), `packages/api/src/admin/devicePolicy/storage.ts` (the fifteen methods).
 *
 * WHAT IS REAL HERE, AND WHY IT HAS TO BE
 *   REAL: MongoDB 7.0.43 at `127.0.0.1:27027`, replica set `cbhrRdcP1`, in a self-owned database whose
 *   name carries the `cbhr_rdc_phase1_` prefix; the `~/models` data layer as the SERVER builds it
 *   (`api/models/index.js` -> `createMethods`), including the pre-existing methods the seam binds
 *   unchanged (`getRoleByName`, `findGroupById`, `findUser`, `getUserPrincipals`); the four Mongoose
 *   schemas and their real indexes; the real audit recorder; the real route file
 *   (`api/server/routes/admin/devicePolicy.js`); the real handlers, validators, guards and resolver
 *   from `@librechat/api`; the real capability middleware; BOTH real Device enforcement modules.
 *   FAKE: only `requireJwtAuth` (it decides whether a session exists — the capability middleware
 *   still decides the 401/403), and `~/cache/getLogStores`, replaced with an in-memory Map so
 *   requiring `~/models` for real does not attach cache namespaces to a `dummy-uri` Mongo that is not
 *   up. Neither is part of what this spec measures.
 *
 * WHY NOT `mongodb-memory-server`, WHICH THE REST OF THE SUITE USES: the substrate is a named part of
 * this work's acceptance — real server version, real replica set, real unique-index enforcement, real
 * `listIndexes()`. An embedded server proves a different thing. The database is created for this file
 * and dropped in `afterAll`; the server-wide namespace is compared before and after and must match,
 * and that comparison lives in `afterAll` because it is only meaningful AFTER the drop.
 *
 * THE ACCEPTANCE THIS FILE EXISTS FOR
 * The storage seam answered 503 to READS as well as writes, because eleven persistence functions did
 * not exist and the seam refuses by name rather than answering from a partial store. Section I drives
 * the real route against the real store and requires 200/201 — and a negative control in section A
 * shows the same port refusing all fifteen on an empty data layer, so "200" is evidence of wiring
 * rather than of a relaxed assertion.
 */

const express = require('express');
const request = require('supertest');
const mongoose = require('mongoose');

/**
 * ENVIRONMENT SHIM (identical to `devicePolicy.spec.js`, and not a double for anything under test).
 *
 * `@librechat/api` is consumed as its built bundle, which requires `@librechat/agents` at LOAD time;
 * that chain reaches an ESM-only `uuid` build the root jest config cannot parse, so EVERY spec that
 * loads `@librechat/api` fails in this worktree (`ldap.spec.js`, `grants.spec.js` too). That is an
 * environment defect in `jest.config.cjs`, out of this change's write scope. The stub replaces the
 * agent runtime with a permissive no-op; nothing here touches it.
 */
jest.mock('@librechat/agents', () => {
  const target = function stub() {};
  const proxy = new Proxy(target, {
    get: (_t, prop) => {
      if (prop === '__esModule') {
        return true;
      }
      if (prop === 'then') {
        return undefined;
      }
      if (prop === 'toString' || prop === Symbol.toPrimitive) {
        return () => 'stub';
      }
      return proxy;
    },
    apply: () => proxy,
    construct: () => proxy,
  });
  return proxy;
});

// An in-memory cache, so requiring `~/models` for real does not build the Keyv/Redis namespaces.
const mockCache = new Map();
jest.mock('~/cache/getLogStores', () =>
  jest.fn(() => ({
    get: jest.fn(async (key) => mockCache.get(key)),
    set: jest.fn(async (key, value) => mockCache.set(key, value)),
    clear: jest.fn(async () => mockCache.clear()),
  })),
);

// Only the SESSION is faked. It is named `mockSession` because a `jest.mock` factory may only close
// over `mock`-prefixed bindings (jest hoists the factory above the declaration); with it null no
// `req.user` is set, and the REAL capability middleware then produces the 401/403 for itself.
let mockSession = null;
jest.mock('~/server/middleware', () => ({
  requireJwtAuth: (req, _res, next) => {
    if (mockSession !== null) {
      req.user = mockSession;
    }
    return next();
  },
}));

const {
  DEVICE_POLICY_AUDIT_ACTION_NAMES,
  DEVICE_POLICY_STORAGE_METHODS,
  resolveDevicePolicy,
  resolveDevicePolicyStorage,
} = require('@librechat/api');
const {
  AUDIT_LOG_ACTIONS,
  AUDIT_LOG_COUNTER_ID,
  AUDIT_LOG_DEVICE_POLICY_ACTIONS,
  AUDIT_LOG_SCHEMA_VERSION,
  SystemCapabilities,
  computeAuditEntryHash,
  createModels,
} = require('@librechat/data-schemas');
const deviceCapabilityPolicy = require('~/server/services/Device/deviceCapabilityPolicy');
const deviceToolRegistry = require('~/server/services/Device/deviceToolRegistry');

/**
 * The server's own startup order, reproduced: `api/db/index.js` runs `createModels(mongoose)` and
 * only then requires anything that queries by model (`indexSync` captures `mongoose.models.Message`
 * at load time, and the same is true of every method that reads a model off the registry). Doing it
 * here means `mongoose.models.Role`, `User`, `Group`, `SystemGrant` and the four W10b models all
 * exist, exactly as they do in the running server. It is idempotent.
 */
createModels(mongoose);

const db = require('~/models');

const router = require('../admin/devicePolicy');

const BASE = '/api/admin/device-policy';

// ── the substrate ───────────────────────────────────────────────────────────────────────────────

const MONGO_HOST = '127.0.0.1';
const MONGO_PORT = 27027;
const REPLICA_SET = 'cbhrRdcP1';
const DB_PREFIX = 'cbhr_rdc_phase1_w10b_storage_';
const DB_NAME = `${DB_PREFIX}${Date.now()}_${process.pid}`;
const SERVER_URI = `mongodb://${MONGO_HOST}:${MONGO_PORT}/?directConnection=true&replicaSet=${REPLICA_SET}&serverSelectionTimeoutMS=15000&retryWrites=false`;
const MONGO_URI = `mongodb://${MONGO_HOST}:${MONGO_PORT}/${DB_NAME}?directConnection=true&replicaSet=${REPLICA_SET}&serverSelectionTimeoutMS=15000&retryWrites=false`;

/** The whole server's database names, read over a SHORT-LIVED driver connection (not mongoose). */
async function serverDatabaseNames() {
  const { MongoClient } = require('mongodb');
  const client = new MongoClient(SERVER_URI, { serverSelectionTimeoutMS: 15000 });
  await client.connect();
  try {
    const listed = await client.db('admin').admin().listDatabases();
    return listed.databases.map((entry) => entry.name).sort();
  } finally {
    await client.close();
  }
}

let namespaceBefore = null;
let namespaceAfter = null;

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────

const TENANT_A = 'tenant-a';
const TENANT_B = 'tenant-b';

const ADMIN_ID = '64b7f0c2f1a2b3c4d5e6f7a8';
const STAFF_ID = '64b7f0c2f1a2b3c4d5e6f7a9';
const OTHER_STAFF_ID = '64b7f0c2f1a2b3c4d5e6f7aa';

const STAFF_ROLE = 'STAFF';

const ADMIN_SESSION = {
  id: ADMIN_ID,
  role: 'ADMIN',
  name: 'Root Admin',
  email: 'admin@example.test',
  tenantId: TENANT_A,
};

/** Stage-A catalog tools: admissible at every stage, so the scopes below are the only narrowing. */
const READ_FILE = 'read_file';
const READ_MULTIPLE = 'read_multiple_files';
const LIST_DIRECTORY = 'list_directory';

/** The tenant-isolation scope pair: A grants a tool, B grants nothing, so a leak is visible. */
const SCOPE_A = 'iso-scope-a';
const SCOPE_B = 'iso-scope-b';

/** The route's own primitives port: both REAL Device modules, so the law is not restated here. */
function realPrimitives() {
  return {
    capabilityPolicy: {
      capabilityStages: deviceCapabilityPolicy.CAPABILITY_STAGES,
      stageRank: deviceCapabilityPolicy.STAGE_RANK,
      catalogToolNames: deviceCapabilityPolicy.TOOL_CATALOG.map((tool) => tool.name),
      getToolDefinition: (name) => deviceCapabilityPolicy.getToolDefinition(name),
      capabilityCeiling: (stage) => deviceCapabilityPolicy.ceilingForStage(stage),
    },
    toolRegistry: {
      effectiveTools: (params) => deviceToolRegistry.effectiveTools(params),
      authorizeDispatch: (toolName, params) => deviceToolRegistry.authorizeDispatch(toolName, params),
      assertDispatchAllowed: (toolName, params) =>
        deviceToolRegistry.assertDispatchAllowed(toolName, params),
    },
  };
}

const CATALOG_TOOL_NAMES = deviceCapabilityPolicy.TOOL_CATALOG.map((tool) => tool.name);

/** A scope document as the admin API writes it. */
function scopeDoc(id, overrides = {}) {
  return {
    id,
    name: overrides.name ?? `Scope ${id}`,
    description: overrides.description ?? '',
    tools: overrides.tools ?? [READ_FILE, READ_MULTIPLE, LIST_DIRECTORY],
    stage: overrides.stage ?? 'full',
    isActive: overrides.isActive ?? true,
    version: overrides.version ?? 1,
  };
}

/** A fresh id per call, so a rerun never collides with a previous one. */
function uniqueId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Every audit entry, in chain order, straight out of the collection. */
async function auditEntries() {
  return mongoose.models.AuditLog.find({}).sort({ seq: 1 }).lean();
}

/**
 * THE CHAIN RULE, stated exactly, and asserted the same way everywhere in this file.
 *
 * For every entry, in `seq` order:
 *   - its `hash` is reproducible from its own stored content (nothing else);
 *   - `seq` strictly increases;
 *   - `prevHash` is the `hash` of the entry at `seq - 1` WHEN THAT ENTRY EXISTS, and `null` when it
 *     does not — which is the first entry, and every entry that follows a sequence number burned by
 *     an append that failed.
 *
 * The `null` case is not a hole in the assertion, it is the assertion: a gap is the truthful record
 * that an append was attempted and did not complete (`~/methods/auditLog` reserves `seq` before the
 * insert on purpose). Asserting "gap-free" instead would make the spec fail for the right behaviour
 * the moment a fail-closed write is exercised — which the tests below do deliberately.
 */
function expectChainIntact(entries) {
  const bySeq = new Map(entries.map((entry) => [entry.seq, entry]));
  entries.forEach((entry, index) => {
    expect(entry.hash).toBe(computeAuditEntryHash(entry));
    if (index > 0) {
      expect(entry.seq).toBeGreaterThan(entries[index - 1].seq);
    }
    const previous = bySeq.get(entry.seq - 1);
    expect(entry.prevHash).toBe(previous ? previous.hash : null);
  });
}

/** The store's own count, so "nothing changed" is provable rather than asserted. */
async function totalScopeCount() {
  return mongoose.models.DeviceToolScope.countDocuments({});
}

/**
 * THE END-TO-END RESOLUTION: exactly what the handler's `resolveFor` does, against the real store.
 * Assignments and the tenant default come from the storage methods; the scopes they name are
 * preloaded by id, so an id that is not in the data stays absent and fails closed.
 */
async function resolveFromStore(principal, options = {}) {
  const tenantId = options.tenantId;
  const scopeOptions = tenantId === undefined ? {} : { tenantId };
  const [assignments, tenantDefault] = await Promise.all([
    db.listAssignments(scopeOptions),
    db.getTenantDefault(scopeOptions),
  ]);
  const referenced = new Set();
  for (const assignment of assignments) {
    if (assignment && typeof assignment.toolScopeId === 'string') {
      referenced.add(assignment.toolScopeId);
    }
  }
  if (tenantDefault && typeof tenantDefault.defaultToolScopeId === 'string') {
    referenced.add(tenantDefault.defaultToolScopeId);
  }
  const loaded = await Promise.all(
    [...referenced].map(async (id) => [id, await db.getToolScope(id, scopeOptions)]),
  );
  return resolveDevicePolicy({
    principal,
    tenantDefault,
    assignments,
    getScope: (id) => new Map(loaded).get(id),
    serverStage: options.serverStage ?? 'full',
    pilot: options.pilot ?? false,
    primitives: realPrimitives(),
  });
}

// ── the suite ───────────────────────────────────────────────────────────────────────────────────

let app = null;

describe('W10b — device-policy persistence and the audit recorder (real MongoDB)', () => {
  beforeAll(async () => {
    // The namespace snapshot must be taken BEFORE this file's database exists.
    namespaceBefore = await serverDatabaseNames();

    await mongoose.connect(MONGO_URI);
    if (mongoose.connection.host !== MONGO_HOST || mongoose.connection.port !== MONGO_PORT) {
      throw new Error(
        `refusing to run: connected to ${mongoose.connection.host}:${mongoose.connection.port}, ` +
          `expected ${MONGO_HOST}:${MONGO_PORT}`,
      );
    }

    // Indexes: `syncIndexes()` builds every schema index on this fresh database. In production the
    // server gets them the same way without being asked — `api/db/index.js` runs `createModels()`
    // before connecting, and Mongoose's `autoIndex` (on unless `MONGO_AUTO_INDEX` turns it off)
    // builds every registered model's indexes on first connect.
    await mongoose.models.DeviceToolScope.syncIndexes();
    await mongoose.models.DevicePolicyAssignment.syncIndexes();
    await mongoose.models.DeviceTenantPolicyDefault.syncIndexes();
    await mongoose.models.AuditLog.syncIndexes();

    // The admin capability comes from the REAL seed: every SystemCapability granted to the ADMIN
    // role at platform scope, which is what the real server runs at startup.
    await db.seedSystemGrants();

    await mongoose.models.Role.create({ name: STAFF_ROLE });
    await mongoose.models.User.create({
      _id: new mongoose.Types.ObjectId(STAFF_ID),
      email: 'staff@example.test',
      name: 'Staffy',
      role: STAFF_ROLE,
      tenantId: TENANT_A,
    });
    await mongoose.models.User.create({
      _id: new mongoose.Types.ObjectId(OTHER_STAFF_ID),
      email: 'other@example.test',
      name: 'Other Staffy',
      role: STAFF_ROLE,
      tenantId: TENANT_B,
    });
    await mongoose.models.Group.create({
      name: 'Tenant A Staff',
      memberIds: [STAFF_ID],
      source: 'local',
      tenantId: TENANT_A,
    });

    app = express();
    app.use(express.json());
    app.use(BASE, router);
  }, 90000);

  afterAll(async () => {
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.dropDatabase();
      await mongoose.disconnect();
    }

    /**
     * The drop is repeated over a raw driver connection, and it is not redundant caution: the whole
     * point of this file is that it leaves the shared lab instance exactly as it found it, and a
     * mongoose-level failure (or a `beforeAll` that threw before the connection was usable) must not
     * be able to leave a database behind. Dropping a database that is already gone is a no-op.
     */
    const { MongoClient } = require('mongodb');
    const cleanup = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 15000 });
    await cleanup.connect();
    try {
      await cleanup.db(DB_NAME).dropDatabase();
    } catch (error) {
      if (error && error.codeName !== 'NamespaceNotFound') {
        throw error;
      }
    } finally {
      await cleanup.close();
    }

    namespaceAfter = await serverDatabaseNames();

    // The namespace check can only be made AFTER the drop, so it lives here. A leftover database is
    // a FAILURE of this file, not a note: the lab instance is shared and must be left as it was found.
    const created = namespaceAfter.filter((name) => !namespaceBefore.includes(name));
    const removed = namespaceBefore.filter((name) => !namespaceAfter.includes(name));
    expect(created).toEqual([]);
    expect(removed).toEqual([]);
    expect(namespaceAfter).toEqual(namespaceBefore);
    expect(namespaceAfter.some((name) => name.startsWith(DB_PREFIX))).toBe(false);
  }, 90000);

  // ── A. the seam is supplied ───────────────────────────────────────────────────────────────────

  describe('A. the storage seam is supplied by the real data layer', () => {
    it('binds all fifteen named methods as REAL functions, so nothing refuses', () => {
      const port = resolveDevicePolicyStorage(db);
      const refused = [];
      for (const method of DEVICE_POLICY_STORAGE_METHODS) {
        if (typeof port[method] !== 'function' || port[method] !== db[method]) {
          refused.push(method);
        }
      }
      expect(refused).toEqual([]);
      expect(DEVICE_POLICY_STORAGE_METHODS).toHaveLength(15);
    });

    it.each([...DEVICE_POLICY_STORAGE_METHODS])(
      'the data layer exposes "%s" as a function',
      (method) => {
        expect(typeof db[method]).toBe('function');
      },
    );

    it('NEGATIVE CONTROL: an empty data layer refuses all fifteen — this is the 503', async () => {
      const port = resolveDevicePolicyStorage({});
      const rejections = await Promise.all(
        DEVICE_POLICY_STORAGE_METHODS.map(async (method) => {
          try {
            await port[method]();
            return null;
          } catch (error) {
            return error && error.code === 'DEVICE_POLICY_STORAGE_UNAVAILABLE' ? method : null;
          }
        }),
      );
      expect(rejections.filter(Boolean)).toHaveLength(15);
    });

    it('exposes the GM-81 audit recorder, which is what opens the write path', () => {
      expect(typeof db.recordAuditEntry).toBe('function');
    });

    it('registers all six device_policy action names, and they are W10`s frozen list exactly', () => {
      expect([...AUDIT_LOG_DEVICE_POLICY_ACTIONS].sort()).toEqual(
        [...DEVICE_POLICY_AUDIT_ACTION_NAMES].sort(),
      );
      expect([...DEVICE_POLICY_AUDIT_ACTION_NAMES]).toHaveLength(6);
      for (const action of DEVICE_POLICY_AUDIT_ACTION_NAMES) {
        expect(AUDIT_LOG_ACTIONS).toContain(action);
      }
      // Upstream's own actions are carried too, so the rebase merges rather than forks.
      expect(AUDIT_LOG_ACTIONS).toContain('grant.assigned');
      expect(AUDIT_LOG_ACTIONS).toContain('grant.removed');
      expect(AUDIT_LOG_SCHEMA_VERSION).toBe(1);
    });

    it('ran against the required substrate: the lab MongoDB, in a prefixed, self-owned database', () => {
      expect(mongoose.connection.host).toBe(MONGO_HOST);
      expect(mongoose.connection.port).toBe(MONGO_PORT);
      expect(mongoose.connection.name).toBe(DB_NAME);
      expect(mongoose.connection.name.startsWith('cbhr_rdc_phase1_')).toBe(true);
      expect(MONGO_URI.startsWith(`mongodb://${MONGO_HOST}:${MONGO_PORT}/`)).toBe(true);
    });
  });

  // ── B. indexes: how a fresh database gets them ────────────────────────────────────────────────

  describe('B. the uniqueness constraints exist as REAL indexes on the server', () => {
    async function indexKeys(model) {
      const listed = await model.collection.indexes();
      return listed.map((index) => ({ key: index.key, unique: index.unique === true }));
    }

    it('devicetoolscopes: `id` unique, plus the tenant-scoped walk index', async () => {
      const indexes = await indexKeys(mongoose.models.DeviceToolScope);
      expect(indexes).toContainEqual({ key: { id: 1 }, unique: true });
      expect(indexes.some((index) => index.key.tenantId === 1 && index.key.id === 1)).toBe(true);
    });

    it('devicepolicyassignments: unique on (tenantId, principalType, principalId)', async () => {
      const indexes = await indexKeys(mongoose.models.DevicePolicyAssignment);
      expect(indexes).toContainEqual({
        key: { tenantId: 1, principalType: 1, principalId: 1 },
        unique: true,
      });
    });

    it('devicetenantpolicydefaults: unique on tenantId', async () => {
      const indexes = await indexKeys(mongoose.models.DeviceTenantPolicyDefault);
      expect(indexes).toContainEqual({ key: { tenantId: 1 }, unique: true });
    });

    it('adminauditlogs: unique on seq', async () => {
      const indexes = await indexKeys(mongoose.models.AuditLog);
      expect(indexes).toContainEqual({ key: { seq: 1 }, unique: true });
    });
  });

  // ── C. tool scopes ────────────────────────────────────────────────────────────────────────────

  describe('C. tool scopes: create / read / update / delete / list, with uniqueness', () => {
    const SCOPE = 'scope-crud';

    it('upsertToolScope CREATES and returns the stored row', async () => {
      const saved = await db.upsertToolScope(scopeDoc(SCOPE), { tenantId: TENANT_A });
      expect(saved.id).toBe(SCOPE);
      expect(saved.name).toBe(`Scope ${SCOPE}`);
      expect(saved.tools).toEqual([READ_FILE, READ_MULTIPLE, LIST_DIRECTORY]);
      expect(saved.stage).toBe('full');
      expect(saved.isActive).toBe(true);
      expect(saved.version).toBe(1);
      expect(saved.tenantId).toBe(TENANT_A);
      expect(saved.createdAt).toBeInstanceOf(Date);
    });

    it('getToolScope READS it back from the server', async () => {
      const found = await db.getToolScope(SCOPE, { tenantId: TENANT_A });
      expect(found).not.toBeNull();
      expect(found.name).toBe(`Scope ${SCOPE}`);
      expect([...found.tools]).toEqual([READ_FILE, READ_MULTIPLE, LIST_DIRECTORY]);
    });

    it('getToolScope returns null for an id that is not there', async () => {
      expect(await db.getToolScope('scope-not-there', { tenantId: TENANT_A })).toBeNull();
    });

    it('listScopes and countScopes answer for the tenant', async () => {
      const rows = await db.listScopes({ tenantId: TENANT_A });
      expect(rows.map((row) => row.id)).toContain(SCOPE);
      expect(await db.countScopes({ tenantId: TENANT_A })).toBe(rows.length);
    });

    it('listScopes honours limit and offset', async () => {
      await db.upsertToolScope(scopeDoc('scope-page-a'), { tenantId: TENANT_A });
      await db.upsertToolScope(scopeDoc('scope-page-b'), { tenantId: TENANT_A });
      const all = await db.listScopes({ tenantId: TENANT_A });
      const paged = await db.listScopes({ tenantId: TENANT_A, limit: 1, offset: 1 });
      expect(all.length).toBeGreaterThanOrEqual(3);
      expect(paged).toHaveLength(1);
      expect(paged[0].id).toBe(all[1].id);
    });

    it('upsertToolScope UPDATES in place: still one row, version bumped', async () => {
      const before = await db.getToolScope(SCOPE, { tenantId: TENANT_A });
      const countBefore = await db.countScopes({ tenantId: TENANT_A });
      const saved = await db.upsertToolScope(
        scopeDoc(SCOPE, { name: 'Renamed', tools: [READ_FILE], version: before.version + 1 }),
        { tenantId: TENANT_A },
      );
      expect(saved.name).toBe('Renamed');
      expect(saved.tools).toEqual([READ_FILE]);
      expect(saved.version).toBe(before.version + 1);
      expect(await db.countScopes({ tenantId: TENANT_A })).toBe(countBefore);
    });

    it('upsertToolScope twice for one id cannot produce two rows (the unique index)', async () => {
      await db.upsertToolScope(scopeDoc('scope-idempotent'), { tenantId: TENANT_A });
      await db.upsertToolScope(scopeDoc('scope-idempotent', { name: 'Second' }), {
        tenantId: TENANT_A,
      });
      const rows = await mongoose.models.DeviceToolScope.find({
        id: 'scope-idempotent',
        tenantId: TENANT_A,
      }).lean();
      expect(rows).toHaveLength(1);
      expect(rows[0].name).toBe('Second');
    });

    it('REJECTS a duplicate slug at the store, via the real unique index', async () => {
      await expect(mongoose.models.DeviceToolScope.create(scopeDoc(SCOPE))).rejects.toMatchObject({
        code: 11000,
      });
    });

    it('retiring a scope (isActive false) keeps the row', async () => {
      const retired = await db.upsertToolScope(
        scopeDoc(SCOPE, { isActive: false, tools: [READ_FILE], version: 5 }),
        { tenantId: TENANT_A },
      );
      expect(retired.isActive).toBe(false);
      expect(await db.getToolScope(SCOPE, { tenantId: TENANT_A })).not.toBeNull();
    });

    it('deleteToolScope REMOVES it and returns the row that was removed', async () => {
      const removed = await db.deleteToolScope('scope-page-a', { tenantId: TENANT_A });
      expect(removed).not.toBeNull();
      expect(removed.id).toBe('scope-page-a');
      expect(await db.getToolScope('scope-page-a', { tenantId: TENANT_A })).toBeNull();
    });

    it('deleteToolScope returns null when there was nothing to remove', async () => {
      expect(await db.deleteToolScope('scope-never-existed', { tenantId: TENANT_A })).toBeNull();
    });
  });

  // ── D. assignments ────────────────────────────────────────────────────────────────────────────

  describe('D. assignments: create / read / update / delete / list, with uniqueness', () => {
    const ASSIGNED_SCOPE = 'scope-assigned';

    beforeAll(async () => {
      await db.upsertToolScope(scopeDoc(ASSIGNED_SCOPE), { tenantId: TENANT_A });
    });

    it('upsertAssignment CREATES and returns the stored row', async () => {
      const saved = await db.upsertAssignment(
        {
          principalType: 'role',
          principalId: STAFF_ROLE,
          toolScopeId: ASSIGNED_SCOPE,
          priority: 5,
          isActive: true,
        },
        { tenantId: TENANT_A },
      );
      expect(saved.principalType).toBe('role');
      expect(saved.principalId).toBe(STAFF_ROLE);
      expect(saved.toolScopeId).toBe(ASSIGNED_SCOPE);
      expect(saved.priority).toBe(5);
      expect(saved.tenantId).toBe(TENANT_A);
    });

    it('getAssignment READS it back', async () => {
      const found = await db.getAssignment('role', STAFF_ROLE, { tenantId: TENANT_A });
      expect(found).not.toBeNull();
      expect(found.toolScopeId).toBe(ASSIGNED_SCOPE);
    });

    it('getAssignment returns null for a principal that has none', async () => {
      expect(await db.getAssignment('role', 'NOBODY', { tenantId: TENANT_A })).toBeNull();
    });

    it('listAssignments answers, and narrows by principal', async () => {
      const all = await db.listAssignments({ tenantId: TENANT_A });
      expect(all.length).toBeGreaterThanOrEqual(1);
      const narrowed = await db.listAssignments({
        tenantId: TENANT_A,
        principalType: 'role',
        principalId: STAFF_ROLE,
      });
      expect(narrowed).toHaveLength(1);
      expect(
        await db.listAssignments({
          tenantId: TENANT_A,
          principalType: 'user',
          principalId: OTHER_STAFF_ID,
        }),
      ).toEqual([]);
    });

    it('upsertAssignment UPDATES in place: one row, new scope, new priority', async () => {
      await db.upsertToolScope(scopeDoc('scope-assigned-2'), { tenantId: TENANT_A });
      const saved = await db.upsertAssignment(
        {
          principalType: 'role',
          principalId: STAFF_ROLE,
          toolScopeId: 'scope-assigned-2',
          priority: 9,
        },
        { tenantId: TENANT_A },
      );
      expect(saved.toolScopeId).toBe('scope-assigned-2');
      expect(saved.priority).toBe(9);
      const rows = await mongoose.models.DevicePolicyAssignment.find({
        tenantId: TENANT_A,
        principalType: 'role',
        principalId: STAFF_ROLE,
      }).lean();
      expect(rows).toHaveLength(1);
    });

    it('REJECTS a second assignment for the same principal in the same tenant', async () => {
      await expect(
        mongoose.models.DevicePolicyAssignment.create({
          principalType: 'role',
          principalId: STAFF_ROLE,
          toolScopeId: ASSIGNED_SCOPE,
          priority: 1,
          isActive: true,
          tenantId: TENANT_A,
        }),
      ).rejects.toMatchObject({ code: 11000 });
    });

    it('the SAME principal may hold a different assignment in a different tenant', async () => {
      const saved = await db.upsertAssignment(
        { principalType: 'role', principalId: STAFF_ROLE, toolScopeId: ASSIGNED_SCOPE },
        { tenantId: TENANT_B },
      );
      expect(saved.tenantId).toBe(TENANT_B);
      const a = await db.getAssignment('role', STAFF_ROLE, { tenantId: TENANT_A });
      expect(a.toolScopeId).toBe('scope-assigned-2');
    });

    it('deleteAssignment REMOVES it and returns the row', async () => {
      const removed = await db.deleteAssignment('role', STAFF_ROLE, { tenantId: TENANT_A });
      expect(removed).not.toBeNull();
      expect(removed.toolScopeId).toBe('scope-assigned-2');
      expect(await db.getAssignment('role', STAFF_ROLE, { tenantId: TENANT_A })).toBeNull();
    });

    it('deleteAssignment returns null when there was nothing to remove', async () => {
      expect(await db.deleteAssignment('role', 'NOBODY', { tenantId: TENANT_A })).toBeNull();
    });
  });

  // ── E. the tenant default ─────────────────────────────────────────────────────────────────────

  describe('E. the tenant default: create / read / update, with uniqueness', () => {
    const DEFAULT_SCOPE = 'scope-tenant-default';

    beforeAll(async () => {
      await db.upsertToolScope(scopeDoc(DEFAULT_SCOPE), { tenantId: TENANT_A });
    });

    it('getTenantDefault returns null when the tenant has none — the fail-closed floor', async () => {
      expect(await db.getTenantDefault({ tenantId: 'tenant-with-no-default' })).toBeNull();
    });

    it('upsertTenantDefault CREATES with version 1', async () => {
      const saved = await db.upsertTenantDefault(
        { defaultToolScopeId: DEFAULT_SCOPE },
        { tenantId: TENANT_A },
      );
      expect(saved.defaultToolScopeId).toBe(DEFAULT_SCOPE);
      expect(saved.version).toBe(1);
      expect(saved.tenantId).toBe(TENANT_A);
      expect(saved.updatedAt).toBeInstanceOf(Date);
    });

    it('getTenantDefault READS it back', async () => {
      const found = await db.getTenantDefault({ tenantId: TENANT_A });
      expect(found.defaultToolScopeId).toBe(DEFAULT_SCOPE);
    });

    it('upsertTenantDefault UPDATES in place and BUMPS the version atomically', async () => {
      await db.upsertToolScope(scopeDoc('scope-tenant-default-2'), { tenantId: TENANT_A });
      const saved = await db.upsertTenantDefault(
        { defaultToolScopeId: 'scope-tenant-default-2' },
        { tenantId: TENANT_A },
      );
      expect(saved.defaultToolScopeId).toBe('scope-tenant-default-2');
      expect(saved.version).toBe(2);
      const rows = await mongoose.models.DeviceTenantPolicyDefault.find({
        tenantId: TENANT_A,
      }).lean();
      expect(rows).toHaveLength(1);
    });

    it('REJECTS a second default document for the same tenant', async () => {
      await expect(
        mongoose.models.DeviceTenantPolicyDefault.create({
          tenantId: TENANT_A,
          defaultToolScopeId: DEFAULT_SCOPE,
          version: 1,
        }),
      ).rejects.toMatchObject({ code: 11000 });
    });

    it('the PLATFORM default (no tenant) is its own document, not the tenant`s', async () => {
      const platform = await db.upsertTenantDefault({ defaultToolScopeId: DEFAULT_SCOPE }, {});
      expect(platform.tenantId).toBeNull();
      const second = await db.upsertTenantDefault({ defaultToolScopeId: DEFAULT_SCOPE }, {});
      expect(second.version).toBe(2);
      // …and the tenant's own default was not touched by either platform write.
      const tenantDefault = await db.getTenantDefault({ tenantId: TENANT_A });
      expect(tenantDefault.version).toBe(2);
      expect(String(platform._id)).not.toBe(String(tenantDefault._id));
    });
  });

  // ── F. the audit recorder ─────────────────────────────────────────────────────────────────────

  describe('F. recordAuditEntry: a real, append-only, hash-chained entry', () => {
    const BEFORE_SNAPSHOT = {
      snapshotType: 'device-tool-scope',
      id: 'scope-audit',
      version: null,
      capturedAt: '2026-10-23T00:00:00.000Z',
      body: null,
    };
    const AFTER_SNAPSHOT = {
      snapshotType: 'device-tool-scope',
      id: 'scope-audit',
      version: 1,
      capturedAt: '2026-10-23T00:00:00.000Z',
      body: '{"id":"scope-audit","name":"Scope scope-audit"}',
    };

    function entryInput(action, overrides = {}) {
      return {
        action,
        category: 'config',
        actor: { type: 'user', id: ADMIN_ID, name: 'Root Admin' },
        target: { type: 'device_policy', id: 'scope-audit', name: 'Scope scope-audit' },
        metadata: {
          actor: 'Root Admin',
          subject: 'Scope scope-audit',
          before: BEFORE_SNAPSHOT,
          after: AFTER_SNAPSHOT,
          fingerprint: 'abc123',
          changedFields: ['id', 'name'],
        },
        ...overrides,
      };
    }

    it('writes an entry and returns it, with actor, target, category, outcome and tenant', async () => {
      const written = await db.recordAuditEntry(
        entryInput('device_policy.scope_created', { tenantId: TENANT_A }),
      );
      expect(written).not.toBeNull();
      expect(written.action).toBe('device_policy.scope_created');
      expect(written.category).toBe('config');
      expect(written.outcome).toBe('success');
      expect(written.severity).toBe('info');
      expect(written.actor.type).toBe('user');
      expect(written.actor.id).toBe(ADMIN_ID);
      expect(written.actor.name).toBe('Root Admin');
      expect(written.target.type).toBe('device_policy');
      expect(written.target.id).toBe('scope-audit');
      expect(written.tenantId).toBe(TENANT_A);
      expect(written.schemaVersion).toBe(1);
    });

    it('is READABLE BACK from the store, before/after payload intact', async () => {
      const found = (await auditEntries()).find(
        (entry) => entry.action === 'device_policy.scope_created',
      );
      expect(found).toBeDefined();
      expect(found.metadata.before).toEqual(BEFORE_SNAPSHOT);
      expect(found.metadata.after).toEqual(AFTER_SNAPSHOT);
      expect(found.metadata.fingerprint).toBe('abc123');
      expect(found.metadata.changedFields).toEqual(['id', 'name']);
    });

    it('reserves a sequence from 1 and CHAINS each entry to its predecessor', async () => {
      await db.recordAuditEntry(entryInput('device_policy.scope_updated', { tenantId: TENANT_A }));
      await db.recordAuditEntry(entryInput('device_policy.scope_deleted', { tenantId: TENANT_A }));
      const entries = await auditEntries();
      expect(entries.length).toBeGreaterThanOrEqual(3);
      // No append has failed yet in this file, so the sequence is contiguous from 1. The fail-closed
      // tests below break that contiguity on purpose; the rule that survives is `expectChainIntact`.
      entries.forEach((entry, index) => {
        expect(entry.seq).toBe(index + 1);
      });
      expectChainIntact(entries);
    });

    it('every stored entry`s hash is a function of its own content — and tampering breaks it', async () => {
      const entries = await auditEntries();
      for (const entry of entries) {
        expect(typeof entry.hash).toBe('string');
        expect(entry.hash).toBe(computeAuditEntryHash(entry));
      }
      const target = entries[0];
      expect(computeAuditEntryHash({ ...target, action: 'device_policy.scope_deleted' })).not.toBe(
        target.hash,
      );
      expect(computeAuditEntryHash({ ...target, seq: target.seq + 1 })).not.toBe(target.hash);
      expect(computeAuditEntryHash({ ...target, prevHash: 'deadbeef' })).not.toBe(target.hash);
    });

    it('the timestamp is the WRITER`s, so it is inside the hash (a caller cannot supply one)', async () => {
      const forged = await db.recordAuditEntry(
        entryInput('device_policy.assignment_set', {
          tenantId: TENANT_A,
          createdAt: new Date('1999-01-01T00:00:00.000Z'),
        }),
      );
      expect(forged.createdAt.getUTCFullYear()).toBeGreaterThan(2000);
      expect(forged.hash).toBe(computeAuditEntryHash(forged));
    });

    it('REFUSES an action that is not in the registry', async () => {
      await expect(
        db.recordAuditEntry(entryInput('device_policy.not_a_real_action')),
      ).rejects.toThrow(/not registered/);
    });

    it('REFUSES a malformed actor or target', async () => {
      await expect(
        db.recordAuditEntry(entryInput('device_policy.scope_created', { actor: { type: 'user' } })),
      ).rejects.toThrow(/actor\.name/);
      await expect(
        db.recordAuditEntry(entryInput('device_policy.scope_created', { target: {} })),
      ).rejects.toThrow(/target\.type/);
    });

    it('FAILS CLOSED by default: a store failure is an error, not a silent skip', async () => {
      const original = mongoose.models.AuditLog.create;
      mongoose.models.AuditLog.create = async () => {
        throw new Error('injected audit-store failure');
      };
      try {
        await expect(
          db.recordAuditEntry(entryInput('device_policy.scope_created', { tenantId: TENANT_A })),
        ).rejects.toMatchObject({ code: 'AUDIT_LOG_WRITE_FAILED' });
        await expect(
          db.recordAuditEntry(entryInput('device_policy.scope_created', { tenantId: TENANT_A }), {
            failClosed: true,
          }),
        ).rejects.toMatchObject({ code: 'AUDIT_LOG_WRITE_FAILED' });
      } finally {
        mongoose.models.AuditLog.create = original;
      }
    });

    it('`failClosed: false` is the only way to skip, and it returns null with no entry', async () => {
      const original = mongoose.models.AuditLog.create;
      const before = (await auditEntries()).length;
      mongoose.models.AuditLog.create = async () => {
        throw new Error('injected audit-store failure');
      };
      try {
        const result = await db.recordAuditEntry(
          entryInput('device_policy.scope_created', { tenantId: TENANT_A }),
          { failClosed: false },
        );
        expect(result).toBeNull();
      } finally {
        mongoose.models.AuditLog.create = original;
      }
      expect((await auditEntries()).length).toBe(before);
    });

    it('is APPEND-ONLY: the mutation operators are refused through the model', async () => {
      const entries = await auditEntries();
      const entry = entries[0];
      await expect(
        mongoose.models.AuditLog.updateOne({ seq: entry.seq }, { $set: { action: 'x' } }),
      ).rejects.toThrow(/append-only/);
      await expect(mongoose.models.AuditLog.deleteMany({})).rejects.toThrow(/append-only/);
      await expect(
        mongoose.models.AuditLog.findOneAndDelete({ seq: entry.seq }),
      ).rejects.toThrow(/append-only/);
      // …and every entry is still there, unedited.
      const after = await auditEntries();
      expect(after).toHaveLength(entries.length);
      expect(after[0].action).toBe(entry.action);
      expect(after[0].hash).toBe(entry.hash);
    });

    it('REJECTS a duplicate sequence number at the store (the chain cannot fork)', async () => {
      const entry = (await auditEntries())[0];
      await expect(
        mongoose.models.AuditLog.create([
          {
            schemaVersion: 1,
            seq: entry.seq,
            prevHash: null,
            hash: 'duplicate',
            action: 'device_policy.scope_created',
            category: 'config',
            outcome: 'success',
            severity: 'info',
            actor: { type: 'user', name: 'Someone' },
            target: { type: 'device_policy' },
            createdAt: new Date(),
          },
        ]),
      ).rejects.toMatchObject({ code: 11000 });
    });
  });

  // ── G. the resolution walk ────────────────────────────────────────────────────────────────────

  describe('G. the resolution walk end-to-end, through W10`s real resolver and the real store', () => {
    const WALK_TENANT = 'tenant-walk';
    const WALK_USER = '64b7f0c2f1a2b3c4d5e6f7c1';
    const WALK_GROUP = '64b7f0c2f1a2b3c4d5e6f7c2';
    const WALK_ROLE = 'WALKER';

    const SCOPES = {
      tenant: ['walk-tenant', [READ_FILE, READ_MULTIPLE, LIST_DIRECTORY]],
      role: ['walk-role', [READ_FILE, READ_MULTIPLE]],
      group: ['walk-group', [READ_FILE]],
      user: ['walk-user', [LIST_DIRECTORY]],
    };

    async function setAssignment(principalType, principalId, toolScopeId) {
      return db.upsertAssignment(
        { principalType, principalId, toolScopeId, isActive: true },
        { tenantId: WALK_TENANT },
      );
    }

    beforeAll(async () => {
      for (const [scopeId, tools] of Object.values(SCOPES)) {
        await db.upsertToolScope(scopeDoc(scopeId, { tools }), { tenantId: WALK_TENANT });
      }
      await mongoose.models.User.create({
        _id: new mongoose.Types.ObjectId(WALK_USER),
        email: 'walker@example.test',
        name: 'Walker',
        role: WALK_ROLE,
        tenantId: WALK_TENANT,
      });
      await mongoose.models.Group.create({
        _id: new mongoose.Types.ObjectId(WALK_GROUP),
        name: 'Walkers',
        memberIds: [WALK_USER],
        source: 'local',
        tenantId: WALK_TENANT,
      });
    });

    const principal = () => ({
      userId: WALK_USER,
      role: WALK_ROLE,
      groupIds: [WALK_GROUP],
      tenantId: WALK_TENANT,
    });

    it('FAILS CLOSED with no policy at all: nothing is enabled', async () => {
      const resolution = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      expect(resolution.failClosed).toBe(true);
      expect(resolution.tools).toEqual([]);
      expect(resolution.governingLevel).toBeNull();
      expect(resolution.resolvedToolScopeId).toBeNull();
      expect(resolution.decisions.every((row) => row.enabled === false)).toBe(true);
    });

    it('the TENANT DEFAULT answers at the tenant level', async () => {
      await db.upsertTenantDefault({ defaultToolScopeId: SCOPES.tenant[0] }, {
        tenantId: WALK_TENANT,
      });
      const resolution = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      expect(resolution.governingLevel).toBe('tenant');
      expect(resolution.resolvedToolScopeId).toBe(SCOPES.tenant[0]);
      expect(new Set(resolution.tools)).toEqual(new Set(SCOPES.tenant[1]));
    });

    it('a ROLE assignment NARROWS the tenant default — first match wins, it is not a union', async () => {
      await setAssignment('role', WALK_ROLE, SCOPES.role[0]);
      const resolution = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      expect(resolution.governingLevel).toBe('role');
      expect(resolution.resolvedToolScopeId).toBe(SCOPES.role[0]);
      expect(new Set(resolution.tools)).toEqual(new Set(SCOPES.role[1]));
      // The decisive part: the tenant scope's extra tool did NOT come along for the ride.
      expect(resolution.tools).not.toContain(LIST_DIRECTORY);
    });

    it('a GROUP assignment NARROWS the role', async () => {
      await setAssignment('group', WALK_GROUP, SCOPES.group[0]);
      const resolution = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      expect(resolution.governingLevel).toBe('group');
      expect(resolution.resolvedToolScopeId).toBe(SCOPES.group[0]);
      expect(new Set(resolution.tools)).toEqual(new Set(SCOPES.group[1]));
      expect(resolution.tools).not.toContain(READ_MULTIPLE);
    });

    it('a USER assignment NARROWS the group, and the group`s tools do not leak through', async () => {
      await setAssignment('user', WALK_USER, SCOPES.user[0]);
      const resolution = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      expect(resolution.governingLevel).toBe('user');
      expect(resolution.resolvedToolScopeId).toBe(SCOPES.user[0]);
      expect(new Set(resolution.tools)).toEqual(new Set(SCOPES.user[1]));
      expect(resolution.tools).not.toContain(READ_FILE);
    });

    it('every level is reported in the trace, in resolution order, with one winner', async () => {
      const resolution = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      expect(resolution.trace.map((row) => row.level)).toEqual(['user', 'group', 'role', 'tenant']);
      expect(resolution.trace[0].outcome).toBe('selected');
      expect(resolution.trace[0].toolScopeId).toBe(SCOPES.user[0]);
      expect(resolution.trace.filter((row) => row.outcome === 'selected')).toHaveLength(1);
    });

    it('a DANGLING scope at a narrow level STOPS the walk instead of falling through', async () => {
      await setAssignment('user', WALK_USER, 'walk-does-not-exist');
      const resolution = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      expect(resolution.failClosed).toBe(true);
      expect(resolution.tools).toEqual([]);
      expect(resolution.trace.find((row) => row.level === 'user').outcome).toBe('scope-missing');
      expect(resolution.trace.find((row) => row.level === 'tenant').outcome).not.toBe('selected');
      await setAssignment('user', WALK_USER, SCOPES.user[0]);
    });

    it('an INACTIVE scope enables nothing (retiring a scope is a downgrade, not a fallback)', async () => {
      await db.upsertToolScope(scopeDoc('walk-retired', { tools: [READ_FILE], isActive: false }), {
        tenantId: WALK_TENANT,
      });
      await setAssignment('user', WALK_USER, 'walk-retired');
      const resolution = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      expect(resolution.tools).toEqual([]);
      expect(resolution.trace.find((row) => row.level === 'user').outcome).toBe('scope-inactive');
      await setAssignment('user', WALK_USER, SCOPES.user[0]);
    });

    it('no enabled tool is ever outside the winning scope or outside the catalog', async () => {
      const resolution = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      expect(resolution.governingLevel).toBe('user');
      const winning = await db.getToolScope(resolution.resolvedToolScopeId, {
        tenantId: WALK_TENANT,
      });
      expect(resolution.tools.length).toBeGreaterThan(0);
      for (const tool of resolution.tools) {
        expect(CATALOG_TOOL_NAMES).toContain(tool);
        expect([...winning.tools]).toContain(tool);
      }
    });

    it('GM-79 rule 3: no request field can widen it — there is no parameter to reach', async () => {
      const plain = await resolveFromStore(principal(), { tenantId: WALK_TENANT });
      const widened = await resolveFromStore(
        {
          ...principal(),
          tools: CATALOG_TOOL_NAMES,
          enabled: CATALOG_TOOL_NAMES,
          ceiling: { schema: 'cbhr.rdc.capability-ceiling/1', tools: CATALOG_TOOL_NAMES },
          policyVersion: 'forged',
          toolScopeId: SCOPES.tenant[0],
          stage: 'full',
          pilot: false,
        },
        { tenantId: WALK_TENANT },
      );
      expect(widened.governingLevel).toBe(plain.governingLevel);
      expect(widened.resolvedToolScopeId).toBe(plain.resolvedToolScopeId);
      expect([...widened.tools]).toEqual([...plain.tools]);
      expect(widened.tools).not.toContain(READ_FILE);
    });
  });

  // ── H. tenant isolation ───────────────────────────────────────────────────────────────────────

  describe('H. tenant isolation: tenant B cannot read or affect tenant A`s policy', () => {
    beforeAll(async () => {
      await db.upsertToolScope(scopeDoc(SCOPE_A, { name: 'A only', tools: [READ_FILE] }), {
        tenantId: TENANT_A,
      });
      await db.upsertToolScope(scopeDoc(SCOPE_B, { name: 'B only', tools: [] }), {
        tenantId: TENANT_B,
      });
      await db.upsertAssignment(
        { principalType: 'role', principalId: STAFF_ROLE, toolScopeId: SCOPE_A },
        { tenantId: TENANT_A },
      );
      await db.upsertAssignment(
        { principalType: 'role', principalId: STAFF_ROLE, toolScopeId: SCOPE_B },
        { tenantId: TENANT_B },
      );
      await db.upsertTenantDefault({ defaultToolScopeId: SCOPE_A }, { tenantId: TENANT_A });
      await db.upsertTenantDefault({ defaultToolScopeId: SCOPE_B }, { tenantId: TENANT_B });
    });

    it('a scope in tenant A is NOT FOUND from tenant B', async () => {
      expect(await db.getToolScope(SCOPE_A, { tenantId: TENANT_B })).toBeNull();
      expect(await db.getToolScope(SCOPE_B, { tenantId: TENANT_A })).toBeNull();
    });

    it('the lists and the tenant default are each tenant-scoped', async () => {
      const aScopes = (await db.listScopes({ tenantId: TENANT_A })).map((row) => row.id);
      const bScopes = (await db.listScopes({ tenantId: TENANT_B })).map((row) => row.id);
      expect(aScopes).toContain(SCOPE_A);
      expect(aScopes).not.toContain(SCOPE_B);
      expect(bScopes).toContain(SCOPE_B);
      expect(bScopes).not.toContain(SCOPE_A);

      const aAssignments = await db.listAssignments({ tenantId: TENANT_A });
      expect(aAssignments.every((row) => row.tenantId === TENANT_A)).toBe(true);
      expect(aAssignments.map((row) => row.toolScopeId)).not.toContain(SCOPE_B);

      expect((await db.getTenantDefault({ tenantId: TENANT_A })).defaultToolScopeId).toBe(SCOPE_A);
      expect((await db.getTenantDefault({ tenantId: TENANT_B })).defaultToolScopeId).toBe(SCOPE_B);
    });

    it('a delete from tenant B leaves tenant A`s row untouched', async () => {
      expect(await db.deleteToolScope(SCOPE_A, { tenantId: TENANT_B })).toBeNull();
      const stillThere = await db.getToolScope(SCOPE_A, { tenantId: TENANT_A });
      expect(stillThere).not.toBeNull();
      expect(stillThere.name).toBe('A only');
    });

    it('a write from tenant B cannot change tenant A`s row (the slug is global)', async () => {
      const before = await db.getToolScope(SCOPE_A, { tenantId: TENANT_A });
      await expect(
        db.upsertToolScope(scopeDoc(SCOPE_A, { name: 'Hijacked' }), { tenantId: TENANT_B }),
      ).rejects.toMatchObject({ code: 11000 });
      const after = await db.getToolScope(SCOPE_A, { tenantId: TENANT_A });
      expect(after.name).toBe(before.name);
      expect(after.version).toBe(before.version);
    });

    it('a delete from a tenant that is not B`s cannot remove B`s assignment', async () => {
      expect(await db.deleteAssignment('role', STAFF_ROLE, { tenantId: 'tenant-c' })).toBeNull();
      expect((await db.getAssignment('role', STAFF_ROLE, { tenantId: TENANT_A })).toolScopeId).toBe(
        SCOPE_A,
      );
      expect((await db.getAssignment('role', STAFF_ROLE, { tenantId: TENANT_B })).toolScopeId).toBe(
        SCOPE_B,
      );
    });

    it('an audit entry records the tenant it was made in', async () => {
      const written = await db.recordAuditEntry({
        action: 'device_policy.tenant_default_set',
        actor: { type: 'user', id: ADMIN_ID, name: 'Root Admin' },
        target: { type: 'device_policy', id: TENANT_B, name: 'tenant-device-policy-default' },
        metadata: { before: null, after: null },
        tenantId: TENANT_B,
      });
      const readBack = (await auditEntries()).find((entry) => entry.seq === written.seq);
      expect(readBack.tenantId).toBe(TENANT_B);
    });

    it('tenant B`s principal resolves from B`s OWN policy, and gains nothing from A`s', async () => {
      const resolution = await resolveFromStore(
        { userId: STAFF_ID, role: STAFF_ROLE, groupIds: [], tenantId: TENANT_B },
        { tenantId: TENANT_B },
      );
      expect(resolution.resolvedToolScopeId).toBe(SCOPE_B);
      // B's scope grants nothing, and A's grant of `read_file` did not reach across.
      expect(resolution.tools).toEqual([]);
      expect(resolution.tools).not.toContain(READ_FILE);
    });
  });

  // ── I. THE ACCEPTANCE: 200, not 503 ───────────────────────────────────────────────────────────

  describe('I. the route answers 200 on reads and writes now that the store and recorder are wired', () => {
    let createdScopeId = null;

    beforeAll(() => {
      mockSession = ADMIN_SESSION;
    });

    it('the admin session holds the capabilities the route gates on (from the real store)', async () => {
      const principals = await db.getUserPrincipals({ userId: ADMIN_ID, role: 'ADMIN' });
      for (const capability of [
        SystemCapabilities.ACCESS_ADMIN,
        SystemCapabilities.READ_CONFIGS,
        SystemCapabilities.MANAGE_CONFIGS,
      ]) {
        await expect(
          db.hasCapabilityForPrincipals({ principals, capability, tenantId: TENANT_A }),
        ).resolves.toBe(true);
      }
    });

    it('GET /scopes is 200 (it was 503 while the storage seam was unwired)', async () => {
      const res = await request(app).get(`${BASE}/scopes`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.scopes)).toBe(true);
      expect(typeof res.body.total).toBe('number');
      expect(res.body.total).toBeGreaterThan(0);
    });

    it('POST /scopes is 201, and the row is really in the store', async () => {
      createdScopeId = uniqueId('route-scope');
      const res = await request(app)
        .post(`${BASE}/scopes`)
        .send({
          id: createdScopeId,
          name: 'Route created',
          description: 'written through the real route',
          tools: [READ_FILE],
          stage: 'full',
        });
      expect(res.status).toBe(201);
      expect(res.body.scope.id).toBe(createdScopeId);
      const stored = await db.getToolScope(createdScopeId, { tenantId: TENANT_A });
      expect(stored).not.toBeNull();
      expect(stored.name).toBe('Route created');
      expect(stored.version).toBe(1);
    });

    it('GET /scopes/:scopeId is 200 and returns the stored scope', async () => {
      const res = await request(app).get(`${BASE}/scopes/${createdScopeId}`);
      expect(res.status).toBe(200);
      expect(res.body.scope.id).toBe(createdScopeId);
      expect(res.body.scope.tools).toEqual([READ_FILE]);
    });

    it('PUT /scopes/:scopeId is 200 and the change is durable', async () => {
      const res = await request(app)
        .put(`${BASE}/scopes/${createdScopeId}`)
        .send({ name: 'Route updated', tools: [READ_FILE, READ_MULTIPLE], stage: 'full' });
      expect(res.status).toBe(200);
      expect(res.body.scope.version).toBe(2);
      const stored = await db.getToolScope(createdScopeId, { tenantId: TENANT_A });
      expect(stored.name).toBe('Route updated');
      expect([...stored.tools]).toEqual([READ_FILE, READ_MULTIPLE]);
    });

    it('GET /assignments, PUT /assignments and DELETE are 200/201 — never 503', async () => {
      const list = await request(app).get(`${BASE}/assignments`);
      expect(list.status).toBe(200);

      const put = await request(app).put(`${BASE}/assignments`).send({
        principalType: 'user',
        principalId: STAFF_ID,
        toolScopeId: createdScopeId,
        priority: 3,
      });
      expect([200, 201]).toContain(put.status);
      expect(put.body.assignment.toolScopeId).toBe(createdScopeId);
      expect(await db.getAssignment('user', STAFF_ID, { tenantId: TENANT_A })).not.toBeNull();

      const again = await request(app)
        .put(`${BASE}/assignments`)
        .send({ principalType: 'user', principalId: STAFF_ID, toolScopeId: createdScopeId });
      expect(again.status).toBe(200);
      expect(again.body.created).toBe(false);

      const removed = await request(app).delete(`${BASE}/assignments/user/${STAFF_ID}`);
      expect(removed.status).toBe(200);
      expect(await db.getAssignment('user', STAFF_ID, { tenantId: TENANT_A })).toBeNull();
    });

    it('GET and PUT /tenant-default are 200', async () => {
      const read = await request(app).get(`${BASE}/tenant-default`);
      expect(read.status).toBe(200);

      const put = await request(app)
        .put(`${BASE}/tenant-default`)
        .send({ defaultToolScopeId: createdScopeId });
      expect(put.status).toBe(200);
      expect(put.body.tenantDefault.defaultToolScopeId).toBe(createdScopeId);
      expect((await db.getTenantDefault({ tenantId: TENANT_A })).defaultToolScopeId).toBe(
        createdScopeId,
      );
    });

    it('resolve-self and resolve-for-principal are 200, computed from the real store', async () => {
      const self = await request(app).get(`${BASE}/resolve-self`);
      expect(self.status).toBe(200);
      // The admin holds no assignment, so the TENANT DEFAULT answers — the store's own answer.
      const tenantDefault = await db.getTenantDefault({ tenantId: TENANT_A });
      expect(self.body.resolution.resolvedToolScopeId).toBe(tenantDefault.defaultToolScopeId);
      expect(self.body.resolution.governingLevel).toBe('tenant');
      expect(self.body.resolution.failClosed).toBe(false);

      const forPrincipal = await request(app).get(`${BASE}/resolve-for-principal/${STAFF_ID}`);
      expect(forPrincipal.status).toBe(200);
      expect(forPrincipal.body.userId).toBe(STAFF_ID);
      // Staff's ROLE assignment (seeded in H) is more specific than the tenant default.
      const roleAssignment = await db.getAssignment('role', STAFF_ROLE, { tenantId: TENANT_A });
      expect(forPrincipal.body.resolution.resolvedToolScopeId).toBe(roleAssignment.toolScopeId);
      expect(forPrincipal.body.resolution.governingLevel).toBe('role');
    });

    it('DELETE /scopes/:scopeId is 200 once nothing references it', async () => {
      // Move the tenant default off the scope under test so the reference check passes.
      const moved = await request(app)
        .put(`${BASE}/tenant-default`)
        .send({ defaultToolScopeId: SCOPE_A });
      expect(moved.status).toBe(200);

      const removed = await request(app).delete(`${BASE}/scopes/${createdScopeId}`);
      expect(removed.status).toBe(200);
      expect(await db.getToolScope(createdScopeId, { tenantId: TENANT_A })).toBeNull();
    });

    it('EVERY write left its audit entry, with actor and before/after, read back from the store', async () => {
      const entries = await auditEntries();
      const byAction = (action) => entries.filter((entry) => entry.action === action);
      /** The route's own entries for the scope under test — never the synthetic ones from section F. */
      const forScope = (action) =>
        entries.filter((entry) => entry.action === action && entry.target.id === createdScopeId);

      expect(byAction('device_policy.assignment_set').length).toBeGreaterThanOrEqual(2);
      expect(byAction('device_policy.assignment_removed').length).toBeGreaterThanOrEqual(1);
      expect(byAction('device_policy.tenant_default_set').length).toBeGreaterThanOrEqual(3);

      const created = forScope('device_policy.scope_created')[0];
      expect(created).toBeDefined();
      expect(created.actor.id).toBe(ADMIN_ID);
      expect(created.actor.name).toBe('Root Admin');
      expect(created.tenantId).toBe(TENANT_A);
      expect(created.category).toBe('config');
      expect(created.target.type).toBe('device_policy');
      expect(created.metadata.actor).toBe('Root Admin');
      // A creation: nothing before, the new document after.
      expect(created.metadata.before.body).toBeNull();
      expect(created.metadata.after.body).toContain(createdScopeId);
      expect(created.metadata.changedFields).toContain('name');
      expect(created.metadata.fingerprint).toEqual(expect.any(String));

      const updated = forScope('device_policy.scope_updated')[0];
      expect(updated).toBeDefined();
      expect(updated.metadata.before.body).not.toBeNull();
      expect(updated.metadata.after.body).not.toBeNull();
      expect(updated.metadata.before.body).not.toBe(updated.metadata.after.body);
      expect(updated.metadata.changedFields).toContain('name');

      const deleted = forScope('device_policy.scope_deleted')[0];
      expect(deleted).toBeDefined();
      expect(deleted.metadata.before.body).not.toBeNull();
      expect(deleted.metadata.after.body).toBeNull();

      // The whole chain verifies end to end, in the store.
      expectChainIntact(entries);
    });

    it('a READ that names a scope belonging to another tenant is 404, not a leak', async () => {
      mockSession = { ...ADMIN_SESSION, tenantId: TENANT_B };
      let res;
      try {
        res = await request(app).get(`${BASE}/scopes/${SCOPE_A}`);
      } finally {
        mockSession = ADMIN_SESSION;
      }
      // Wait — SCOPE_A belongs to TENANT_A, and the session is in TENANT_B.
      expect(res.status).toBe(404);
    });

    it('resolve-for-principal for a user in another tenant is 403', async () => {
      mockSession = { ...ADMIN_SESSION, tenantId: TENANT_B };
      let res;
      try {
        res = await request(app).get(`${BASE}/resolve-for-principal/${STAFF_ID}`);
      } finally {
        mockSession = ADMIN_SESSION;
      }
      expect(res.status).toBe(403);
    });

    it('a tenant B session is NOT affected by tenant A`s policy at all', async () => {
      mockSession = { id: OTHER_STAFF_ID, role: STAFF_ROLE, name: 'Other Staffy', tenantId: TENANT_B };
      let res;
      try {
        res = await request(app).get(`${BASE}/resolve-self`);
      } finally {
        mockSession = ADMIN_SESSION;
      }
      expect(res.status).toBe(200);
      // Tenant B's own policy answers (an empty scope), and tenant A's grant of read_file — which the
      // same role holds in tenant A — did NOT reach across the tenant boundary.
      expect(res.body.resolution.resolvedToolScopeId).toBe(SCOPE_B);
      expect(res.body.resolution.tools).not.toContain(READ_FILE);
      expect(res.body.resolution.tools).toEqual([]);
    });

    it('a non-admin is 403 on the admin surface but 200 on their own resolve-self', async () => {
      mockSession = { id: STAFF_ID, role: STAFF_ROLE, name: 'Staffy', tenantId: TENANT_A };
      let denied;
      let self;
      try {
        denied = await request(app).get(`${BASE}/scopes`);
        self = await request(app).get(`${BASE}/resolve-self`);
      } finally {
        mockSession = ADMIN_SESSION;
      }
      expect(denied.status).toBe(403);
      expect(self.status).toBe(200);
    });

    /**
     * THE FAIL-CLOSED ORDERING (GM-81). The handler writes the audit entry FIRST and mutates the
     * store second. With a genuinely working store and a genuinely failing audit path, the request
     * must be refused with 503 and NOTHING may change — which is the point of catching an unauditable
     * write before it is made.
     */
    describe('a write whose AUDIT fails leaves no change', () => {
      const FAILING_SCOPE = 'audit-fails-scope';

      /** A minimal valid recorder input, for the chain-gap test below. */
      function auditInput(action) {
        return {
          action,
          category: 'config',
          actor: { type: 'user', id: ADMIN_ID, name: 'Root Admin' },
          target: { type: 'device_policy', id: 'gap-probe', name: 'gap probe' },
          metadata: { before: null, after: null },
          tenantId: TENANT_A,
        };
      }

      /** Runs `body` with the audit store throwing, then restores it. */
      async function withFailingAudit(body) {
        const original = mongoose.models.AuditLog.create;
        mongoose.models.AuditLog.create = async () => {
          throw new Error('injected audit-store failure');
        };
        try {
          return await body();
        } finally {
          mongoose.models.AuditLog.create = original;
        }
      }

      it('POST /scopes is 503, no scope is created, and no audit entry is written', async () => {
        const scopesBefore = await totalScopeCount();
        const entriesBefore = (await auditEntries()).length;
        const res = await withFailingAudit(() =>
          request(app)
            .post(`${BASE}/scopes`)
            .send({ id: FAILING_SCOPE, name: 'Never lands', tools: [READ_FILE], stage: 'full' }),
        );

        expect(res.status).toBe(503);
        // The store is UNCHANGED — not merely "looks unchanged".
        expect(await totalScopeCount()).toBe(scopesBefore);
        expect(await db.getToolScope(FAILING_SCOPE, { tenantId: TENANT_A })).toBeNull();
        expect((await auditEntries()).length).toBe(entriesBefore);
      });

      it('PUT /tenant-default is 503 and the existing default is untouched', async () => {
        const before = await db.getTenantDefault({ tenantId: TENANT_A });
        const entriesBefore = (await auditEntries()).length;
        // Aim at a scope that EXISTS in this tenant, so the request reaches the audit step rather
        // than being refused earlier with a 404 (`scope-tenant-default` was created in section E).
        const res = await withFailingAudit(() =>
          request(app)
            .put(`${BASE}/tenant-default`)
            .send({ defaultToolScopeId: 'scope-tenant-default' }),
        );
        expect(res.status).toBe(503);
        const after = await db.getTenantDefault({ tenantId: TENANT_A });
        expect(after.defaultToolScopeId).toBe(before.defaultToolScopeId);
        expect(after.version).toBe(before.version);
        expect((await auditEntries()).length).toBe(entriesBefore);
      });

      it('PUT /assignments is 503 and no assignment is written', async () => {
        // A real role and a real scope, so the write would otherwise SUCCEED and change the row —
        // which is what makes "unchanged" mean something.
        const before = await db.getAssignment('role', STAFF_ROLE, { tenantId: TENANT_A });
        expect(before).not.toBeNull();
        const entriesBefore = (await auditEntries()).length;
        const res = await withFailingAudit(() =>
          request(app).put(`${BASE}/assignments`).send({
            principalType: 'role',
            principalId: STAFF_ROLE,
            toolScopeId: 'scope-crud',
          }),
        );
        expect(res.status).toBe(503);
        expect(await db.getAssignment('role', STAFF_ROLE, { tenantId: TENANT_A })).toEqual(before);
        expect((await auditEntries()).length).toBe(entriesBefore);
      });

      it('reads still answer 200 while the audit path is down (a read is not an audited event)', async () => {
        const res = await withFailingAudit(() => request(app).get(`${BASE}/scopes`));
        expect(res.status).toBe(200);
      });

      /**
       * THE GAP IS THE POINT. `seq` is reserved (atomically) BEFORE the entry is inserted, so an
       * append that fails burns its number and leaves a hole. That is deliberate and is asserted
       * here rather than hidden: a hole says "an append was attempted at position N and did not
       * complete", which is more truthful than a dense sequence that silently renumbers itself. The
       * next entry links ACROSS the hole with `prevHash: null`, and nothing is invented to fill it.
       */
      it('a failed append BURNS its sequence number, and the next entry links across the gap', async () => {
        const entriesBefore = await auditEntries();
        // The counter is the authority on the next number — it runs AHEAD of the stored maximum
        // exactly because failed appends burn their reservation, so it is read rather than inferred.
        const counterBefore = await mongoose.models.AuditLogCounter.findOne({
          _id: AUDIT_LOG_COUNTER_ID,
        }).lean();
        const reservedBefore = counterBefore ? counterBefore.seq : 0;

        await expect(
          withFailingAudit(() =>
            db.recordAuditEntry(auditInput('device_policy.scope_created'), { failClosed: true }),
          ),
        ).rejects.toMatchObject({ code: 'AUDIT_LOG_WRITE_FAILED' });

        const burned = reservedBefore + 1;
        // The burned position is really empty on the server…
        expect(await mongoose.models.AuditLog.findOne({ seq: burned }).lean()).toBeNull();
        // …and the next append takes the number AFTER the hole, linking across it with `prevHash: null`
        // because there is no entry at `burned` to link to.
        const next = await db.recordAuditEntry(auditInput('device_policy.scope_created'));
        expect(next.seq).toBe(burned + 1);
        expect(next.prevHash).toBeNull();
        // Exactly one entry was added: nothing was invented to fill the hole.
        expect(await auditEntries()).toHaveLength(entriesBefore.length + 1);
        expectChainIntact(await auditEntries());
      });
    });
  });
});
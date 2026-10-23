'use strict';

/**
 * W10 — THE ADMIN DEVICE-POLICY API (GM-76, GM-78, GM-79, GM-81).
 *
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3/§6,
 * `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §2/§3 (W10),
 * `docs/GM-RULING-ABSOLUTE-ADMIN-POLICY-AND-AUDIT-SEAM-20261023.md` §2.
 *
 * WHAT IS REAL IN THIS SPEC AND WHAT IS FAKE
 *   REAL: the route file (`api/server/routes/admin/devicePolicy.js`), the handlers and the resolver
 *   (`@librechat/api`), the widening guards, the audit writer, the capability middleware
 *   (`~/server/middleware/roles/capabilities` -> `generateCapabilityCheck`), the validators
 *   (`@librechat/data-schemas`) and BOTH enforcement modules (`deviceCapabilityPolicy`,
 *   `deviceToolRegistry`) — the law is not stubbed, so the hard denies and the approval gate in
 *   these tests are the real ones.
 *   FAKE: the data layer (`~/models`) — an in-memory store with a write counter, so "nothing
 *   changed" is provable rather than asserted — and `requireJwtAuth`, which only decides whether a
 *   session exists. Capabilities are still decided by the REAL middleware, from the fake store.
 *
 * The recorder is WIRED here, so this file proves what an audited write looks like. The unwired
 * case (every write 503, nothing changes) lives in `devicePolicy.audit.spec.js`, where the fake data
 * layer exposes no `recordAuditEntry` at all.
 */

const express = require('express');
const request = require('supertest');
const { hasImpliedCapability, SystemCapabilities } = require('@librechat/data-schemas');
const deviceCapabilityPolicy = require('~/server/services/Device/deviceCapabilityPolicy');
const deviceToolRegistry = require('~/server/services/Device/deviceToolRegistry');

/**
 * ENVIRONMENT SHIM (not a test double for anything W10 uses).
 *
 * `@librechat/api` is consumed as its built bundle (`packages/api/dist/index.cjs`), which requires
 * `@librechat/agents` at LOAD time. In this worktree that chain reaches
 * `@langchain/langgraph-checkpoint/node_modules/uuid`, an ESM-only build the root jest config cannot
 * parse (no `transformIgnorePatterns`/`moduleNameMapper` entry for it), so EVERY spec that loads
 * `@librechat/api` fails here — including pre-existing ones (`ldap.spec.js`, `grants.spec.js`).
 * That is an environment defect, not a W10 behaviour, and the fix belongs in `jest.config.cjs`
 * (out of this change's write scope).
 *
 * This stub is the smallest spec-local workaround: the agent-runtime module is replaced by a
 * permissive no-op so the bundle loads. Nothing under test touches it — the device-policy handlers,
 * the resolver, the guards, the real capability middleware and BOTH enforcement modules are the
 * genuine implementations.
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

const BASE = '/api/admin/device-policy';

const USER_ID = '64b7f0c2f1a2b3c4d5e6f7a8';
const GROUP_ID = '64b7f0c2f1a2b3c4d5e6f7a9';
const OTHER_USER_ID = '64b7f0c2f1a2b3c4d5e6f7aa';

let mockDataLayer = null;
let mockUser = null;

/** Calls into the current fake data layer, or fails loudly when the fake lacks the method. */
const mockCall = (name) => (...args) => {
  const fn = mockDataLayer?.[name];
  if (typeof fn !== 'function') {
    throw new Error(`fake data layer has no ${name}`);
  }
  return fn(...args);
};

jest.mock('~/models', () => ({
  listScopes: (...a) => mockCall('listScopes')(...a),
  countScopes: (...a) => mockCall('countScopes')(...a),
  getToolScope: (...a) => mockCall('getToolScope')(...a),
  upsertToolScope: (...a) => mockCall('upsertToolScope')(...a),
  deleteToolScope: (...a) => mockCall('deleteToolScope')(...a),
  listAssignments: (...a) => mockCall('listAssignments')(...a),
  getAssignment: (...a) => mockCall('getAssignment')(...a),
  upsertAssignment: (...a) => mockCall('upsertAssignment')(...a),
  deleteAssignment: (...a) => mockCall('deleteAssignment')(...a),
  getTenantDefault: (...a) => mockCall('getTenantDefault')(...a),
  upsertTenantDefault: (...a) => mockCall('upsertTenantDefault')(...a),
  getRoleByName: (...a) => mockCall('getRoleByName')(...a),
  findGroupById: (...a) => mockCall('findGroupById')(...a),
  findUser: (...a) => mockCall('findUser')(...a),
  getUserPrincipals: (...a) => mockCall('getUserPrincipals')(...a),
  hasCapabilityForPrincipals: (...a) => mockCall('hasCapabilityForPrincipals')(...a),
  recordAuditEntry: (...a) => mockCall('recordAuditEntry')(...a),
}));

// Only the session is faked: no session -> `next()` without `req.user`, so the REAL capability
// middleware produces the 401 (that is the point of the unauthenticated test below).
jest.mock('~/server/middleware', () => ({
  requireJwtAuth: (req, _res, next) => {
    if (mockUser !== null) {
      req.user = mockUser;
    }
    return next();
  },
}));

const router = require('../admin/devicePolicy');

/**
 * The enforcement-primitives port, exactly as the route builds it: both REAL Device modules, so a
 * test that builds handlers directly still exercises the real law rather than a restatement of it.
 */
const REAL_PRIMITIVES = () => ({
  capabilityPolicy: {
    capabilityStages: deviceCapabilityPolicy.CAPABILITY_STAGES,
    // Derived from the ladder, exactly as the route derives it: the module exports the order, not
    // its internal rank table.
    stageRank: Object.freeze(
      Object.fromEntries(
        deviceCapabilityPolicy.CAPABILITY_STAGES.map((stage, index) => [stage, index]),
      ),
    ),
    catalogToolNames: deviceCapabilityPolicy.TOOL_CATALOG.map((tool) => tool.name),
    getToolDefinition: (name) => deviceCapabilityPolicy.getToolDefinition(name),
    capabilityCeiling: (stage) => deviceCapabilityPolicy.ceilingForStage(stage),
  },
  toolRegistry: {
    effectiveTools: (params) => deviceToolRegistry.effectiveTools(params),
    authorizeDispatch: (toolName, params) => deviceToolRegistry.authorizeDispatch(toolName, params),
  },
});

const ADMIN_SESSION = { id: 'user-admin', role: 'ADMIN', name: 'Root Admin', tenantId: 'tenant-1' };
const STAFF_SESSION = { id: 'user-staff', role: 'USER', name: 'Staffy', tenantId: 'tenant-1' };

const ADMIN_CAPABILITIES = [
  SystemCapabilities.ACCESS_ADMIN,
  SystemCapabilities.READ_CONFIGS,
  SystemCapabilities.MANAGE_CONFIGS,
];

const ALL_ROUTES = [
  { method: 'get', path: `${BASE}/scopes` },
  { method: 'post', path: `${BASE}/scopes`, body: { id: 'x-scope', name: 'X', tools: [], stage: 'A' } },
  { method: 'get', path: `${BASE}/scopes/x-scope` },
  {
    method: 'put',
    path: `${BASE}/scopes/x-scope`,
    body: { name: 'X', tools: [], stage: 'A' },
  },
  { method: 'delete', path: `${BASE}/scopes/x-scope` },
  { method: 'get', path: `${BASE}/assignments` },
  {
    method: 'put',
    path: `${BASE}/assignments`,
    body: { principalType: 'user', principalId: USER_ID, toolScopeId: 'x-scope' },
  },
  { method: 'delete', path: `${BASE}/assignments/user/${USER_ID}` },
  { method: 'get', path: `${BASE}/tenant-default` },
  { method: 'put', path: `${BASE}/tenant-default`, body: { defaultToolScopeId: 'x-scope' } },
  { method: 'get', path: `${BASE}/resolve-for-principal?userId=${USER_ID}` },
  { method: 'get', path: `${BASE}/resolve-for-principal/${USER_ID}` },
];

const SELF_ROUTE = { method: 'get', path: `${BASE}/resolve-self` };

/** Runs one route spec against the app, whichever verb and body it carries. */
function hit(app, route) {
  const agent = request(app)[route.method](route.path);
  return route.body === undefined ? agent : agent.send(route.body);
}

/**
 * The in-memory data layer. `writes` counts every mutating call, so a test that requires "nothing
 * changed" can assert the store was not merely left looking the same but never touched.
 */
function createFakeDataLayer(seed = {}) {
  const scopes = new Map();
  const assignments = new Map();
  const users = new Map();
  const groups = new Map();
  const roles = new Map();
  const capabilities = new Map();
  const audits = [];
  const state = { writes: 0, reads: 0, tenantDefault: null, failing: null };

  const assignmentKey = (principalType, principalId) => `${principalType}:${principalId}`;
  const stamp = () => new Date('2026-10-23T20:00:00.000Z');

  const layer = {
    listScopes: async ({ limit = 50, offset = 0 } = {}) => {
      state.reads += 1;
      return [...scopes.values()].slice(offset, offset + limit);
    },
    countScopes: async () => scopes.size,
    getToolScope: async (id) => {
      state.reads += 1;
      return scopes.get(id) ?? null;
    },
    upsertToolScope: async (document) => {
      state.writes += 1;
      const saved = { ...document, createdAt: stamp(), updatedAt: stamp() };
      scopes.set(document.id, saved);
      return saved;
    },
    deleteToolScope: async (id) => {
      state.writes += 1;
      const existing = scopes.get(id) ?? null;
      scopes.delete(id);
      return existing;
    },
    listAssignments: async (filter = {}) =>
      [...assignments.values()].filter(
        (row) =>
          (filter.principalType === undefined || row.principalType === filter.principalType) &&
          (filter.principalId === undefined || row.principalId === filter.principalId) &&
          (filter.tenantId === undefined || row.tenantId === filter.tenantId),
      ),
    getAssignment: async (principalType, principalId) =>
      assignments.get(assignmentKey(principalType, principalId)) ?? null,
    upsertAssignment: async (document) => {
      state.writes += 1;
      const saved = { ...document, createdAt: stamp(), updatedAt: stamp() };
      assignments.set(assignmentKey(document.principalType, document.principalId), saved);
      return saved;
    },
    deleteAssignment: async (principalType, principalId) => {
      state.writes += 1;
      const existing = assignments.get(assignmentKey(principalType, principalId)) ?? null;
      assignments.delete(assignmentKey(principalType, principalId));
      return existing;
    },
    getTenantDefault: async () => state.tenantDefault,
    upsertTenantDefault: async ({ defaultToolScopeId }) => {
      state.writes += 1;
      state.tenantDefault = {
        defaultToolScopeId,
        version: (state.tenantDefault?.version ?? 0) + 1,
        updatedAt: stamp(),
      };
      return state.tenantDefault;
    },
    getRoleByName: async (name) => roles.get(name) ?? null,
    findGroupById: async (id) => groups.get(id) ?? null,
    findUser: async (criteria) => users.get(String(criteria?._id)) ?? null,
    getUserPrincipals: async ({ userId, role }) => {
      const user = users.get(String(userId));
      const principalRole = role ?? user?.role ?? null;
      const principals = [{ principalType: 'user', principalId: userId }];
      if (principalRole) {
        principals.push({ principalType: 'role', principalId: principalRole });
      }
      for (const groupId of user?.groupIds ?? []) {
        principals.push({ principalType: 'group', principalId: groupId });
      }
      return principals;
    },
    hasCapabilityForPrincipals: async ({ principals, capability }) => {
      const userPrincipal = principals.find((entry) => entry.principalType === 'user');
      const held = capabilities.get(String(userPrincipal?.principalId)) ?? [];
      return hasImpliedCapability(held, capability);
    },
    recordAuditEntry: async (entry, options) => {
      if (state.failing === 'audit') {
        throw new Error('audit store unavailable');
      }
      audits.push({ entry, options });
      return entry;
    },
  };

  // Seeded through the same maps the handlers read, so a test can place data the API itself
  // refuses to create (a dangling assignment, a malformed scope row).
  users.set(USER_ID, {
    _id: USER_ID,
    role: 'USER',
    name: 'Staff User',
    groupIds: [GROUP_ID],
    tenantId: 'tenant-1',
  });
  users.set(OTHER_USER_ID, { _id: OTHER_USER_ID, role: 'ADMIN', tenantId: 'tenant-1' });
  groups.set(GROUP_ID, { _id: GROUP_ID, name: 'Staff' });
  roles.set('USER', { name: 'USER' });
  roles.set('ADMIN', { name: 'ADMIN' });
  capabilities.set('user-admin', [...ADMIN_CAPABILITIES]);
  capabilities.set('user-staff', []);

  Object.assign(layer, seed.layer ?? {});
  return { layer, scopes, assignments, users, groups, roles, capabilities, audits, state, assignmentKey };
}

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(BASE, router);
  return app;
}

let fake;

beforeEach(() => {
  fake = createFakeDataLayer();
  mockDataLayer = fake.layer;
  mockUser = ADMIN_SESSION;
});

const scopeBody = (over = {}) => ({
  id: 'staff-scope',
  name: 'Staff scope',
  description: 'Read-only tools for non-technical staff',
  tools: ['read_file', 'list_directory'],
  stage: 'A',
  ...over,
});

const assignmentBody = (over = {}) => ({
  principalType: 'user',
  principalId: USER_ID,
  toolScopeId: 'staff-scope',
  priority: 0,
  ...over,
});

/** Seeds a scope through the API (so the write path is exercised, not bypassed). */
async function seedScope(app, body = scopeBody()) {
  const res = await request(app).post(`${BASE}/scopes`).send(body);
  expect(res.status).toBe(201);
  return res.body.scope;
}

describe('W10 — authorization: every route, both refusals (GM-79 rule 1)', () => {
  it('refuses EVERY admin route with 401 when there is no authenticated session', async () => {
    mockUser = null;
    const app = createApp();
    for (const route of ALL_ROUTES) {
      const res = await hit(app, route);
      expect([route.method, route.path, res.status]).toEqual([route.method, route.path, 401]);
      expect(res.body).toEqual({ message: 'Authentication required' });
    }
  });

  it('refuses EVERY admin route with 403 when the session lacks the capability', async () => {
    mockUser = STAFF_SESSION;
    const app = createApp();
    for (const route of ALL_ROUTES) {
      const res = await hit(app, route);
      expect([route.method, route.path, res.status]).toEqual([route.method, route.path, 403]);
      expect(res.body).toEqual({ message: 'Forbidden' });
    }
  });

  it('refuses the self-service read with 401 when there is no session', async () => {
    mockUser = null;
    const res = await hit(createApp(), SELF_ROUTE);
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Authentication required' });
  });

  it('allows the self-service read for a NON-admin — and only that route', async () => {
    mockUser = STAFF_SESSION;
    const app = createApp();

    const allowed = await request(app).get(`${BASE}/resolve-self`);
    expect(allowed.status).toBe(200);
    expect(allowed.body.resolution.failClosed).toBe(true);

    for (const route of ALL_ROUTES) {
      const res = await hit(app, route);
      expect([route.method, route.path, res.status]).toEqual([route.method, route.path, 403]);
    }
  });

  it('lets a manage-capability holder read (MANAGE implies READ through the real middleware)', async () => {
    fake.capabilities.set('user-admin', [
      SystemCapabilities.ACCESS_ADMIN,
      SystemCapabilities.MANAGE_CONFIGS,
    ]);
    const res = await request(createApp()).get(`${BASE}/scopes`);
    expect(res.status).toBe(200);
  });

  it('enforces the PER-ROUTE gates: a read-capability holder cannot write, and vice versa', async () => {
    // `access:admin` alone is what gets past the router gate; the per-route capability decides the
    // rest. A reader must be refused on every write and allowed on every read — and a writer must
    // not be locked out of reads (MANAGE_CONFIGS implies READ_CONFIGS).
    fake.capabilities.set('user-admin', [
      SystemCapabilities.ACCESS_ADMIN,
      SystemCapabilities.READ_CONFIGS,
    ]);
    const readerApp = createApp();

    const reads = [
      { method: 'get', path: `${BASE}/scopes` },
      { method: 'get', path: `${BASE}/assignments` },
      { method: 'get', path: `${BASE}/tenant-default` },
      { method: 'get', path: `${BASE}/resolve-for-principal/${USER_ID}` },
    ];
    const writes = [
      { method: 'post', path: `${BASE}/scopes`, body: scopeBody() },
      { method: 'put', path: `${BASE}/scopes/staff-scope`, body: { name: 'X', tools: [], stage: 'A' } },
      { method: 'delete', path: `${BASE}/scopes/staff-scope` },
      { method: 'put', path: `${BASE}/assignments`, body: assignmentBody() },
      { method: 'delete', path: `${BASE}/assignments/user/${USER_ID}` },
      { method: 'put', path: `${BASE}/tenant-default`, body: { defaultToolScopeId: 'staff-scope' } },
    ];

    for (const route of reads) {
      const res = await hit(readerApp, route);
      expect([route.method, route.path, res.status]).toEqual([route.method, route.path, 200]);
    }
    for (const route of writes) {
      const res = await hit(readerApp, route);
      expect([route.method, route.path, res.status]).toEqual([route.method, route.path, 403]);
      expect(res.body).toEqual({ message: 'Forbidden' });
    }
    expect(fake.state.writes).toBe(0);
  });
});

describe('W10 — tool scope CRUD and response shapes', () => {
  it('creates a scope: 201 { scope } with the stored shape', async () => {
    const app = createApp();
    const res = await request(app).post(`${BASE}/scopes`).send(scopeBody());

    expect(res.status).toBe(201);
    expect(res.body.scope).toMatchObject({
      id: 'staff-scope',
      name: 'Staff scope',
      description: 'Read-only tools for non-technical staff',
      tools: ['read_file', 'list_directory'],
      stage: 'A',
      isActive: true,
      version: 1,
      tenantId: 'tenant-1',
    });
    expect(typeof res.body.scope.createdAt).toBe('string');
  });

  it('lists scopes with parsePagination: 200 { scopes, total, limit, offset }', async () => {
    const app = createApp();
    await seedScope(app);
    await seedScope(app, scopeBody({ id: 'other-scope', name: 'Other' }));

    const res = await request(app).get(`${BASE}/scopes?limit=1&offset=1`);
    expect(res.status).toBe(200);
    expect(Object.keys(res.body).sort()).toEqual(['limit', 'offset', 'scopes', 'total']);
    expect(res.body).toMatchObject({ total: 2, limit: 1, offset: 1 });
    expect(res.body.scopes).toHaveLength(1);
  });

  it('reads one scope: 200 { scope }, and 404 for an unknown id', async () => {
    const app = createApp();
    await seedScope(app);

    const found = await request(app).get(`${BASE}/scopes/staff-scope`);
    expect(found.status).toBe(200);
    expect(found.body.scope.id).toBe('staff-scope');

    const missing = await request(app).get(`${BASE}/scopes/no-such-scope`);
    expect(missing.status).toBe(404);
    expect(missing.body).toEqual({ error: 'Tool scope not found' });
  });

  it('updates a scope as a FULL replacement and bumps version: 200 { scope }', async () => {
    const app = createApp();
    await seedScope(app);

    const res = await request(app)
      .put(`${BASE}/scopes/staff-scope`)
      .send({ name: 'Staff scope v2', tools: ['read_file'], stage: 'A' });

    expect(res.status).toBe(200);
    expect(res.body.scope.tools).toEqual(['read_file']);
    expect(res.body.scope.name).toBe('Staff scope v2');
    expect(res.body.scope.version).toBe(2);
    // `description` was omitted: the stored value survives, it is not silently blanked.
    expect(res.body.scope.description).toBe('Read-only tools for non-technical staff');
  });

  it('keeps `isActive: false` on update, and an explicitly retired scope still reads back', async () => {
    const app = createApp();
    await seedScope(app);

    const res = await request(app)
      .put(`${BASE}/scopes/staff-scope`)
      .send({ name: 'Staff scope', tools: [], stage: 'A', isActive: false });

    expect(res.status).toBe(200);
    expect(res.body.scope.isActive).toBe(false);
  });

  it('refuses a duplicate scope id with 409', async () => {
    const app = createApp();
    await seedScope(app);

    const res = await request(app).post(`${BASE}/scopes`).send(scopeBody());
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/already exists/);
  });

  it('deletes an unreferenced scope: 200 { success: true }', async () => {
    const app = createApp();
    await seedScope(app);

    const res = await request(app).delete(`${BASE}/scopes/staff-scope`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true });
    expect(fake.scopes.size).toBe(0);

    const again = await request(app).delete(`${BASE}/scopes/staff-scope`);
    expect(again.status).toBe(404);
  });

  it('refuses to delete a scope an assignment points at (409): no dangling references', async () => {
    const app = createApp();
    await seedScope(app);
    await request(app).put(`${BASE}/assignments`).send(assignmentBody());

    const res = await request(app).delete(`${BASE}/scopes/staff-scope`);
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/still referenced by 1 assignment/);
    expect(fake.scopes.has('staff-scope')).toBe(true);
  });

  it('refuses to delete the scope the tenant default points at (409)', async () => {
    const app = createApp();
    await seedScope(app);
    await request(app).put(`${BASE}/tenant-default`).send({ defaultToolScopeId: 'staff-scope' });

    const res = await request(app).delete(`${BASE}/scopes/staff-scope`);
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/the tenant default/);
  });
});

describe('W10 — validator-first 400s (no storage touched)', () => {
  const cases = [
    {
      name: 'scope id that is not lower-kebab',
      route: { method: 'post', path: `${BASE}/scopes`, body: scopeBody({ id: 'Staff Scope' }) },
      message: /lower-kebab-case/,
    },
    {
      name: 'scope id that is a reserved path segment',
      route: { method: 'post', path: `${BASE}/scopes`, body: scopeBody({ id: 'assignments' }) },
      message: /reserved path segment/,
    },
    {
      name: 'missing tools list',
      route: { method: 'post', path: `${BASE}/scopes`, body: { id: 'a-scope', name: 'A', stage: 'A' } },
      message: /tools is required/,
    },
    {
      name: 'duplicate tool names',
      route: {
        method: 'post',
        path: `${BASE}/scopes`,
        body: scopeBody({ tools: ['read_file', 'read_file'] }),
      },
      message: /more than once/,
    },
    {
      name: 'unknown stage',
      route: { method: 'post', path: `${BASE}/scopes`, body: scopeBody({ stage: 'Z' }) },
      message: /stage must be one of A, B, C, full/,
    },
    {
      name: 'non-boolean isActive',
      route: { method: 'post', path: `${BASE}/scopes`, body: scopeBody({ isActive: 'yes' }) },
      message: /isActive must be a boolean/,
    },
    {
      name: 'bad scope id in the path',
      route: { method: 'get', path: `${BASE}/scopes/Bad_ID` },
      message: /lower-kebab-case/,
    },
    {
      name: 'bad principalType',
      route: { method: 'put', path: `${BASE}/assignments`, body: assignmentBody({ principalType: 'team' }) },
      message: /principalType must be one of user, group, role/,
    },
    {
      name: 'principal id that is not an ObjectId',
      route: { method: 'put', path: `${BASE}/assignments`, body: assignmentBody({ principalId: 'not-an-id' }) },
      message: /Invalid principal ID format/,
    },
    {
      name: 'priority out of range',
      route: { method: 'put', path: `${BASE}/assignments`, body: assignmentBody({ priority: 999999 }) },
      message: /priority must be an integer between 0 and 10000/,
    },
    {
      name: 'missing defaultToolScopeId',
      route: { method: 'put', path: `${BASE}/tenant-default`, body: {} },
      message: /defaultToolScopeId/,
    },
    {
      name: 'bad principalType in the path',
      route: { method: 'delete', path: `${BASE}/assignments/team/${USER_ID}` },
      message: /principalType must be one of user, group, role/,
    },
  ];

  for (const testCase of cases) {
    it(`400s on ${testCase.name}`, async () => {
      const before = fake.state.writes;
      const res = await hit(createApp(), testCase.route);
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(testCase.message);
      expect(fake.state.writes).toBe(before);
      expect(fake.audits).toHaveLength(0);
    });
  }
});

describe('W10 — assignments and the tenant default', () => {
  it('creates an assignment: 201 { assignment, created: true }', async () => {
    const app = createApp();
    await seedScope(app);

    const res = await request(app).put(`${BASE}/assignments`).send(assignmentBody());
    expect(res.status).toBe(201);
    expect(res.body.created).toBe(true);
    expect(res.body.assignment).toMatchObject({
      principalType: 'user',
      principalId: USER_ID,
      toolScopeId: 'staff-scope',
      priority: 0,
      isActive: true,
    });
  });

  it('re-setting the same assignment is 200 { created: false } (upsert, not a conflict)', async () => {
    const app = createApp();
    await seedScope(app);
    await request(app).put(`${BASE}/assignments`).send(assignmentBody());

    const res = await request(app)
      .put(`${BASE}/assignments`)
      .send(assignmentBody({ priority: 5 }));
    expect(res.status).toBe(200);
    expect(res.body.created).toBe(false);
    expect(res.body.assignment.priority).toBe(5);
  });

  it('refuses an assignment naming a scope that does not exist (404): no dangling policy', async () => {
    const res = await request(createApp())
      .put(`${BASE}/assignments`)
      .send(assignmentBody({ toolScopeId: 'ghost-scope' }));
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/Tool scope "ghost-scope" not found/);
    expect(fake.assignments.size).toBe(0);
  });

  it('refuses an assignment naming a principal that does not exist (404), per principal type', async () => {
    const app = createApp();
    await seedScope(app);

    const role = await request(app)
      .put(`${BASE}/assignments`)
      .send(assignmentBody({ principalType: 'role', principalId: 'NOPE' }));
    expect(role.status).toBe(404);
    expect(role.body).toEqual({ error: 'Role not found' });

    const group = await request(app)
      .put(`${BASE}/assignments`)
      .send(assignmentBody({ principalType: 'group', principalId: OTHER_USER_ID }));
    expect(group.status).toBe(404);
    expect(group.body).toEqual({ error: 'Group not found' });

    const user = await request(app)
      .put(`${BASE}/assignments`)
      .send(assignmentBody({ principalId: OTHER_USER_ID.replace(/.$/, 'b') }));
    expect(user.status).toBe(404);
    expect(user.body).toEqual({ error: 'User not found' });
  });

  it('lists assignments: 200 { assignments, total }', async () => {
    const app = createApp();
    await seedScope(app);
    await request(app).put(`${BASE}/assignments`).send(assignmentBody());

    const res = await request(app).get(`${BASE}/assignments`);
    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
    expect(res.body.assignments[0].toolScopeId).toBe('staff-scope');
  });

  it('filters the assignment list by principalType/principalId from the query', async () => {
    const app = createApp();
    await seedScope(app);
    await request(app).put(`${BASE}/assignments`).send(assignmentBody());

    const filtered = await request(app).get(`${BASE}/assignments?principalType=role&principalId=USER`);
    expect(filtered.status).toBe(200);
    expect(filtered.body.assignments).toEqual([]);

    const matched = await request(app).get(`${BASE}/assignments?principalType=user&principalId=${USER_ID}`);
    expect(matched.body.assignments).toHaveLength(1);
  });

  it('removes an assignment: 200 { success: true }, and 404 when there is none', async () => {
    const app = createApp();
    await seedScope(app);
    await request(app).put(`${BASE}/assignments`).send(assignmentBody());

    const removed = await request(app).delete(`${BASE}/assignments/user/${USER_ID}`);
    expect(removed.status).toBe(200);
    expect(removed.body).toEqual({ success: true });
    expect(fake.assignments.size).toBe(0);

    const again = await request(app).delete(`${BASE}/assignments/user/${USER_ID}`);
    expect(again.status).toBe(404);
    expect(again.body).toEqual({ error: 'Policy assignment not found' });
  });

  it('reads an absent tenant default as 200 { tenantDefault: null } — absent is not an error', async () => {
    const res = await request(createApp()).get(`${BASE}/tenant-default`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ tenantDefault: null });
  });

  it('sets the tenant default: 200 { tenantDefault } with a bumped version', async () => {
    const app = createApp();
    await seedScope(app);

    const first = await request(app)
      .put(`${BASE}/tenant-default`)
      .send({ defaultToolScopeId: 'staff-scope' });
    expect(first.status).toBe(200);
    expect(first.body.tenantDefault).toMatchObject({ defaultToolScopeId: 'staff-scope', version: 1 });

    const second = await request(app)
      .put(`${BASE}/tenant-default`)
      .send({ defaultToolScopeId: 'staff-scope' });
    expect(second.body.tenantDefault.version).toBe(2);
  });

  it('refuses a tenant default naming a scope that does not exist (404)', async () => {
    const res = await request(createApp())
      .put(`${BASE}/tenant-default`)
      .send({ defaultToolScopeId: 'ghost-scope' });
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/Tool scope "ghost-scope" not found/);
    expect(fake.state.tenantDefault).toBeNull();
  });
});

describe('W10 — every write is audited with actor, before and after (GM-79 rule 2)', () => {
  it('records scope_created with a null before and the stored after', async () => {
    const app = createApp();
    await seedScope(app);

    expect(fake.audits).toHaveLength(1);
    const { entry, options } = fake.audits[0];
    expect(options).toEqual({ failClosed: true });
    expect(entry.action).toBe('device_policy.scope_created');
    expect(entry.category).toBe('config');
    expect(entry.actor).toEqual({ type: 'user', id: 'user-admin', name: 'Root Admin' });
    expect(entry.target).toEqual({ type: 'device_policy', id: 'staff-scope', name: 'Staff scope' });
    expect(entry.metadata.before.body).toBeNull();
    expect(JSON.parse(entry.metadata.after.body)).toMatchObject({
      id: 'staff-scope',
      tools: ['read_file', 'list_directory'],
      stage: 'A',
      version: 1,
    });
    expect(entry.metadata.changedFields).toEqual(
      expect.arrayContaining(['id', 'name', 'tools', 'stage', 'version']),
    );
    expect(entry.metadata.fingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it('records scope_updated with the real before and after (the version bump is visible)', async () => {
    const app = createApp();
    await seedScope(app);
    fake.audits.length = 0;

    await request(app)
      .put(`${BASE}/scopes/staff-scope`)
      .send({ name: 'Staff scope', tools: ['read_file'], stage: 'A' });

    const { entry } = fake.audits[0];
    expect(entry.action).toBe('device_policy.scope_updated');
    expect(JSON.parse(entry.metadata.before.body).tools).toEqual(['read_file', 'list_directory']);
    expect(JSON.parse(entry.metadata.after.body).tools).toEqual(['read_file']);
    expect(entry.metadata.before.version).toBe(1);
    expect(entry.metadata.changedFields).toEqual(expect.arrayContaining(['tools', 'version']));
    expect(entry.metadata.changedFields).not.toContain('name');
  });

  it('records scope_deleted with the before and a null after', async () => {
    const app = createApp();
    await seedScope(app);
    fake.audits.length = 0;

    await request(app).delete(`${BASE}/scopes/staff-scope`);
    const { entry } = fake.audits[0];
    expect(entry.action).toBe('device_policy.scope_deleted');
    expect(JSON.parse(entry.metadata.before.body).id).toBe('staff-scope');
    expect(entry.metadata.after.body).toBeNull();
  });

  it('records assignment_set and assignment_removed, naming the principal', async () => {
    const app = createApp();
    await seedScope(app);
    fake.audits.length = 0;

    await request(app).put(`${BASE}/assignments`).send(assignmentBody());
    await request(app).delete(`${BASE}/assignments/user/${USER_ID}`);

    expect(fake.audits.map((row) => row.entry.action)).toEqual([
      'device_policy.assignment_set',
      'device_policy.assignment_removed',
    ]);
    const [set, removed] = fake.audits.map((row) => row.entry);
    expect(set.target.id).toBe(`user:${USER_ID}`);
    expect(set.metadata.before.body).toBeNull();
    expect(JSON.parse(set.metadata.after.body).toolScopeId).toBe('staff-scope');
    expect(JSON.parse(removed.metadata.before.body).toolScopeId).toBe('staff-scope');
    expect(removed.metadata.after.body).toBeNull();
  });

  it('records tenant_default_set with the before (absent) and after', async () => {
    const app = createApp();
    await seedScope(app);
    fake.audits.length = 0;

    await request(app).put(`${BASE}/tenant-default`).send({ defaultToolScopeId: 'staff-scope' });
    const { entry } = fake.audits[0];
    expect(entry.action).toBe('device_policy.tenant_default_set');
    expect(entry.metadata.before).toMatchObject({ version: null, body: null });
    expect(JSON.parse(entry.metadata.after.body).defaultToolScopeId).toBe('staff-scope');
    expect(entry.tenantId).toBe('tenant-1');
  });

  it('refuses the change with 503 when the recorder itself fails, and changes nothing', async () => {
    const app = createApp();
    await seedScope(app);
    fake.audits.length = 0;
    const writesAfterSeed = fake.state.writes;

    fake.state.failing = 'audit';
    const res = await request(app)
      .put(`${BASE}/scopes/staff-scope`)
      .send({ name: 'Renamed', tools: ['read_file'], stage: 'A' });

    expect(res.status).toBe(503);
    expect(res.body.error).toMatch(/audit path/);
    // The refusal happened BEFORE the store was touched: the pre-existing scope is untouched.
    expect(fake.state.writes).toBe(writesAfterSeed);
    expect(fake.scopes.get('staff-scope').tools).toEqual(['read_file', 'list_directory']);
    expect(fake.scopes.get('staff-scope').name).toBe('Staff scope');
  });

  it('records the intended change before the store write, so a storage refusal leaves no silent gap', async () => {
    const {
      createAdminDevicePolicyHandlers,
      resolveDevicePolicyStorage,
      DevicePolicyStorageUnavailableError,
    } = require('@librechat/api');

    // The STORAGE SEAM exactly as the route binds it: `~/models` is asked for the persistence
    // functions, and the one this build does not have is bound to a named refusal.
    const audits = [];
    const stored = new Map([
      [
        'staff-scope',
        { id: 'staff-scope', name: 'Staff scope', tools: ['read_file'], stage: 'A', isActive: true, version: 1 },
      ],
    ]);
    const dataLayer = {
      ...fake.layer,
      getToolScope: async (id) => stored.get(id) ?? null,
      recordAuditEntry: async (entry, options) => {
        audits.push({ entry, options });
        return entry;
      },
    };
    delete dataLayer.upsertToolScope;

    const bound = resolveDevicePolicyStorage(dataLayer);
    expect(bound.upsertToolScope).toEqual(expect.any(Function));
    await expect(bound.upsertToolScope({})).rejects.toBeInstanceOf(DevicePolicyStorageUnavailableError);

    const handlers = createAdminDevicePolicyHandlers({
      ...bound,
      // The recorder IS wired here: this test is about the storage half of the seam.
      recordAuditEntry: dataLayer.recordAuditEntry,
      primitives: REAL_PRIMITIVES(),
      serverStage: 'A',
    });
    const bare = express();
    bare.use(express.json());
    bare.use((req, _res, next) => {
      req.user = ADMIN_SESSION;
      next();
    });
    bare.put('/scopes/:scopeId', handlers.updateScope);

    const res = await request(bare)
      .put('/scopes/staff-scope')
      .send({ name: 'Staff scope', tools: ['read_file', 'list_directory'], stage: 'A' });

    expect(res.status).toBe(503);
    expect(res.body.error).toMatch(/storage is not wired/i);
    // The audit entry exists (written first) and the store still holds the old value: the trail
    // describes the change that was attempted, never a change nobody can see.
    expect(audits.map((row) => row.entry.action)).toEqual(['device_policy.scope_updated']);
    expect(audits[0].options).toEqual({ failClosed: true });
    expect(stored.get('staff-scope').tools).toEqual(['read_file']);
  });
});

describe('W10 — widening via the request body is stripped and has no effect (GM-79 rule 3)', () => {
  it('ignores privilege fields on a scope write and takes the tenant from the session', async () => {
    const app = createApp();
    const res = await request(app)
      .post(`${BASE}/scopes`)
      .send(
        scopeBody({
          granted: true,
          grant: ['manage:configs'],
          capabilities: ['manage:configs', 'access:admin'],
          isAdmin: true,
          admin: true,
          role: 'ADMIN',
          roles: ['ADMIN'],
          groups: ['admins'],
          toolScopeId: 'tenant-scope',
          toolScope: 'tenant-scope',
          policyVersion: 'forged',
          ceiling: { stage: 'full' },
          pilot: false,
          tenantId: 'evil-tenant',
        }),
      );

    expect(res.status).toBe(201);
    const stored = fake.scopes.get('staff-scope');
    // The document is built from the validated shape only: no request field can ride along.
    expect(Object.keys(stored).sort()).toEqual([
      'createdAt',
      'description',
      'id',
      'isActive',
      'name',
      'stage',
      'tenantId',
      'tools',
      'updatedAt',
      'version',
    ]);
    expect(stored.tenantId).toBe('tenant-1');
    expect(stored.tools).toEqual(['read_file', 'list_directory']);
  });

  it('ignores the same spellings on an assignment write and on the tenant default', async () => {
    const app = createApp();
    await seedScope(app);

    const assignment = await request(app)
      .put(`${BASE}/assignments`)
      .send(
        assignmentBody({
          granted: true,
          capabilities: ['access:admin'],
          isAdmin: true,
          tenantId: 'evil-tenant',
          policyVersion: 'forged',
        }),
      );
    expect(assignment.status).toBe(201);
    expect(fake.assignments.get(`user:${USER_ID}`).tenantId).toBe('tenant-1');

    const tenantDefault = await request(app)
      .put(`${BASE}/tenant-default`)
      .send({ defaultToolScopeId: 'staff-scope', version: 99, tenantId: 'evil-tenant' });
    expect(tenantDefault.status).toBe(200);
    expect(fake.state.tenantDefault.version).toBe(1);
    expect(fake.state.tenantDefault.tenantId).toBeUndefined();
  });

  it('strips unknown-but-harmless fields instead of honouring them, and still writes the policy fields', async () => {
    const app = createApp();
    const res = await request(app)
      .post(`${BASE}/scopes`)
      .send(scopeBody({ somethingElse: 'ignored', tools: ['list_directory'], stage: 'A' }));

    expect(res.status).toBe(201);
    expect(res.body.scope.tools).toEqual(['list_directory']);
  });
});

describe('W10 — failures that are not the caller’s fault', () => {
  it('500s a read when the data layer throws, without leaking the error', async () => {
    mockDataLayer = {
      ...fake.layer,
      listScopes: async () => {
        throw new Error('mongo is down');
      },
    };
    const res = await request(createApp()).get(`${BASE}/scopes`);
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Failed to list tool scopes' });
  });

  it('500s a write when the resolver primitives are unusable, rather than guessing a policy', async () => {
    const app = createApp();
    const { createAdminDevicePolicyHandlers } = require('@librechat/api');
    const handlers = createAdminDevicePolicyHandlers({
      ...fake.layer,
      primitives: {},
      serverStage: 'A',
    });
    const bare = express();
    bare.use(express.json());
    bare.get('/resolve-self', (req, _res, next) => {
      req.user = { id: 'user-staff', role: 'USER' };
      next();
    }, handlers.resolveSelf);

    const res = await request(bare).get('/resolve-self');
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Device-policy enforcement primitives are unavailable' });
  });
});
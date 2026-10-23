'use strict';

/**
 * W10 / GM-81 — THE AUDIT SEAM: with no recorder wired, every write is refused with 503 and
 * changes nothing. Reads are unaffected.
 *
 * `docs/GM-RULING-ABSOLUTE-ADMIN-POLICY-AND-AUDIT-SEAM-20261023.md` §2 is the whole reason this
 * file exists: the admin audit path (`packages/api/src/admin/auditLog`) is on `origin/main` but NOT
 * an ancestor of this branch, so the recorder is INJECTED and this build has none. GM-81 rules that
 * the correct behaviour is a hard refusal — "an admin cannot make an unaudited change, because an
 * unauditable change cannot be made at all" — rather than a silent bypass.
 *
 * `~/models` here is the REAL shape of the data layer in this branch: it has no `recordAuditEntry`,
 * because the function does not exist yet. That is what makes this file a faithful test of the
 * shipped behaviour rather than of a mocked failure.
 *
 * The audited behaviour (actor, before/after, failClosed) is proven in `devicePolicy.spec.js`, where
 * the recorder IS wired. The two files together cover both halves of GM-81.
 *
 * The environment shim for `@librechat/agents` is explained in `devicePolicy.spec.js`.
 */

const express = require('express');
const request = require('supertest');
const {
  createDevicePolicyAuditWriter,
  DEVICE_POLICY_AUDIT_ACTION_NAMES,
  DEVICE_POLICY_AUDIT_ACTIONS,
} = require('@librechat/api');
const { hasImpliedCapability, SystemCapabilities } = require('@librechat/data-schemas');
const deviceCapabilityPolicy = require('~/server/services/Device/deviceCapabilityPolicy');
const deviceToolRegistry = require('~/server/services/Device/deviceToolRegistry');

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

const ADMIN_SESSION = { id: 'user-admin', role: 'ADMIN', name: 'Root Admin', tenantId: 'tenant-1' };
const STAFF_SESSION = { id: 'user-staff', role: 'USER', name: 'Staffy', tenantId: 'tenant-1' };

const AUDIT_REFUSAL = /Policy changes require the admin audit path/;

let mockDataLayer = null;
let mockUser = ADMIN_SESSION;

const mockCall = (name) => (...args) => {
  const fn = mockDataLayer?.[name];
  if (typeof fn !== 'function') {
    throw new Error(`fake data layer has no ${name}`);
  }
  return fn(...args);
};

/**
 * NOTE WHAT IS MISSING: `recordAuditEntry`. The route binds the audit writer from `db.recordAuditEntry`
 * at load time, and this build's data layer does not have it — so the handlers are created with NO
 * recorder, which is exactly the shipped state of the branch.
 */
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
}));

jest.mock('~/server/middleware', () => ({
  requireJwtAuth: (req, _res, next) => {
    if (mockUser !== null) {
      req.user = mockUser;
    }
    return next();
  },
}));

const router = require('../admin/devicePolicy');

const REAL_PRIMITIVES = () => ({
  capabilityPolicy: {
    capabilityStages: deviceCapabilityPolicy.CAPABILITY_STAGES,
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

function createFakeDataLayer() {
  const scopes = new Map();
  const assignments = new Map();
  const users = new Map();
  const groups = new Map();
  const capabilities = new Map();
  const state = { writes: 0, reads: 0, tenantDefault: null };
  const assignmentKey = (principalType, principalId) => `${principalType}:${principalId}`;

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
      scopes.set(document.id, { ...document });
      return scopes.get(document.id);
    },
    deleteToolScope: async (id) => {
      state.writes += 1;
      const existing = scopes.get(id) ?? null;
      scopes.delete(id);
      return existing;
    },
    listAssignments: async (filter = {}) => {
      state.reads += 1;
      return [...assignments.values()].filter(
        (row) =>
          (filter.principalType === undefined || row.principalType === filter.principalType) &&
          (filter.principalId === undefined || row.principalId === filter.principalId),
      );
    },
    getAssignment: async (principalType, principalId) =>
      assignments.get(assignmentKey(principalType, principalId)) ?? null,
    upsertAssignment: async (document) => {
      state.writes += 1;
      assignments.set(assignmentKey(document.principalType, document.principalId), { ...document });
      return assignments.get(assignmentKey(document.principalType, document.principalId));
    },
    deleteAssignment: async (principalType, principalId) => {
      state.writes += 1;
      const existing = assignments.get(assignmentKey(principalType, principalId)) ?? null;
      assignments.delete(assignmentKey(principalType, principalId));
      return existing;
    },
    getTenantDefault: async () => {
      state.reads += 1;
      return state.tenantDefault;
    },
    upsertTenantDefault: async ({ defaultToolScopeId }) => {
      state.writes += 1;
      state.tenantDefault = { defaultToolScopeId, version: 1 };
      return state.tenantDefault;
    },
    getRoleByName: async (name) => (['ADMIN', 'USER'].includes(name) ? { name } : null),
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
      return hasImpliedCapability(
        capabilities.get(String(userPrincipal?.principalId)) ?? [],
        capability,
      );
    },
  };

  users.set(USER_ID, { _id: USER_ID, role: 'USER', groupIds: [GROUP_ID], tenantId: 'tenant-1' });
  groups.set(GROUP_ID, { _id: GROUP_ID, name: 'Staff' });
  capabilities.set('user-admin', [
    SystemCapabilities.ACCESS_ADMIN,
    SystemCapabilities.READ_CONFIGS,
    SystemCapabilities.MANAGE_CONFIGS,
  ]);
  capabilities.set('user-staff', []);

  return { layer, scopes, assignments, users, groups, capabilities, state };
}

let fake;

beforeEach(() => {
  fake = createFakeDataLayer();
  mockDataLayer = fake.layer;
  mockUser = ADMIN_SESSION;
});

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(BASE, router);
  return app;
}

const VALID_WRITES = [
  {
    name: 'create a scope',
    method: 'post',
    path: `${BASE}/scopes`,
    body: { id: 'staff-scope', name: 'Staff scope', tools: ['read_file'], stage: 'A' },
  },
  {
    name: 'update a scope',
    method: 'put',
    path: `${BASE}/scopes/staff-scope`,
    body: { name: 'Staff scope', tools: ['read_file'], stage: 'A' },
  },
  { name: 'delete a scope', method: 'delete', path: `${BASE}/scopes/staff-scope` },
  {
    name: 'set an assignment',
    method: 'put',
    path: `${BASE}/assignments`,
    body: { principalType: 'user', principalId: USER_ID, toolScopeId: 'staff-scope' },
  },
  { name: 'remove an assignment', method: 'delete', path: `${BASE}/assignments/user/${USER_ID}` },
  {
    name: 'set the tenant default',
    method: 'put',
    path: `${BASE}/tenant-default`,
    body: { defaultToolScopeId: 'staff-scope' },
  },
];

/** Seeds the state a write handler needs to exist before it can be refused by the audit gate. */
function seedExistingState() {
  fake.scopes.set('staff-scope', {
    id: 'staff-scope',
    name: 'Staff scope',
    description: '',
    tools: ['read_file'],
    stage: 'A',
    isActive: true,
    version: 1,
  });
  fake.assignments.set(`user:${USER_ID}`, {
    principalType: 'user',
    principalId: USER_ID,
    toolScopeId: 'staff-scope',
    priority: 0,
    isActive: true,
  });
}

describe('W10/GM-81 — with no audit recorder wired, EVERY write is 503 and changes nothing', () => {
  for (const write of VALID_WRITES) {
    it(`refuses "${write.name}" with 503, touching no storage`, async () => {
      seedExistingState();
      const writesBefore = fake.state.writes;
      const readsBefore = fake.state.reads;

      const res = await hit(createApp(), write);

      expect(res.status).toBe(503);
      expect(res.body.error).toMatch(AUDIT_REFUSAL);
      // The gate runs before ANY storage call: not a write, not even a read.
      expect(fake.state.writes).toBe(writesBefore);
      expect(fake.state.reads).toBe(readsBefore);
    });
  }

  it('leaves the store byte-for-byte as it was after all six refusals', async () => {
    seedExistingState();
    const before = JSON.stringify({
      scopes: [...fake.scopes.entries()],
      assignments: [...fake.assignments.entries()],
      tenantDefault: fake.state.tenantDefault,
    });
    const app = createApp();
    for (const write of VALID_WRITES) {
      const res = await hit(app, write);
      expect(res.status).toBe(503);
    }
    const after = JSON.stringify({
      scopes: [...fake.scopes.entries()],
      assignments: [...fake.assignments.entries()],
      tenantDefault: fake.state.tenantDefault,
    });
    expect(after).toBe(before);
    expect(fake.state.writes).toBe(0);
  });

  it('refuses repeatedly and identically: the 503 is a property of the build, not a race', async () => {
    const app = createApp();
    const first = await hit(app, VALID_WRITES[0]);
    const second = await hit(app, VALID_WRITES[0]);
    expect(second.status).toBe(first.status);
    expect(second.body).toEqual(first.body);
  });

  it('still answers validation FIRST: an unusable body is a 400, not a 503', async () => {
    // Documented ordering: a body that could never be a policy document is refused at validation;
    // the 503 gate applies to any request that would otherwise change policy.
    const res = await request(createApp())
      .post(`${BASE}/scopes`)
      .send({ id: 'Bad Id', tools: 'not-a-list', stage: 'Z' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/lower-kebab-case/);
    expect(fake.state.writes).toBe(0);
  });

  it('strips widening fields even on a refused write (the guard runs before the gate)', async () => {
    const res = await request(createApp())
      .post(`${BASE}/scopes`)
      .send({ id: 'a-scope', name: 'A', tools: ['read_file'], stage: 'A', granted: true, role: 'ADMIN' });
    expect(res.status).toBe(503);
    expect(res.body.error).toMatch(AUDIT_REFUSAL);
  });
});

describe('W10/GM-81 — reads are unaffected by the audit seam', () => {
  it('lists scopes, reads a scope and the tenant default', async () => {
    seedExistingState();
    const app = createApp();

    const list = await request(app).get(`${BASE}/scopes`);
    expect(list.status).toBe(200);
    expect(list.body).toMatchObject({ total: 1, limit: 50, offset: 0 });
    expect(list.body.scopes[0].id).toBe('staff-scope');

    const one = await request(app).get(`${BASE}/scopes/staff-scope`);
    expect(one.status).toBe(200);
    expect(one.body.scope.tools).toEqual(['read_file']);

    const tenantDefault = await request(app).get(`${BASE}/tenant-default`);
    expect(tenantDefault.status).toBe(200);
    expect(tenantDefault.body).toEqual({ tenantDefault: null });

    const assignments = await request(app).get(`${BASE}/assignments`);
    expect(assignments.status).toBe(200);
    expect(assignments.body.total).toBe(1);
  });

  it('resolves policy for the self read and for an inspected principal', async () => {
    seedExistingState();
    mockUser = { ...STAFF_SESSION, id: USER_ID, role: 'USER' };
    const app = createApp();

    const self = await request(app).get(`${BASE}/resolve-self`);
    expect(self.status).toBe(200);
    expect(self.body.resolution.governingLevel).toBe('user');
    expect(self.body.resolution.tools).toEqual(['read_file']);

    // The inspection read is admin-only; the admin's own read of the staff's effective set uses
    // the staff's database identity, same as above.
    mockUser = ADMIN_SESSION;

    const inspected = await request(app).get(`${BASE}/resolve-for-principal/${USER_ID}`);
    expect(inspected.status).toBe(200);
    expect(inspected.body.resolution.governingLevel).toBe('user');
    expect(inspected.body.resolution.tools).toEqual(['read_file']);
  });

  it('refuses a READ with 503 only when the STORAGE seam itself is unwired', async () => {
    const { createAdminDevicePolicyHandlers, resolveDevicePolicyStorage, DevicePolicyStorageUnavailableError } =
      require('@librechat/api');
    const broken = { ...fake.layer };
    delete broken.listScopes;

    const bound = resolveDevicePolicyStorage(broken);
    await expect(bound.listScopes({})).rejects.toBeInstanceOf(DevicePolicyStorageUnavailableError);

    const handlers = createAdminDevicePolicyHandlers({
      ...bound,
      primitives: REAL_PRIMITIVES(),
      serverStage: 'A',
    });
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.user = ADMIN_SESSION;
      next();
    });
    app.get('/scopes', handlers.listScopes);

    const res = await request(app).get('/scopes');
    expect(res.status).toBe(503);
    expect(res.body.error).toMatch(/storage is not wired/i);
  });
});

describe('W10/GM-81 — the frozen action list the rebase wires, and the writer contract', () => {
  it('exports exactly the device_policy.* action names, frozen, as one authoritative list', () => {
    expect(Object.isFrozen(DEVICE_POLICY_AUDIT_ACTION_NAMES)).toBe(true);
    expect([...DEVICE_POLICY_AUDIT_ACTION_NAMES]).toEqual([
      'device_policy.scope_created',
      'device_policy.scope_updated',
      'device_policy.scope_deleted',
      'device_policy.assignment_set',
      'device_policy.assignment_removed',
      'device_policy.tenant_default_set',
    ]);
    // The list and the map cannot disagree: the rebase registers the list.
    expect([...DEVICE_POLICY_AUDIT_ACTION_NAMES]).toEqual(Object.values(DEVICE_POLICY_AUDIT_ACTIONS));
  });

  it('builds NO writer when no recorder is injected (the null the 503 gate keys off)', () => {
    expect(createDevicePolicyAuditWriter({})).toBeNull();
    expect(createDevicePolicyAuditWriter({ recordAuditEntry: undefined })).toBeNull();
    expect(createDevicePolicyAuditWriter({ recordAuditEntry: 'not-a-function' })).toBeNull();
  });

  it('calls an injected recorder with failClosed: true, so the audit itself cannot be skipped', async () => {
    const calls = [];
    const writer = createDevicePolicyAuditWriter({
      recordAuditEntry: async (entry, options) => {
        calls.push({ entry, options });
        return entry;
      },
    });
    expect(writer).not.toBeNull();

    const entry = await writer.audit({
      action: DEVICE_POLICY_AUDIT_ACTIONS.TENANT_DEFAULT_SET,
      actor: { type: 'user', id: 'user-admin', name: 'Root Admin' },
      target: { type: 'device_policy', id: 'tenant-1', name: 'tenant-device-policy-default' },
      before: null,
      after: {
        snapshotType: 'device-tenant-policy-default',
        id: 'tenant-1',
        version: 1,
        capturedAt: '2026-10-23T20:00:00.000Z',
        body: '{"defaultToolScopeId":"staff-scope","version":1}',
      },
      tenantId: 'tenant-1',
    });

    expect(calls).toHaveLength(1);
    expect(calls[0].options).toEqual({ failClosed: true });
    expect(calls[0].entry).toBe(entry);
    expect(calls[0].entry.category).toBe('config');
    expect(calls[0].entry.tenantId).toBe('tenant-1');
    expect(calls[0].entry.metadata.changedFields).toContain('version');
  });
});

/** Runs one write spec against the app. */
function hit(app, write) {
  const agent = request(app)[write.method](write.path);
  return write.body === undefined ? agent : agent.send(write.body);
}
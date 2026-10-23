'use strict';

/**
 * W10 — THE RESOLUTION ORDER, PROVEN AT EVERY LEVEL (GM-76 rule 3, GM-78, GM-79 rules 3–6).
 *
 * `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §2 and
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3/§5/§6 fix the order:
 *
 *     user override  ->  group  ->  role  ->  tenant default  ->  FAIL CLOSED (nothing enabled)
 *
 * Every case below runs through the REAL admin API (route -> handlers -> resolver) against the REAL
 * law (`deviceCapabilityPolicy` + `deviceToolRegistry`), so the invariants are asserted where they
 * are enforced rather than where they are described. The data layer is an in-memory store; the
 * environment shim for `@librechat/agents` is explained in `devicePolicy.spec.js`.
 *
 * The server stage is set to `full` for this file, which is what makes the stage ladder, the pilot
 * deny-list, the approval tier and the narrowing test all observable in one place. A scope may still
 * only narrow it — the `stage` a caller sends is stripped, and a scope declaring a wider stage than
 * the server's is not honoured.
 */

process.env.CBHR_DEVICE_CAPABILITY_STAGE = 'full';

const express = require('express');
const request = require('supertest');
const { authorizeResolvedTool, DEVICE_POLICY_AUDIT_ACTIONS, DEVICE_POLICY_CODES } = require('@librechat/api');
const {
  DEVICE_POLICY_LEVELS,
  hasImpliedCapability,
  SystemCapabilities,
} = require('@librechat/data-schemas');
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
const SECOND_GROUP_ID = '64b7f0c2f1a2b3c4d5e6f7ab';
const OTHER_TENANT_USER_ID = '64b7f0c2f1a2b3c4d5e6f7ac';

const ADMIN_SESSION = { id: 'user-admin', role: 'ADMIN', name: 'Root Admin', tenantId: 'tenant-1' };
const STAFF_SESSION = { id: 'user-staff', role: 'USER', name: 'Staffy', tenantId: 'tenant-1' };

let mockDataLayer = null;
let mockUser = ADMIN_SESSION;

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
    // Derived from the exported ladder, exactly as the route does it.
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

/** A trimmed store: enough for policy resolution, and every write is visible to the test. */
function createFakeDataLayer() {
  const scopes = new Map();
  const assignments = new Map();
  const users = new Map();
  const groups = new Map();
  const roles = new Map();
  const capabilities = new Map();
  const audits = [];
  const state = { writes: 0, tenantDefault: null };
  const assignmentKey = (principalType, principalId) => `${principalType}:${principalId}`;
  const stamp = () => new Date('2026-10-23T20:00:00.000Z');

  const layer = {
    listScopes: async ({ limit = 50, offset = 0 } = {}) =>
      [...scopes.values()].slice(offset, offset + limit),
    countScopes: async () => scopes.size,
    getToolScope: async (id) => scopes.get(id) ?? null,
    upsertToolScope: async (document) => {
      state.writes += 1;
      const saved = { ...document, updatedAt: stamp() };
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
          (filter.principalId === undefined || row.principalId === filter.principalId),
      ),
    getAssignment: async (principalType, principalId) =>
      assignments.get(assignmentKey(principalType, principalId)) ?? null,
    upsertAssignment: async (document) => {
      state.writes += 1;
      const saved = { ...document, updatedAt: stamp() };
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
      return hasImpliedCapability(capabilities.get(String(userPrincipal?.principalId)) ?? [], capability);
    },
    recordAuditEntry: async (entry, options) => {
      audits.push({ entry, options });
      return entry;
    },
  };

  users.set(USER_ID, {
    _id: USER_ID,
    role: 'USER',
    name: 'Staff User',
    groupIds: [GROUP_ID, SECOND_GROUP_ID],
    tenantId: 'tenant-1',
  });
  users.set(OTHER_TENANT_USER_ID, { _id: OTHER_TENANT_USER_ID, role: 'USER', tenantId: 'tenant-2' });
  groups.set(GROUP_ID, { _id: GROUP_ID, name: 'Staff' });
  groups.set(SECOND_GROUP_ID, { _id: SECOND_GROUP_ID, name: 'Contractors' });
  roles.set('USER', { name: 'USER' });
  roles.set('ADMIN', { name: 'ADMIN' });
  capabilities.set('user-admin', [
    SystemCapabilities.ACCESS_ADMIN,
    SystemCapabilities.READ_CONFIGS,
    SystemCapabilities.MANAGE_CONFIGS,
  ]);
  capabilities.set('user-staff', []);

  return { layer, scopes, assignments, users, groups, roles, capabilities, audits, state };
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

/** Creates a scope through the admin API and returns its id. */
async function createScope(app, id, tools, over = {}) {
  const res = await request(app)
    .post(`${BASE}/scopes`)
    .send({ id, name: id, tools, stage: over.stage ?? 'full', ...over });
  expect([id, res.status]).toEqual([id, 201]);
  return id;
}

async function assign(app, principalType, principalId, toolScopeId, over = {}) {
  const res = await request(app)
    .put(`${BASE}/assignments`)
    .send({ principalType, principalId, toolScopeId, ...over });
  expect([`${principalType}:${principalId}`, res.status]).toEqual([
    `${principalType}:${principalId}`,
    over.expectStatus ?? (over.created === false ? 200 : 201),
  ]);
  return res.body.assignment;
}

async function resolveFor(app, userId = USER_ID, query = '') {
  const res = await request(app).get(`${BASE}/resolve-for-principal/${userId}${query}`);
  expect([userId, res.status]).toEqual([userId, 200]);
  return res.body.resolution;
}

const toolsOf = (resolution) => [...resolution.tools];
const traceOutcome = (resolution, level) =>
  resolution.trace.find((row) => row.level === level)?.outcome;
const decisionFor = (resolution, tool) =>
  resolution.decisions.find((row) => row.tool === tool) ?? null;

describe('W10/GM-76 — the resolution order, proven one level at a time', () => {
  /** The four scopes, each naming one more tool than the level below it. */
  async function seedFourLevels(app) {
    await createScope(app, 'tenant-scope', ['read_file', 'list_directory', 'get_file_info', 'list_searches']);
    await createScope(app, 'role-scope', ['read_file', 'list_directory', 'get_file_info']);
    await createScope(app, 'group-scope', ['read_file', 'list_directory']);
    await createScope(app, 'user-scope', ['read_file']);

    await assign(app, 'role', 'USER', 'role-scope');
    await assign(app, 'group', GROUP_ID, 'group-scope');
    await assign(app, 'user', USER_ID, 'user-scope');
    const res = await request(app).put(`${BASE}/tenant-default`).send({ defaultToolScopeId: 'tenant-scope' });
    expect(res.status).toBe(200);
  }

  it('walks user -> group -> role -> tenant, then fails closed, one level per removal', async () => {
    const app = createApp();
    await seedFourLevels(app);

    // 1. USER WINS. The lower levels are not consulted at all: first-match-wins, never a union.
    const atUser = await resolveFor(app);
    expect(atUser.governingLevel).toBe('user');
    expect(atUser.resolvedToolScopeId).toBe('user-scope');
    expect(toolsOf(atUser)).toEqual(['read_file']);
    expect(traceOutcome(atUser, 'user')).toBe('selected');
    for (const level of DEVICE_POLICY_LEVELS.slice(1)) {
      expect(traceOutcome(atUser, level)).toBe('not-requested');
    }
    // The union would have been four tools; `list_directory` is not enabled, because the winning
    // level is the ONLY level that grants (a tool nobody listed has no decision row at all).
    expect(toolsOf(atUser)).not.toContain('list_directory');
    expect(atUser.counts.enabled).toBe(1);

    // 2. GROUP BEATS ROLE (and NARROWS it: three role tools become two, no union).
    await request(app).delete(`${BASE}/assignments/user/${USER_ID}`);
    const atGroup = await resolveFor(app);
    expect(atGroup.governingLevel).toBe('group');
    expect(atGroup.resolvedToolScopeId).toBe('group-scope');
    expect(toolsOf(atGroup)).toEqual(['read_file', 'list_directory']);
    expect(traceOutcome(atGroup, 'group')).toBe('selected');
    expect(traceOutcome(atGroup, 'role')).toBe('not-requested');
    expect(toolsOf(atGroup)).not.toContain('get_file_info');
    expect(atGroup.counts.enabled).toBe(2);

    // 3. ROLE BEATS TENANT.
    await request(app).delete(`${BASE}/assignments/group/${GROUP_ID}`);
    const atRole = await resolveFor(app);
    expect(atRole.governingLevel).toBe('role');
    expect(atRole.resolvedToolScopeId).toBe('role-scope');
    expect(toolsOf(atRole)).toEqual(['read_file', 'list_directory', 'get_file_info']);
    expect(traceOutcome(atRole, 'tenant')).toBe('not-requested');

    // 4. TENANT DEFAULT answers when nothing more specific does.
    await request(app).delete(`${BASE}/assignments/role/USER`);
    const atTenant = await resolveFor(app);
    expect(atTenant.governingLevel).toBe('tenant');
    expect(atTenant.resolvedToolScopeId).toBe('tenant-scope');
    // The report is in CATALOG order (the registry's own order), not in the order the scope listed.
    const catalogNames = deviceCapabilityPolicy.TOOL_CATALOG.map((entry) => entry.name);
    const tenantTools = ['read_file', 'list_directory', 'get_file_info', 'list_searches'];
    expect(toolsOf(atTenant)).toEqual(catalogNames.filter((name) => tenantTools.includes(name)));
    expect([...toolsOf(atTenant)].sort()).toEqual([...tenantTools].sort());

    // 5. NOTHING ANYWHERE -> NOTHING ENABLED (fail closed, GM-74/GM-76).
    const emptied = createFakeDataLayer();
    emptied.state.tenantDefault = null;
    mockDataLayer = emptied.layer;
    const nothing = await resolveFor(createApp());

    expect(nothing.failClosed).toBe(true);
    expect(toolsOf(nothing)).toEqual([]);
    expect(nothing.governingLevel).toBeNull();
    expect(nothing.resolvedToolScopeId).toBeNull();
    expect(nothing.counts.enabled).toBe(0);
    expect(nothing.trace.map((row) => row.outcome)).toEqual([
      'no-assignment',
      'no-assignment',
      'no-assignment',
      'no-assignment',
    ]);
    // Fail-closed is not "an empty list": EVERY catalog tool is reported off, with the reason.
    expect(nothing.decisions).toHaveLength(deviceCapabilityPolicy.TOOL_CATALOG.length);
    for (const row of nothing.decisions) {
      expect([row.tool, row.enabled, row.reasonCode]).toEqual([
        row.tool,
        false,
        DEVICE_POLICY_CODES.NOT_CONFIGURED,
      ]);
    }
    expect(decisionFor(nothing, 'read_file').detail).toMatch(/An admin must assign a tool scope/);
  });

  it('breaks a tie between two assignments at the SAME level deterministically (priority, then id)', async () => {
    const app = createApp();
    await createScope(app, 'group-b-scope', ['read_file']);
    await createScope(app, 'group-scope', ['read_file', 'list_directory']);
    await assign(app, 'group', GROUP_ID, 'group-scope', { priority: 1 });
    await assign(app, 'group', SECOND_GROUP_ID, 'group-b-scope', { priority: 1 });

    const tied = await resolveFor(app);
    expect(tied.governingLevel).toBe('group');
    expect(tied.resolvedToolScopeId).toBe('group-b-scope');

    await assign(app, 'group', GROUP_ID, 'group-scope', { priority: 5, created: false });
    const raised = await resolveFor(app);
    expect(raised.resolvedToolScopeId).toBe('group-scope');
    expect(toolsOf(raised)).toEqual(['read_file', 'list_directory']);
  });

  it('two DIFFERENT requests for the same principal get the same answer (no request-order drift)', async () => {
    const app = createApp();
    await createScope(app, 'role-scope', ['read_file']);
    await assign(app, 'role', 'USER', 'role-scope');

    const [first, second] = await Promise.all([resolveFor(app), resolveFor(app)]);
    expect(first).toEqual(second);
  });
});

describe('W10/GM-79 rule 6 — law outranks policy: two tools stay denied, whatever a scope says', () => {
  it('denies track_ui_event and the feedback tool even when a scope names them', async () => {
    const app = createApp();
    await createScope(app, 'law-scope', [
      'read_file',
      'track_ui_event',
      'give_feedback_to_desktop_commander',
    ]);
    await assign(app, 'user', USER_ID, 'law-scope');

    const resolution = await resolveFor(app);
    expect(toolsOf(resolution)).toEqual(['read_file']);
    expect(toolsOf(resolution)).not.toContain('track_ui_event');
    expect(toolsOf(resolution)).not.toContain('give_feedback_to_desktop_commander');

    // track_ui_event is not a tool at all (it is an internal handler): the scope cannot make it one.
    expect(decisionFor(resolution, 'track_ui_event')).toMatchObject({
      enabled: false,
      requiresApproval: false,
      reasonCode: DEVICE_POLICY_CODES.TOOL_NOT_IN_CATALOG,
      deniedBy: 'law',
    });
    expect(decisionFor(resolution, 'give_feedback_to_desktop_commander')).toMatchObject({
      enabled: false,
      requiresApproval: false,
    });
    expect(resolution.counts.notInCatalog).toBe(1);

    // THE DISPATCH GATE (what W12 calls) refuses both, with tier-1 law's own codes — the scope
    // layer is not what denies them, and it cannot be what allows them.
    const denied = authorizeResolvedTool('track_ui_event', resolution, REAL_PRIMITIVES());
    expect(denied).toMatchObject({ allowed: false, decision: 'denied', code: 'TOOL_NOT_PERMITTED' });
    expect(denied.reasonCode).toBe('always-denied');

    const feedback = authorizeResolvedTool(
      'give_feedback_to_desktop_commander',
      resolution,
      REAL_PRIMITIVES(),
    );
    expect(feedback.allowed).toBe(false);
    expect(feedback.reasonCode).toBe('pilot-denied');

    // A tool the scope DOES grant and the law admits is allowed: the gate is not a blanket refusal.
    expect(authorizeResolvedTool('read_file', resolution, REAL_PRIMITIVES()).allowed).toBe(true);
  });

  it('cannot be widened by a scope that claims a wider stage than the server is at', async () => {
    const app = createApp();
    // Server stage is `full` in this file; a scope may narrow it and never widen it. The other
    // direction (scope wider than the server) is covered in `devicePolicy.spec.js`, where the
    // server default is the narrowest stage.
    await createScope(app, 'narrow-scope', ['read_file', 'write_file', 'start_process'], {
      stage: 'A',
    });
    await assign(app, 'user', USER_ID, 'narrow-scope');

    const resolution = await resolveFor(app);
    expect(resolution.stage).toBe('A');
    expect(toolsOf(resolution)).toEqual(['read_file']);
    // `write_file` is stage B and `start_process` is stage C: both are refused by the ladder.
    for (const tool of ['write_file', 'start_process']) {
      expect(decisionFor(resolution, tool).enabled).toBe(false);
      expect(authorizeResolvedTool(tool, resolution, REAL_PRIMITIVES()).allowed).toBe(false);
    }
  });
});

describe('W10/GM-79 rule 5 — the approval gate survives any scope', () => {
  it('keeps the owner-approval tools gated when a scope lists them, and law-denied ones refused', async () => {
    const app = createApp();
    const approvalTools = [...deviceCapabilityPolicy.OWNER_APPROVAL_TOOLS];
    // Read from the law, not restated: one of the four is also denied outright during the pilot.
    const deniedByLaw = new Set(deviceCapabilityPolicy.deniedToolNames({ stage: 'full', pilot: true }));
    const gatedTools = approvalTools.filter((tool) => !deniedByLaw.has(tool));
    const lawDeniedGated = approvalTools.filter((tool) => deniedByLaw.has(tool));

    expect(gatedTools.length).toBeGreaterThan(0);
    expect(lawDeniedGated.length + gatedTools.length).toBe(approvalTools.length);

    await createScope(app, 'ops-scope', ['read_file', ...approvalTools]);
    await assign(app, 'user', USER_ID, 'ops-scope');

    const resolution = await resolveFor(app);
    for (const tool of gatedTools) {
      expect(toolsOf(resolution)).toContain(tool);
      expect([...resolution.approvalRequired]).toContain(tool);
      expect(decisionFor(resolution, tool)).toMatchObject({
        enabled: true,
        requiresApproval: true,
        reasonCode: 'OWNER_APPROVAL_REQUIRED',
      });
      const gate = authorizeResolvedTool(tool, resolution, REAL_PRIMITIVES());
      expect(gate).toMatchObject({ allowed: true, requiresApproval: true, decision: 'approval-required' });
      expect(gate.code).toBe('OWNER_APPROVAL_REQUIRED');
    }
    // A scope can grant an approval-gated tool; it can NEVER drop the gate or turn it into a plain
    // allow. The law-denied member of the four is refused entirely — either way, never a plain allow.
    for (const tool of lawDeniedGated) {
      expect(toolsOf(resolution)).not.toContain(tool);
      const gate = authorizeResolvedTool(tool, resolution, REAL_PRIMITIVES());
      expect(gate.allowed).toBe(false);
      expect(gate.requiresApproval).toBe(false);
    }

    expect(authorizeResolvedTool('read_file', resolution, REAL_PRIMITIVES())).toMatchObject({
      allowed: true,
      requiresApproval: false,
    });
  });
});

describe('W10/GM-78 rule 4 + GM-79 rule 4 — a stale policyVersion cannot escape a downgrade', () => {
  it('serves the CURRENT policy, with a version that changes when the policy changes', async () => {
    const app = createApp();
    await createScope(app, 'wide-scope', ['read_file', 'list_directory', 'get_file_info']);
    await assign(app, 'user', USER_ID, 'wide-scope');

    const before = await resolveFor(app);
    expect(toolsOf(before)).toEqual(['read_file', 'list_directory', 'get_file_info']);

    // Deterministic: the same policy always yields the same version.
    expect((await resolveFor(app)).policyVersion).toBe(before.policyVersion);

    // The admin downgrades the scope: the content-derived version must move.
    await request(app)
      .put(`${BASE}/scopes/wide-scope`)
      .send({ name: 'wide-scope', tools: ['read_file'], stage: 'full' });
    const after = await resolveFor(app);
    expect(toolsOf(after)).toEqual(['read_file']);
    expect(after.policyVersion).not.toBe(before.policyVersion);

    // A device holding the OLD document asks for it back, with every spelling a device can assert.
    const stale = await resolveFor(
      app,
      USER_ID,
      `?policyVersion=${before.policyVersion}&version=1&tools=read_file,list_directory,get_file_info` +
        `&enabled=read_file&deviceFloor=%5B%22read_file%22%5D&ceiling=%7B%22stage%22%3A%22full%22%7D` +
        `&stage=full&pilot=false&toolScopeId=wide-scope&allow=true`,
    );

    expect(stale.policyVersion).toBe(after.policyVersion);
    expect(toolsOf(stale)).toEqual(['read_file']);
    expect(stale).not.toEqual(before);
    expect(authorizeResolvedTool('list_directory', stale, REAL_PRIMITIVES()).allowed).toBe(false);
  });

  it('changes the version when a scope is RETIRED, and retiring fails closed', async () => {
    const app = createApp();
    await createScope(app, 'live-scope', ['read_file']);
    await assign(app, 'user', USER_ID, 'live-scope');
    const live = await resolveFor(app);

    await request(app)
      .put(`${BASE}/scopes/live-scope`)
      .send({ name: 'live-scope', tools: ['read_file'], stage: 'full', isActive: false });
    const retired = await resolveFor(app);

    expect(retired.failClosed).toBe(true);
    expect(toolsOf(retired)).toEqual([]);
    expect(retired.policyVersion).not.toBe(live.policyVersion);
  });

  it('strips every device-asserted policy hint from the self-service read, changing nothing', async () => {
    const app = createApp();
    await createScope(app, 'self-scope', ['read_file']);
    // Assigned to the ROLE the staff session holds, so the self read resolves through the session.
    await assign(app, 'role', 'USER', 'self-scope');
    mockUser = STAFF_SESSION;

    const clean = await request(app).get(`${BASE}/resolve-self`);
    expect(clean.status).toBe(200);
    expect(toolsOf(clean.body.resolution)).toEqual(['read_file']);

    const forged = await request(app).get(
      `${BASE}/resolve-self?tools=read_file,list_directory&enabled=write_file` +
        `&deviceFloor=%7B%22enabled%22%3A%5B%22write_file%22%5D%7D&policyVersion=stale` +
        `&ceiling=%7B%22stage%22%3A%22full%22%7D&stage=full&pilot=false&toolScopeId=tenant-scope` +
        `&allow=true&grants=all`,
    );
    expect(forged.status).toBe(200);
    // The strong invariant first: the answer is IDENTICAL to the clean request, so no hint — owned
    // by the guard or not — had any effect. (A spelling outside the guard's own list is inert for a
    // second reason: the self read looks at no query field at all.)
    expect(forged.body.resolution).toEqual(clean.body.resolution);
    expect(forged.body.ignoredFields).toEqual(
      expect.arrayContaining([
        'tools',
        'enabled',
        'policyVersion',
        'ceiling',
        'stage',
        'pilot',
        'toolScopeId',
      ]),
    );
  });
});

describe('W10/GM-79 rule 3 — no claim can raise a resolution', () => {
  it('resolves the principal’s DATABASE role, not the role asserted in the request', async () => {
    const app = createApp();
    await createScope(app, 'admin-wide-scope', ['read_file', 'list_directory', 'get_file_info']);
    await createScope(app, 'user-scope', ['read_file']);
    await assign(app, 'role', 'ADMIN', 'admin-wide-scope');
    await assign(app, 'role', 'USER', 'user-scope');

    const honest = await resolveFor(app);
    expect(honest.governingLevel).toBe('role');
    expect(honest.resolvedToolScopeId).toBe('user-scope');

    // A claimed role, claimed group and a claimed scope: all stripped, none honoured.
    const claimed = await resolveFor(
      app,
      USER_ID,
      `?role=ADMIN&roles=ADMIN&groups=${GROUP_ID}&groupIds=${GROUP_ID}&capabilities=access:admin` +
        `&toolScopeId=admin-wide-scope&toolScope=admin-wide-scope&isAdmin=true&tenantId=tenant-2`,
    );
    expect(claimed).toEqual(honest);
    expect(claimed.resolvedToolScopeId).toBe('user-scope');
    expect(toolsOf(claimed)).toEqual(['read_file']);
  });

  it('refuses cross-tenant inspection with 403 (the policy documents are tenant-scoped)', async () => {
    const res = await request(createApp()).get(
      `${BASE}/resolve-for-principal/${OTHER_TENANT_USER_ID}`,
    );
    expect(res.status).toBe(403);
    expect(res.body).toEqual({
      error: 'Cannot resolve device policy for a principal in another tenant',
    });
  });

  it('leaves the identity alone for the self-service read as well (session, never query)', async () => {
    const app = createApp();
    await createScope(app, 'staff-scope', ['read_file']);
    await createScope(app, 'admin-scope', ['read_file', 'list_directory', 'get_file_info']);
    await assign(app, 'role', 'USER', 'staff-scope');
    await assign(app, 'role', 'ADMIN', 'admin-scope');
    mockUser = { ...STAFF_SESSION, role: 'USER' };

    const res = await request(app).get(`${BASE}/resolve-self?role=ADMIN&toolScopeId=admin-scope`);
    expect(res.status).toBe(200);
    expect(res.body.resolution.resolvedToolScopeId).toBe('staff-scope');
    expect(toolsOf(res.body.resolution)).toEqual(['read_file']);
  });
});

describe('W10 — a broken narrow scope STOPS the walk and does not fall through to a wider one', () => {
  /** A group scope that WOULD answer if the user level were skipped. */
  async function seedWiderFallback(app) {
    await createScope(app, 'group-wide-scope', ['read_file', 'list_directory', 'get_file_info']);
    await assign(app, 'group', GROUP_ID, 'group-wide-scope');
  }

  it('a DANGLING user scope fails closed: the group below it is not consulted', async () => {
    const app = createApp();
    await seedWiderFallback(app);
    // Seeded directly: the API refuses to create this state (404), which is its own guarantee.
    fake.assignments.set(`user:${USER_ID}`, {
      principalType: 'user',
      principalId: USER_ID,
      toolScopeId: 'ghost-scope',
      priority: 0,
      isActive: true,
    });

    const resolution = await resolveFor(app);
    expect(resolution.failClosed).toBe(true);
    expect(toolsOf(resolution)).toEqual([]);
    expect(resolution.governingLevel).toBeNull();
    expect(resolution.resolvedToolScopeId).toBe('ghost-scope');
    expect(traceOutcome(resolution, 'user')).toBe('scope-missing');
    expect(traceOutcome(resolution, 'group')).toBe('not-requested');
    expect(decisionFor(resolution, 'read_file').reasonCode).toBe(DEVICE_POLICY_CODES.SCOPE_UNKNOWN);
    expect(decisionFor(resolution, 'read_file').deniedBy).toBe('user');
  });

  it('an INACTIVE user scope fails closed: a retired scope is a decision, not an absence', async () => {
    const app = createApp();
    await seedWiderFallback(app);
    await createScope(app, 'retired-scope', ['read_file'], { isActive: false });
    await assign(app, 'user', USER_ID, 'retired-scope');

    const resolution = await resolveFor(app);
    expect(resolution.failClosed).toBe(true);
    expect(toolsOf(resolution)).toEqual([]);
    expect(traceOutcome(resolution, 'user')).toBe('scope-inactive');
    expect(traceOutcome(resolution, 'group')).toBe('not-requested');
    expect(decisionFor(resolution, 'read_file').reasonCode).toBe(DEVICE_POLICY_CODES.SCOPE_INACTIVE);
  });

  it('a MALFORMED user scope fails closed: unreadable data is never guessed at', async () => {
    const app = createApp();
    await seedWiderFallback(app);
    // A stored row with no usable id: the resolver cannot read it as a scope.
    fake.scopes.set('broken-scope', { name: 'Broken', tools: ['read_file'], stage: 'full' });
    fake.assignments.set(`user:${USER_ID}`, {
      principalType: 'user',
      principalId: USER_ID,
      toolScopeId: 'broken-scope',
      priority: 0,
      isActive: true,
    });

    const resolution = await resolveFor(app);
    expect(resolution.failClosed).toBe(true);
    expect(toolsOf(resolution)).toEqual([]);
    expect(traceOutcome(resolution, 'user')).toBe('scope-malformed');
    expect(traceOutcome(resolution, 'group')).toBe('not-requested');
    expect(decisionFor(resolution, 'read_file').reasonCode).toBe(
      DEVICE_POLICY_CODES.SCOPE_MALFORMED,
    );
  });

  it('does not fall through when the broken scope is the TENANT default (the last level)', async () => {
    const app = createApp();
    fake.state.tenantDefault = { defaultToolScopeId: 'ghost-scope', version: 1 };
    await createScope(app, 'group-wide-scope', ['read_file']);
    await assign(app, 'group', GROUP_ID, 'group-wide-scope');

    // The group level answers here, and the tenant level is not consulted — the walk stops at the
    // first usable level, and a dangling tenant default only matters when it IS the first.
    expect((await resolveFor(app)).governingLevel).toBe('group');

    await request(app).delete(`${BASE}/assignments/group/${GROUP_ID}`);
    const tenantOnly = await resolveFor(app);
    expect(tenantOnly.failClosed).toBe(true);
    expect(traceOutcome(tenantOnly, 'tenant')).toBe('scope-missing');
  });
});

describe('W10 — reads are unaffected by the audit seam, and the resolution is explainable', () => {
  it('answers the resolution report with the trace, the provenance and the reasons', async () => {
    const app = createApp();
    await createScope(app, 'explain-scope', ['read_file']);
    await assign(app, 'user', USER_ID, 'explain-scope');

    const resolution = await resolveFor(app);
    expect(resolution.schema).toBe('cbhr.rdc.device-policy-resolution/1');
    expect(resolution.trace).toHaveLength(DEVICE_POLICY_LEVELS.length);
    expect(resolution.provenance).toEqual([
      expect.objectContaining({
        tool: 'read_file',
        level: 'user',
        toolScopeId: 'explain-scope',
        decision: 'scope',
        requiresApproval: false,
      }),
    ]);
    expect(resolution.stage).toBe('full');
    // The report is self-consistent and complete for what the scope considered: every enabled row is
    // in `tools`, every tool in `tools` has a row, and the counts are the rows' own arithmetic.
    const decided = resolution.decisions.map((row) => row.tool);
    for (const row of resolution.decisions) {
      if (row.enabled) {
        expect(toolsOf(resolution)).toContain(row.tool);
      }
    }
    for (const tool of toolsOf(resolution)) {
      expect(decided).toContain(tool);
    }
    expect(resolution.counts.enabled).toBe(toolsOf(resolution).length);
    expect(resolution.counts.denied).toBe(resolution.decisions.filter((row) => !row.enabled).length);
    // And a tool the winning scope did not list is off, everywhere, always.
    expect(toolsOf(resolution)).not.toContain('write_file');
  });

  it('audits nothing on a read, and records every write it performs while seeding', async () => {
    const app = createApp();
    await createScope(app, 'audit-scope', ['read_file']);
    await assign(app, 'user', USER_ID, 'audit-scope');
    await resolveFor(app);

    expect(fake.audits.map((row) => row.entry.action)).toEqual([
      DEVICE_POLICY_AUDIT_ACTIONS.SCOPE_CREATED,
      DEVICE_POLICY_AUDIT_ACTIONS.ASSIGNMENT_SET,
    ]);
  });
});
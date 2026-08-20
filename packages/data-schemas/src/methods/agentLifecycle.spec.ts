import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { AccessRoleIds, ResourceType } from 'librechat-data-provider';
import type { IAgent, IAclEntry, IUser, IAccessRole } from '..';
import { createAgentMethods, type AgentMethods } from './agent';
import { createAclEntryMethods } from './aclEntry';
import { createModels } from '~/models';

jest.mock('~/config/winston', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
}));

let mongoServer: InstanceType<typeof MongoMemoryServer>;
let Agent: mongoose.Model<IAgent>;
let AclEntry: mongoose.Model<IAclEntry>;
let modelsToCleanup: string[] = [];

let createAgent: AgentMethods['createAgent'];
let getAgent: AgentMethods['getAgent'];
let updateAgent: AgentMethods['updateAgent'];
let archiveAgent: AgentMethods['archiveAgent'];
let restoreAgent: AgentMethods['restoreAgent'];
let diffAgentVersions: AgentMethods['diffAgentVersions'];

const getActions = jest.fn().mockResolvedValue([]);

function createTestIds() {
  return {
    agentId: `agent_${uuidv4()}`,
    authorId: new mongoose.Types.ObjectId(),
  };
}

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();

  const models = createModels(mongoose);
  modelsToCleanup = Object.keys(models);
  Agent = mongoose.models.Agent as mongoose.Model<IAgent>;
  AclEntry = mongoose.models.AclEntry as mongoose.Model<IAclEntry>;
  const User = mongoose.models.User as mongoose.Model<IUser>;
  const AccessRole = mongoose.models.AccessRole as mongoose.Model<IAccessRole>;
  void User;

  const removeAllPermissions = async ({
    resourceType,
    resourceId,
  }: {
    resourceType: string;
    resourceId: unknown;
  }) => {
    await AclEntry.deleteMany({ resourceType, resourceId });
  };

  const aclEntryMethods = createAclEntryMethods(mongoose);
  const { getSoleOwnedResourceIds } = aclEntryMethods;

  const methods = createAgentMethods(mongoose, {
    removeAllPermissions,
    getActions,
    getSoleOwnedResourceIds,
  });
  createAgent = methods.createAgent;
  getAgent = methods.getAgent;
  updateAgent = methods.updateAgent;
  archiveAgent = methods.archiveAgent;
  restoreAgent = methods.restoreAgent;
  diffAgentVersions = methods.diffAgentVersions;

  await mongoose.connect(mongoUri);

  await AccessRole.create({
    accessRoleId: AccessRoleIds.AGENT_OWNER,
    name: 'Owner',
    description: 'Full control over agents',
    resourceType: ResourceType.AGENT,
    permBits: 15,
  });
}, 30000);

afterAll(async () => {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany({});
  }
  for (const modelName of modelsToCleanup) {
    if (mongoose.models[modelName]) {
      delete (mongoose.models as Record<string, unknown>)[modelName];
    }
  }
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await Agent.deleteMany({});
});

describe('archiveAgent / restoreAgent (8S5 lifecycle)', () => {
  test('archiveAgent sets lifecycle_state=archived, archivedAt, archivedBy', async () => {
    const { agentId, authorId } = createTestIds();
    await createAgent({ id: agentId, name: 'A', provider: 'test', model: 'm', author: authorId });
    const actingUserId = new mongoose.Types.ObjectId().toString();

    const archived = await archiveAgent({ id: agentId }, actingUserId);

    expect(archived).toBeDefined();
    expect(archived!.lifecycle_state).toBe('archived');
    expect(archived!.archivedAt).toBeInstanceOf(Date);
    expect(String(archived!.archivedBy)).toBe(actingUserId);
  });

  test('restoreAgent sets lifecycle_state=active and clears archivedAt/archivedBy', async () => {
    const { agentId, authorId } = createTestIds();
    await createAgent({ id: agentId, name: 'A', provider: 'test', model: 'm', author: authorId });
    const actingUserId = new mongoose.Types.ObjectId().toString();
    await archiveAgent({ id: agentId }, actingUserId);

    const restored = await restoreAgent({ id: agentId }, actingUserId);

    expect(restored!.lifecycle_state).toBe('active');
    expect(restored!.archivedAt == null).toBe(true);
    expect(restored!.archivedBy == null).toBe(true);
  });

  test('archive/restore do NOT push a version snapshot (skipVersioning) — lifecycle is not behavioral', async () => {
    const { agentId, authorId } = createTestIds();
    const created = await createAgent({
      id: agentId,
      name: 'A',
      provider: 'test',
      model: 'm',
      author: authorId,
    });
    const versionCountBefore = created.versions ? created.versions.length : 0;
    const actingUserId = new mongoose.Types.ObjectId().toString();

    const archived = await archiveAgent({ id: agentId }, actingUserId);
    expect(archived!.versions ? archived!.versions.length : 0).toBe(versionCountBefore);

    const restored = await restoreAgent({ id: agentId }, actingUserId);
    expect(restored!.versions ? restored!.versions.length : 0).toBe(versionCountBefore);
  });

  test('a behavioral updateAgent call after restore still versions normally (lifecycle fields do not poison versioning)', async () => {
    const { agentId, authorId } = createTestIds();
    const created = await createAgent({
      id: agentId,
      name: 'A',
      provider: 'test',
      model: 'm',
      author: authorId,
      instructions: 'v1 instructions',
    });
    const versionCountBefore = created.versions ? created.versions.length : 0;
    const actingUserId = new mongoose.Types.ObjectId().toString();
    await archiveAgent({ id: agentId }, actingUserId);
    await restoreAgent({ id: agentId }, actingUserId);

    const updated = await updateAgent(
      { id: agentId },
      { instructions: 'v2 instructions' },
      { updatingUserId: actingUserId },
    );
    expect(updated!.versions!.length).toBeGreaterThan(versionCountBefore);
  });

  test('archiveAgent on a non-existent agent resolves to null, not throw', async () => {
    const actingUserId = new mongoose.Types.ObjectId().toString();
    const result = await archiveAgent({ id: 'agent_does_not_exist' }, actingUserId);
    expect(result).toBeNull();
  });
});

describe('diffAgentVersions (8S5)', () => {
  test('returns empty array for identical snapshots', () => {
    const snap = { name: 'A', model: 'gpt', instructions: 'do things', tools: ['web_search'] };
    expect(diffAgentVersions(snap, { ...snap })).toEqual([]);
  });

  test('detects a change in a scalar behavioral field (instructions)', () => {
    const a = { instructions: 'old' };
    const b = { instructions: 'new' };
    const changes = diffAgentVersions(a, b);
    expect(changes).toEqual([{ field: 'instructions', before: 'old', after: 'new' }]);
  });

  test('detects a change in an array behavioral field (tools)', () => {
    const a = { tools: ['web_search'] };
    const b = { tools: ['web_search', 'execute_code'] };
    const changes = diffAgentVersions(a, b);
    expect(changes).toEqual([
      { field: 'tools', before: ['web_search'], after: ['web_search', 'execute_code'] },
    ]);
  });

  test('detects a change in an object behavioral field (model_parameters)', () => {
    const a = { model_parameters: { temperature: 0.5 } };
    const b = { model_parameters: { temperature: 0.9 } };
    const changes = diffAgentVersions(a, b);
    expect(changes).toHaveLength(1);
    expect(changes[0].field).toBe('model_parameters');
  });

  test('ignores non-behavioral / internal fields entirely (never appear even when they differ)', () => {
    const a = {
      _id: 'aaa',
      __v: 0,
      updatedAt: new Date('2026-01-01'),
      createdAt: new Date('2020-01-01'),
      author: 'user_a',
      name: 'same',
    };
    const b = {
      _id: 'bbb',
      __v: 5,
      updatedAt: new Date('2026-06-01'),
      createdAt: new Date('2020-01-01'),
      author: 'user_b',
      name: 'same',
    };
    const changes = diffAgentVersions(a, b);
    expect(changes).toEqual([]);
  });

  test('reports multiple simultaneous field changes', () => {
    const a = { name: 'A', model: 'm1', recursion_limit: 5 };
    const b = { name: 'B', model: 'm2', recursion_limit: 10 };
    const changes = diffAgentVersions(a, b);
    const fields = changes.map((c) => c.field).sort();
    expect(fields).toEqual(['model', 'name', 'recursion_limit']);
  });

  test('treats undefined and null as equivalent "absent" for a field (no spurious diff)', () => {
    const a = { description: undefined };
    const b = { description: null };
    expect(diffAgentVersions(a, b)).toEqual([]);
  });

  test('works end-to-end against real stored version snapshots from updateAgent', async () => {
    const { agentId, authorId } = createTestIds();
    await createAgent({
      id: agentId,
      name: 'A',
      provider: 'test',
      model: 'm1',
      author: authorId,
      instructions: 'v1',
    });
    const actingUserId = new mongoose.Types.ObjectId().toString();
    const updated = await updateAgent(
      { id: agentId },
      { instructions: 'v2' },
      { updatingUserId: actingUserId },
    );
    const versions = updated!.versions!;
    const changes = diffAgentVersions(versions[0], versions[versions.length - 1]);
    const instructionsChange = changes.find((c) => c.field === 'instructions');
    expect(instructionsChange).toBeDefined();
    expect(instructionsChange!.before).toBe('v1');
    expect(instructionsChange!.after).toBe('v2');
  });
});

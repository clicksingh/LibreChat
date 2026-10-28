import mongoose from 'mongoose';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { createModels, createMethods, runAsSystem } from '@librechat/data-schemas';
import type { ModelPolicyCommitDeps } from './publisher';
import { commitManagedModelPolicy } from './publisher';

const AUDIENCES = { USER: 'locked-current-default', ADMIN: 'managed-catalog' } as const;
const payload = (expectedVersion: number, model = 'model-alpha') => ({
  expectedVersion,
  endpointName: 'CBHR AI',
  actor: 'isolated-transaction-test',
  source: 'jest-replica-set',
  policy: {
    companyDefaultDeploymentId: 'deployment-alpha',
    deployments: [{ deploymentId: 'deployment-alpha', model }],
    audiences: AUDIENCES,
  },
});

describe('real replica-set managed-model policy transactions', () => {
  let replica: MongoMemoryReplSet;
  type ModelPolicyDb = ReturnType<typeof createMethods> & {
    getModelPolicyHead: (tenantId: string) => Promise<{ tenantId: string; version: number } | null>;
    getModelPolicyRevision: (tenantId: string, version: number) => Promise<object | null>;
    commitModelPolicyRevision: ModelPolicyCommitDeps['commitModelPolicyRevision'];
    listActiveNonRoleConfigsForTenant: ModelPolicyCommitDeps['listActiveNonRoleConfigsForTenant'];
  };
  let db: ModelPolicyDb;
  let invalidations = 0;

  beforeAll(async () => {
    replica = await MongoMemoryReplSet.create({
      replSet: { count: 1, storageEngine: 'wiredTiger' },
    });
    await mongoose.connect(replica.getUri('cbhr_model_policy_unit_isolation'));
    createModels(mongoose);
    await Promise.all([
      mongoose.models.ModelPolicyHead.init(),
      mongoose.models.ModelPolicyRevision.init(),
      mongoose.models.Config.init(),
    ]);
    db = createMethods(mongoose) as ModelPolicyDb;
  }, 120000);

  afterAll(async () => {
    await mongoose.disconnect();
    if (replica) await replica.stop();
  }, 120000);

  function depsFor(tenantId: string): ModelPolicyCommitDeps {
    return {
      findConfigByPrincipal: db.findConfigByPrincipal,
      listActiveNonRoleConfigsForTenant: db.listActiveNonRoleConfigsForTenant,
      patchConfigFields: db.patchConfigFields,
      commitModelPolicyRevision: db.commitModelPolicyRevision,
      startSession: () => mongoose.startSession(),
      invalidateConfigCaches: async () => {
        invalidations += 1;
      },
      tenantId,
      baseAppConfig: {
        endpoints: {
          custom: [
            {
              name: 'CBHR AI',
              default: true,
              apiKey: 'synthetic-qa-service-key',
              baseURL: 'http://qa-bridge.internal/v1',
              models: { default: ['legacy'] },
            },
          ],
        },
      },
    } as unknown as ModelPolicyCommitDeps;
  }

  it('independently commits version one for two tenants in the same replica set', async () => {
    await runAsSystem(async () => {
      const alpha = await commitManagedModelPolicy(payload(0), depsFor('synthetic-tenant-alpha'));
      const beta = await commitManagedModelPolicy(payload(0), depsFor('synthetic-tenant-beta'));
      expect(alpha.policyVersion).toBe(1);
      expect(beta.policyVersion).toBe(1);
      expect(alpha.transition).toBe('create');
      expect(beta.transition).toBe('create');
      const headAlpha = await db.getModelPolicyHead('synthetic-tenant-alpha');
      const headBeta = await db.getModelPolicyHead('synthetic-tenant-beta');
      expect(headAlpha?.tenantId).toBe('synthetic-tenant-alpha');
      expect(headBeta?.tenantId).toBe('synthetic-tenant-beta');
      expect(await db.getModelPolicyRevision('synthetic-tenant-alpha', 1)).not.toBeNull();
      expect(await db.getModelPolicyRevision('synthetic-tenant-beta', 1)).not.toBeNull();
      expect(await db.getModelPolicyRevision('synthetic-tenant-absent', 1)).toBeNull();
    });
  }, 120000);

  it('rolls back canonical version and Config projections on mid-transaction failure', async () => {
    await runAsSystem(async () => {
      const normal = depsFor('synthetic-tenant-alpha');
      const failing: ModelPolicyCommitDeps = {
        ...normal,
        patchConfigFields: async (...args) => {
          if (args[1] === 'ADMIN') throw new Error('synthetic ADMIN patch failure');
          return normal.patchConfigFields(...args);
        },
      };
      const revisionBefore = await db.getModelPolicyHead('synthetic-tenant-alpha');
      const invalidationsBefore = invalidations;
      await expect(commitManagedModelPolicy(payload(1, 'model-beta'), failing)).rejects.toThrow(
        'synthetic ADMIN patch failure',
      );
      const revisionAfter = await db.getModelPolicyHead('synthetic-tenant-alpha');
      expect(revisionAfter?.version).toBe(revisionBefore?.version);
      expect(await db.getModelPolicyRevision('synthetic-tenant-alpha', 2)).toBeNull();
      expect(invalidations).toBe(invalidationsBefore);
    });
  }, 120000);

  it('records model rebinding at version two and prevents stale version-one reversal', async () => {
    await runAsSystem(async () => {
      const deps = depsFor('synthetic-tenant-beta');
      const changed = await commitManagedModelPolicy(payload(1, 'model-beta'), deps);
      expect(changed.policyVersion).toBe(2);
      expect(changed.policyNoop).toBe(false);
      const revision = (await db.getModelPolicyRevision('synthetic-tenant-beta', 2)) as {
        routing?: { endpointName?: string; deployments?: Array<{ model: string }> };
      } | null;
      expect(revision?.routing?.endpointName).toBe('CBHR AI');
      expect(revision?.routing?.deployments?.[0]?.model).toBe('model-beta');
      await expect(commitManagedModelPolicy(payload(1, 'model-alpha'), deps)).rejects.toMatchObject(
        { code: 'MODEL_POLICY_REVISION_CONFLICT' },
      );
      expect((await db.getModelPolicyHead('synthetic-tenant-beta'))?.version).toBe(2);
    });
  }, 120000);
});

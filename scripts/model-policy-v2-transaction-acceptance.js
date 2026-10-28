#!/usr/bin/env node
'use strict';

const mongoose = require('mongoose');
const { createModels, createMethods, runAsSystem } = require('@librechat/data-schemas');
const { commitManagedModelPolicy } = require('../api/server/services/Config/modelPolicyPublisher');

const ACCEPTANCE_DB_PATTERN = /^cbhr_model_policy_acceptance_[A-Za-z0-9_-]{1,80}$/;
const AUDIENCES = {
  USER: 'locked-current-default',
  ADMIN: 'managed-catalog',
};
const DEPLOYMENTS = {
  alpha: { deploymentId: 'deployment-alpha', model: 'stage-alpha' },
  beta: { deploymentId: 'deployment-beta', model: 'stage-beta' },
};

function acceptanceUri(baseUri, dbName) {
  const uri = new URL(baseUri);
  uri.pathname = `/${dbName}`;
  return uri.toString();
}

function payload({ expectedVersion, defaultKey, order }) {
  return {
    expectedVersion,
    endpointName: 'CBHR AI',
    actor: 'stage-acceptance',
    source: 'transaction-acceptance',
    policy: {
      companyDefaultDeploymentId: DEPLOYMENTS[defaultKey].deploymentId,
      deployments: order.map((key) => DEPLOYMENTS[key]),
      audiences: AUDIENCES,
    },
  };
}

function managedEndpoint(doc) {
  return doc?.overrides?.endpoints?.custom?.find((item) => item?.name === 'CBHR AI');
}

async function readPolicy(db, tenantId) {
  const head = await db.getModelPolicyHead(tenantId);
  const revision = head ? await db.getModelPolicyRevision(tenantId, head.version) : null;
  return { head, revision };
}

async function main() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  const dbName = process.env.MODEL_POLICY_ACCEPTANCE_DB;
  if (!ACCEPTANCE_DB_PATTERN.test(dbName || '')) {
    throw new Error(
      'MODEL_POLICY_ACCEPTANCE_DB must match cbhr_model_policy_acceptance_<suffix>; refusing unsafe database',
    );
  }

  await mongoose.connect(acceptanceUri(process.env.MONGO_URI, dbName));
  if (mongoose.connection.name !== dbName) {
    throw new Error(
      'Connected database does not match the explicitly authorized acceptance database',
    );
  }

  createModels(mongoose);
  await Promise.all(Object.values(mongoose.models).map((model) => model.init()));
  const db = createMethods(mongoose);
  let invalidations = 0;
  const deps = {
    findConfigByPrincipal: db.findConfigByPrincipal,
    patchConfigFields: db.patchConfigFields,
    commitModelPolicyRevision: db.commitModelPolicyRevision,
    invalidateConfigCaches: async () => {
      invalidations += 1;
    },
    startSession: () => mongoose.startSession(),
    tenantId: 'synthetic-qa-tenant',
    baseAppConfig: {
      endpoints: {
        custom: [
          {
            name: 'CBHR AI',
            apiKey: 'qa-only-service-key',
            baseURL: 'http://bridge.internal',
            models: { default: ['legacy'] },
          },
        ],
      },
    },
  };

  await runAsSystem(async () => {
    await db.upsertConfig(
      'role',
      '__base__',
      'Role',
      {
        endpoints: {
          custom: [
            { name: 'Other API', baseURL: 'http://other.internal' },
            {
              name: 'CBHR AI',
              baseURL: 'http://bridge.internal',
              tokenConfig: { keep: true },
              models: { default: ['legacy'] },
            },
          ],
        },
      },
      10,
    );
    await db.upsertConfig(
      'role',
      'USER',
      'Role',
      { interface: { modelSelect: true, fileSearch: true } },
      20,
    );
    await db.upsertConfig(
      'role',
      'ADMIN',
      'Role',
      {
        endpoints: {
          custom: [
            {
              name: 'CBHR AI',
              customParams: { unrelatedFlag: true, reasoningProfiles: { keep: {} } },
              models: { default: ['legacy'] },
            },
          ],
        },
      },
      20,
    );

    // This script is restricted above to an isolated throwaway database.
    // Seed the same explicit tenant that the service-side publisher binds.
    const tagged = await mongoose.connection.db
      .collection('configs')
      .updateMany(
        { principalType: 'role', principalId: { $in: ['__base__', 'USER', 'ADMIN'] } },
        { $set: { tenantId: deps.tenantId } },
      );
    if (tagged.matchedCount !== 3) throw new Error('Synthetic tenant fixture incomplete');

    const first = await commitManagedModelPolicy(
      payload({ expectedVersion: 0, defaultKey: 'alpha', order: ['alpha', 'beta'] }),
      deps,
    );
    const policy1 = await readPolicy(db, deps.tenantId);
    const base1 = await db.findConfigByPrincipal('role', '__base__', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });
    const user1 = await db.findConfigByPrincipal('role', 'USER', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });
    const admin1 = await db.findConfigByPrincipal('role', 'ADMIN', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });

    if (
      first.transition !== 'create' ||
      first.policyVersion !== 1 ||
      policy1.head?.version !== 1 ||
      policy1.revision?.companyDefaultDeploymentId !== DEPLOYMENTS.alpha.deploymentId ||
      invalidations !== 1
    ) {
      throw new Error('initial canonical policy commit failed');
    }
    if (managedEndpoint(base1).models.default[0] !== 'stage-alpha') {
      throw new Error('base default mismatch');
    }
    if (
      user1.overrides.interface.modelSelect !== false ||
      user1.overrides.interface.fileSearch !== true
    ) {
      throw new Error('USER projection/preservation mismatch');
    }
    if (managedEndpoint(admin1)?.customParams?.unrelatedFlag !== true) {
      throw new Error('ADMIN unrelated params lost');
    }
    if (
      base1.overrides.endpoints.custom.find((item) => item.name === 'Other API')?.baseURL !==
      'http://other.internal'
    ) {
      throw new Error('unrelated endpoint lost');
    }

    const firstVersions = {
      base: base1.configVersion,
      user: user1.configVersion,
      admin: admin1.configVersion,
    };
    const retry = await commitManagedModelPolicy(
      payload({ expectedVersion: 1, defaultKey: 'alpha', order: ['alpha', 'beta'] }),
      deps,
    );
    const baseRetry = await db.findConfigByPrincipal('role', '__base__', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });
    const policyRetry = await readPolicy(db, deps.tenantId);
    if (
      retry.transition !== 'noop' ||
      retry.policyNoop !== true ||
      policyRetry.head?.version !== 1 ||
      invalidations !== 1 ||
      baseRetry.configVersion !== firstVersions.base
    ) {
      throw new Error('idempotent retry failed');
    }

    const second = await commitManagedModelPolicy(
      payload({ expectedVersion: 1, defaultKey: 'beta', order: ['beta', 'alpha'] }),
      deps,
    );
    const policy2 = await readPolicy(db, deps.tenantId);
    const base2 = await db.findConfigByPrincipal('role', '__base__', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });
    const user2 = await db.findConfigByPrincipal('role', 'USER', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });
    const admin2 = await db.findConfigByPrincipal('role', 'ADMIN', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });

    if (
      second.transition !== 'advance' ||
      second.policyVersion !== 2 ||
      policy2.head?.version !== 2 ||
      policy2.revision?.companyDefaultDeploymentId !== DEPLOYMENTS.beta.deploymentId ||
      managedEndpoint(base2).models.default[0] !== 'stage-beta'
    ) {
      throw new Error('revision 2 advance failed');
    }

    const beforeFailure = {
      headVersion: policy2.head.version,
      revisionDefault: policy2.revision.companyDefaultDeploymentId,
      baseVersion: base2.configVersion,
      userVersion: user2.configVersion,
      adminVersion: admin2.configVersion,
      baseDefault: managedEndpoint(base2).models.default[0],
      adminModels: managedEndpoint(admin2).models.default.slice(),
      invalidations,
    };

    const failingDeps = {
      ...deps,
      patchConfigFields: async (type, id, model, fields, priority, session, tenantId) => {
        if (id === 'ADMIN') throw new Error('synthetic mid-transaction ADMIN write failure');
        return db.patchConfigFields(type, id, model, fields, priority, session, tenantId);
      },
    };

    let rolledBack = false;
    try {
      await commitManagedModelPolicy(
        payload({ expectedVersion: 2, defaultKey: 'alpha', order: ['alpha', 'beta'] }),
        failingDeps,
      );
    } catch (error) {
      rolledBack = error.message.includes('synthetic mid-transaction');
    }
    if (!rolledBack) throw new Error('failure injection did not trigger');

    const policyAfter = await readPolicy(db, deps.tenantId);
    const revision3 = await db.getModelPolicyRevision(deps.tenantId, 3);
    const baseAfter = await db.findConfigByPrincipal('role', '__base__', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });
    const userAfter = await db.findConfigByPrincipal('role', 'USER', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });
    const adminAfter = await db.findConfigByPrincipal('role', 'ADMIN', {
      includeInactive: true,
      tenantId: deps.tenantId,
    });

    if (
      policyAfter.head?.version !== beforeFailure.headVersion ||
      policyAfter.revision?.companyDefaultDeploymentId !== beforeFailure.revisionDefault ||
      revision3 != null
    ) {
      throw new Error('canonical policy revision did not roll back');
    }
    if (
      baseAfter.configVersion !== beforeFailure.baseVersion ||
      userAfter.configVersion !== beforeFailure.userVersion ||
      adminAfter.configVersion !== beforeFailure.adminVersion
    ) {
      throw new Error('config versions did not roll back');
    }
    if (managedEndpoint(baseAfter).models.default[0] !== beforeFailure.baseDefault) {
      throw new Error('base projection did not roll back');
    }
    if (
      JSON.stringify(managedEndpoint(adminAfter).models.default) !==
      JSON.stringify(beforeFailure.adminModels)
    ) {
      throw new Error('ADMIN projection changed after rollback');
    }
    if (invalidations !== beforeFailure.invalidations) {
      throw new Error('cache invalidated after failed transaction');
    }

    let staleRejected = false;
    try {
      await commitManagedModelPolicy(
        payload({ expectedVersion: 1, defaultKey: 'alpha', order: ['alpha', 'beta'] }),
        deps,
      );
    } catch (error) {
      staleRejected = error.code === 'MODEL_POLICY_REVISION_CONFLICT';
    }
    if (!staleRejected) throw new Error('stale expected version was not rejected');

    console.log(
      'MODEL_POLICY_V2_TRANSACTION_ACCEPTANCE_PASS',
      JSON.stringify({
        initial: first.transition,
        retry: retry.transition,
        advance: second.transition,
        activeVersion: policyAfter.head.version,
        rollback: true,
        staleRejected,
        invalidations,
        database: dbName,
      }),
    );
  });

  return dbName;
}

async function cleanup(dbName) {
  if (!ACCEPTANCE_DB_PATTERN.test(dbName || '') || mongoose.connection.name !== dbName) {
    throw new Error('Refusing cleanup outside the explicit model-policy acceptance database');
  }
  await mongoose.connection.dropDatabase();
}

main()
  .then(async (dbName) => {
    await cleanup(dbName);
    await mongoose.disconnect();
  })
  .catch(async (error) => {
    console.error('MODEL_POLICY_V2_TRANSACTION_ACCEPTANCE_FAILED', error.code || '', error.message);
    try {
      const dbName = process.env.MODEL_POLICY_ACCEPTANCE_DB;
      if (ACCEPTANCE_DB_PATTERN.test(dbName || '') && mongoose.connection.name === dbName) {
        await mongoose.connection.dropDatabase();
      }
    } catch (cleanupError) {
      console.warn('MODEL_POLICY_ACCEPTANCE_CLEANUP_WARNING', cleanupError.message);
    }
    try {
      await mongoose.disconnect();
    } catch (disconnectError) {
      console.warn('MODEL_POLICY_ACCEPTANCE_DISCONNECT_WARNING', disconnectError.message);
    }
    process.exitCode = 1;
  });

#!/usr/bin/env node
'use strict';

const mongoose = require('mongoose');
const { createModels, createMethods, runAsSystem } = require('@librechat/data-schemas');
const {
  publishModelPolicyProjection,
} = require('../api/server/services/Config/modelPolicyPublisher');

const FIRST = {
  policyVersion: 1,
  endpointName: 'CBHR AI',
  companyDefault: 'stage-alpha',
  adminModels: ['stage-alpha', 'stage-beta'],
};

function managedEndpoint(doc) {
  return doc?.overrides?.endpoints?.custom?.find((item) => item?.name === 'CBHR AI');
}

async function main() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  createModels(mongoose);
  const db = createMethods(mongoose);
  let invalidations = 0;
  const deps = {
    findConfigByPrincipal: db.findConfigByPrincipal,
    patchConfigFields: db.patchConfigFields,
    claimModelPolicyPublication: db.claimModelPolicyPublication,
    invalidateConfigCaches: async () => {
      invalidations += 1;
    },
    startSession: () => mongoose.startSession(),
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
              customParams: { reasoningProfiles: { keep: {} } },
              models: { default: ['legacy'] },
            },
          ],
        },
      },
      20,
    );

    const first = await publishModelPolicyProjection(FIRST, deps);
    const base1 = await db.findConfigByPrincipal('role', '__base__', { includeInactive: true });
    const user1 = await db.findConfigByPrincipal('role', 'USER', { includeInactive: true });
    const admin1 = await db.findConfigByPrincipal('role', 'ADMIN', { includeInactive: true });
    if (first.transition !== 'create' || invalidations !== 1) throw new Error('initial publication failed');
    if (managedEndpoint(base1).models.default[0] !== 'stage-alpha') throw new Error('base default mismatch');
    if (user1.overrides.interface.modelSelect !== false || user1.overrides.interface.fileSearch !== true) {
      throw new Error('USER projection/preservation mismatch');
    }
    if (managedEndpoint(admin1).customParams.reasoningProfiles.keep == null) {
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
    const retry = await publishModelPolicyProjection(FIRST, deps);
    const baseRetry = await db.findConfigByPrincipal('role', '__base__', { includeInactive: true });
    if (
      retry.transition !== 'noop' ||
      invalidations !== 1 ||
      baseRetry.configVersion !== firstVersions.base
    ) {
      throw new Error('idempotent retry failed');
    }

    const secondPolicy = {
      ...FIRST,
      policyVersion: 2,
      companyDefault: 'stage-beta',
      adminModels: ['stage-beta', 'stage-alpha'],
    };
    const second = await publishModelPolicyProjection(secondPolicy, deps);
    const publication2 = await db.getModelPolicyPublication();
    const base2 = await db.findConfigByPrincipal('role', '__base__', { includeInactive: true });
    const user2 = await db.findConfigByPrincipal('role', 'USER', { includeInactive: true });
    const admin2 = await db.findConfigByPrincipal('role', 'ADMIN', { includeInactive: true });
    if (
      second.transition !== 'advance' ||
      publication2.policyVersion !== 2 ||
      managedEndpoint(base2).models.default[0] !== 'stage-beta'
    ) {
      throw new Error('revision 2 advance failed');
    }

    const beforeFailure = {
      publicationVersion: publication2.policyVersion,
      publicationDigest: publication2.digest,
      baseVersion: base2.configVersion,
      userVersion: user2.configVersion,
      adminVersion: admin2.configVersion,
      baseDefault: managedEndpoint(base2).models.default[0],
      adminModels: managedEndpoint(admin2).models.default.slice(),
      invalidations,
    };

    const failingDeps = {
      ...deps,
      patchConfigFields: async (type, id, model, fields, priority, session) => {
        if (id === 'ADMIN') throw new Error('synthetic mid-transaction ADMIN write failure');
        return db.patchConfigFields(type, id, model, fields, priority, session);
      },
    };
    let rolledBack = false;
    try {
      await publishModelPolicyProjection({ ...FIRST, policyVersion: 3 }, failingDeps);
    } catch (error) {
      rolledBack = error.message.includes('synthetic mid-transaction');
    }
    if (!rolledBack) throw new Error('failure injection did not trigger');

    const publicationAfter = await db.getModelPolicyPublication();
    const baseAfter = await db.findConfigByPrincipal('role', '__base__', { includeInactive: true });
    const userAfter = await db.findConfigByPrincipal('role', 'USER', { includeInactive: true });
    const adminAfter = await db.findConfigByPrincipal('role', 'ADMIN', { includeInactive: true });
    if (
      publicationAfter.policyVersion !== beforeFailure.publicationVersion ||
      publicationAfter.digest !== beforeFailure.publicationDigest
    ) {
      throw new Error('publication state did not roll back');
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

    console.log(
      'MODEL_POLICY_V2_TRANSACTION_ACCEPTANCE_PASS',
      JSON.stringify({
        initial: first.transition,
        retry: retry.transition,
        advance: second.transition,
        activeVersion: publicationAfter.policyVersion,
        rollback: true,
        invalidations,
      }),
    );
  });
}

main()
  .then(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  })
  .catch(async (error) => {
    console.error(
      'MODEL_POLICY_V2_TRANSACTION_ACCEPTANCE_FAILED',
      error.code || '',
      error.message,
    );
    try {
      await mongoose.connection.dropDatabase();
    } catch {}
    try {
      await mongoose.disconnect();
    } catch {}
    process.exitCode = 1;
  });

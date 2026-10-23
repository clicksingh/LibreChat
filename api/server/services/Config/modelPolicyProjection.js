const SAFE_ENDPOINT = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$/;
const SAFE_MODEL = /^[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,255}$/;
const SAFE_DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const MAX_MODELS = 128;
const AUDIENCES = Object.freeze({
  USER: 'locked-current-default',
  ADMIN: 'managed-catalog',
});

function invalid(message) {
  const error = new Error(message);
  error.code = 'MODEL_POLICY_PROJECTION_INVALID';
  error.status = 422;
  return error;
}

function normalizeModel(value) {
  const model = typeof value === 'string' ? value.trim() : '';
  if (!SAFE_MODEL.test(model)) throw invalid('Invalid managed deployment model id');
  return model;
}

function normalizeEndpointName(value) {
  const endpointName = typeof value === 'string' ? value.trim() : '';
  if (!SAFE_ENDPOINT.test(endpointName)) throw invalid('Invalid managed endpoint name');
  return endpointName;
}

function buildRoleProjection({ endpointName, companyDefault, adminModels }) {
  return {
    endpointName,
    companyDefault,
    adminModels,
    roles: {
      __base__: {
        endpoints: {
          custom: [
            {
              name: endpointName,
              default: true,
              models: { default: [companyDefault], fetch: false },
            },
          ],
        },
      },
      USER: { interface: { modelSelect: false } },
      ADMIN: {
        interface: { modelSelect: true },
        endpoints: {
          custom: [{ name: endpointName, models: { default: adminModels, fetch: false } }],
        },
      },
    },
  };
}

function buildModelPolicyProjection(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw invalid('Projection payload is required');
  }
  if (!Number.isInteger(input.policyVersion) || input.policyVersion < 1) {
    throw invalid('policyVersion must be a positive integer');
  }
  const endpointName = normalizeEndpointName(input.endpointName);
  const companyDefault = normalizeModel(input.companyDefault);
  if (
    !Array.isArray(input.adminModels) ||
    input.adminModels.length < 1 ||
    input.adminModels.length > MAX_MODELS
  ) {
    throw invalid('adminModels must contain between 1 and 128 deployments');
  }
  const adminModels = [...new Set(input.adminModels.map(normalizeModel))];
  if (adminModels.length !== input.adminModels.length) {
    throw invalid('adminModels must be unique');
  }
  if (!adminModels.includes(companyDefault)) {
    throw invalid('Company default must be in the ADMIN managed catalogue');
  }
  return {
    policyVersion: input.policyVersion,
    ...buildRoleProjection({ endpointName, companyDefault, adminModels }),
  };
}

function buildModelPolicyCommitPlan(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw invalid('Commit payload is required');
  }
  if (!Number.isInteger(input.expectedVersion) || input.expectedVersion < 0) {
    throw invalid('expectedVersion must be a non-negative integer');
  }
  const endpointName = normalizeEndpointName(input.endpointName);
  const actor = typeof input.actor === 'string' ? input.actor.trim() : '';
  const source = typeof input.source === 'string' ? input.source.trim() : 'cbhr-admin';
  if (!actor || actor.length > 320) throw invalid('actor is required');
  if (!source || source.length > 80) throw invalid('Invalid policy source');

  const policy = input.policy;
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw invalid('policy is required');
  }
  if (
    policy.audiences?.USER !== AUDIENCES.USER ||
    policy.audiences?.ADMIN !== AUDIENCES.ADMIN
  ) {
    throw invalid('Unsupported managed-model audience contract');
  }
  if (
    !Array.isArray(policy.deployments) ||
    policy.deployments.length < 1 ||
    policy.deployments.length > MAX_MODELS
  ) {
    throw invalid('policy.deployments must contain between 1 and 128 deployments');
  }

  const deployments = policy.deployments.map((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      throw invalid('Each deployment must be an object');
    }
    const deploymentId =
      typeof row.deploymentId === 'string' ? row.deploymentId.trim() : '';
    if (!SAFE_DEPLOYMENT_ID.test(deploymentId)) {
      throw invalid('Invalid managed deployment id');
    }
    return { deploymentId, model: normalizeModel(row.model) };
  });
  const deploymentIds = deployments.map((row) => row.deploymentId);
  const adminModels = deployments.map((row) => row.model);
  if (new Set(deploymentIds).size !== deploymentIds.length) {
    throw invalid('Deployment ids must be unique');
  }
  if (new Set(adminModels).size !== adminModels.length) {
    throw invalid('Managed model ids must be unique');
  }

  const companyDefaultDeploymentId =
    typeof policy.companyDefaultDeploymentId === 'string'
      ? policy.companyDefaultDeploymentId.trim()
      : '';
  if (!SAFE_DEPLOYMENT_ID.test(companyDefaultDeploymentId)) {
    throw invalid('Invalid company default deployment id');
  }
  const defaultDeployment = deployments.find(
    (row) => row.deploymentId === companyDefaultDeploymentId,
  );
  if (!defaultDeployment) {
    throw invalid('Company default deployment must be active');
  }

  return {
    expectedVersion: input.expectedVersion,
    actor,
    source,
    candidate: {
      schemaVersion: 1,
      companyDefaultDeploymentId,
      activeDeploymentIds: deploymentIds,
      audiences: { ...AUDIENCES },
    },
    projection: buildRoleProjection({
      endpointName,
      companyDefault: defaultDeployment.model,
      adminModels,
    }),
  };
}

module.exports = {
  AUDIENCES,
  buildRoleProjection,
  buildModelPolicyProjection,
  buildModelPolicyCommitPlan,
};

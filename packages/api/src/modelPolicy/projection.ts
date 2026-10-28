/** Typed managed-model policy projection and canonical commit plan. */
export interface ReasoningProfile {
  transport: 'chat.completions.reasoning_effort';
  options: string[];
  default: string;
}

export interface ModelPolicyRoleProjection {
  endpointName: string;
  companyDefault: string;
  adminModels: string[];
  roles: {
    __base__: {
      endpoints: {
        custom: Array<{
          name: string;
          default: boolean;
          models: { default: string[]; fetch: boolean };
        }>;
      };
    };
    USER: { interface: { modelSelect: boolean } };
    ADMIN: {
      interface: { modelSelect: boolean };
      endpoints: {
        custom: Array<{
          name: string;
          models: { default: string[]; fetch: boolean };
          customParams: { reasoningProfiles: Record<string, ReasoningProfile> };
        }>;
      };
    };
  };
}

export interface ModelPolicyCommitPlan {
  expectedVersion: number;
  actor: string;
  source: string;
  refreshConfigCaches: boolean;
  candidate: {
    schemaVersion: number;
    companyDefaultDeploymentId: string;
    activeDeploymentIds: string[];
    audiences: { USER: 'locked-current-default'; ADMIN: 'managed-catalog' };
  };
  projection: ModelPolicyRoleProjection;
}

const SAFE_ENDPOINT = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$/;
const SAFE_MODEL = /^[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,255}$/;
const SAFE_DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const MAX_MODELS = 128;
const REASONING_TRANSPORT = 'chat.completions.reasoning_effort';
const REASONING_LEVEL = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
export const AUDIENCES: Readonly<{
  USER: 'locked-current-default';
  ADMIN: 'managed-catalog';
}> = Object.freeze({
  USER: 'locked-current-default',
  ADMIN: 'managed-catalog',
});

function invalid(message: string) {
  const error = new Error(message);
  return Object.assign(error, { code: 'MODEL_POLICY_PROJECTION_INVALID', status: 422 });
}

function normalizeModel(value: unknown): string {
  const model = typeof value === 'string' ? value.trim() : '';
  if (!SAFE_MODEL.test(model)) throw invalid('Invalid managed deployment model id');
  return model;
}

function normalizeEndpointName(value: unknown): string {
  const endpointName = typeof value === 'string' ? value.trim() : '';
  if (!SAFE_ENDPOINT.test(endpointName)) throw invalid('Invalid managed endpoint name');
  return endpointName;
}

export function normalizeReasoningProfile(value: unknown): ReasoningProfile | null {
  if (value == null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalid('Invalid reasoning capability metadata');
  }
  const profile = value as Record<string, unknown>;
  if (profile.transport !== REASONING_TRANSPORT) {
    throw invalid('Unsupported reasoning transport');
  }
  if (
    !Array.isArray(profile.options) ||
    profile.options.length < 1 ||
    profile.options.length > 16
  ) {
    throw invalid('Reasoning options must contain between 1 and 16 values');
  }
  const options = (profile.options as unknown[]).map((item: unknown) => String(item || '').trim());
  if (
    new Set(options).size !== options.length ||
    options.some((item) => !REASONING_LEVEL.test(item))
  ) {
    throw invalid('Reasoning options must contain unique valid identifiers');
  }
  const defaultValue = String(profile.default || '').trim();
  if (!options.includes(defaultValue)) {
    throw invalid('Reasoning default must be one of the supported options');
  }
  return { transport: REASONING_TRANSPORT, options, default: defaultValue };
}

export function buildRoleProjection({
  endpointName,
  companyDefault,
  adminModels,
  reasoningProfiles = {},
}: {
  endpointName: string;
  companyDefault: string;
  adminModels: string[];
  reasoningProfiles?: Record<string, ReasoningProfile>;
}): ModelPolicyRoleProjection {
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
          custom: [
            {
              name: endpointName,
              models: { default: adminModels, fetch: false },
              customParams: { reasoningProfiles },
            },
          ],
        },
      },
    },
  };
}

export function buildModelPolicyProjection(
  input: unknown,
): ModelPolicyRoleProjection & { policyVersion: number } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw invalid('Projection payload is required');
  }
  const data = input as Record<string, unknown>;
  if (!Number.isInteger(data.policyVersion) || (data.policyVersion as number) < 1) {
    throw invalid('policyVersion must be a positive integer');
  }
  const endpointName = normalizeEndpointName(data.endpointName);
  const companyDefault = normalizeModel(data.companyDefault);
  if (
    !Array.isArray(data.adminModels) ||
    (data.adminModels as unknown[]).length < 1 ||
    (data.adminModels as unknown[]).length > MAX_MODELS
  ) {
    throw invalid('adminModels must contain between 1 and 128 deployments');
  }
  const adminModels = [...new Set((data.adminModels as unknown[]).map(normalizeModel))];
  if (adminModels.length !== (data.adminModels as unknown[]).length) {
    throw invalid('adminModels must be unique');
  }
  if (!adminModels.includes(companyDefault)) {
    throw invalid('Company default must be in the ADMIN managed catalogue');
  }
  return {
    policyVersion: data.policyVersion as number,
    ...buildRoleProjection({ endpointName, companyDefault, adminModels }),
  };
}

export function buildModelPolicyCommitPlan(input: unknown): ModelPolicyCommitPlan {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw invalid('Commit payload is required');
  }
  const data = input as Record<string, unknown>;
  if (!Number.isInteger(data.expectedVersion) || (data.expectedVersion as number) < 0) {
    throw invalid('expectedVersion must be a non-negative integer');
  }
  const endpointName = normalizeEndpointName(data.endpointName);
  const actor = typeof data.actor === 'string' ? data.actor.trim() : '';
  const source = typeof data.source === 'string' ? data.source.trim() : 'cbhr-admin';
  if (!actor || actor.length > 320) throw invalid('actor is required');
  if (!source || source.length > 80) throw invalid('Invalid policy source');

  const policy = data.policy;
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw invalid('policy is required');
  }
  const settings = policy as Record<string, unknown>;
  const audiences = settings.audiences as Record<string, unknown> | undefined;
  if (audiences?.USER !== AUDIENCES.USER || audiences?.ADMIN !== AUDIENCES.ADMIN) {
    throw invalid('Unsupported managed-model audience contract');
  }
  if (
    !Array.isArray(settings.deployments) ||
    (settings.deployments as unknown[]).length < 1 ||
    (settings.deployments as unknown[]).length > MAX_MODELS
  ) {
    throw invalid('settings.deployments must contain between 1 and 128 deployments');
  }

  const deployments = (settings.deployments as unknown[]).map((row: unknown) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      throw invalid('Each deployment must be an object');
    }
    const item = row as Record<string, unknown>;
    const deploymentId = typeof item.deploymentId === 'string' ? item.deploymentId.trim() : '';
    if (!SAFE_DEPLOYMENT_ID.test(deploymentId)) {
      throw invalid('Invalid managed deployment id');
    }
    return {
      deploymentId,
      model: normalizeModel(item.model),
      reasoning: normalizeReasoningProfile(item.reasoning),
    };
  });
  const deploymentIds = deployments.map((row) => row.deploymentId);
  const adminModels = deployments.map((row) => row.model);
  const reasoningProfiles: Record<string, ReasoningProfile> = {};
  for (const row of deployments) {
    if (row.reasoning) reasoningProfiles[row.model] = row.reasoning;
  }
  if (new Set(deploymentIds).size !== deploymentIds.length) {
    throw invalid('Deployment ids must be unique');
  }
  if (new Set(adminModels).size !== adminModels.length) {
    throw invalid('Managed model ids must be unique');
  }

  const companyDefaultDeploymentId =
    typeof settings.companyDefaultDeploymentId === 'string'
      ? settings.companyDefaultDeploymentId.trim()
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
    expectedVersion: data.expectedVersion as number,
    actor,
    source,
    refreshConfigCaches: data.refreshConfigCaches === true,
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
      reasoningProfiles,
    }),
  };
}

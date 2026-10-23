const SAFE_ENDPOINT = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$/;
const SAFE_MODEL = /^[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,255}$/;
const MAX_MODELS = 128;

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

function buildModelPolicyProjection(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw invalid('Projection payload is required');
  if (!Number.isInteger(input.policyVersion) || input.policyVersion < 1) throw invalid('policyVersion must be a positive integer');
  const endpointName = typeof input.endpointName === 'string' ? input.endpointName.trim() : '';
  if (!SAFE_ENDPOINT.test(endpointName)) throw invalid('Invalid managed endpoint name');
  const companyDefault = normalizeModel(input.companyDefault);
  if (!Array.isArray(input.adminModels) || input.adminModels.length < 1 || input.adminModels.length > MAX_MODELS) {
    throw invalid('adminModels must contain between 1 and 128 deployments');
  }
  const adminModels = [...new Set(input.adminModels.map(normalizeModel))];
  if (!adminModels.includes(companyDefault)) throw invalid('Company default must be in the ADMIN managed catalogue');

  return {
    policyVersion: input.policyVersion, endpointName, companyDefault, adminModels,
    roles: {
      __base__: { endpoints: { custom: [{ name: endpointName, default: true, models: { default: [companyDefault], fetch: false } }] } },
      USER: { interface: { modelSelect: false } },
      ADMIN: {
        interface: { modelSelect: true },
        endpoints: { custom: [{ name: endpointName, models: { default: adminModels, fetch: false } }] },
      },
    },
  };
}

module.exports = { buildModelPolicyProjection };
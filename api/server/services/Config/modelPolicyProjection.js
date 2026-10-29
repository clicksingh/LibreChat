// Compatibility shim: policy validation and projection live in packages/api TypeScript.
const {
  AUDIENCES,
  buildRoleProjection,
  buildModelPolicyProjection,
  buildModelPolicyCommitPlan,
  normalizeReasoningProfile,
} = require('@librechat/api');

module.exports = {
  AUDIENCES,
  buildRoleProjection,
  buildModelPolicyProjection,
  buildModelPolicyCommitPlan,
  normalizeReasoningProfile,
};

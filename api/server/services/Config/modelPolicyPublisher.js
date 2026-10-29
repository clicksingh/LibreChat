// Compatibility shim: all transactional policy logic lives in packages/api TypeScript.
const {
  mergeEndpointList,
  applyProjectionInSession,
  commitManagedModelPolicy,
} = require('@librechat/api');

module.exports = {
  mergeEndpointList,
  applyProjectionInSession,
  commitManagedModelPolicy,
};

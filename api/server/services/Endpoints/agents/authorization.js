/**
 * 8S3C.2 — request-scoped RUN_CODE authorization (Blocker 1 fix).
 *
 * RUN_CODE.USE is the authority ceiling for the document workstation in this
 * phase. Every path that previously derived `codeEnvAvailable` from the GLOBAL
 * `endpoints.agents.capabilities` set alone — the agent-chat init path
 * (initialize.js), the ToolService capability resolver, the remote v1 agent
 * controllers, the memory-agent path, and the exported SDK — must AND in the
 * requesting user's RUN_CODE.USE permission using the canonical `checkAccess`
 * semantics already used by the direct execute_code endpoint
 * (api/server/controllers/tools.js:callTool → 403 for denied users).
 *
 * `checkAccessWithRequestCache` caches the resolution on the request object
 * keyed by `[permissionType, permissions, user.id, user.role]`, so the check
 * is computed at most once per request no matter how many call sites consult
 * it. This satisfies the "one request-scoped effective authorization
 * resolution" requirement WITHOUT creating a second permission family — the
 * global platform capability and the user's effective permission AND together
 * gate model tool exposure:
 *
 *     effectiveCodeEnvAvailable = globalCodeCapability && userRunCodeAllowed
 *
 * This is the effective-run-code authorization resolution. No client-supplied
 * flag (e.g. `ephemeralAgent.execute_code`) is ever treated as authorization.
 */
const { PermissionTypes, Permissions } = require('librechat-data-provider');
const { checkAccessWithRequestCache } = require('@librechat/api');
const { getRoleByName } = require('~/models');

/**
 * Canonical RUN_CODE.USE resolution for a request user (fail-closed).
 *
 * Mirrors the direct execute_code endpoint's check exactly:
 *   checkAccess({ user, permissionType: RUN_CODE, permissions: [USE] }).
 * Returns false when the user, role, or permission cannot be established, so
 * an anonymous/partial request can never obtain code execution.
 *
 * @param {Express.Request} req
 * @returns {Promise<boolean>}
 */
async function isRunCodeUseAllowed(req) {
  const user = req?.user;
  if (!user?.id || !user?.role) {
    return false;
  }
  return checkAccessWithRequestCache({
    req,
    user,
    permissionType: PermissionTypes.RUN_CODE,
    permissions: [Permissions.USE],
    getRoleByName,
  });
}

/**
 * Effective code-environment availability for a request:
 *   globalCodeCapability && userRunCodeAllowed(req).
 *
 * @param {Express.Request} req
 * @param {boolean} globalCodeCapability - resolved global
 *   `endpoints.agents.capabilities` execute_code flag.
 * @returns {Promise<boolean>}
 */
async function resolveEffectiveCodeEnv(req, globalCodeCapability) {
  if (!globalCodeCapability) {
    return false;
  }
  return isRunCodeUseAllowed(req);
}

module.exports = { isRunCodeUseAllowed, resolveEffectiveCodeEnv };

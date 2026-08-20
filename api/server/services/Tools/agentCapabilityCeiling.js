'use strict';

/**
 * 8S5 — shared creation/update capability ceiling for RUN_CODE-gated tools.
 * Used by both the REST Agent controller (api/server/controllers/agents/v1.js)
 * and the conversational agent_management tool
 * (api/server/services/Tools/agentManagement.js) so the two surfaces cannot
 * drift.
 *
 * Defense-in-depth, not the live security boundary: runtime tool-loading
 * (ToolService.js's `loadToolsForExecution`, the 8S3C.2 fix) independently
 * re-validates RUN_CODE.USE at actual invocation time regardless of what is
 * stored on the agent document, so a stored-but-unauthorized tool is inert,
 * not exploitable. Rejecting it at write time is still correct hygiene
 * ("Do not create a latent privilege-escalation artifact").
 */

const { Tools, Permissions, PermissionTypes } = require('librechat-data-provider');
const { checkAccessWithRequestCache } = require('@librechat/api');

const RUN_CODE_GATED_TOOLS = new Set([Tools.execute_code, Tools.bash_tool]);

/**
 * @param {string[]} tools - the FINAL tool list about to be persisted.
 * @param {Express.Request} req
 * @throws {Error & {status: number, code: string}} when the actor lacks
 *   RUN_CODE.USE and `tools` contains a RUN_CODE-gated tool name.
 */
async function assertToolCapabilityCeiling(tools, req) {
  if (!Array.isArray(tools) || tools.length === 0) {
    return;
  }
  const requestsRunCode = tools.some((tool) => RUN_CODE_GATED_TOOLS.has(tool));
  if (!requestsRunCode) {
    return;
  }
  const { getRoleByName } = require('~/models');
  const allowed = await checkAccessWithRequestCache({
    req,
    user: req.user,
    permissionType: PermissionTypes.RUN_CODE,
    permissions: [Permissions.USE],
    getRoleByName,
  });
  if (!allowed) {
    const err = new Error('You do not have permission to configure a Run Code tool on an agent.');
    err.status = 403;
    err.code = 'AGENT_CAPABILITY_NOT_ALLOWED';
    throw err;
  }
}

module.exports = { assertToolCapabilityCeiling, RUN_CODE_GATED_TOOLS };

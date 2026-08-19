/**
 * 8S3D.1 — thin authenticated proxy from LibreChat's REST surface to
 * CodeAPI's /workspace/* endpoints. LibreChat never talks to the
 * workspace-quota-helper directly (no socket, no host paths, no project
 * quota ids exposed) — CodeAPI remains the single boundary that resolves
 * kind/owner from the same signed-claim contract used everywhere else.
 */
const { logger } = require('@librechat/data-schemas');
const { getCodeBaseURL } = require('@librechat/agents');
const { createAxiosInstance, logAxiosError, getCodeApiAuthHeaders } = require('@librechat/api');

const axios = createAxiosInstance();

/**
 * @param {Express.Request} req
 * @param {'user'|'project'} kind
 * @param {string} [workspaceId] - required for kind='project' (the caller
 *   must already have set req.workspaceContext via resolveWorkspaceContext
 *   or resolveWorkspaceContextExplicit BEFORE calling this — the signed JWT
 *   claim, not this parameter, is what CodeAPI actually trusts).
 */
async function codeApiGet(req, path, query = {}) {
  const baseURL = getCodeBaseURL();
  const authHeaders = await getCodeApiAuthHeaders(req);
  const qs = new URLSearchParams(query).toString();
  const url = `${baseURL}${path}${qs ? `?${qs}` : ''}`;
  const res = await axios.get(url, { headers: authHeaders, timeout: 15000 });
  return res.data;
}

async function codeApiPost(req, path, body) {
  const baseURL = getCodeBaseURL();
  const authHeaders = await getCodeApiAuthHeaders(req);
  const res = await axios.post(`${baseURL}${path}`, body, {
    headers: { ...authHeaders, 'Content-Type': 'application/json' },
    timeout: 15000,
  });
  return res.data;
}

async function getUsage(req, kind, id) {
  return codeApiGet(req, '/workspace/usage', { kind, ...(id ? { id } : {}) });
}

async function listFiles(req, kind, id, cursor, limit) {
  return codeApiGet(req, '/workspace/files', {
    kind,
    ...(id ? { id } : {}),
    ...(cursor ? { cursor } : {}),
    ...(limit ? { limit } : {}),
  });
}

async function listTrash(req, kind, id, cursor, limit) {
  return codeApiGet(req, '/workspace/trash', {
    kind,
    ...(id ? { id } : {}),
    ...(cursor ? { cursor } : {}),
    ...(limit ? { limit } : {}),
  });
}

async function trashFile(req, kind, id, sessionId, fileId) {
  return codeApiPost(req, '/workspace/trash', {
    kind,
    ...(id ? { id } : {}),
    session_id: sessionId,
    file_id: fileId,
  });
}

async function restoreFile(req, kind, id, trashId, newName) {
  return codeApiPost(req, '/workspace/restore', {
    kind,
    ...(id ? { id } : {}),
    trash_id: trashId,
    ...(newName ? { newName } : {}),
  });
}

/** PURGE — irreversible. Caller MUST have already obtained explicit human
 * confirmation client-side; this function itself does not gate that, same
 * as CodeAPI's own contract (ADR 005 approval boundary is a UI/product
 * concern, not something the transport layer can enforce). */
async function purgeFile(req, kind, id, trashId) {
  return codeApiPost(req, '/workspace/purge', { kind, ...(id ? { id } : {}), trash_id: trashId });
}

function handleProxyError(res, error, fallbackMessage) {
  logAxiosError({ error, message: fallbackMessage });
  const status = error?.response?.status || 502;
  const data = error?.response?.data || { error: fallbackMessage };
  logger.warn(`[Workspace proxy] ${fallbackMessage}: ${status}`);
  res.status(status).json(data);
}

module.exports = {
  getUsage,
  listFiles,
  listTrash,
  trashFile,
  restoreFile,
  purgeFile,
  handleProxyError,
};

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

// CodeAPI session/file identifiers are opaque storage keys, never paths.
const safeFileKey = (key) =>
  typeof key === 'string' && /^[A-Za-z0-9_.-]{1,180}$/.test(key) && key !== '.' && key !== '..';

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

async function getCleanupPreview(req, kind, id) {
  return codeApiGet(req, '/workspace/cleanup-preview', { kind, ...(id ? { id } : {}) });
}

async function cleanup(req, kind, id) {
  return codeApiPost(req, '/workspace/cleanup', { kind, ...(id ? { id } : {}) });
}

async function listFiles(req, kind, id, cursor, limit) {
  return codeApiGet(req, '/workspace/files', {
    kind,
    ...(id ? { id } : {}),
    ...(cursor ? { cursor } : {}),
    ...(limit ? { limit } : {}),
  });
}

/**
 * Stream a single listed workspace file from CodeAPI through the same authenticated
 * boundary as the file browser. The caller must validate project ACL membership and
 * set req.workspaceContext before requesting any project file.
 */
async function downloadFile(req, res, kind, id, sessionId, fileId) {
  if (!safeFileKey(sessionId) || !safeFileKey(fileId)) {
    const error = new Error('invalid file identifier');
    error.status = 400;
    throw error;
  }
  const baseURL = getCodeBaseURL();
  const authHeaders = await getCodeApiAuthHeaders(req);
  const query = new URLSearchParams({ kind, ...(id ? { id } : {}) }).toString();
  const url = `${baseURL}/download/${encodeURIComponent(sessionId)}/${encodeURIComponent(fileId)}?${query}`;
  const upstream = await axios.get(url, {
    headers: authHeaders,
    responseType: 'stream',
    maxRedirects: 0,
    timeout: 30000,
  });
  res.status(200);
  res.set({
    'Content-Type': upstream.headers['content-type'] || 'application/octet-stream',
    'Content-Disposition': upstream.headers['content-disposition'] || 'attachment',
    'Cache-Control': 'private, no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  if (upstream.headers['content-length']) {
    res.set('Content-Length', upstream.headers['content-length']);
  }
  upstream.data.on('error', (error) => {
    logger.warn(`[Workspace proxy] download stream failed: ${error.message}`);
    if (!res.headersSent) return res.status(502).end();
    res.destroy(error);
  });
  res.on('close', () => {
    if (!upstream.data.destroyed) upstream.data.destroy();
  });
  upstream.data.pipe(res);
}

/**
 * Server-only bounded read for attaching a previously published workspace
 * object. Auth is the SAME per-request signed CodeAPI claim as downloads.
 * Never expose this buffer to the browser or follow redirect URLs.
 */
async function readWorkspaceFile(req, kind, id, sessionId, fileId, maxBytes) {
  if (!safeFileKey(sessionId) || !safeFileKey(fileId)) {
    const error = new Error('invalid file identifier');
    error.status = 400;
    throw error;
  }
  const baseURL = getCodeBaseURL();
  const headers = await getCodeApiAuthHeaders(req);
  const query = new URLSearchParams({ kind, ...(id ? { id } : {}) }).toString();
  const url =
    baseURL +
    '/download/' +
    encodeURIComponent(sessionId) +
    '/' +
    encodeURIComponent(fileId) +
    '?' +
    query;
  const upstream = await axios.get(url, {
    headers,
    responseType: 'stream',
    maxRedirects: 0,
    timeout: 30000,
  });
  const declared = Number(upstream.headers['content-length']);
  if (Number.isFinite(declared) && declared > maxBytes) {
    upstream.data.destroy();
    throw Object.assign(new Error('Workspace file too large'), { status: 413 });
  }
  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of upstream.data) {
      size += chunk.length;
      if (size > maxBytes) {
        throw Object.assign(new Error('Workspace file too large'), { status: 413 });
      }
      chunks.push(chunk);
    }
  } finally {
    upstream.data.destroy();
  }
  return Buffer.concat(chunks, size);
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
  const proposedStatus = Number(error?.response?.status ?? error?.status);
  const status =
    Number.isInteger(proposedStatus) && proposedStatus >= 400 && proposedStatus <= 599
      ? proposedStatus
      : 502;
  const upstreamData = error?.response?.data;
  // Axios with responseType:'stream' returns an IncomingMessage even for 4xx.
  // Express JSON serialization of that stream is circular and turns an owner
  // denial into HTTP 500. Never serialize or expose an upstream error stream.
  if (upstreamData && typeof upstreamData.pipe === 'function') {
    upstreamData.destroy?.();
    logger.warn(`[Workspace proxy] ${fallbackMessage}: ${status}`);
    return res.status(status).json({ error: fallbackMessage });
  }
  const data = upstreamData || { error: fallbackMessage };
  logger.warn(`[Workspace proxy] ${fallbackMessage}: ${status}`);
  return res.status(status).json(data);
}

module.exports = {
  getUsage,
  getCleanupPreview,
  cleanup,
  listFiles,
  downloadFile,
  readWorkspaceFile,
  listTrash,
  trashFile,
  restoreFile,
  purgeFile,
  handleProxyError,
};

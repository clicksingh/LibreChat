'use strict';

/** B1: attest only DB-backed *explicitly primed* Personal/Project documents.
 * No browser/model-provided session ID, file ID, file path or role is a grant.
 * The caller already resolved the active chat/session and workspace membership.
 * Cross-conversation reuse requires a matching, user-owned Mongo file record.
 */
const { createHash } = require('crypto');
const DOC = /\.(?:docx|pdf|xlsx)$/i;
const SAFE = /^[A-Za-z0-9._-]{1,200}$/;
const NAME = /^[A-Za-z0-9_. -]{1,180}$/;
const LIMIT = 20;
const MAX_BYTES = 25 * 1024 * 1024;

function authorizedFileGrants({ req, sessionFiles, dbFiles }) {
  const userId = String(req?.user?.id || '');
  if (!userId || !Array.isArray(sessionFiles) || sessionFiles.length > LIMIT ||
      !Array.isArray(dbFiles)) {
    throw new Error('CODEAPI_EXECUTION_INPUT_SCOPE_UNVERIFIED');
  }
  const tenantId = req.user?.tenantId == null ? null : String(req.user.tenantId);
  const projectId = req.workspaceContext?.kind === 'project'
    ? String(req.workspaceContext.workspaceId || '') : null;
  const grants = [];
  const seen = new Set();
  for (const ref of sessionFiles) {
    const name = ref?.name;
    if (!ref || !['user','project'].includes(ref.kind) || !SAFE.test(ref.resource_id) ||
        !SAFE.test(ref.storage_session_id) || !SAFE.test(ref.id) ||
        !NAME.test(name) || !DOC.test(name) ||
        (ref.kind === 'user' && ref.resource_id !== userId) ||
        (ref.kind === 'project' && (!projectId || projectId !== ref.resource_id))) {
      // Unsupported skill, agent, arbitrary file, or mismatched workspace:
      // refuse the whole run instead of silently dropping input.
      throw new Error('CODEAPI_EXECUTION_INPUT_SCOPE_UNVERIFIED');
    }
    const matching = dbFiles.filter((file) => {
      const proof = file?.metadata?.codeEnvRef;
      const user = file?.user?.toString?.() ?? file?.user;
      const tenant = file?.tenantId?.toString?.() ?? file?.tenantId;
      return user === userId &&
        (tenantId === null ? tenant == null : tenant === tenantId) &&
        proof?.kind === ref.kind &&
        proof.id === ref.resource_id &&
        proof.storage_session_id === ref.storage_session_id &&
        proof.file_id === ref.id &&
        file.filename === name &&
        Number.isSafeInteger(file.bytes) && file.bytes > 0 && file.bytes <= MAX_BYTES &&
        (ref.kind !== 'project' || file.metadata?.workspaceFileAttachment === true);
    });
    // Reattaching the same immutable Files object to two chats creates two
    // user-owned metadata associations with the SAME source identity. That
    // is valid reuse, not a forged duplicate. Reject inconsistent byte sizes.
    if (!matching.length || matching.some((f) => f.bytes !== matching[0].bytes)) {
      throw new Error('CODEAPI_EXECUTION_INPUT_SCOPE_UNVERIFIED');
    }
    const key = [ref.kind,ref.resource_id,ref.storage_session_id,ref.id,name].join(':');
    if (seen.has(key)) throw new Error('CODEAPI_EXECUTION_INPUT_DUPLICATE');
    seen.add(key);
    grants.push(Object.freeze({
      kind: ref.kind, owner: ref.resource_id, session_id: ref.storage_session_id,
      file_id: ref.id, name, bytes: matching[0].bytes,
    }));
  }
  return Object.freeze(grants);
}

async function hashFileWithStorage(req, file) {
  // Hash the AUTHORIZED saved TFile bytes, not a mutable CodeAPI source
  // path supplied by the model. CodeAPI compares its source to this signed
  // hash before root copies into the separate-UID conversation sandbox.
  const { getStrategyFunctions } = require('~/server/services/Files/strategies');
  const loader = getStrategyFunctions(file.source)?.getDownloadStream;
  if (typeof loader !== 'function') throw Error('CODEAPI_EXECUTION_HASH_SOURCE_UNAVAILABLE');
  const stream = await loader(req, file.filepath);
  if (!stream || typeof stream[Symbol.asyncIterator] !== 'function') {
    throw Error('CODEAPI_EXECUTION_HASH_SOURCE_UNAVAILABLE');
  }
  const digest = createHash('sha256');
  let bytes = 0;
  try {
    for await (const chunk of stream) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buf.length;
      if (bytes > MAX_BYTES || bytes > file.bytes) {
        throw Error('CODEAPI_EXECUTION_INPUT_CHANGED_DURING_GRANT');
      }
      digest.update(buf);
    }
  } finally {
    if (typeof stream.destroy === 'function') stream.destroy();
  }
  if (bytes !== file.bytes) throw Error('CODEAPI_EXECUTION_INPUT_CHANGED_DURING_GRANT');
  return digest.digest('hex');
}

async function resolveAuthorizedFileGrants({ req, initialSessions, getFiles, hashFile = hashFileWithStorage }) {
  const files = initialSessions?.get?.('execute_code')?.files ?? [];
  if (!Array.isArray(files) || files.length > LIMIT) {
    throw new Error('CODEAPI_EXECUTION_INPUT_SCOPE_UNVERIFIED');
  }
  if (files.length === 0) return Object.freeze([]);
  if (typeof getFiles !== 'function') throw new Error('CODEAPI_EXECUTION_FILES_DB_UNAVAILABLE');
  // Only the specific primed storage object IDs are fetched; owner, tenant,
  // chat context and exact source identity are checked against each record.
  const dbFiles = await getFiles({
    user: req.user.id,
    'metadata.codeEnvRef.file_id': { $in: files.map((f) => f.id) },
  });
  const authorized = authorizedFileGrants({ req, sessionFiles: files, dbFiles });
  const attested = [];
  for (const grant of authorized) {
    const original = dbFiles.find((file) => {
      const ref = file?.metadata?.codeEnvRef;
      return ref?.kind === grant.kind && ref.id === grant.owner &&
        ref.storage_session_id === grant.session_id && ref.file_id === grant.file_id &&
        file.filename === grant.name && file.bytes === grant.bytes;
    });
    if (!original) throw Error('CODEAPI_EXECUTION_INPUT_SCOPE_UNVERIFIED');
    const sha256 = await hashFile(req, original);
    if (typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(sha256)) {
      throw Error('CODEAPI_EXECUTION_HASH_SOURCE_UNAVAILABLE');
    }
    attested.push(Object.freeze({ ...grant, sha256 }));
  }
  return Object.freeze(attested);
}

module.exports = { authorizedFileGrants, resolveAuthorizedFileGrants, hashFileWithStorage };

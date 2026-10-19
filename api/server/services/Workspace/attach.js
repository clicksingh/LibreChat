/**
 * Reuse a CodeAPI workspace object as a normal chat attachment.
 *
 * The workspace list is the authority for existence and scope: never trust a
 * browser-supplied name/path/role, nor use raw host paths. For compatibility
 * with the current local/S3 file-download pipeline we materialize ONE bounded
 * server-side copy into the requester's file storage, then persist a Mongo TFile
 * with the ORIGINAL CodeAPI reference for zero-reupload agent priming.
 * Bytes never pass through the browser.
 */
const { v4 } = require('uuid');
const path = require('path');
const { getStorageMetadata } = require('@librechat/api');
const { FileContext, inferMimeType } = require('librechat-data-provider');
const { getStrategyFunctions } = require('~/server/services/Files/strategies');
const { getRetentionExpiry } = require('~/server/services/Files/retention');
const db = require('~/models');
const proxy = require('./proxy');

// Unlike browser uploads, CodeAPI workspace listings have no MIME field.
// The existing inferMimeType helper intentionally lacks several Office/PDF
// mappings, so explicitly supply these to preserve agent file classification.
const MIME_BY_EXTENSION = Object.freeze({
  '.pdf': 'application/pdf',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.doc': 'application/msword',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.xls': 'application/vnd.ms-excel',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.csv': 'text/csv',
  '.md': 'text/markdown',
  '.txt': 'text/plain',
  '.html': 'text/html',
  '.htm': 'text/html',
});
const workspaceMimeType = (filename) =>
  MIME_BY_EXTENSION[path.extname(filename).toLowerCase()] ||
  inferMimeType(filename, '') ||
  'application/octet-stream';

const MAX_ATTACH_BYTES = 25 * 1024 * 1024;
const MAX_LIST_ENTRIES = 10000;
const SAFE_KEY = /^[A-Za-z0-9_.-]{1,180}$/;
const isKey = (value) =>
  typeof value === 'string' && SAFE_KEY.test(value) && value !== '.' && value !== '..';

function attachmentError(status, message) {
  return Object.assign(new Error(message), { status });
}

async function resolveListedArtifact(req, kind, projectId, sessionId, fileId) {
  if (!isKey(sessionId) || !isKey(fileId)) {
    throw attachmentError(400, 'Invalid workspace file identifier');
  }
  const targetPath = sessionId + '/' + fileId;
  let cursor;
  let examined = 0;
  while (examined < MAX_LIST_ENTRIES) {
    // CodeAPI verifies the SIGNED kind/project claims and lists only live
    // files, excluding trashed objects; no host paths or user-supplied names.
    const result = await proxy.listFiles(req, kind, projectId, cursor, 500);
    const items = result?.items ?? [];
    const match = items.find(
      (f) => f.sessionId === sessionId && f.fileId === fileId && f.path === targetPath,
    );
    if (match) {
      if (!match.name || typeof match.name !== 'string' || match.name.length > 255) {
        throw attachmentError(422, 'Invalid workspace filename');
      }
      if (!Number.isSafeInteger(match.size) || match.size <= 0 || match.size > MAX_ATTACH_BYTES) {
        throw attachmentError(413, 'Workspace file exceeds chat attachment size limit');
      }
      // The signed CodeAPI Files listing contains only visible, retained files.
      // Pre-role-metadata legacy entries omit role, but remain owner-scoped,
      // downloadable and explicitly chosen by the user. Do not deny their
      // chat reuse. Explicit unsupported roles still fail closed.
      if (match.role != null && match.role !== 'input' && match.role !== 'output') {
        throw attachmentError(403, 'Only published or uploaded workspace files may be attached');
      }
      return match;
    }
    examined += items.length;
    if (!result?.nextCursor || result.nextCursor === cursor || !items.length) {
      throw attachmentError(404, 'Workspace file no longer exists');
    }
    cursor = result.nextCursor;
  }
  throw attachmentError(413, 'Workspace contains too many files to resolve this attachment');
}

async function verifyChatScope(req, kind, projectId, conversationId) {
  if (!conversationId || conversationId === 'new') return;
  if (typeof conversationId !== 'string' || conversationId.length > 180) {
    throw attachmentError(400, 'Invalid conversation');
  }
  const conversation = await db.getConvo(req.user.id, conversationId);
  if (!conversation) throw attachmentError(404, 'Conversation not found');
  const actual = conversation.workspaceId ? String(conversation.workspaceId) : null;
  const expected = kind === 'project' ? String(projectId) : null;
  if (actual !== expected) {
    throw attachmentError(409, 'Select files from the current chat workspace');
  }
}

async function attachWorkspaceFile(req, { kind, projectId, sessionId, fileId, conversationId }) {
  await verifyChatScope(req, kind, projectId, conversationId);
  const file = await resolveListedArtifact(req, kind, projectId, sessionId, fileId);
  // A chat association is a metadata reference, NOT a second upload.
  // CodeAPI owns the bytes; reads are checked against current signed scope.
  const file_id = v4();
  const cleanName = file.name.replace(/[\/\\\0-\x1f]/g, '_').slice(0, 180);
  const mimeType = workspaceMimeType(cleanName);
  const source = 'local';
  const filepath = 'cbhrwsref://' + [
    kind, kind === 'project' ? projectId : req.user.id, sessionId, fileId,
  ].join('/');
  const newFile = {
    file_id,
    filename: cleanName,
    filepath,
    object: 'file',
    type: mimeType,
    bytes: file.size,
    usage: 1,
    context: FileContext.message_attachment,
    source,
    user: req.user.id,
    tenantId: req.user.tenantId,
    ...(conversationId && conversationId !== 'new' ? { conversationId } : {}),
    metadata: {
      workspaceFileAttachment: true,
      codeEnvRef: {
        kind,
        id: kind === 'project' ? projectId : req.user.id,
        storage_session_id: sessionId,
        file_id: fileId,
      },
    },
    ...(await getRetentionExpiry(req)),
  };
  // Persist without the transient one-hour TTL.
  await db.createFile(newFile, true);
  return {
    file_id: newFile.file_id,
    filename: newFile.filename,
    filepath: newFile.filepath,
    type: newFile.type,
    bytes: newFile.bytes,
    source: newFile.source,
    metadata: newFile.metadata,
  };
}

module.exports = {
  attachWorkspaceFile,
  resolveListedArtifact,
  verifyChatScope,
  workspaceMimeType,
  MAX_ATTACH_BYTES,
};

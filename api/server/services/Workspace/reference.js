/**
 * Authenticated, on-demand reference to a retained CodeAPI Files object.
 * No new stored upload bytes. Never trust the URI as authorization.
 */
const { Readable } = require('stream');
const {
  resolveWorkspaceContextExplicit,
} = require('~/server/services/Endpoints/agents/authorization');
const { resolveListedArtifact, MAX_ATTACH_BYTES } = require('./attach');
const proxy = require('./proxy');
const FILE_REF_RE =
  /^cbhrwsref:\/\/(user|project)\/([A-Za-z0-9_-]{1,180})\/([A-Za-z0-9_.-]{1,180})\/([A-Za-z0-9_.-]{1,180})$/;

async function readWorkspaceRefStream(req, filepath) {
  const match = typeof filepath === 'string' ? FILE_REF_RE.exec(filepath) : null;
  if (
    !match ||
    !req?.user?.id ||
    match[3] === '.' ||
    match[3] === '..' ||
    match[4] === '.' ||
    match[4] === '..'
  ) {
    throw Object.assign(new Error('Invalid or unauthenticated workspace reference'), {
      status: 403,
    });
  }
  const [, kind, owner, sessionId, fileId] = match;
  if (kind === 'user' && owner !== String(req.user.id)) {
    throw Object.assign(new Error('Workspace reference belongs to another user'), { status: 403 });
  }
  if (kind === 'project') {
    req.workspaceContext = await resolveWorkspaceContextExplicit(req, owner);
  }
  const projectId = kind === 'project' ? owner : undefined;
  const file = await resolveListedArtifact(req, kind, projectId, sessionId, fileId);
  const buffer = await proxy.readWorkspaceFile(
    req,
    kind,
    projectId,
    sessionId,
    fileId,
    MAX_ATTACH_BYTES,
  );
  if (buffer.length !== file.size) {
    throw Object.assign(new Error('Workspace reference changed during read'), { status: 409 });
  }
  return Readable.from([buffer]);
}
module.exports = { readWorkspaceRefStream };

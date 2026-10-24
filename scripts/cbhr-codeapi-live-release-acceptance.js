'use strict';

require('module-alias')({ base: '/app/api' });

const crypto = require('crypto');
const { Readable } = require('stream');
const mongoose = require('mongoose');
const { connectDb } = require('/app/api/db');
const db = require('/app/api/models');
const { grantPermission } = require('/app/api/server/services/PermissionService');
const {
  resolveWorkspaceContext,
  resolveWorkspaceContextExplicit,
} = require('/app/api/server/services/Endpoints/agents/authorization');
const workspaceProxy = require('/app/api/server/services/Workspace/proxy');
const { syncProjectQuota } = require('/app/api/server/services/Workspace/quotaSync');
const { uploadCodeEnvFile } = require('/app/api/server/services/Files/Code/crud');
const {
  getCodeApiAuthHeaders,
  bindCodeApiExecutionScope,
  mintInternalAdminToken,
} = require('@librechat/api');
const { getCodeBaseURL } = require('@librechat/agents');
const { PrincipalType, ResourceType, AccessRoleIds } = require('librechat-data-provider');

const TENANT = 'legacy';
const stamp = Date.now().toString(36);
const prefix = `release-acceptance-${stamp}-${crypto.randomBytes(3).toString('hex')}`;
const conversationId = crypto.randomUUID();
const executionSessionId = 'conv-' + crypto.randomUUID();
const personalBytes = Buffer.from(`personal acceptance ${prefix}`);
const projectText = `project acceptance ${prefix}`;
let userA;
let userB;
let workspace;
let projectFile;
let personalUpload;

function pass(label, detail = '') {
  console.log('PASS', label, detail);
}

function must(condition, label, detail = '') {
  if (!condition) {
    throw new Error(`${label}${detail ? ': ' + detail : ''}`);
  }
  pass(label, detail);
}

function reqFor(user, body = {}) {
  return {
    user: {
      id: String(user._id),
      _id: user._id,
      role: 'USER',
      provider: 'openid',
      tenantId: TENANT,
    },
    body,
  };
}

async function codeApi(req, method, path, body) {
  const headers = {
    'User-Agent': 'LibreChat-Release-Acceptance/1.0',
    ...(await getCodeApiAuthHeaders(req)),
  };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  const response = await fetch(getCodeBaseURL() + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const bytes = Buffer.from(await response.arrayBuffer());
  let json = null;
  try {
    json = JSON.parse(bytes.toString('utf8'));
  } catch {
    // Non-JSON bodies (downloads/denials) are returned through bytes/text below.
  }
  return { status: response.status, bytes, json, text: bytes.toString('utf8') };
}

async function deleteSyntheticStorage() {
  try {
    if (projectFile?.sessionId && projectFile?.fileId && workspace) {
      const reqA = reqFor(userA);
      reqA.workspaceContext = await resolveWorkspaceContextExplicit(reqA, String(workspace._id));
      const trashed = await workspaceProxy.trashFile(
        reqA,
        'project',
        String(workspace._id),
        projectFile.sessionId,
        projectFile.fileId,
      );
      if (trashed?.trash_id) {
        await workspaceProxy.purgeFile(reqA, 'project', String(workspace._id), trashed.trash_id);
      }
    }
  } catch (error) {
    console.error('CLEANUP_PROJECT_FILE_WARNING', error.message);
  }

  try {
    if (personalUpload?.storage_session_id && personalUpload?.file_id && userA) {
      const reqA = reqFor(userA);
      const trashed = await workspaceProxy.trashFile(
        reqA,
        'user',
        undefined,
        personalUpload.storage_session_id,
        personalUpload.file_id,
      );
      if (trashed?.trash_id) {
        await workspaceProxy.purgeFile(reqA, 'user', undefined, trashed.trash_id);
      }
    }
  } catch (error) {
    console.error('CLEANUP_PERSONAL_FILE_WARNING', error.message);
  }
}

async function cleanupDatabase() {
  try {
    if (userA?._id) {
      await db.deleteConvos(String(userA._id), { conversationId }).catch(() => {});
    }
    if (workspace?._id) {
      await mongoose.models.AclEntry?.deleteMany({ resourceId: workspace._id });
      await mongoose.models.Workspace?.deleteOne({ _id: workspace._id });
    }
    if (userA?._id) {
      await db.deleteUserById(String(userA._id));
    }
    if (userB?._id) {
      await db.deleteUserById(String(userB._id));
    }
  } catch (error) {
    console.error('CLEANUP_DB_WARNING', error.message);
  }
}

(async () => {
  await connectDb();
  try {
    userA = await db.createUser(
      {
        name: prefix + ' A',
        username: prefix + '-a',
        email: prefix + '-a@example.invalid',
        emailVerified: true,
        provider: 'openid',
        idOnTheSource: prefix + '-a',
        role: 'USER',
      },
      undefined,
      true,
      true,
    );
    userB = await db.createUser(
      {
        name: prefix + ' B',
        username: prefix + '-b',
        email: prefix + '-b@example.invalid',
        emailVerified: true,
        provider: 'openid',
        idOnTheSource: prefix + '-b',
        role: 'USER',
      },
      undefined,
      true,
      true,
    );
    must(userA?._id && userB?._id, 'synthetic principals created');

    workspace = await db.createWorkspace({
      name: prefix + ' project',
      description: 'disposable release acceptance',
      ownerId: String(userA._id),
    });
    const workspaceId = String(workspace._id);

    await grantPermission({
      principalType: PrincipalType.USER,
      principalId: String(userA._id),
      resourceType: ResourceType.WORKSPACE,
      resourceId: workspaceId,
      accessRoleId: AccessRoleIds.WORKSPACE_OWNER,
      grantedBy: String(userA._id),
    });
    must(true, 'project owner ACL created');
    await syncProjectQuota(workspaceId);
    pass('project quota boundary provisioned');

    const reqA = reqFor(userA);
    const reqB = reqFor(userB);
    let deniedBefore = false;
    try {
      await resolveWorkspaceContextExplicit(reqB, workspaceId);
    } catch (error) {
      deniedBefore = error.status === 403;
    }
    must(deniedBefore, 'non-member project access denied before grant');

    await grantPermission({
      principalType: PrincipalType.USER,
      principalId: String(userB._id),
      resourceType: ResourceType.WORKSPACE,
      resourceId: workspaceId,
      accessRoleId: AccessRoleIds.WORKSPACE_EDITOR,
      grantedBy: String(userA._id),
    });
    reqB.workspaceContext = await resolveWorkspaceContextExplicit(reqB, workspaceId);
    const editorUsage = await workspaceProxy.getUsage(reqB, 'project', workspaceId);
    must(
      editorUsage?.workspace_id === workspaceId && editorUsage?.kind === 'project',
      'project editor gets signed quota access',
    );

    personalUpload = await uploadCodeEnvFile({
      req: reqA,
      stream: Readable.from(personalBytes),
      filename: 'release-personal.txt',
      kind: 'user',
      id: String(userA._id),
    });
    must(personalUpload?.storage_session_id && personalUpload?.file_id, 'personal signed upload');
    const personalDownload = await codeApi(
      reqA,
      'GET',
      `/download/${personalUpload.storage_session_id}/${personalUpload.file_id}?kind=user&id=${userB._id}`,
    );
    must(
      personalDownload.status === 200 && personalDownload.bytes.equals(personalBytes),
      'personal owner download ignores forged query owner',
      String(personalDownload.status),
    );
    const crossPersonal = await codeApi(
      reqB,
      'GET',
      `/download/${personalUpload.storage_session_id}/${personalUpload.file_id}?kind=user&id=${userA._id}`,
    );
    must(
      crossPersonal.status !== 200,
      'cross-user personal download denied',
      String(crossPersonal.status),
    );

    const convo = await db.saveConvo(
      { userId: String(userA._id), isTemporary: false },
      {
        conversationId,
        title: prefix + ' project conversation',
        endpoint: 'agents',
        workspaceId,
      },
      { context: 'release-acceptance' },
    );
    must(
      convo && !convo.message && String(convo.workspaceId) === workspaceId,
      'project conversation bound to workspace',
    );

    const execReq = reqFor(userA, { conversationId });
    execReq.workspaceContext = await resolveWorkspaceContext(execReq);
    must(
      execReq.workspaceContext?.workspaceId === workspaceId,
      'conversation workspace ACL resolved on execution request',
    );

    bindCodeApiExecutionScope(execReq, {
      userId: String(userA._id),
      tenantId: TENANT,
      conversationId,
      sessionId: executionSessionId,
      workspaceKind: 'project',
      workspaceId,
      fileGrants: [],
    });

    const execution = await codeApi(execReq, 'POST', '/exec', {
      lang: 'python',
      code:
        'import os\n' +
        'os.makedirs("outputs", exist_ok=True)\n' +
        `open("outputs/release-final.txt","w").write(${JSON.stringify(projectText)})\n` +
        'print("release-acceptance-ok")\n',
    });
    must(
      execution.status === 200 && execution.json?.session_id === executionSessionId,
      'scoped project execution accepted',
      `${execution.status} ${execution.text.slice(0, 180)}`,
    );
    const output = execution.json?.files?.find((file) => file.name === 'release-final.txt');
    must(output?.id, 'scoped execution published final');

    const browseA = reqFor(userA);
    browseA.workspaceContext = await resolveWorkspaceContextExplicit(browseA, workspaceId);
    const projectFiles = await workspaceProxy.listFiles(browseA, 'project', workspaceId);
    projectFile =
      projectFiles?.items?.find(
        (file) => file.fileId === output.id && file.name === 'release-final.txt',
      ) ?? null;
    must(
      projectFile?.sessionId?.startsWith('pub-'),
      'project final mirrored into browser-visible pub session',
    );

    const ownerFinal = await codeApi(
      browseA,
      'GET',
      `/download/${projectFile.sessionId}/${projectFile.fileId}?kind=project&id=${workspaceId}`,
    );
    must(
      ownerFinal.status === 200 && ownerFinal.bytes.toString('utf8') === projectText,
      'project owner final download',
    );

    const editorFinal = await codeApi(
      reqB,
      'GET',
      `/download/${projectFile.sessionId}/${projectFile.fileId}?kind=project&id=${workspaceId}`,
    );
    must(
      editorFinal.status === 200 && editorFinal.bytes.toString('utf8') === projectText,
      'authorized project editor final download',
    );

    const forgedWorkspace = new mongoose.Types.ObjectId().toString();
    const forged = await codeApi(
      browseA,
      'GET',
      `/download/${projectFile.sessionId}/${projectFile.fileId}?kind=project&id=${forgedWorkspace}`,
    );
    must(
      forged.status === 403,
      'signed project token cannot forge query workspace',
      String(forged.status),
    );

    await db.revokePermission(
      PrincipalType.USER,
      String(userB._id),
      ResourceType.WORKSPACE,
      workspaceId,
    );
    let deniedAfter = false;
    try {
      await resolveWorkspaceContextExplicit(reqFor(userB), workspaceId);
    } catch (error) {
      deniedAfter = error.status === 403;
    }
    must(deniedAfter, 'project membership revocation blocks next access');

    const adminToken = await mintInternalAdminToken();
    const revokeResponse = await fetch(getCodeBaseURL() + '/internal/execution-sessions/revoke', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + adminToken,
        'Content-Type': 'application/json',
        'User-Agent': 'LibreChat-Release-Acceptance/1.0',
      },
      body: JSON.stringify({
        user_id: String(userA._id),
        workspace_kind: 'project',
        workspace_id: workspaceId,
        conversation_id: conversationId,
        session_id: executionSessionId,
      }),
    });
    const revokeJson = await revokeResponse.json();
    must(
      revokeResponse.status === 200 && revokeJson?.revoked === true,
      'internal execution-session revocation accepted',
      `${revokeResponse.status}`,
    );

    const revokedReq = reqFor(userA, { conversationId });
    revokedReq.workspaceContext = await resolveWorkspaceContext(revokedReq);
    bindCodeApiExecutionScope(revokedReq, {
      userId: String(userA._id),
      tenantId: TENANT,
      conversationId,
      sessionId: executionSessionId,
      workspaceKind: 'project',
      workspaceId,
      fileGrants: [],
    });
    const postRevokeExec = await codeApi(revokedReq, 'POST', '/exec', {
      lang: 'python',
      code: 'print("must-not-run")',
    });
    must(
      postRevokeExec.status === 403 && /REVOKED/.test(postRevokeExec.text),
      'revoked scoped execution denied',
      String(postRevokeExec.status),
    );
    const postRevokeScopedDownload = await codeApi(
      revokedReq,
      'GET',
      `/download/${executionSessionId}/${output.id}?kind=project&id=${workspaceId}`,
    );
    must(
      postRevokeScopedDownload.status === 403,
      'revoked scoped-session download denied',
      String(postRevokeScopedDownload.status),
    );

    const retainedFinal = await codeApi(
      browseA,
      'GET',
      `/download/${projectFile.sessionId}/${projectFile.fileId}?kind=project&id=${workspaceId}`,
    );
    must(
      retainedFinal.status === 200 && retainedFinal.bytes.toString('utf8') === projectText,
      'published project final remains owner-downloadable after execution revocation',
    );

    const quota = await workspaceProxy.getUsage(browseA, 'project', workspaceId);
    must(
      Number.isFinite(quota?.used_bytes) && Number.isFinite(quota?.quota_bytes),
      'project quota snapshot',
      JSON.stringify(quota),
    );

    const missingAuth = await fetch(
      getCodeBaseURL() + `/workspace/files?kind=project&id=${workspaceId}`,
      { headers: { 'User-Agent': 'LibreChat-Release-Acceptance/1.0' } },
    );
    must(missingAuth.status === 401, 'missing CodeAPI auth denied', String(missingAuth.status));

    const digest = crypto
      .createHash('sha256')
      .update(
        JSON.stringify([
          TENANT,
          String(userA._id),
          'project',
          workspaceId,
          conversationId,
          executionSessionId,
        ]),
      )
      .digest('hex');
    const bindingName = crypto
      .createHash('sha256')
      .update(JSON.stringify([TENANT, 'project', workspaceId, executionSessionId]))
      .digest('hex');
    const uid = 1000000000 + (parseInt(digest.slice(0, 8), 16) % 800000000);
    const scopedUser = 'lcs_' + digest.slice(0, 24);

    console.log(
      'LIBRECHAT_CODEAPI_LIVE_ACCEPTANCE_PASS ' +
        JSON.stringify({
          prefix,
          userA: String(userA._id),
          userB: String(userB._id),
          workspaceId,
          conversationId,
          executionSessionId,
          personalUpload,
          projectFile: {
            sessionId: projectFile.sessionId,
            fileId: projectFile.fileId,
            name: projectFile.name,
          },
          quota,
          cleanup: { digest, bindingName, uid, scopedUser },
        }),
    );
  } finally {
    await deleteSyntheticStorage();
    await cleanupDatabase();
    await mongoose.disconnect();
  }
})().catch((error) => {
  console.error('LIBRECHAT_CODEAPI_LIVE_ACCEPTANCE_FAILED', error.stack || error.message);
  process.exit(1);
});

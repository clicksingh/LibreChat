/**
 * 8S3D.1 browser E2E — workspace REST helpers for TEST FIXTURE SETUP only
 * (create a project, grant/revoke membership). The actual behavior under
 * test (who can see/access what) is always exercised through the real
 * browser in the J6-J10 specs — these helpers only establish preconditions,
 * mirroring how J4/J5 used Mongo session injection for auth setup rather
 * than the login form.
 */
import { BASE } from './constants';
import { accessToken } from './auth';

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';

async function call(userId: string, method: string, path: string, body?: unknown) {
  const token = accessToken(userId);
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'User-Agent': UA,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let json: Record<string, unknown> | undefined;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: r.status, json };
}

export async function createWorkspace(ownerId: string, name: string): Promise<{ id: string }> {
  const { status, json } = await call(ownerId, 'POST', '/api/workspaces', { name });
  if (status !== 201 || !json?._id) {
    throw new Error(`createWorkspace failed: ${status} ${JSON.stringify(json)}`);
  }
  return { id: json._id as string };
}

export async function addMember(
  ownerId: string,
  workspaceId: string,
  principalId: string,
  accessRoleId: 'workspace_viewer' | 'workspace_editor' | 'workspace_owner' = 'workspace_editor',
): Promise<void> {
  const { status, json } = await call(ownerId, 'POST', `/api/workspaces/${workspaceId}/members`, {
    principalType: 'user',
    principalId,
    accessRoleId,
  });
  if (status !== 201) {
    throw new Error(`addMember failed: ${status} ${JSON.stringify(json)}`);
  }
}

export async function removeMember(
  ownerId: string,
  workspaceId: string,
  principalId: string,
): Promise<void> {
  const { status } = await call(
    ownerId,
    'DELETE',
    `/api/workspaces/${workspaceId}/members/user/${principalId}`,
  );
  if (status !== 200) {
    throw new Error(`removeMember failed: ${status}`);
  }
}

export async function archiveWorkspace(ownerId: string, workspaceId: string): Promise<void> {
  await call(ownerId, 'PATCH', `/api/workspaces/${workspaceId}`, { archive: true });
}

export async function getUsage(
  userId: string,
  scope: 'personal' | { workspaceId: string },
): Promise<{ used_bytes: number; quota_bytes: number | null; state: string }> {
  const path =
    scope === 'personal'
      ? '/api/workspaces/personal/usage'
      : `/api/workspaces/${scope.workspaceId}/usage`;
  const { status, json } = await call(userId, 'GET', path);
  if (status !== 200) {
    throw new Error(`getUsage failed: ${status} ${JSON.stringify(json)}`);
  }
  return json as { used_bytes: number; quota_bytes: number | null; state: string };
}

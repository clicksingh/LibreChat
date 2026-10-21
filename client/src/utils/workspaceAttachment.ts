import type { TWorkspaceFileEntry } from 'librechat-data-provider';

export const WORKSPACE_FILE_DRAG_TYPE = 'application/x-cbhr-workspace-file';
export const WORKSPACE_ATTACH_EVENT = 'cbhr:attach-workspace-file';

export type WorkspaceAttachRequest = {
  kind: 'personal' | 'project';
  projectId?: string;
  sessionId: string;
  fileId: string;
  name: string;
  size: number;
};

export function makeWorkspaceAttachRequest(
  item: TWorkspaceFileEntry,
  selection: { kind: 'personal' } | { kind: 'project'; id: string },
): WorkspaceAttachRequest {
  return {
    kind: selection.kind,
    ...(selection.kind === 'project' ? { projectId: selection.id } : {}),
    sessionId: item.sessionId,
    fileId: item.fileId,
    name: item.name,
    size: item.size,
  };
}

/**
 * Project/personal scope is what matters, not the endpoint label. Custom
 * endpoints such as "CBHR AI" use the same composer attachment contract.
 */
export function matchesWorkspaceChatScope(
  item: WorkspaceAttachRequest,
  conversation: { workspaceId?: string | null; endpoint?: string | null } | null,
): boolean {
  const workspaceId = conversation?.workspaceId || undefined;
  return item.kind === 'project'
    ? !!item.projectId && item.projectId === workspaceId
    : !workspaceId;
}

/**
 * Browser drag metadata is an untrusted hint, never authorization. Accept only
 * the opaque keys CodeAPI's attach endpoint understands; the backend must
 * still re-list the authorized workspace and verify chat/project ownership.
 */
const OPAQUE_WORKSPACE_KEY = /^[A-Za-z0-9_.-]{1,180}$/;
const isOpaqueWorkspaceKey = (value: unknown): value is string =>
  typeof value === 'string' &&
  OPAQUE_WORKSPACE_KEY.test(value) &&
  !value.startsWith('.') &&
  !value.endsWith('.pending') &&
  !value.endsWith('.meta.json');

export function isWorkspaceAttachRequest(value: unknown): value is WorkspaceAttachRequest {
  if (value == null || typeof value !== 'object') return false;
  const item = value as Partial<WorkspaceAttachRequest>;
  if (
    !isOpaqueWorkspaceKey(item.sessionId) ||
    !isOpaqueWorkspaceKey(item.fileId) ||
    typeof item.name !== 'string' ||
    !item.name.trim() ||
    item.name.length > 255 ||
    !Number.isSafeInteger(item.size) ||
    (item.size ?? 0) <= 0
  ) {
    return false;
  }
  return item.kind === 'personal'
    ? item.projectId == null
    : item.kind === 'project' && isOpaqueWorkspaceKey(item.projectId);
}

export function readWorkspaceFileDrop(
  dataTransfer: Pick<DataTransfer, 'getData'>,
): WorkspaceAttachRequest | null {
  try {
    const data: unknown = JSON.parse(dataTransfer.getData(WORKSPACE_FILE_DRAG_TYPE));
    return isWorkspaceAttachRequest(data) ? data : null;
  } catch {
    // Missing/invalid drag metadata should never trigger a normal file upload.
  }
  return null;
}

export function isWorkspaceFileDrag(dataTransfer: Pick<DataTransfer, 'types'>): boolean {
  return Array.from(dataTransfer.types).includes(WORKSPACE_FILE_DRAG_TYPE);
}

/**
 * Acquire synchronously before awaiting the authorized server attach.
 * React's shared filesLoading state updates on the next render, which leaves
 * a short window where duplicate drops would otherwise start two requests.
 * The returned release is idempotent and must be called from finally.
 */
export function beginWorkspaceFileAttach(
  lock: { current: boolean },
  setLoading: (loading: boolean) => void,
): (() => void) | null {
  if (lock.current) return null;
  lock.current = true;
  setLoading(true);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    lock.current = false;
    setLoading(false);
  };
}

export function requestWorkspaceFileAttach(item: WorkspaceAttachRequest): void {
  window.dispatchEvent(
    new CustomEvent<WorkspaceAttachRequest>(WORKSPACE_ATTACH_EVENT, { detail: item }),
  );
}

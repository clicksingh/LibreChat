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

export function readWorkspaceFileDrop(
  dataTransfer: Pick<DataTransfer, 'getData'>,
): WorkspaceAttachRequest | null {
  try {
    const data = JSON.parse(dataTransfer.getData(WORKSPACE_FILE_DRAG_TYPE));
    if (
      data &&
      (data.kind === 'personal' ||
        (data.kind === 'project' &&
          typeof data.projectId === 'string' &&
          data.projectId.length > 0)) &&
      typeof data.sessionId === 'string' &&
      typeof data.fileId === 'string' &&
      typeof data.name === 'string' &&
      Number.isSafeInteger(data.size) &&
      data.size > 0
    ) {
      return data as WorkspaceAttachRequest;
    }
  } catch {
    // Missing/invalid drag metadata should never trigger a normal file upload.
  }
  return null;
}

export function isWorkspaceFileDrag(dataTransfer: Pick<DataTransfer, 'types'>): boolean {
  return Array.from(dataTransfer.types).includes(WORKSPACE_FILE_DRAG_TYPE);
}

export function requestWorkspaceFileAttach(item: WorkspaceAttachRequest): void {
  window.dispatchEvent(
    new CustomEvent<WorkspaceAttachRequest>(WORKSPACE_ATTACH_EVENT, { detail: item }),
  );
}

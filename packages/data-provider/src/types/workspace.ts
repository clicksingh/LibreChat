/**
 * 8S3D.1 — Workspace OS client types. Mirrors the shapes returned by
 * api/server/routes/workspaces.js (Mongo-side project metadata) and
 * codeapi's /workspace/* endpoints (proxied through those same routes).
 */

export type WorkspaceState = 'active' | 'archived';
export type WorkspaceUsageState = 'NORMAL' | 'WARNING' | 'CRITICAL' | 'FULL';

export interface TWorkspace {
  _id: string;
  name: string;
  description?: string;
  ownerId: string;
  state: WorkspaceState;
  quotaBytesOverride?: number | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface TWorkspaceListResponse {
  personal: { kind: 'personal'; workspace_id: string };
  projects: TWorkspace[];
}

export interface TWorkspaceUsage {
  workspace_id: string;
  kind: 'personal' | 'project';
  used_bytes: number;
  quota_bytes: number | null;
  state: WorkspaceUsageState;
}

export interface TWorkspaceFileEntry {
  sessionId: string;
  fileId: string;
  path: string;
  name: string;
  size: number;
  modified: string;
}

export interface TWorkspaceFileListResponse {
  items: TWorkspaceFileEntry[];
  nextCursor: string | null;
}

export interface TWorkspaceTrashEntry {
  trashId: string;
  originalRelPath: string;
  sessionId: string;
  fileId: string;
  name: string;
  size: number;
  trashedAt: string;
}

export interface TWorkspaceTrashListResponse {
  items: TWorkspaceTrashEntry[];
  nextCursor: string | null;
}

export interface TCreateWorkspaceRequest {
  name: string;
  description?: string;
}

export interface TWorkspaceMemberGrantRequest {
  principalType: 'user' | 'group';
  principalId: string;
  accessRoleId: 'workspace_viewer' | 'workspace_editor' | 'workspace_owner';
}

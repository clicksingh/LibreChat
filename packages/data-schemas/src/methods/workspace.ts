import type { Model, Types } from 'mongoose';
import { createWorkspaceModel } from '~/models/workspace';
import type { IWorkspace, IWorkspaceDocument } from '~/types';

export type CreateWorkspaceInput = {
  name: string;
  description?: string;
  ownerId: string;
};

export interface WorkspaceMethods {
  createWorkspace(input: CreateWorkspaceInput): Promise<IWorkspace>;
  getWorkspace(workspaceId: string): Promise<IWorkspace | null>;
  listWorkspacesByIds(workspaceIds: Array<string | Types.ObjectId>): Promise<IWorkspace[]>;
  renameWorkspace(workspaceId: string, name: string): Promise<IWorkspace | null>;
  archiveWorkspace(workspaceId: string): Promise<IWorkspace | null>;
  setWorkspaceQuotaOverride(
    workspaceId: string,
    quotaBytesOverride: number | null,
  ): Promise<IWorkspace | null>;
}

/**
 * Minimal CRUD for project-workspace metadata (8S3D.1). Membership/ACL is
 * deliberately NOT here — it lives in AclEntry (ResourceType.WORKSPACE) via
 * the generic permission system (see PermissionService.grantPermission/
 * findAccessibleResources). This model only ever answers "what is this
 * workspace," never "who can access it."
 */
export function createWorkspaceMethods(mongoose: typeof import('mongoose')): WorkspaceMethods {
  const Workspace: Model<IWorkspaceDocument> = createWorkspaceModel(mongoose);

  async function createWorkspace(input: CreateWorkspaceInput): Promise<IWorkspace> {
    const doc = await Workspace.create({
      name: input.name,
      description: input.description ?? '',
      ownerId: input.ownerId,
      state: 'active',
      quotaBytesOverride: null,
    });
    return doc.toObject();
  }

  async function getWorkspace(workspaceId: string): Promise<IWorkspace | null> {
    return Workspace.findById(workspaceId).lean();
  }

  async function listWorkspacesByIds(
    workspaceIds: Array<string | Types.ObjectId>,
  ): Promise<IWorkspace[]> {
    if (!workspaceIds.length) return [];
    return Workspace.find({ _id: { $in: workspaceIds } }).lean();
  }

  async function renameWorkspace(workspaceId: string, name: string): Promise<IWorkspace | null> {
    return Workspace.findByIdAndUpdate(workspaceId, { $set: { name } }, { new: true }).lean();
  }

  async function archiveWorkspace(workspaceId: string): Promise<IWorkspace | null> {
    return Workspace.findByIdAndUpdate(
      workspaceId,
      { $set: { state: 'archived' } },
      { new: true },
    ).lean();
  }

  async function setWorkspaceQuotaOverride(
    workspaceId: string,
    quotaBytesOverride: number | null,
  ): Promise<IWorkspace | null> {
    return Workspace.findByIdAndUpdate(
      workspaceId,
      { $set: { quotaBytesOverride } },
      { new: true },
    ).lean();
  }

  return {
    createWorkspace,
    getWorkspace,
    listWorkspacesByIds,
    renameWorkspace,
    archiveWorkspace,
    setWorkspaceQuotaOverride,
  };
}

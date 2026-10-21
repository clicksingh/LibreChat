import type { Document, Types } from 'mongoose';

/**
 * A project workspace (8S3D.1) — a governed storage/quota boundary that
 * multiple authorized users can share. Membership/ACL lives entirely in
 * AclEntry (ResourceType.WORKSPACE) via the generic permission system, NOT
 * on this document — this model holds only the workspace's own metadata.
 * The personal workspace (one per user) has no corresponding document here;
 * it's implicit (workspace_id === userId) and enforced entirely at CodeAPI.
 */
export interface IWorkspace {
  _id?: Types.ObjectId;
  name: string;
  description?: string;
  ownerId: string;
  state: 'active' | 'archived';
  /** Explicit quota override in bytes; null = fall back to platform/group policy. */
  quotaBytesOverride?: number | null;
  createdAt?: Date;
  updatedAt?: Date;
  tenantId?: string;
}

export interface IWorkspaceDocument extends Omit<IWorkspace, '_id'>, Document {}

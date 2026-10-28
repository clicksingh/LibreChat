import type { Document, Types } from 'mongoose';

export type ModelPolicyUserMode = 'locked-current-default';
export type ModelPolicyAdminMode = 'managed-catalog';

export interface IModelPolicyAudiences {
  USER: ModelPolicyUserMode;
  ADMIN: ModelPolicyAdminMode;
}

export interface IModelPolicyCandidate {
  schemaVersion: number;
  companyDefaultDeploymentId: string;
  activeDeploymentIds: string[];
  audiences: IModelPolicyAudiences;
}

export interface IModelPolicyHead {
  tenantId: string;
  _id?: Types.ObjectId;
  key: string;
  version: number;
  schemaVersion: number;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface IModelPolicyRevision extends IModelPolicyCandidate {
  tenantId: string;
  _id?: Types.ObjectId;
  version: number;
  parentVersion: number;
  publishedBy: string;
  publishedAt: Date;
  source: string;
}

export interface IModelPolicyHeadDocument extends Omit<IModelPolicyHead, '_id'>, Document {}
export interface IModelPolicyRevisionDocument extends Omit<IModelPolicyRevision, '_id'>, Document {}

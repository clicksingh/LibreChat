import type { Document, Types } from 'mongoose';

/**
 * 8S3D.1 quota policy override. A small, DEDICATED collection rather than
 * folding quota numbers into the existing generic config-override engine —
 * that engine's merge semantics are boolean-capability UNION (most
 * permissive wins), whereas quota resolution needs numeric MAX-of-applicable
 * precedence (explicit user override > group entitlement > platform
 * default), a different enough shape that reusing it risked subtle
 * cross-feature bugs for a change made under time pressure. Documented as a
 * deliberate scoping choice, not an oversight (milestones/8S3D-workspace-os.md).
 */
export type QuotaPolicyScope = 'platformPersonal' | 'platformProject' | 'group' | 'user' | 'project';

export interface IQuotaPolicy {
  _id?: Types.ObjectId;
  scope: QuotaPolicyScope;
  /** null for platform-wide scopes; a groupId/userId/workspaceId otherwise. */
  scopeId?: string | null;
  quotaBytes: number;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface IQuotaPolicyDocument extends Omit<IQuotaPolicy, '_id'>, Document {}

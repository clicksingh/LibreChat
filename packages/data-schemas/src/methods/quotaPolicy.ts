import type { Model } from 'mongoose';
import { createQuotaPolicyModel } from '~/models/quotaPolicy';
import type { IQuotaPolicy, IQuotaPolicyDocument, QuotaPolicyScope } from '~/types';

const DEFAULT_PERSONAL_QUOTA_BYTES = 2 * 1024 * 1024 * 1024; // 2GiB — matches the 8S3D cutover default
const DEFAULT_PROJECT_QUOTA_BYTES = 10 * 1024 * 1024 * 1024; // 10GiB

export interface EffectivePersonalQuotaInput {
  userId: string;
  groupIds: string[];
}

export interface EffectiveQuotaResult {
  quotaBytes: number;
  source: 'default' | 'group' | 'user' | 'project';
}

export interface WorkspaceQuotaMethods {
  upsertQuotaPolicy(
    scope: QuotaPolicyScope,
    scopeId: string | null,
    quotaBytes: number,
  ): Promise<IQuotaPolicy>;
  deleteQuotaPolicy(scope: QuotaPolicyScope, scopeId: string | null): Promise<boolean>;
  listQuotaPolicies(): Promise<IQuotaPolicy[]>;
  /**
   * Personal-workspace precedence: explicit user override > the MOST
   * PERMISSIVE (highest) applicable group entitlement > platform default.
   * Documented explicitly (per 8S3D.1 directive) since CBHR's existing
   * group-capability convention is boolean-union "most permissive wins" —
   * this generalizes the same intent to a numeric ceiling.
   */
  resolveEffectivePersonalQuota(input: EffectivePersonalQuotaInput): Promise<EffectiveQuotaResult>;
  /** Project precedence: explicit project override > project default. */
  resolveEffectiveProjectQuota(workspaceId: string): Promise<EffectiveQuotaResult>;
}

export function createQuotaPolicyMethods(
  mongoose: typeof import('mongoose'),
): WorkspaceQuotaMethods {
  const QuotaPolicy: Model<IQuotaPolicyDocument> = createQuotaPolicyModel(mongoose);

  async function upsertQuotaPolicy(
    scope: QuotaPolicyScope,
    scopeId: string | null,
    quotaBytes: number,
  ): Promise<IQuotaPolicy> {
    const doc = await QuotaPolicy.findOneAndUpdate(
      { scope, scopeId },
      { $set: { quotaBytes } },
      { upsert: true, new: true },
    ).lean();
    return doc as IQuotaPolicy;
  }

  async function deleteQuotaPolicy(scope: QuotaPolicyScope, scopeId: string | null): Promise<boolean> {
    const result = await QuotaPolicy.deleteOne({ scope, scopeId });
    return result.deletedCount > 0;
  }

  async function listQuotaPolicies(): Promise<IQuotaPolicy[]> {
    return QuotaPolicy.find({}).lean();
  }

  async function resolveEffectivePersonalQuota(
    input: EffectivePersonalQuotaInput,
  ): Promise<EffectiveQuotaResult> {
    const userOverride = await QuotaPolicy.findOne({
      scope: 'user',
      scopeId: input.userId,
    }).lean();
    if (userOverride) {
      return { quotaBytes: userOverride.quotaBytes, source: 'user' };
    }

    if (input.groupIds.length > 0) {
      const groupPolicies = await QuotaPolicy.find({
        scope: 'group',
        scopeId: { $in: input.groupIds },
      }).lean();
      if (groupPolicies.length > 0) {
        // Most-permissive applicable group entitlement wins (highest byte
        // ceiling), mirroring CBHR's existing group-capability union
        // convention generalized to a numeric max.
        const maxBytes = Math.max(...groupPolicies.map((p) => p.quotaBytes));
        return { quotaBytes: maxBytes, source: 'group' };
      }
    }

    const platformDefault = await QuotaPolicy.findOne({
      scope: 'platformPersonal',
      scopeId: null,
    }).lean();
    return {
      quotaBytes: platformDefault?.quotaBytes ?? DEFAULT_PERSONAL_QUOTA_BYTES,
      source: 'default',
    };
  }

  async function resolveEffectiveProjectQuota(workspaceId: string): Promise<EffectiveQuotaResult> {
    const projectOverride = await QuotaPolicy.findOne({
      scope: 'project',
      scopeId: workspaceId,
    }).lean();
    if (projectOverride) {
      return { quotaBytes: projectOverride.quotaBytes, source: 'project' };
    }
    const platformDefault = await QuotaPolicy.findOne({
      scope: 'platformProject',
      scopeId: null,
    }).lean();
    return {
      quotaBytes: platformDefault?.quotaBytes ?? DEFAULT_PROJECT_QUOTA_BYTES,
      source: 'default',
    };
  }

  return {
    upsertQuotaPolicy,
    deleteQuotaPolicy,
    listQuotaPolicies,
    resolveEffectivePersonalQuota,
    resolveEffectiveProjectQuota,
  };
}

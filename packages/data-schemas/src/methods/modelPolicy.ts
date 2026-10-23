import type { ClientSession, Model } from 'mongoose';
import type {
  IModelPolicyAudiences,
  IModelPolicyCandidate,
  IModelPolicyHead,
  IModelPolicyHeadDocument,
  IModelPolicyRevision,
  IModelPolicyRevisionDocument,
} from '~/types';
import { createModelPolicyHeadModel, createModelPolicyRevisionModel } from '~/models/modelPolicy';

export const MODEL_POLICY_KEY = 'managed-models';
export const MODEL_POLICY_SCHEMA_VERSION = 1;
export const MODEL_POLICY_AUDIENCES: Readonly<IModelPolicyAudiences> = Object.freeze({
  USER: 'locked-current-default' as const,
  ADMIN: 'managed-catalog' as const,
});

const MAX_DEPLOYMENTS = 128;
const SAFE_DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;

export class ModelPolicyRevisionConflictError extends Error {
  code = 'MODEL_POLICY_REVISION_CONFLICT';
  status = 409;
}

export class ModelPolicyInvalidError extends Error {
  code = 'MODEL_POLICY_INVALID';
  status = 422;
}

function conflict(message = 'Managed-model policy changed; reload and retry'): never {
  throw new ModelPolicyRevisionConflictError(message);
}

function invalid(message: string): never {
  throw new ModelPolicyInvalidError(message);
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

export function normalizeModelPolicyCandidate(
  candidate: IModelPolicyCandidate,
): IModelPolicyCandidate {
  if (!candidate || typeof candidate !== 'object') invalid('Policy candidate is required');
  if (candidate.schemaVersion !== MODEL_POLICY_SCHEMA_VERSION) {
    invalid('Unsupported model-policy schema version');
  }

  const companyDefaultDeploymentId = String(candidate.companyDefaultDeploymentId || '').trim();
  if (!SAFE_DEPLOYMENT_ID.test(companyDefaultDeploymentId)) {
    invalid('Invalid company default deployment id');
  }

  if (
    !Array.isArray(candidate.activeDeploymentIds) ||
    candidate.activeDeploymentIds.length < 1 ||
    candidate.activeDeploymentIds.length > MAX_DEPLOYMENTS
  ) {
    invalid('activeDeploymentIds must contain between 1 and 128 deployments');
  }

  const activeDeploymentIds = unique(
    candidate.activeDeploymentIds.map((value) => String(value || '').trim()),
  );
  if (
    activeDeploymentIds.length !== candidate.activeDeploymentIds.length ||
    activeDeploymentIds.some((value) => !SAFE_DEPLOYMENT_ID.test(value))
  ) {
    invalid('activeDeploymentIds must contain unique valid deployment ids');
  }
  if (!activeDeploymentIds.includes(companyDefaultDeploymentId)) {
    invalid('Company default deployment must be active');
  }
  if (
    candidate.audiences?.USER !== MODEL_POLICY_AUDIENCES.USER ||
    candidate.audiences?.ADMIN !== MODEL_POLICY_AUDIENCES.ADMIN
  ) {
    invalid('Unsupported managed-model audience contract');
  }

  return {
    schemaVersion: MODEL_POLICY_SCHEMA_VERSION,
    companyDefaultDeploymentId,
    activeDeploymentIds,
    audiences: { ...MODEL_POLICY_AUDIENCES },
  };
}

export function sameModelPolicyCandidate(
  revision: Pick<
    IModelPolicyRevision,
    'schemaVersion' | 'companyDefaultDeploymentId' | 'activeDeploymentIds' | 'audiences'
  >,
  candidate: IModelPolicyCandidate,
): boolean {
  const normalized = normalizeModelPolicyCandidate(candidate);
  return (
    revision.schemaVersion === normalized.schemaVersion &&
    String(revision.companyDefaultDeploymentId) === normalized.companyDefaultDeploymentId &&
    JSON.stringify(revision.activeDeploymentIds) ===
      JSON.stringify(normalized.activeDeploymentIds) &&
    revision.audiences?.USER === normalized.audiences.USER &&
    revision.audiences?.ADMIN === normalized.audiences.ADMIN
  );
}

export interface ModelPolicyMethods {
  getModelPolicyHead(key?: string, session?: ClientSession): Promise<IModelPolicyHead | null>;
  getModelPolicyRevision(
    version: number,
    session?: ClientSession,
  ): Promise<IModelPolicyRevision | null>;
  commitModelPolicyRevision(
    candidate: IModelPolicyCandidate,
    options: {
      expectedVersion: number;
      actor?: string;
      source?: string;
      key?: string;
    },
    session?: ClientSession,
  ): Promise<{ version: number; revision: IModelPolicyRevision; noop: boolean }>;
}

export function createModelPolicyMethods(mongoose: typeof import('mongoose')): ModelPolicyMethods {
  const Head: Model<IModelPolicyHeadDocument> = createModelPolicyHeadModel(mongoose);
  const Revision: Model<IModelPolicyRevisionDocument> = createModelPolicyRevisionModel(mongoose);

  async function getModelPolicyHead(
    key = MODEL_POLICY_KEY,
    session?: ClientSession,
  ): Promise<IModelPolicyHead | null> {
    return Head.findOne({ key })
      .session(session ?? null)
      .lean<IModelPolicyHead>();
  }

  async function getModelPolicyRevision(
    version: number,
    session?: ClientSession,
  ): Promise<IModelPolicyRevision | null> {
    return Revision.findOne({ version })
      .session(session ?? null)
      .lean<IModelPolicyRevision>();
  }

  async function commitModelPolicyRevision(
    candidate: IModelPolicyCandidate,
    options: {
      expectedVersion: number;
      actor?: string;
      source?: string;
      key?: string;
    },
    session?: ClientSession,
  ): Promise<{ version: number; revision: IModelPolicyRevision; noop: boolean }> {
    const normalized = normalizeModelPolicyCandidate(candidate);
    const expectedVersion = options?.expectedVersion;
    if (!Number.isInteger(expectedVersion) || expectedVersion < 0) {
      invalid('expectedVersion must be a non-negative integer');
    }

    const key = options?.key || MODEL_POLICY_KEY;
    const currentHead = await getModelPolicyHead(key, session);
    if (expectedVersion === 0 ? currentHead != null : currentHead?.version !== expectedVersion) {
      conflict();
    }

    if (currentHead) {
      const currentRevision = await getModelPolicyRevision(currentHead.version, session);
      if (!currentRevision) invalid('Active model-policy revision is missing');
      if (sameModelPolicyCandidate(currentRevision, normalized)) {
        return { version: currentHead.version, revision: currentRevision, noop: true };
      }
    }

    const nextVersion = expectedVersion + 1;
    let revisionDocument: IModelPolicyRevisionDocument;
    try {
      const rows = await Revision.create(
        [
          {
            ...normalized,
            version: nextVersion,
            parentVersion: expectedVersion,
            publishedBy: String(options?.actor || 'system'),
            publishedAt: new Date(),
            source: String(options?.source || 'v2'),
          },
        ],
        session ? { session } : undefined,
      );
      revisionDocument = rows[0];
    } catch (error: unknown) {
      if ((error as { code?: number }).code === 11000) conflict();
      throw error;
    }

    if (expectedVersion === 0) {
      try {
        await Head.create(
          [{ key, version: nextVersion, schemaVersion: MODEL_POLICY_SCHEMA_VERSION }],
          session ? { session } : undefined,
        );
      } catch (error: unknown) {
        if ((error as { code?: number }).code === 11000) conflict();
        throw error;
      }
    } else {
      const result = await Head.updateOne(
        { key, version: expectedVersion },
        { $set: { version: nextVersion, schemaVersion: MODEL_POLICY_SCHEMA_VERSION } },
        session ? { session } : undefined,
      );
      if (result.modifiedCount !== 1) conflict();
    }

    return {
      version: nextVersion,
      revision: revisionDocument.toObject() as IModelPolicyRevision,
      noop: false,
    };
  }

  return { getModelPolicyHead, getModelPolicyRevision, commitModelPolicyRevision };
}

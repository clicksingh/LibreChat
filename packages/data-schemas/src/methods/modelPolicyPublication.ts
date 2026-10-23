import type { ClientSession, Model } from 'mongoose';
import { createModelPolicyPublicationModel } from '~/models/modelPolicyPublication';
import type { IModelPolicyPublication, IModelPolicyPublicationDocument } from '~/types';

export type PublicationTransition = 'create' | 'noop' | 'advance';

export class ModelPolicyPublicationConflictError extends Error {
  code = 'MODEL_POLICY_PUBLICATION_CONFLICT';
  status = 409;
}

export class ModelPolicyPublicationInvalidError extends Error {
  code = 'MODEL_POLICY_PUBLICATION_INVALID';
  status = 422;
}

export function decideModelPolicyPublicationTransition(
  current: Pick<IModelPolicyPublication, 'policyVersion' | 'digest'> | null,
  incoming: Pick<IModelPolicyPublication, 'policyVersion' | 'digest'>,
): PublicationTransition {
  if (!Number.isInteger(incoming.policyVersion) || incoming.policyVersion < 1) {
    throw new ModelPolicyPublicationInvalidError('policyVersion must be a positive integer');
  }
  if (!/^[a-f0-9]{64}$/.test(incoming.digest)) {
    throw new ModelPolicyPublicationInvalidError('digest must be lowercase sha256 hex');
  }
  if (!current) {
    if (incoming.policyVersion !== 1) {
      throw new ModelPolicyPublicationConflictError('First publication must be revision 1');
    }
    return 'create';
  }
  if (incoming.policyVersion === current.policyVersion) {
    if (incoming.digest === current.digest) return 'noop';
    throw new ModelPolicyPublicationConflictError('Revision replayed with different content');
  }
  if (incoming.policyVersion < current.policyVersion) {
    throw new ModelPolicyPublicationConflictError('Stale policy revision');
  }
  if (incoming.policyVersion !== current.policyVersion + 1) {
    throw new ModelPolicyPublicationConflictError('Policy revision gap');
  }
  return 'advance';
}

export interface ModelPolicyPublicationMethods {
  getModelPolicyPublication(
    key?: string,
    session?: ClientSession,
  ): Promise<IModelPolicyPublication | null>;
  claimModelPolicyPublication(
    input: { key?: string; policyVersion: number; digest: string },
    session?: ClientSession,
  ): Promise<{ publication: IModelPolicyPublication; transition: PublicationTransition }>;
}

export function createModelPolicyPublicationMethods(
  mongoose: typeof import('mongoose'),
): ModelPolicyPublicationMethods {
  const Publication: Model<IModelPolicyPublicationDocument> =
    createModelPolicyPublicationModel(mongoose);

  async function getModelPolicyPublication(
    key = 'managed-models',
    session?: ClientSession,
  ): Promise<IModelPolicyPublication | null> {
    return Publication.findOne({ key })
      .session(session ?? null)
      .lean<IModelPolicyPublication>();
  }

  async function claimModelPolicyPublication(
    input: { key?: string; policyVersion: number; digest: string },
    session?: ClientSession,
  ): Promise<{ publication: IModelPolicyPublication; transition: PublicationTransition }> {
    const key = input.key ?? 'managed-models';
    const current = await getModelPolicyPublication(key, session);
    const transition = decideModelPolicyPublicationTransition(current, input);
    if (transition === 'noop') return { publication: current!, transition };

    if (transition === 'create') {
      try {
        const rows = await Publication.create(
          [{ key, policyVersion: input.policyVersion, digest: input.digest }],
          session ? { session } : undefined,
        );
        return { publication: rows[0].toObject() as IModelPolicyPublication, transition };
      } catch (error: unknown) {
        if ((error as { code?: number }).code === 11000) {
          throw new ModelPolicyPublicationConflictError('Concurrent initial publication');
        }
        throw error;
      }
    }

    const result = await Publication.findOneAndUpdate(
      { key, policyVersion: current!.policyVersion, digest: current!.digest },
      { $set: { policyVersion: input.policyVersion, digest: input.digest } },
      { new: true, ...(session ? { session } : {}) },
    ).lean<IModelPolicyPublication>();
    if (!result) {
      throw new ModelPolicyPublicationConflictError('Concurrent policy publication');
    }
    return { publication: result, transition };
  }

  return { getModelPolicyPublication, claimModelPolicyPublication };
}

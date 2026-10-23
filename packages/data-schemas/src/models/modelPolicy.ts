import type { Model } from 'mongoose';
import type { IModelPolicyHeadDocument, IModelPolicyRevisionDocument } from '~/types';
import { modelPolicyHeadSchema, modelPolicyRevisionSchema } from '~/schema/modelPolicy';

export function createModelPolicyHeadModel(
  mongoose: typeof import('mongoose'),
): Model<IModelPolicyHeadDocument> {
  return (
    mongoose.models.ModelPolicyHead ||
    mongoose.model<IModelPolicyHeadDocument>('ModelPolicyHead', modelPolicyHeadSchema, 'modelpolicyheads')
  );
}

export function createModelPolicyRevisionModel(
  mongoose: typeof import('mongoose'),
): Model<IModelPolicyRevisionDocument> {
  return (
    mongoose.models.ModelPolicyRevision ||
    mongoose.model<IModelPolicyRevisionDocument>(
      'ModelPolicyRevision',
      modelPolicyRevisionSchema,
      'modelpolicyrevisions',
    )
  );
}

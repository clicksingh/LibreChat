import type { Model } from 'mongoose';
import type { IModelPolicyPublicationDocument } from '~/types';
import modelPolicyPublicationSchema from '~/schema/modelPolicyPublication';

export function createModelPolicyPublicationModel(
  mongoose: typeof import('mongoose'),
): Model<IModelPolicyPublicationDocument> {
  return (
    mongoose.models.ModelPolicyPublication ||
    mongoose.model<IModelPolicyPublicationDocument>(
      'ModelPolicyPublication',
      modelPolicyPublicationSchema,
      'modelpolicypublications',
    )
  );
}
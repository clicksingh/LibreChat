import { Model } from 'mongoose';
import type { IQuotaPolicyDocument } from '~/types';
import quotaPolicySchema from '~/schema/quotaPolicy';

export function createQuotaPolicyModel(
  mongoose: typeof import('mongoose'),
): Model<IQuotaPolicyDocument> {
  return (
    mongoose.models.QuotaPolicy ||
    mongoose.model<IQuotaPolicyDocument>('QuotaPolicy', quotaPolicySchema, 'quotapolicies')
  );
}

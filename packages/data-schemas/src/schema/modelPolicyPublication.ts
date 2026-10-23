import { Schema } from 'mongoose';
import type { IModelPolicyPublicationDocument } from '~/types';

const modelPolicyPublicationSchema: Schema<IModelPolicyPublicationDocument> =
  new Schema<IModelPolicyPublicationDocument>(
    {
      key: { type: String, required: true, unique: true, index: true },
      policyVersion: { type: Number, required: true, min: 1 },
      digest: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
    },
    { timestamps: true },
  );

export default modelPolicyPublicationSchema;

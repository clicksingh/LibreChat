import { Schema } from 'mongoose';
import type { IQuotaPolicyDocument } from '~/types';

const quotaPolicySchema: Schema<IQuotaPolicyDocument> = new Schema<IQuotaPolicyDocument>(
  {
    scope: {
      type: String,
      enum: ['platformPersonal', 'platformProject', 'group', 'user', 'project'],
      required: true,
    },
    scopeId: {
      type: String,
      default: null,
    },
    quotaBytes: {
      type: Number,
      required: true,
      min: 0,
    },
  },
  { timestamps: true },
);

// One override per (scope, scopeId) — platform scopes have scopeId=null,
// which Mongo's unique index treats as a single shared value (fine: there
// is only ever one platformPersonal and one platformProject document).
quotaPolicySchema.index({ scope: 1, scopeId: 1 }, { unique: true });

export default quotaPolicySchema;

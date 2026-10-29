import { Schema } from 'mongoose';
import type { IModelPolicyHeadDocument, IModelPolicyRevisionDocument } from '~/types';

const modelPolicyDeploymentBindingSchema = new Schema(
  {
    deploymentId: { type: String, required: true, trim: true },
    model: { type: String, required: true, trim: true },
    reasoning: { type: Schema.Types.Mixed, default: null },
  },
  { _id: false },
);

const modelPolicyRoutingSchema = new Schema(
  {
    endpointName: { type: String, required: true, trim: true },
    deployments: {
      type: [modelPolicyDeploymentBindingSchema],
      required: true,
    },
  },
  { _id: false },
);

export const modelPolicyHeadSchema: Schema<IModelPolicyHeadDocument> =
  new Schema<IModelPolicyHeadDocument>(
    {
      tenantId: { type: String, required: true, trim: true },
      key: { type: String, required: true },
      version: { type: Number, required: true, min: 1 },
      schemaVersion: { type: Number, required: true, min: 1, default: 1 },
    },
    { timestamps: true },
  );

export const modelPolicyRevisionSchema: Schema<IModelPolicyRevisionDocument> =
  new Schema<IModelPolicyRevisionDocument>(
    {
      tenantId: { type: String, required: true, trim: true },
      version: { type: Number, required: true, min: 1 },
      parentVersion: { type: Number, required: true, min: 0 },
      schemaVersion: { type: Number, required: true, min: 1, default: 1 },
      companyDefaultDeploymentId: { type: String, required: true, trim: true },
      activeDeploymentIds: [{ type: String, required: true }],
      routing: { type: modelPolicyRoutingSchema, required: true },
      audiences: {
        USER: {
          type: String,
          enum: ['locked-current-default'],
          required: true,
        },
        ADMIN: {
          type: String,
          enum: ['managed-catalog'],
          required: true,
        },
      },
      publishedBy: { type: String, required: true, trim: true },
      publishedAt: { type: Date, required: true, default: Date.now },
      source: { type: String, required: true, trim: true },
    },
    { timestamps: false },
  );

// A single database may host more than one tenant. Neither policy revisions
// nor the mutable head may rely on globally unique version numbers.
modelPolicyHeadSchema.index({ tenantId: 1, key: 1 }, { unique: true });
modelPolicyRevisionSchema.index({ tenantId: 1, version: 1 }, { unique: true });

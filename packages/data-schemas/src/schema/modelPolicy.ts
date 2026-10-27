import { Schema } from 'mongoose';
import type { IModelPolicyHeadDocument, IModelPolicyRevisionDocument } from '~/types';

export const modelPolicyHeadSchema: Schema<IModelPolicyHeadDocument> =
  new Schema<IModelPolicyHeadDocument>(
    {
      key: { type: String, required: true, unique: true, index: true },
      version: { type: Number, required: true, min: 1 },
      schemaVersion: { type: Number, required: true, min: 1, default: 1 },
    },
    { timestamps: true },
  );

export const modelPolicyRevisionSchema: Schema<IModelPolicyRevisionDocument> =
  new Schema<IModelPolicyRevisionDocument>(
    {
      version: { type: Number, required: true, unique: true, index: true, min: 1 },
      parentVersion: { type: Number, required: true, min: 0 },
      schemaVersion: { type: Number, required: true, min: 1, default: 1 },
      companyDefaultDeploymentId: { type: String, required: true, trim: true },
      activeDeploymentIds: [{ type: String, required: true }],
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

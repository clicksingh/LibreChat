import { Schema } from 'mongoose';
import type { IWorkspaceDocument } from '~/types';

const workspaceSchema: Schema<IWorkspaceDocument> = new Schema<IWorkspaceDocument>(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
      index: true,
    },
    description: {
      type: String,
      default: '',
      trim: true,
      maxlength: 1000,
    },
    ownerId: {
      type: String,
      required: true,
      index: true,
    },
    state: {
      type: String,
      enum: ['active', 'archived'],
      default: 'active',
      index: true,
    },
    quotaBytesOverride: {
      type: Number,
      default: null,
      min: 0,
    },
    tenantId: {
      type: String,
      index: true,
    },
  },
  { timestamps: true },
);

workspaceSchema.index({ ownerId: 1, state: 1, createdAt: -1 });

export default workspaceSchema;

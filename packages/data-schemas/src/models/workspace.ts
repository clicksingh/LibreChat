import { Model } from 'mongoose';
import type { IWorkspaceDocument } from '~/types';
import { applyTenantIsolation } from '~/models/plugins/tenantIsolation';
import workspaceSchema from '~/schema/workspace';

export function createWorkspaceModel(
  mongoose: typeof import('mongoose'),
): Model<IWorkspaceDocument> {
  applyTenantIsolation(workspaceSchema);
  return (
    mongoose.models.Workspace ||
    mongoose.model<IWorkspaceDocument>('Workspace', workspaceSchema, 'workspaces')
  );
}

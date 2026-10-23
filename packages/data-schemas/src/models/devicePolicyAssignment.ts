import { Model } from 'mongoose';
import { applyTenantIsolation } from '~/models/plugins/tenantIsolation';
import devicePolicyAssignmentSchema, {
  IDevicePolicyAssignmentDocument,
} from '~/schema/devicePolicyAssignment';

export function createDevicePolicyAssignmentModel(
  mongoose: typeof import('mongoose'),
): Model<IDevicePolicyAssignmentDocument> {
  applyTenantIsolation(devicePolicyAssignmentSchema);
  return (
    mongoose.models.DevicePolicyAssignment ||
    mongoose.model<IDevicePolicyAssignmentDocument>(
      'DevicePolicyAssignment',
      devicePolicyAssignmentSchema,
      'devicepolicyassignments',
    )
  );
}
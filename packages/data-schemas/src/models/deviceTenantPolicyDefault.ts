import { Model } from 'mongoose';
import { applyTenantIsolation } from '~/models/plugins/tenantIsolation';
import deviceTenantPolicyDefaultSchema, {
  IDeviceTenantPolicyDefaultDocument,
} from '~/schema/deviceTenantPolicyDefault';

export function createDeviceTenantPolicyDefaultModel(
  mongoose: typeof import('mongoose'),
): Model<IDeviceTenantPolicyDefaultDocument> {
  applyTenantIsolation(deviceTenantPolicyDefaultSchema);
  return (
    mongoose.models.DeviceTenantPolicyDefault ||
    mongoose.model<IDeviceTenantPolicyDefaultDocument>(
      'DeviceTenantPolicyDefault',
      deviceTenantPolicyDefaultSchema,
      'devicetenantpolicydefaults',
    )
  );
}
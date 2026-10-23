import { Model } from 'mongoose';
import { applyTenantIsolation } from '~/models/plugins/tenantIsolation';
import deviceToolScopeSchema, { IDeviceToolScopeDocument } from '~/schema/deviceToolScope';

export function createDeviceToolScopeModel(
  mongoose: typeof import('mongoose'),
): Model<IDeviceToolScopeDocument> {
  applyTenantIsolation(deviceToolScopeSchema);
  return (
    mongoose.models.DeviceToolScope ||
    mongoose.model<IDeviceToolScopeDocument>(
      'DeviceToolScope',
      deviceToolScopeSchema,
      'devicetoolscopes',
    )
  );
}
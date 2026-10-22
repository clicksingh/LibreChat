import { Model } from 'mongoose';
import { applyTenantIsolation } from '~/models/plugins/tenantIsolation';
import deviceAuthoritySchema, { IDeviceAuthority } from '~/schema/deviceAuthority';

export function createDeviceAuthorityModel(
  mongoose: typeof import('mongoose'),
): Model<IDeviceAuthority> {
  applyTenantIsolation(deviceAuthoritySchema);
  return (
    mongoose.models.DeviceAuthority ||
    mongoose.model<IDeviceAuthority>('DeviceAuthority', deviceAuthoritySchema, 'deviceauthorities')
  );
}

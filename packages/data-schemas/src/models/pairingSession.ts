import { Model } from 'mongoose';
import { applyTenantIsolation } from '~/models/plugins/tenantIsolation';
import pairingSessionSchema, { IPairingSession } from '~/schema/pairingSession';

export function createPairingSessionModel(
  mongoose: typeof import('mongoose'),
): Model<IPairingSession> {
  applyTenantIsolation(pairingSessionSchema);
  return (
    mongoose.models.PairingSession ||
    mongoose.model<IPairingSession>('PairingSession', pairingSessionSchema, 'pairingsessions')
  );
}

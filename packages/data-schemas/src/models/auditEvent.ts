import { Model } from 'mongoose';
import { applyTenantIsolation } from '~/models/plugins/tenantIsolation';
import auditEventSchema, { IAuditEvent } from '~/schema/auditEvent';

export function createAuditEventModel(mongoose: typeof import('mongoose')): Model<IAuditEvent> {
  applyTenantIsolation(auditEventSchema);
  return (
    mongoose.models.AuditEvent ||
    mongoose.model<IAuditEvent>('AuditEvent', auditEventSchema, 'deviceauthorityevents')
  );
}

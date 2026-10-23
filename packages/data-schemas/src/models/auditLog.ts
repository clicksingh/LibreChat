import { Model } from 'mongoose';
import {
  auditLogSchema,
  auditLogCounterSchema,
  IAuditLogCounterDocument,
  IAuditLogDocument,
} from '~/schema/auditLog';

/**
 * The append-only admin audit log (`recordAuditEntry`'s store — see `~/schema/auditLog` for why this
 * collection exists rather than the device `AuditEvent` table).
 *
 * The tenant-isolation plugin is applied inside `~/schema/auditLog` itself, next to the append-only
 * guards, so the schema that is registered through the schema barrel carries exactly the same
 * behaviour as the one registered here.
 */
export function createAuditLogModel(mongoose: typeof import('mongoose')): Model<IAuditLogDocument> {
  return (
    mongoose.models.AuditLog ||
    mongoose.model<IAuditLogDocument>('AuditLog', auditLogSchema, 'adminauditlogs')
  );
}

/**
 * The chain head, in its own one-document collection so `seq` can be reserved with a single atomic
 * `$inc` (schema/auditLog explains why reserving beats reading the last entry).
 */
export function createAuditLogCounterModel(
  mongoose: typeof import('mongoose'),
): Model<IAuditLogCounterDocument> {
  return (
    mongoose.models.AuditLogCounter ||
    mongoose.model<IAuditLogCounterDocument>(
      'AuditLogCounter',
      auditLogCounterSchema,
      'adminauditlogcounters',
    )
  );
}
import { Schema, Document } from 'mongoose';

export interface IAuditEvent extends Document {
  tenantId: string;
  deviceId: string | null;
  ownerId: string | null;
  grantId: string | null;
  epoch: number | null;
  seq: number | null;
  kind:
    | 'register'
    | 'grant'
    | 'renew'
    | 'revoke'
    | 'expire'
    | 'retire'
    | 'release'
    | 'claim-refused';
  ts: Date;
  actor: string | null;
  reasonCode: string | null;
}

const auditEventSchema: Schema<IAuditEvent> = new Schema({
  tenantId: {
    type: String,
    required: true,
  },
  deviceId: {
    type: String,
    default: null,
  },
  ownerId: {
    type: String,
    default: null,
  },
  grantId: {
    type: String,
    default: null,
  },
  epoch: {
    type: Number,
    default: null,
  },
  seq: {
    type: Number,
    default: null,
  },
  kind: {
    type: String,
    enum: ['register', 'grant', 'renew', 'revoke', 'expire', 'retire', 'release', 'claim-refused'],
    required: true,
  },
  ts: {
    type: Date,
    required: true,
  },
  actor: {
    type: String,
    default: null,
  },
  reasonCode: {
    type: String,
    default: null,
  },
});

auditEventSchema.index({ tenantId: 1, deviceId: 1, ts: -1 });
auditEventSchema.index({ tenantId: 1, ownerId: 1, ts: -1 });

export default auditEventSchema;

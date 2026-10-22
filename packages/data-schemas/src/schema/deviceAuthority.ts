import { Schema } from 'mongoose';
import type { Document } from 'mongoose';

/** Frozen authority lease/grant duration: 172800000 ms, exactly 48 hours. */
export const DEVICE_AUTHORITY_LEASE_TTL_MS = 172800000;

export interface IDeviceAuthority extends Document<string> {
  _id: string;
  tenantId: string;
  deviceKeyId: string;
  devicePublicKey: string;
  deviceName?: string;
  platform?: string;
  agentVersion?: string;
  identityState: 'pending' | 'active' | 'retired';
  leaseState: 'never' | 'active' | 'expired' | 'revoked';
  epoch: number;
  ownerId: string | null;
  grantId: string | null;
  registeredAt?: Date;
  lastSeenAt?: Date;
  retiredAt: Date | null;
  retiredBy: string | null;
  activatedAt: Date | null;
  expiresAt: Date | null;
  renewedAt: Date | null;
  renewalCount: number;
  revokedAt: Date | null;
  revokedBy: string | null;
  grantedByPairingSessionId: string | null;
  grantProof: {
    ownerConfirmedAt: Date | null;
    endpointSignatureVerifiedAt: Date | null;
    verifiedKeyId: string | null;
    localApprovalNonceHash: string | null;
  };
  prevOwner: string | null;
  prevGrantId: string | null;
  prevEpoch: number | null;
}

const deviceAuthoritySchema: Schema<IDeviceAuthority> = new Schema<IDeviceAuthority>({
  _id: {
    type: String,
    required: true,
  },
  tenantId: {
    type: String,
    required: true,
  },
  deviceKeyId: {
    type: String,
    required: true,
  },
  devicePublicKey: {
    type: String,
    required: true,
  },
  deviceName: {
    type: String,
  },
  platform: {
    type: String,
  },
  agentVersion: {
    type: String,
  },
  identityState: {
    type: String,
    enum: ['pending', 'active', 'retired'],
    required: true,
  },
  leaseState: {
    type: String,
    enum: ['never', 'active', 'expired', 'revoked'],
    required: true,
  },
  epoch: {
    type: Number,
    required: true,
    default: 0,
    min: 0,
  },
  ownerId: {
    type: String,
    default: null,
  },
  grantId: {
    type: String,
    default: null,
  },
  registeredAt: {
    type: Date,
  },
  lastSeenAt: {
    type: Date,
  },
  retiredAt: {
    type: Date,
    default: null,
  },
  retiredBy: {
    type: String,
    default: null,
  },
  activatedAt: {
    type: Date,
    default: null,
  },
  expiresAt: {
    type: Date,
    default: null,
  },
  renewedAt: {
    type: Date,
    default: null,
  },
  renewalCount: {
    type: Number,
    default: 0,
    min: 0,
  },
  revokedAt: {
    type: Date,
    default: null,
  },
  revokedBy: {
    type: String,
    default: null,
  },
  grantedByPairingSessionId: {
    type: String,
    default: null,
  },
  grantProof: {
    type: new Schema(
      {
        ownerConfirmedAt: { type: Date, default: null },
        endpointSignatureVerifiedAt: { type: Date, default: null },
        verifiedKeyId: { type: String, default: null },
        localApprovalNonceHash: { type: String, default: null },
      },
      { _id: false },
    ),
  },
  prevOwner: {
    type: String,
    default: null,
  },
  prevGrantId: {
    type: String,
    default: null,
  },
  prevEpoch: {
    type: Number,
    default: null,
  },
});

deviceAuthoritySchema.index({ deviceKeyId: 1, tenantId: 1 }, { unique: true });
deviceAuthoritySchema.index(
  { ownerId: 1, tenantId: 1 },
  { unique: true, partialFilterExpression: { leaseState: 'active' } },
);
deviceAuthoritySchema.index(
  { tenantId: 1, grantId: 1 },
  { unique: true, partialFilterExpression: { grantId: { $type: 'string' } } },
);
/**
 * Sweep/display scan only. Authority rows must never expire implicitly, so this
 * collection carries no TTL index; lease ending is an explicit CAS transition.
 */
deviceAuthoritySchema.index({ leaseState: 1, expiresAt: 1 });

export default deviceAuthoritySchema;

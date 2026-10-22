import { Schema } from 'mongoose';
import type { Document } from 'mongoose';

export type PairingSessionState =
  | 'open'
  | 'claim_pending'
  | 'consumed'
  | 'denied'
  | 'failed'
  | 'expired'
  | 'superseded'
  | 'exhausted';

export interface IPairingSession extends Document {
  tenantId: string;
  deviceId: string;
  deviceKeyId: string;
  /**
   * Persisted HMAC-SHA-256 lookup tag (43-char base64url) derived from the
   * pairing code. The six-digit code itself is never persisted.
   */
  lookupTag: string;
  state: PairingSessionState;
  sessionVersion: number;
  pendingOwnerId: string | null;
  attemptsUsed: number;
  issuedAt: Date;
  expiresAt: Date;
  claimedAt: Date | null;
  claim: {
    challengeRef: string | null;
    openedAt: Date | null;
    expectedEpoch: number | null;
  };
  consumedAt: Date | null;
  grantedGrantId: string | null;
  /** Request-source hash only; a raw client IP is never persisted. */
  issuedFromSourceHash: string | null;
  deviceSessionId: string | null;
}

const pairingSessionSchema: Schema<IPairingSession> = new Schema<IPairingSession>({
  tenantId: {
    type: String,
    required: true,
  },
  deviceId: {
    type: String,
    required: true,
  },
  deviceKeyId: {
    type: String,
    required: true,
  },
  lookupTag: {
    type: String,
    required: true,
  },
  state: {
    type: String,
    required: true,
    enum: [
      'open',
      'claim_pending',
      'consumed',
      'denied',
      'failed',
      'expired',
      'superseded',
      'exhausted',
    ],
  },
  sessionVersion: {
    type: Number,
    required: true,
    default: 0,
    min: 0,
    validate: {
      validator: (v: number) => Number.isInteger(v),
      message: '`sessionVersion` must be a non-negative integer',
    },
  },
  pendingOwnerId: {
    type: String,
    default: null,
  },
  attemptsUsed: {
    type: Number,
    required: true,
    default: 0,
    min: 0,
  },
  issuedAt: {
    type: Date,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
  claimedAt: {
    type: Date,
    default: null,
  },
  claim: new Schema(
    {
      challengeRef: { type: String, default: null },
      openedAt: { type: Date, default: null },
      expectedEpoch: {
        type: Number,
        default: null,
        min: 0,
        validate: {
          validator: (v: number | null) => v === null || Number.isInteger(v),
          message: '`expectedEpoch` must be a non-negative integer',
        },
      },
    },
    { _id: false },
  ),
  consumedAt: {
    type: Date,
    default: null,
  },
  grantedGrantId: {
    type: String,
    default: null,
  },
  issuedFromSourceHash: {
    type: String,
    default: null,
  },
  deviceSessionId: {
    type: String,
    default: null,
  },
});

pairingSessionSchema.index(
  { tenantId: 1, lookupTag: 1 },
  { unique: true, partialFilterExpression: { state: { $in: ['open', 'claim_pending'] } } },
);
pairingSessionSchema.index(
  { deviceId: 1, tenantId: 1 },
  { unique: true, partialFilterExpression: { state: { $in: ['open', 'claim_pending'] } } },
);
pairingSessionSchema.index({ deviceId: 1, state: 1 });
pairingSessionSchema.index({ pendingOwnerId: 1, claimedAt: -1 });
/**
 * Storage hygiene only. Expiry is always enforced by the service lane through
 * an explicit `expiresAt: { $gt: now }` predicate plus the state/consumedAt CAS.
 */
pairingSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default pairingSessionSchema;

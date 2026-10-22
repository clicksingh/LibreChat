import { Schema, Document } from 'mongoose';

export interface IChallenge extends Document {
  challengeHash: string;
  purpose: 'registration' | 'pairing-open' | 'pairing-claim' | 'renewal';
  deviceId: string | null;
  deviceKeyId: string | null;
  tenantId: string;
  boundPairingSessionId: string | null;
  boundOwnerId: string | null;
  boundGrantId: string | null;
  boundEpoch: number | null;
  boundSessionVersion: number | null;
  issuedAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
}

const challengeSchema: Schema<IChallenge> = new Schema({
  challengeHash: {
    type: String,
    required: true,
  },
  purpose: {
    type: String,
    enum: ['registration', 'pairing-open', 'pairing-claim', 'renewal'],
    required: true,
  },
  deviceId: {
    type: String,
    default: null,
  },
  deviceKeyId: {
    type: String,
    default: null,
  },
  tenantId: {
    type: String,
    required: true,
  },
  boundPairingSessionId: {
    type: String,
    default: null,
  },
  boundOwnerId: {
    type: String,
    default: null,
  },
  boundGrantId: {
    type: String,
    default: null,
  },
  boundEpoch: {
    type: Number,
    default: null,
    min: 0,
    validate: {
      validator: (v: number | null) => v === null || Number.isInteger(v),
      message: '`boundEpoch` must be a non-negative integer',
    },
  },
  boundSessionVersion: {
    type: Number,
    default: null,
    min: 0,
    validate: {
      validator: (v: number | null) => v === null || Number.isInteger(v),
      message: '`boundSessionVersion` must be a non-negative integer',
    },
  },
  issuedAt: {
    type: Date,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
  consumedAt: {
    type: Date,
    default: null,
  },
});

challengeSchema.index({ challengeHash: 1 }, { unique: true });
challengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default challengeSchema;

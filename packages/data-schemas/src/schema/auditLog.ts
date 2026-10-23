/**
 * W10b — THE ADMIN AUDIT LOG: the append-only store behind `db.recordAuditEntry` (GM-81).
 *
 * `docs/GM-RULING-ABSOLUTE-ADMIN-POLICY-AND-AUDIT-SEAM-20261023.md` §2 (GM-81),
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §6.2 (GM-79 rule 2: "Every policy
 * change is audited with actor, before and after, and a timestamp, in the same audit path used
 * elsewhere").
 *
 * WHICH STORAGE THIS IS, AND WHY (the GM-81 question, answered)
 * The upstream admin audit log (`packages/api/src/admin/auditLog.ts` +
 * `packages/data-schemas/src/methods/auditLog.ts` + `schema/auditLog.ts` on `origin/main`, commit
 * `6a63531eb`) is NOT an ancestor of this branch. What this branch DOES have is `AuditEvent`
 * (`deviceauthorityevents`) plus `api/server/services/Device/auditSink.js` — and that store does NOT
 * fit, for reasons that are structural rather than stylistic:
 *
 *   1. `AuditEvent.kind` is a Mongoose ENUM of exactly eight device-authority kinds
 *      ('register', 'grant', 'renew', 'revoke', 'expire', 'retire', 'release', 'claim-refused').
 *      A `device_policy.scope_updated` cannot be stored in it at all.
 *   2. `projectAuditEvent` (the sunk R1-B contract) whitelists exactly TEN keys and REJECTS any
 *      forbidden key before any write. It has no `metadata`, no `before`, no `after`, no `actor` as a
 *      structured value (only a nullable string), no `target` and no `category`. GM-79 rule 2
 *      requires before/after; that store cannot express them, and forcing them in would mean
 *      relaxing a frozen, tested device contract.
 *   3. Using it would make "what happened?" unanswerable from one place — the exact outcome GM-81 §2
 *      rejects when it says two audit logs are worse than one gap.
 *
 * So this is the SECOND option GM-81 names: a minimal append-only writer that satisfies the SAME
 * CONTRACT as upstream — `recordAuditEntry(input, { failClosed })` over an append-only, hash-chained
 * record (`schemaVersion`, `seq`, `prevHash`, `hash`, `createdAt`, open `metadata`). The contract is
 * what `packages/api/src/admin/devicePolicy/audit.ts` binds to structurally, so the rebase replaces
 * this collection with upstream's in one line and nothing above it changes.
 *
 * This is NOT a second audit log for the same events: it is the only place admin policy changes are
 * recorded, and the device audit table keeps recording device-authority events, which is what it is
 * for. The two do not overlap. The action registry and recorder input shapes live in
 * `~/admin/auditLog`; the W10b spec proves the six `device_policy.*` names there match W10's frozen
 * list.
 *
 * APPEND-ONLY IS ENFORCED, not merely intended: the mutation operators are refused by middleware, so
 * an entry cannot be edited or deleted through the model at all. `dropDatabase()` (used by tests and
 * by an operator deliberately wiping a database) is unaffected — it does not run model middleware.
 */

import { Schema, Document } from 'mongoose';
import { applyTenantIsolation } from '~/models/plugins/tenantIsolation';
import {
  AUDIT_LOG_ACTIONS,
  AUDIT_LOG_OUTCOMES,
  AUDIT_LOG_SCHEMA_VERSION,
  AUDIT_LOG_SEVERITIES,
  type AuditLogAction,
} from '~/admin/auditLog';

/** Actor / target. Structurally the `AuditLogActorInput`/`AuditLogTargetInput` of `~/admin/auditLog`. */
export type IAuditLogActor = {
  type: string;
  id?: string | null;
  name: string;
};

export type IAuditLogTarget = {
  type: string;
  id?: string | null;
  name?: string | null;
};

/** A stored audit entry. */
export interface IAuditLogDocument extends Document {
  schemaVersion: number;
  /** Monotonic position in the log. Reserved atomically before the entry is written. */
  seq: number;
  /** The hash of `seq - 1`, or null for the first entry (and after a detected gap). */
  prevHash: string | null;
  /** SHA-256 over this entry's content, `seq` and `prevHash`. */
  hash: string;
  action: AuditLogAction;
  category: string;
  outcome: string;
  severity: string;
  actor: IAuditLogActor;
  target: IAuditLogTarget;
  /** The open payload field — where before/after snapshots live. */
  metadata: Record<string, unknown> | null;
  context: Record<string, unknown> | null;
  /** The owning tenant, or `null` for the platform tenant. */
  tenantId: string | null;
  createdAt: Date;
}

/** The sequence allocator: `seq` is reserved from here atomically, so no two entries share a number. */
export interface IAuditLogCounterDocument extends Document<string> {
  _id: string;
  seq: number;
}

const actorSchema = new Schema<IAuditLogActor>(
  {
    type: { type: String, required: true },
    id: { type: String, default: null },
    name: { type: String, required: true },
  },
  { _id: false },
);

const targetSchema = new Schema<IAuditLogTarget>(
  {
    type: { type: String, required: true },
    id: { type: String, default: null },
    name: { type: String, default: null },
  },
  { _id: false },
);

const auditLogSchema: Schema<IAuditLogDocument> = new Schema<IAuditLogDocument>(
  {
    schemaVersion: {
      type: Number,
      default: AUDIT_LOG_SCHEMA_VERSION,
      required: true,
    },
    seq: {
      type: Number,
      required: true,
      min: 1,
    },
    prevHash: {
      type: String,
      default: null,
    },
    hash: {
      type: String,
      required: true,
    },
    action: {
      type: String,
      enum: [...AUDIT_LOG_ACTIONS],
      required: true,
    },
    category: {
      type: String,
      default: 'config',
      required: true,
    },
    outcome: {
      type: String,
      enum: [...AUDIT_LOG_OUTCOMES],
      default: 'success',
    },
    severity: {
      type: String,
      enum: [...AUDIT_LOG_SEVERITIES],
      default: 'info',
    },
    actor: {
      type: actorSchema,
      required: true,
    },
    target: {
      type: targetSchema,
      required: true,
    },
    /** Open payload: before/after snapshots, fingerprints, changed fields, notes. */
    metadata: {
      type: Schema.Types.Mixed,
      default: null,
    },
    context: {
      type: Schema.Types.Mixed,
      default: null,
    },
    tenantId: {
      type: String,
      default: null,
    },
    /**
     * The entry's own timestamp, set by the WRITER (`~/methods/auditLog`) and covered by the entry
     * hash. `timestamps` is deliberately NOT used: Mongoose's timestamp plugin runs outside the
     * writer's control, so a `createdAt` it decided would not be the value the hash was computed over,
     * and the timestamp would stop being tamper-evident. There is no `updatedAt` — an append-only
     * record has nothing to update.
     */
    createdAt: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
  },
);

/** One entry per sequence number, and the read-back order. */
auditLogSchema.index({ seq: 1 }, { unique: true });

/** "What happened to this tenant's policy?" — the admin and reviewer query. */
auditLogSchema.index({ tenantId: 1, action: 1, createdAt: -1 });

/** "What did this actor do?" — the attribution query GM-79 rule 2 exists to answer. */
auditLogSchema.index({ 'actor.id': 1, createdAt: -1 });

/** "What happened to this document?" — the target walk. */
auditLogSchema.index({ 'target.type': 1, 'target.id': 1, createdAt: -1 });

/**
 * Append-only enforcement. Every mutation operator throws BEFORE it reaches the server, so an entry
 * that has been written cannot be rewritten or removed through the model. `insertOne`/`create`/
 * `save`/`insertMany` are deliberately absent: appending is the one permitted operation.
 */
auditLogSchema.pre('updateOne', function () {
  throw new Error('[AuditLog] append-only: updateOne is not permitted on the audit log');
});
auditLogSchema.pre('updateMany', function () {
  throw new Error('[AuditLog] append-only: updateMany is not permitted on the audit log');
});
auditLogSchema.pre('findOneAndUpdate', function () {
  throw new Error('[AuditLog] append-only: findOneAndUpdate is not permitted on the audit log');
});
auditLogSchema.pre('findOneAndReplace', function () {
  throw new Error('[AuditLog] append-only: findOneAndReplace is not permitted on the audit log');
});
auditLogSchema.pre('replaceOne', function () {
  throw new Error('[AuditLog] append-only: replaceOne is not permitted on the audit log');
});
auditLogSchema.pre('deleteOne', function () {
  throw new Error('[AuditLog] append-only: deleteOne is not permitted on the audit log');
});
auditLogSchema.pre('deleteMany', function () {
  throw new Error('[AuditLog] append-only: deleteMany is not permitted on the audit log');
});
auditLogSchema.pre('findOneAndDelete', function () {
  throw new Error('[AuditLog] append-only: findOneAndDelete is not permitted on the audit log');
});

/**
 * The tenant-isolation plugin is applied for the same reason it is applied to every other
 * tenant-bearing collection here, and `models/plugins/tenantIsolation.coverage.spec.ts` requires it:
 * a query inside a tenant context is scoped to that tenant without the caller restating the filter.
 * The recorder always passes `tenantId` explicitly as well, so the chain's own tenant is recorded
 * even when no ambient context exists.
 */
applyTenantIsolation(auditLogSchema);

/**
 * THE SEQUENCE COUNTER: one document, and its only job is to hand out `seq`.
 *
 * `seq` is reserved from HERE with a single atomic `$inc`, rather than by reading the newest entry —
 * two concurrent appends must never compute the same number, and a read-then-write would let them.
 *
 * The chain HEAD is deliberately NOT cached here. The head is `findOne().sort({ seq: -1 })`, one read,
 * and a cached head that a concurrent writer has already moved past would be a second source of truth
 * about the same fact. `prevHash` links each entry to the entry at `seq - 1` by NUMBER, so the chain
 * is a pure function of the stored sequence and cannot fork.
 */
const auditLogCounterSchema: Schema<IAuditLogCounterDocument> =
  new Schema<IAuditLogCounterDocument>(
    {
      _id: {
        type: String,
        required: true,
      },
      seq: {
        type: Number,
        default: 0,
        min: 0,
      },
    },
    { versionKey: false },
  );

export { auditLogSchema, auditLogCounterSchema };
export default auditLogSchema;
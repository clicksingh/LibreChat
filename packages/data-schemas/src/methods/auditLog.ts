/**
 * W10b — `recordAuditEntry`: THE RECORDER GM-81 LEAVES INJECTED, NOW REAL.
 *
 * `docs/GM-RULING-ABSOLUTE-ADMIN-POLICY-AND-AUDIT-SEAM-20261023.md` §2 (GM-81) and
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §6.2 (GM-79 rule 2).
 *
 * WHAT WAS WRONG BEFORE THIS FILE
 * `api/server/routes/admin/devicePolicy.js` wires `recordAuditEntry: db.recordAuditEntry`, and
 * `~/models` did not export it. `createDevicePolicyAuditWriter` therefore returned `null`, every write
 * handler refused with 503 before touching anything, and GM-79's "every policy change is audited" was
 * true only because no change was possible. This function is the missing half: with it exported, the
 * writer is built, the 503 gate opens, and every write lands an entry FIRST and the store mutation
 * second (the ordering is the handler's, and `packages/api/src/admin/devicePolicy/handlers.ts`
 * documents why).
 *
 * THE CONTRACT, AND WHY IT IS SHAPED THIS WAY
 * `packages/api/src/admin/devicePolicy/audit.ts` binds to upstream's recorder STRUCTURALLY:
 *
 *     recordAuditEntry(input, { failClosed }) : Promise<entry|null>
 *     input = { action, category?, outcome?, severity?, actor{type,id?,name},
 *               target{type,id?,name?}, metadata?, context?, tenantId? }
 *
 * Nothing in this package imports that one, and it imports nothing from here — the two agree on the
 * shape, and the W10b spec asserts the shape against the entries W10's writer actually produces
 * (action, category, actor, target, `metadata.before`/`metadata.after`/`metadata.fingerprint`, and
 * `tenantId`). That is what makes the rebase a one-line swap rather than a rewrite.
 *
 * `failClosed` DEFAULTS TO TRUE. Upstream's option is optional; here, an entry that cannot be durably
 * written is an ERROR unless the caller explicitly opts out with `failClosed: false`. The
 * device-policy writer passes `true` either way, so this changes nothing for it — it only means that a
 * future caller who forgets the option gets the safe behaviour (a refusal) rather than the unsafe one
 * (a silent skip). GM-81's invariant is "an unauditable change cannot be made", and a default that
 * errs toward refusing is the only default consistent with it.
 *
 * DURABILITY. Every write uses the explicit write concern `{ w: 'majority', j: true }` — the same
 * frozen concern the device audit sink uses (`api/server/services/Device/auditSink.js`) — so "the
 * entry exists" means "the entry is on a majority of the replica set and journalled", which is what
 * lets the handler treat the subsequent store mutation as safe.
 *
 * THE CHAIN, AND WHAT IT DOES AND DOES NOT CLAIM
 *   seq       reserved from a one-document counter with a single atomic `$inc`, BEFORE the entry is
 *             inserted. Two concurrent appends therefore cannot share a number, and no read-then-write
 *             race exists. A failed insert leaves a GAP in `seq`, which is deliberate: a gap is the
 *             truthful record that an append was attempted and did not complete, and `failClosed`
 *             reports the same fact to the caller.
 *   prevHash  the `hash` of the entry at `seq - 1`, looked up BY NUMBER rather than by "the newest
 *             row". That makes the chain a pure function of the stored order: it cannot fork because
 *             the head was read at a different moment than the reservation, and it is verifiable by
 *             walking `seq` upward.
 *   hash      SHA-256 over this entry's own content plus `seq` and `prevHash`, canonically serialised
 *             (object keys sorted, array order preserved). `createdAt` is generated HERE and included
 *             in the hash, so a stored entry's timestamp cannot be edited without breaking its own
 *             hash — a caller cannot supply one.
 * The head is intentionally NOT cached: it is `findOne().sort({ seq: -1 })`, one read, and a cached
 * head that can be stale would be a second source of truth about the same thing.
 *
 * VALIDATION IS NOT OPTIONAL AND IS NOT SUBJECT TO `failClosed`. An unregistered action, or an actor
 * or target without a type, is a CALLER BUG rather than a store failure, so it throws even when
 * `failClosed: false`. The action enum means an unregistered action could not be stored anyway; the
 * check moves the failure to a readable error instead of a Mongoose cast error.
 */

import { createHash } from 'node:crypto';
import type { Model } from 'mongoose';
import {
  AUDIT_LOG_ACTIONS,
  AUDIT_LOG_COUNTER_ID,
  AUDIT_LOG_SCHEMA_VERSION,
  type RecordAuditEntryInput,
  type RecordAuditEntryOptions,
} from '~/admin/auditLog';
import { createAuditLogCounterModel, createAuditLogModel } from '~/models/auditLog';
import type { IAuditLogDocument } from '~/schema/auditLog';
import logger from '~/config/winston';

/** The frozen write concern: journalled and acknowledged by a majority before the call returns. */
const AUDIT_WRITE_CONCERN = Object.freeze({ w: 'majority', j: true });

/** One coalesced error type, so a caller can tell an audit failure from anything else. */
export class AuditLogWriteError extends Error {
  code = 'AUDIT_LOG_WRITE_FAILED';

  constructor(detail: string, options?: { cause?: unknown }) {
    super(`the admin audit log could not record the entry: ${detail}`, options);
    this.name = 'AuditLogWriteError';
  }
}

/** Stable stringify: object keys sorted, so two structurally equal entries always hash the same. */
function canonicalize(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (value instanceof Date) {
    return JSON.stringify(value.toISOString());
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalize(entry)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(',')}}`;
  }
  return 'null';
}

/** A non-empty string, or `null`. One spelling of "no tenant", shared with the policy store. */
function tenantKey(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}

/** The hashable content of an entry: exactly the fields that are stored, plus the chain position. */
export type AuditEntryHashInput = {
  schemaVersion?: number;
  seq: number;
  prevHash: string | null;
  action: string;
  category: string;
  outcome: string;
  severity: string;
  actor: unknown;
  target: unknown;
  metadata?: unknown;
  context?: unknown;
  tenantId?: string | null;
  createdAt: Date | string;
};

/**
 * SHA-256 over an entry's content, its `seq` and its `prevHash`.
 *
 * Exported so the integrity of a STORED entry is checkable from outside: recomputing this over a row
 * read back from the database must reproduce `hash`, and changing any field must not.
 */
export function computeAuditEntryHash(entry: AuditEntryHashInput): string {
  /**
   * A hydrated Mongoose document is unwrapped first, for the reason the writer gives when it returns
   * `toObject()`: its own enumerable keys include circular internals, so hashing one raw would not
   * terminate. `.lean()` output has no `toObject` and is used as-is.
   */
  const source =
    typeof (entry as unknown as { toObject?: unknown }).toObject === 'function'
      ? (entry as unknown as { toObject: () => AuditEntryHashInput }).toObject()
      : entry;
  const payload = {
    schemaVersion: source.schemaVersion ?? AUDIT_LOG_SCHEMA_VERSION,
    seq: source.seq,
    prevHash: source.prevHash,
    action: source.action,
    category: source.category,
    outcome: source.outcome,
    severity: source.severity,
    actor: source.actor ?? null,
    target: source.target ?? null,
    metadata: source.metadata ?? null,
    context: source.context ?? null,
    tenantId: source.tenantId ?? null,
    createdAt:
      source.createdAt instanceof Date ? source.createdAt.toISOString() : source.createdAt,
  };
  return createHash('sha256').update(canonicalize(payload)).digest('hex');
}

export interface AuditLogMethods {
  /**
   * Append one entry. Resolves to the stored entry, or to `null` only when the caller passed
   * `failClosed: false` and the write failed.
   */
  recordAuditEntry: (
    input: RecordAuditEntryInput,
    options?: RecordAuditEntryOptions,
  ) => Promise<IAuditLogDocument | null>;
}

/**
 * The shape check. Returns a readable reason, or `null` when the input is usable.
 *
 * Deliberately narrow: it checks what the STORE requires (a registered action, a typed actor and
 * target) and nothing about the payload, because `metadata` is the open field by design and the
 * before/after snapshots in it are the caller's business.
 */
function describeInvalidInput(input: unknown): string | null {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return 'input must be an object';
  }
  const record = input as Record<string, unknown>;
  const action = record.action;
  if (typeof action !== 'string' || action.trim().length === 0) {
    return 'action must be a non-empty string';
  }
  if (!(AUDIT_LOG_ACTIONS as readonly string[]).includes(action)) {
    return `action "${action}" is not registered in AUDIT_LOG_ACTIONS`;
  }
  const actor = record.actor;
  if (actor === null || typeof actor !== 'object' || Array.isArray(actor)) {
    return 'actor must be an object';
  }
  const actorRecord = actor as Record<string, unknown>;
  if (typeof actorRecord.type !== 'string' || actorRecord.type.trim().length === 0) {
    return 'actor.type must be a non-empty string';
  }
  if (typeof actorRecord.name !== 'string' || actorRecord.name.trim().length === 0) {
    return 'actor.name must be a non-empty string';
  }
  const target = record.target;
  if (target === null || typeof target !== 'object' || Array.isArray(target)) {
    return 'target must be an object';
  }
  const targetRecord = target as Record<string, unknown>;
  if (typeof targetRecord.type !== 'string' || targetRecord.type.trim().length === 0) {
    return 'target.type must be a non-empty string';
  }
  return null;
}

export function createAuditLogMethods(mongoose: typeof import('mongoose')): AuditLogMethods {
  const AuditLog: Model<IAuditLogDocument> = createAuditLogModel(mongoose);
  const AuditLogCounter = createAuditLogCounterModel(mongoose);

  /**
   * Reserve the next sequence number. One atomic `$inc` on a one-document collection: no
   * read-then-write, so no two appends can compute the same number.
   *
   * `setDefaultsOnInsert` is OFF on purpose: the counter schema defaults `seq` to 0, which would land
   * in `$setOnInsert` and collide with this `$inc` on the same path — an update MongoDB rejects.
   * `$inc` on a missing field already produces exactly the right value (1).
   */
  async function reserveSequence(): Promise<number> {
    const counter = await AuditLogCounter.findOneAndUpdate(
      { _id: AUDIT_LOG_COUNTER_ID },
      { $inc: { seq: 1 } },
      { upsert: true, new: true, setDefaultsOnInsert: false, writeConcern: AUDIT_WRITE_CONCERN },
    ).lean();
    // Mongoose 8's `findOneAndUpdate().lean()` resolves to the updated counter document here (the
    // projection is not a single-path numeric projection); read the seq defensively in case a driver
    // or version difference hands back a raw number instead, and treat anything else as a refusal.
    const seq =
      typeof counter === 'number'
        ? counter
        : (counter as unknown as { seq?: number } | null)?.seq;
    if (typeof seq !== 'number' || !Number.isInteger(seq) || seq < 1) {
      throw new AuditLogWriteError('the audit sequence counter did not yield a usable sequence');
    }
    return seq;
  }

  /** The `hash` of the entry at `seq - 1`, or `null` when there is none (first entry, or a gap). */
  async function previousHash(seq: number): Promise<string | null> {
    if (seq <= 1) {
      return null;
    }
    const previous = await AuditLog.findOne({ seq: seq - 1 })
      .select('hash')
      .lean();
    const hash = (previous as unknown as { hash?: string } | null)?.hash;
    return typeof hash === 'string' && hash.length > 0 ? hash : null;
  }

  async function appendEntry(input: RecordAuditEntryInput): Promise<IAuditLogDocument> {
    const seq = await reserveSequence();
    const prevHash = await previousHash(seq);
    // Generated here, never taken from the caller: a caller-supplied timestamp would not be covered
    // by the entry's own hash, which is the property that makes the timestamp tamper-evident.
    const createdAt = new Date();

    const record = {
      schemaVersion: AUDIT_LOG_SCHEMA_VERSION,
      seq,
      prevHash,
      hash: computeAuditEntryHash({
        seq,
        prevHash,
        action: input.action,
        category: input.category ?? 'config',
        outcome: input.outcome ?? 'success',
        severity: input.severity ?? 'info',
        actor: {
          type: input.actor.type,
          id: input.actor.id ?? null,
          name: input.actor.name,
        },
        target: {
          type: input.target.type,
          id: input.target.id ?? null,
          name: input.target.name ?? null,
        },
        metadata: input.metadata ?? null,
        context: input.context ?? null,
        tenantId: tenantKey(input.tenantId),
        createdAt,
      }),
      action: input.action,
      category: input.category ?? 'config',
      outcome: input.outcome ?? 'success',
      severity: input.severity ?? 'info',
      actor: {
        type: input.actor.type,
        id: input.actor.id ?? null,
        name: input.actor.name,
      },
      target: {
        type: input.target.type,
        id: input.target.id ?? null,
        name: input.target.name ?? null,
      },
      metadata: input.metadata ?? null,
      context: input.context ?? null,
      tenantId: tenantKey(input.tenantId),
      createdAt,
    };

    const [created] = await AuditLog.create([record], { writeConcern: AUDIT_WRITE_CONCERN });
    /**
     * The STORED record, as plain data — never the hydrated document.
     *
     * Two reasons, and the second is not cosmetic. First, consistency: every other method in this
     * data layer (`upsertToolScope`, `getAssignment`, …) returns `.lean()`, and a caller should not
     * have to know which storage call hands back a Mongoose instance. Second, correctness of the
     * hash: `computeAuditEntryHash` walks the entry's own enumerable keys, and a hydrated document's
     * keys include Mongoose's internals (`$__`, `_doc`, `$isNew`, …), which are circular — hashing
     * one recurses until the stack gives out. `toObject()` yields exactly the stored content, so a
     * caller can hash what it was handed and get the same digest a later read produces.
     */
    return (created as unknown as { toObject?: () => IAuditLogDocument }).toObject
      ? (created as unknown as { toObject: () => IAuditLogDocument }).toObject()
      : (created as unknown as IAuditLogDocument);
  }

  async function recordAuditEntry(
    input: RecordAuditEntryInput,
    options?: RecordAuditEntryOptions,
  ): Promise<IAuditLogDocument | null> {
    const invalid = describeInvalidInput(input);
    if (invalid !== null) {
      // A caller bug, not a store failure: `failClosed: false` does not excuse it.
      throw new AuditLogWriteError(invalid);
    }

    // Fail closed unless the caller explicitly opts out — see the header.
    const failClosed = options?.failClosed !== false;

    try {
      return await appendEntry(input);
    } catch (error) {
      if (failClosed) {
        if (error instanceof AuditLogWriteError) {
          throw error;
        }
        throw new AuditLogWriteError(
          error instanceof Error ? error.message : String(error),
          { cause: error },
        );
      }
      logger.warn(
        `[AuditLog] entry for "${input.action}" was NOT recorded and failClosed was disabled: ` +
          `${error instanceof Error ? error.message : String(error)}`,
      );
      return null;
    }
  }

  return { recordAuditEntry };
}
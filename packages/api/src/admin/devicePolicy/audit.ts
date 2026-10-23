/**
 * W10 — GM-79 rule 2: EVERY policy change is audited, with actor, before, after and a timestamp.
 *
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §6.2: "Every policy change is
 * audited with actor, before and after, and a timestamp, in the same audit path used elsewhere."
 *
 * WHICH AUDIT PATH, AND WHY THIS FILE LOOKS LIKE THIS
 * The ruling and the plan name `packages/api/src/admin/auditLog`. **That module does not exist in
 * this worktree.** It is introduced by upstream commit `6a63531eb` ("Audit Log Backend for
 * SystemGrant Assign and Revoke Events"), which is on `origin/main` but is NOT an ancestor of this
 * branch — verified: `git merge-base --is-ancestor 6a63531eb HEAD` returns 1. The plan's §4 rule 3
 * ("rebase before integration, not after") is exactly the step that brings it in.
 *
 * This module therefore binds to that path's CONTRACT — read from the upstream commit, not
 * guessed:
 *
 *   recordAuditEntry(
 *     { action, category?, outcome?, severity?, actor: { type, id?, name },
 *       target: { type, id?, name? }, metadata?, context?, tenantId? },
 *     { failClosed?: boolean },
 *   ): Promise<IAuditLog | null>
 *
 * — with `AuditLog` being an append-only, hash-chained record (`schemaVersion`, `seq`, `prevHash`,
 * `hash`, `createdAt`) whose `metadata` is the open payload field. The before/after snapshots go in
 * `metadata`, which is where upstream puts event-specific payload (e.g. `{ capability }` for
 * grants); the timestamp is the entry's own `createdAt`, set by the writer so it is covered by the
 * entry hash, rather than a caller-supplied time that could be forged.
 *
 * TWO CONSEQUENCES, BOTH DELIBERATE AND BOTH REPORTED
 *   1. The recorder is a DEPENDENCY. Nothing here imports a module that does not exist in this
 *      branch, so the package builds and every test in this workstream runs today.
 *   2. The device-policy WRITE handlers REFUSE to change anything when no recorder is wired
 *      (`recordAuditEntry` absent). "Every change is audited" is then unconditionally true on this
 *      branch: there is no window in which a policy can be edited without a durable audit record.
 *      A missing recorder is a 503, never a silent bypass.
 *
 * ACTION NAMESPACE: `device_policy.*`, category `config`.
 * Upstream's `AUDIT_ACTIONS` registry is exactly `['grant.assigned', 'grant.removed']` and the
 * action is a Mongoose enum, so the rebase must add these six names to that registry (one line,
 * in the same commit that wires this module). They are exported as a frozen constant here so the
 * integration edits one authoritative list. Until then the recorder dependency is unwired and the
 * write paths are closed — the failure mode is "cannot edit policy", never "edited un-audited".
 */

import { createHash } from 'node:crypto';
import { DEVICE_POLICY_AUDIT_ACTIONS } from './types';

/** The `AUDIT_ACTIONS` names the rebase must add to the upstream registry. */
export const DEVICE_POLICY_AUDIT_ACTION_NAMES: readonly string[] = Object.freeze(
  Object.values(DEVICE_POLICY_AUDIT_ACTIONS),
);

/** The audit category device-policy changes belong to. */
export const DEVICE_POLICY_AUDIT_CATEGORY = 'config';

/** The target type recorded for a policy document. */
export const DEVICE_POLICY_AUDIT_TARGET_TYPE = 'device_policy';

/** Actor as the recorder accepts it (mirrors `AuditActorInput` upstream). */
export type AuditActorInput = {
  type: string;
  id?: string;
  name: string;
};

/** Target as the recorder accepts it (mirrors `AuditTargetInput` upstream). */
export type AuditTargetInput = {
  type: string;
  id?: string;
  name?: string;
};

/** The input the recorder accepts (mirrors `RecordAuditEntryInput` upstream). */
export type RecordAuditEntryInput = {
  action: string;
  category?: string;
  outcome?: string;
  severity?: string;
  actor: AuditActorInput;
  target: AuditTargetInput;
  metadata?: Record<string, unknown>;
  context?: Record<string, unknown>;
  tenantId?: string;
};

/**
 * The injected upstream recorder. Structural, so the real `recordAuditEntry` (or a knip-compatible
 * adapter) satisfies it without this package importing an absent module.
 */
export type RecordAuditEntry = (
  input: RecordAuditEntryInput,
  options?: { failClosed?: boolean },
) => Promise<unknown>;

/** An immutable before/after snapshot of one policy document. */
export type PolicySnapshot = {
  /** What kind of document this is. */
  snapshotType: string;
  /** The document's stable identifier. */
  id: string | null;
  /** The document's own version counter, when it has one. */
  version: number | null;
  /** ISO-8601 timestamp from the audit writer's own clock (see `now`). */
  capturedAt: string;
  /** Canonical JSON of the document, or null for a creation / a deletion. */
  body: string | null;
};

/** The shape passed to `recordAuditEntry` — kept open so a spec can assert on its fields. */
export type DevicePolicyAuditEntry = {
  action: string;
  category: string;
  outcome: string;
  actor: AuditActorInput;
  target: AuditTargetInput;
  metadata: {
    /** Bullet-proof attribution: the audience should never have to guess who acted. */
    actor: string;
    subject: string;
    before: PolicySnapshot | null;
    after: PolicySnapshot | null;
    /** SHA-256 over `before` and `after`, so tampering with a snapshot is detectable on its own. */
    fingerprint: string;
    /** Fields whose values differ between `before` and `after`. */
    changedFields: string[];
    /** Free-form, secret-free notes (e.g. `{ reason: 'scope-not-found' }`). */
    note?: Record<string, unknown>;
  };
  tenantId?: string;
};

/** What the writer hands the recorder, and what the handlers log on failure. */
export interface DevicePolicyAuditWriter {
  recordAuditEntry: RecordAuditEntry;
  audit: (input: {
    action: string;
    actor: AuditActorInput;
    target: AuditTargetInput;
    before: PolicySnapshot | null;
    after: PolicySnapshot | null;
    tenantId?: string;
    note?: Record<string, unknown>;
  }) => Promise<DevicePolicyAuditEntry>;
}

/**
 * Stable stringify: object keys sorted, so two structurally equal snapshots always hash the same.
 * Arrays keep their order (a tool list's order is data, and sorting it would hide a real change).
 */
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

/** SHA-256 of the canonical form of a value. */
export function fingerprintOf(value: unknown): string {
  return createHash('sha256').update(canonicalize(value)).digest('hex');
}

/**
 * Fields that must never reach an audit payload: a snapshot is a record of POLICY, and secrets,
 * pairing material and request bodies have no place in it. Mirrors the forbidden-key list the
 * device audit sink already enforces, so the two audit paths cannot disagree about what is
 * un-auditable.
 */
export const AUDIT_FORBIDDEN_SNAPSHOT_KEYS: ReadonlySet<string> = new Set([
  'lookupTag',
  'code',
  'pairingCode',
  'pepper',
  'pepperLookup',
  'privateKey',
  'devicePublicKey',
  'signature',
  'challenge',
  'challengeNonce',
  'authorization',
  'headers',
  'body',
  'query',
  'params',
  'ip',
  'rawIp',
  'sourceIp',
  'password',
  'token',
  'accessToken',
  'refreshToken',
  'secret',
]);

/**
 * Snapshots a policy document for the audit trail.
 *
 * The document is whitelisted by DRIVING the snapshot off its own enumerable keys minus the
 * forbidden set, then canonically serialized. A live Mongoose document is unwrapped with
 * `toObject` when available, so the snapshot records the stored data rather than a hydrated
 * instance's internals.
 *
 * @param document the policy document (or null for an absence)
 * @param options.snapshotType what kind of document this is
 * @param options.id the document's identifier
 * @param options.now the capture instant (injected so a spec can freeze the clock)
 */
export function snapshotPolicyDocument(
  document: unknown,
  options: { snapshotType: string; id?: string | null; now?: Date },
): PolicySnapshot {
  const now = options.now ?? new Date();
  const capturedAt = now.toISOString();

  if (document === null || document === undefined) {
    return {
      snapshotType: options.snapshotType,
      id: options.id ?? null,
      version: null,
      capturedAt,
      body: null,
    };
  }

  let source: unknown = document;
  if (typeof (document as { toObject?: unknown }).toObject === 'function') {
    source = (document as { toObject: () => unknown }).toObject();
  }

  if (source === null || typeof source !== 'object' || Array.isArray(source)) {
    return {
      snapshotType: options.snapshotType,
      id: options.id ?? null,
      version: null,
      capturedAt,
      body: JSON.stringify(source ?? null),
    };
  }

  const record = source as Record<string, unknown>;
  const safe: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    if (AUDIT_FORBIDDEN_SNAPSHOT_KEYS.has(key)) {
      continue;
    }
    safe[key] = record[key];
  }

  const id =
    options.id ??
    (typeof safe.id === 'string'
      ? safe.id
      : typeof safe.principalId === 'string'
        ? `${String(safe.principalType ?? '')}:${safe.principalId}`
        : null);

  return {
    snapshotType: options.snapshotType,
    id,
    version: typeof safe.version === 'number' ? safe.version : null,
    capturedAt,
    body: canonicalize(safe),
  };
}

/** The fields whose values differ between two snapshots. */
export function changedFieldsBetween(
  before: PolicySnapshot | null,
  after: PolicySnapshot | null,
): string[] {
  const parse = (snapshot: PolicySnapshot | null): Record<string, unknown> => {
    if (snapshot === null || snapshot.body === null) {
      return {};
    }
    try {
      const value: unknown = JSON.parse(snapshot.body);
      return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    } catch {
      return {};
    }
  };

  const beforeRecord = parse(before);
  const afterRecord = parse(after);
  const keys = new Set([...Object.keys(beforeRecord), ...Object.keys(afterRecord)]);

  return [...keys]
    .filter((key) => canonicalize(beforeRecord[key]) !== canonicalize(afterRecord[key]))
    .sort();
}

/** Builds the entry body. Exported so the spec can assert the shape without a writer. */
export function buildDevicePolicyAuditEntry(input: {
  action: string;
  actor: AuditActorInput;
  target: AuditTargetInput;
  before: PolicySnapshot | null;
  after: PolicySnapshot | null;
  tenantId?: string;
  note?: Record<string, unknown>;
}): DevicePolicyAuditEntry {
  const entry: DevicePolicyAuditEntry = {
    action: input.action,
    category: DEVICE_POLICY_AUDIT_CATEGORY,
    outcome: 'success',
    actor: {
      type: input.actor.type,
      ...(input.actor.id === undefined ? {} : { id: input.actor.id }),
      name: input.actor.name,
    },
    target: {
      type: DEVICE_POLICY_AUDIT_TARGET_TYPE,
      ...(input.target.id === undefined ? {} : { id: input.target.id }),
      ...(input.target.name === undefined ? {} : { name: input.target.name }),
    },
    metadata: {
      actor: input.actor.name,
      subject: input.target.name ?? input.target.id ?? 'device-policy',
      before: input.before,
      after: input.after,
      fingerprint: fingerprintOf({ before: input.before, after: input.after }),
      changedFields: changedFieldsBetween(input.before, input.after),
      ...(input.note === undefined ? {} : { note: input.note }),
    },
  };

  if (input.tenantId !== undefined && input.tenantId.trim().length > 0) {
    entry.tenantId = input.tenantId;
  }

  return entry;
}

/**
 * Builds the audit writer for the device-policy handlers.
 *
 * @param deps.recordAuditEntry the upstream recorder (see the header). Absent -> `null`, and the
 *   write handlers then refuse every change rather than change something un-audited.
 */
export function createDevicePolicyAuditWriter(deps: {
  recordAuditEntry?: RecordAuditEntry;
}): DevicePolicyAuditWriter | null {
  const { recordAuditEntry } = deps ?? {};
  if (typeof recordAuditEntry !== 'function') {
    return null;
  }

  async function audit(input: {
    action: string;
    actor: AuditActorInput;
    target: AuditTargetInput;
    before: PolicySnapshot | null;
    after: PolicySnapshot | null;
    tenantId?: string;
    note?: Record<string, unknown>;
  }): Promise<DevicePolicyAuditEntry> {
    const entry = buildDevicePolicyAuditEntry(input);

    // failClosed: a policy change must not be possible without its audit record.
    await recordAuditEntry(entry as unknown as RecordAuditEntryInput, { failClosed: true });
    return entry;
  }

  return { recordAuditEntry, audit };
}

/**
 * The refusal thrown when a write is attempted with no audit path wired. A 503 at the route, never
 * a silent bypass: see the header's consequence 2.
 */
export class DevicePolicyAuditUnavailableError extends Error {
  code = 'DEVICE_POLICY_AUDIT_UNAVAILABLE';

  constructor() {
    super(
      'device-policy changes require the admin audit path, and no audit recorder is wired in this build. ' +
        'The change was refused rather than applied without a durable audit record (GM-79 rule 2).',
    );
    this.name = 'DevicePolicyAuditUnavailableError';
  }
}
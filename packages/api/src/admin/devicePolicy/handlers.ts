/**
 * W10 — THE ADMIN DEVICE-POLICY HANDLERS (GM-76, GM-78, GM-79; GM-81 on the audit seam).
 *
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3, §5, §6,
 * `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §2/§3 (W10), and
 * `docs/GM-RULING-ABSOLUTE-ADMIN-POLICY-AND-AUDIT-SEAM-20261023.md` §2 (the 503 refusal).
 *
 * CONVENTIONS: this mirrors `packages/api/src/admin/roles.ts` exactly —
 *   - validator-FIRST: an unusable body is a 400 `{ error: '...' }` with one readable message,
 *     before any storage, audit or resolution work happens;
 *   - `parsePagination` on the list route, `{ items, total, limit, offset }` like `{ roles, … }`;
 *   - `logger.error('[adminDevicePolicy] …')` on every unexpected failure, 500 `{ error }`;
 *   - one handler factory, dependencies injected: the route file owns the database and the two
 *     Device modules, and this package never imports `api/server/**`.
 *
 * THE SIX STATUS CODES, AND WHO PRODUCES EACH
 *   200 read/update success          400 an unusable body or path parameter (validator-first)
 *   201 a document was created       403 a principal outside the caller's tenant
 *   404 the document is not there    409 a conflict (already exists / still referenced)
 *   500 an unexpected failure        503 a seam is unwired, so the change is refused
 *
 * THE 503 RULE (GM-81) — THE LOAD-BEARING PART
 * A policy change must be auditable, so a request that would change policy is checked for the
 * audit recorder BEFORE anything else happens. With no recorder wired, every write route returns
 * 503 and touches NOTHING: no storage read, no storage write, no audit entry. "Every change is
 * audited" is therefore unconditionally true rather than aspirational. Reads are unaffected — a
 * read is not an audited event and refusing it would break the admin surface for no gain.
 *
 * A second seam is refused the same way: storage. `resolveDevicePolicyStorage()` (storage.ts)
 * binds a data layer that names each missing persistence function instead of leaving it
 * `undefined`; the refusal is a 503, never a silent 500 and never a partial answer.
 *
 * WHY THE AUDIT ENTRY IS WRITTEN BEFORE THE STORE MUTATION
 * The audit log and the policy store are two stores; no shared transaction spans them. Writing the
 * entry FIRST makes the invariant unconditional — a change cannot exist that the audit log does not
 * already describe, because the entry (with `failClosed: true`) is durable before the store is
 * touched. The alternative ordering (apply, then audit, with a compensating rollback on audit
 * failure) leaves one hole this ordering cannot have: the change is live for the whole window in
 * which the audit write might fail. Everything that can refuse the change on its own merits — a 400,
 * a 404, a 409, a cross-tenant 403 — is decided BEFORE the entry is written, so the log carries no
 * phantom refusals; only a genuine store failure can leave an entry whose change did not land, and
 * that failure is logged with the entry's action so it is correlatable rather than silent.
 *
 * WHAT A CALLER CANNOT DO
 *   - Widening: every read request shape is passed through `stripRequestWideningFields(mode:'read')`
 *     and every write shape through `mode:'write'` with its own allow-list. `tools` and `stage` are
 *     legitimate SCOPE fields (they are the policy an admin edits) and are kept ONLY on the scope
 *     write shape; everywhere else they are stripped and reported. `tenantId` always comes from the
 *     authenticated session, never from a body or a query.
 *   - Claiming an identity: the resolver's principal is built from the database (the user document's
 *     role, its real group rows via `getUserPrincipals`), never from a token or a request field.
 *   - Escaping a downgrade: the resolution is computed live on every call from the current documents
 *     and `policyVersion` is content-derived, so a stale value a client sends changes nothing — the
 *     guard strips it, and the response carries the current version regardless.
 *   - Sharpening the stage: `serverStage` is read from the server's own environment, never from a
 *     request; a scope may narrow it and a request cannot touch it.
 */

import { logger, isValidObjectIdString } from '@librechat/data-schemas';
import {
  DEVICE_POLICY_PRINCIPAL_TYPES,
  validateDevicePolicyAssignmentBody,
  validateDeviceTenantDefaultBody,
  validateDeviceToolScopeBody,
  validateDeviceToolScopeId,
  type AdminDevicePolicyAssignment,
  type AdminDeviceTenantDefault,
  type AdminDeviceToolScope,
  type DevicePolicyValidation,
  type IDevicePolicyAssignment,
  type IDeviceTenantPolicyDefault,
  type IDeviceToolScope,
} from '@librechat/data-schemas';
import type { Response } from 'express';
import type { ServerRequest } from '~/types/http';
import { parsePagination } from '../pagination';
import {
  createDevicePolicyAuditWriter,
  DevicePolicyAuditUnavailableError,
  DEVICE_POLICY_AUDIT_TARGET_TYPE,
  snapshotPolicyDocument,
  type AuditActorInput,
  type AuditTargetInput,
  type DevicePolicyAuditWriter,
  type PolicySnapshot,
} from './audit';
import {
  ASSIGNMENT_WRITE_FIELDS,
  SCOPE_WRITE_FIELDS,
  TENANT_DEFAULT_WRITE_FIELDS,
  stripRequestWideningFields,
  type WideningAttempt,
} from './guards';
import { DevicePolicyError, resolveDevicePolicy } from './resolver';
import { DevicePolicyStorageUnavailableError } from './storage';
import {
  DEVICE_POLICY_AUDIT_ACTIONS,
  DEVICE_POLICY_RESOLUTION_SCHEMA,
  type AdminDevicePolicyDeps,
  type DevicePolicyPrincipal,
  type DevicePolicyResolution,
} from './types';

/** Upper bound on the scope documents one resolution preloads; excess is reported and fails closed. */
const MAX_SCOPE_PRELOAD = 256;

/** The snapshot type recorded for each kind of policy document. */
const SNAPSHOT_TYPES = Object.freeze({
  scope: 'device-tool-scope',
  assignment: 'device-policy-assignment',
  tenantDefault: 'device-tenant-policy-default',
});

/** A data-layer operation, as the handlers call it. */
type StorageOp = (...args: unknown[]) => Promise<unknown>;

export interface AdminDevicePolicyHandlerDeps extends AdminDevicePolicyDeps {
  /** Group memberships for an identity (`getUserPrincipals`), server-resolved. */
  getUserPrincipals?: (params: { userId: string; role?: string | null }) => Promise<
    Array<{ principalType: string; principalId?: string | { toString(): string } }>
  >;
  /** The enforcement primitives (the real `deviceCapabilityPolicy` + `deviceToolRegistry`). */
  primitives: unknown;
  /** The stage the SERVER is currently at. A scope may narrow it; no request can raise it. */
  serverStage: string;
  /** Apply the pilot deny-list overlay. Defaults to true, like the registry's own default. */
  pilot?: boolean;
}

export interface AdminDevicePolicyHandlers {
  listScopes: (req: ServerRequest, res: Response) => Promise<Response>;
  getScope: (req: ServerRequest, res: Response) => Promise<Response>;
  createScope: (req: ServerRequest, res: Response) => Promise<Response>;
  updateScope: (req: ServerRequest, res: Response) => Promise<Response>;
  deleteScope: (req: ServerRequest, res: Response) => Promise<Response>;
  listAssignments: (req: ServerRequest, res: Response) => Promise<Response>;
  setAssignment: (req: ServerRequest, res: Response) => Promise<Response>;
  removeAssignment: (req: ServerRequest, res: Response) => Promise<Response>;
  getTenantDefault: (req: ServerRequest, res: Response) => Promise<Response>;
  setTenantDefault: (req: ServerRequest, res: Response) => Promise<Response>;
  resolveSelf: (req: ServerRequest, res: Response) => Promise<Response>;
  resolveForPrincipal: (req: ServerRequest, res: Response) => Promise<Response>;
}

interface ScopeIdParams {
  scopeId?: string;
}

interface AssignmentParams {
  principalType?: string;
  principalId?: string;
}

interface PrincipalParams {
  userId?: string;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Reads a record off a possibly-hydrated document (`toObject`), or `null`. */
function recordOf(value: unknown): Record<string, unknown> | null {
  if (value === null || value === undefined) {
    return null;
  }
  let source: unknown = value;
  if (typeof (value as { toObject?: unknown }).toObject === 'function') {
    source = (value as { toObject: () => unknown }).toObject();
  }
  return isPlainRecord(source) ? source : null;
}

function asTrimmedString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

/** Reads a string list, dropping non-strings — a stored list can only ever be a policy detail. */
function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry): entry is string => typeof entry === 'string');
}

/** The first validator message, with the rest logged so nothing is silently dropped. */
function firstError(validation: DevicePolicyValidation, context: string): string {
  if (validation.ok) {
    return '';
  }
  if (validation.errors.length > 1) {
    logger.warn(
      `[adminDevicePolicy] ${context}: ${validation.errors.length} validation errors; reporting the first`,
    );
  }
  return validation.errors[0];
}

function actorFrom(req: ServerRequest): AuditActorInput {
  const user = req.user as
    | { id?: string; _id?: { toString(): string }; name?: string; email?: string }
    | undefined;
  const id = user?.id ?? (user?._id === undefined ? undefined : String(user._id));
  const name =
    asTrimmedString(user?.name) ?? asTrimmedString(user?.email) ?? id ?? 'unknown-admin';
  return { type: 'user', ...(id === undefined ? {} : { id }), name };
}

/** The recorder's target for a device-policy document (`audit.ts` owns the type string). */
function auditTarget(id: string, name: string): AuditTargetInput {
  return { type: DEVICE_POLICY_AUDIT_TARGET_TYPE, id, name };
}

/**
 * The tenant a request's policy documents are read and written in: the AUTHENTICATED session's
 * tenant, never a body or query field (the guards strip those spellings).
 */
function tenantOf(req: ServerRequest): string | undefined {
  const tenantId = (req.user as { tenantId?: unknown } | undefined)?.tenantId;
  return asTrimmedString(tenantId) ?? undefined;
}

/** Passes a genuine data-layer function through; binds a named refusal for an absent one. */
function storageOp(candidate: unknown, name: string): StorageOp {
  if (typeof candidate === 'function') {
    return candidate as StorageOp;
  }
  return (() => Promise.reject(new DevicePolicyStorageUnavailableError(name))) as StorageOp;
}

/** The stored scope, as the admin API returns it. `null` when the row cannot yield an id. */
function toScopeResponse(raw: unknown): AdminDeviceToolScope | null {
  const record = recordOf(raw);
  if (record === null) {
    return null;
  }
  const id = asTrimmedString(record.id);
  if (id === null) {
    return null;
  }
  const stage = asTrimmedString(record.stage);
  const response: AdminDeviceToolScope = {
    id,
    name: asTrimmedString(record.name) ?? id,
    description: typeof record.description === 'string' ? record.description : '',
    tools: asStringList(record.tools),
    // An unreadable stage is reported as the narrowest one, never as a wide one.
    stage: (stage ?? 'A') as AdminDeviceToolScope['stage'],
    isActive: record.isActive !== false,
    version: typeof record.version === 'number' && Number.isInteger(record.version) ? record.version : 0,
  };
  const tenantId = asTrimmedString(record.tenantId);
  if (tenantId !== null) {
    response.tenantId = tenantId;
  }
  const createdAt = isoOf(record.createdAt);
  if (createdAt !== null) {
    response.createdAt = createdAt;
  }
  const updatedAt = isoOf(record.updatedAt);
  if (updatedAt !== null) {
    response.updatedAt = updatedAt;
  }
  return response;
}

function toAssignmentResponse(raw: unknown): AdminDevicePolicyAssignment | null {
  const record = recordOf(raw);
  if (record === null) {
    return null;
  }
  const principalType = asTrimmedString(record.principalType);
  const principalId = asTrimmedString(record.principalId);
  const toolScopeId = asTrimmedString(record.toolScopeId);
  if (principalType === null || principalId === null || toolScopeId === null) {
    return null;
  }
  const response: AdminDevicePolicyAssignment = {
    principalType: principalType as AdminDevicePolicyAssignment['principalType'],
    principalId,
    toolScopeId,
    priority: typeof record.priority === 'number' && Number.isInteger(record.priority) ? record.priority : 0,
    isActive: record.isActive !== false,
  };
  const tenantId = asTrimmedString(record.tenantId);
  if (tenantId !== null) {
    response.tenantId = tenantId;
  }
  const createdAt = isoOf(record.createdAt);
  if (createdAt !== null) {
    response.createdAt = createdAt;
  }
  const updatedAt = isoOf(record.updatedAt);
  if (updatedAt !== null) {
    response.updatedAt = updatedAt;
  }
  return response;
}

function toTenantDefaultResponse(raw: unknown): AdminDeviceTenantDefault | null {
  const record = recordOf(raw);
  if (record === null) {
    return null;
  }
  const defaultToolScopeId = asTrimmedString(record.defaultToolScopeId);
  if (defaultToolScopeId === null) {
    return null;
  }
  const response: AdminDeviceTenantDefault = {
    defaultToolScopeId,
    version: typeof record.version === 'number' && Number.isInteger(record.version) ? record.version : 0,
  };
  const tenantId = asTrimmedString(record.tenantId);
  if (tenantId !== null) {
    response.tenantId = tenantId;
  }
  const updatedAt = isoOf(record.updatedAt);
  if (updatedAt !== null) {
    response.updatedAt = updatedAt;
  }
  return response;
}

function isoOf(value: unknown): string | null {
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return value.toISOString();
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    return value;
  }
  return null;
}

/**
 * The admin-facing resolution report: the whole decision, including every excluded tool with its
 * reason and its decision-maker. `describeResolution()` (resolver.ts) stays the DEVICE document
 * view — a signed policy document does not need the refusal ledger, an admin editing a scope does.
 */
function serializeResolution(resolution: DevicePolicyResolution): Record<string, unknown> {
  return {
    schema: DEVICE_POLICY_RESOLUTION_SCHEMA,
    stage: resolution.stage,
    failClosed: resolution.failClosed,
    governingLevel: resolution.governingLevel,
    resolvedToolScopeId: resolution.resolvedToolScopeId,
    resolvedToolScopeName: resolution.resolvedToolScopeName,
    policyVersion: resolution.policyVersion,
    tools: [...resolution.tools],
    approvalRequired: [...resolution.approvalRequired],
    decisions: resolution.decisions.map((row) => ({ ...row })),
    provenance: resolution.provenance.map((row) => ({ ...row })),
    trace: resolution.trace.map((row) => ({ ...row })),
    counts: { ...resolution.counts },
  };
}

export function createAdminDevicePolicyHandlers(
  deps: AdminDevicePolicyHandlerDeps,
): AdminDevicePolicyHandlers {
  const auditWriter: DevicePolicyAuditWriter | null = createDevicePolicyAuditWriter({
    recordAuditEntry: deps.recordAuditEntry,
  });

  const listScopes = storageOp(deps.listScopes, 'listScopes');
  const countScopes = storageOp(deps.countScopes, 'countScopes');
  const getToolScope = storageOp(deps.getToolScope, 'getToolScope');
  const upsertToolScope = storageOp(deps.upsertToolScope, 'upsertToolScope');
  const deleteToolScope = storageOp(deps.deleteToolScope, 'deleteToolScope');
  const listAssignments = storageOp(deps.listAssignments, 'listAssignments');
  const getAssignment = storageOp(deps.getAssignment, 'getAssignment');
  const upsertAssignment = storageOp(deps.upsertAssignment, 'upsertAssignment');
  const deleteAssignment = storageOp(deps.deleteAssignment, 'deleteAssignment');
  const getTenantDefault = storageOp(deps.getTenantDefault, 'getTenantDefault');
  const upsertTenantDefault = storageOp(deps.upsertTenantDefault, 'upsertTenantDefault');
  const getRoleByName = storageOp(deps.getRoleByName, 'getRoleByName');
  const findGroupById = storageOp(deps.findGroupById, 'findGroupById');
  const findUser = storageOp(deps.findUser, 'findUser');
  const getUserPrincipals = storageOp(deps.getUserPrincipals, 'getUserPrincipals');

  /**
   * The 503 gate. Returns `null` when the request may proceed, or the refusal response when the
   * audit seam is unwired. Called by every write handler before it touches anything.
   */
  function auditUnavailable(actor: string): { status: number; body: { error: string } } | null {
    if (auditWriter !== null) {
      return null;
    }
    logger.error(
      `[adminDevicePolicy] write refused (${actor}): no audit recorder is wired in this build (GM-79 rule 2)`,
    );
    return {
      status: 503,
      body: {
        error:
          'Policy changes require the admin audit path, and no audit recorder is wired in this build. ' +
          'The change was refused rather than applied without an audit record.',
      },
    };
  }

  function snapshot(document: unknown, snapshotType: string, id?: string | null): PolicySnapshot {
    return snapshotPolicyDocument(document, {
      snapshotType,
      ...(id === undefined ? {} : { id }),
    });
  }

  /**
   * Records the change, or refuses it.
   *
   * The recorder is called with `failClosed: true` (see `audit.ts`), so it refuses when it cannot
   * durably write. ANY recorder failure is re-thrown as the typed refusal, so the write routes
   * answer 503 rather than 500 and the store is never touched without its audit record — a 500
   * would read as "try again later", while 503 here means "this build cannot audit, so it cannot
   * change policy".
   */
  async function recordPolicyChange(
    input: Parameters<DevicePolicyAuditWriter['audit']>[0],
  ): Promise<ReturnType<DevicePolicyAuditWriter['audit']>> {
    try {
      return await auditWriter!.audit(input);
    } catch (error) {
      logger.error(
        `[adminDevicePolicy] audit write failed for ${input.action}; refusing the change:`,
        error,
      );
      throw new DevicePolicyAuditUnavailableError();
    }
  }

  /**
   * Runs the write guard for a shape and returns the cleaned body plus what was probed. The guard
   * MUTATES `req.body` in place, which is deliberate: a stripped privilege field is then unreadable
   * by anything downstream, not merely ignored by this handler.
   */
  function guardedWriteBody(
    req: ServerRequest,
    keep: ReadonlySet<string>,
    actor: string,
  ): { body: unknown; attempts: WideningAttempt[] } {
    const result = stripRequestWideningFields(
      (req.body ?? {}) as Record<string, unknown>,
      { mode: 'write', source: 'body', actor, keep },
    );
    return { body: result.body, attempts: result.attempts };
  }

  /** The read guard: every guarded spelling is stripped from a copy of the query. */
  function guardedReadQuery(
    req: ServerRequest,
    actor: string,
  ): { query: Record<string, unknown>; attempts: WideningAttempt[] } {
    const result = stripRequestWideningFields(
      { ...((req.query ?? {}) as Record<string, unknown>) },
      { mode: 'read', source: 'query', actor },
    );
    return { query: result.body as Record<string, unknown>, attempts: result.attempts };
  }

  /**
   * The identity the resolver is given, built from the DATABASE — never from a claim. Group ids come
   * from the real membership rows via `getUserPrincipals`, role from the user document when one is
   * available, and `tenantId` from the authenticated session.
   */
  async function principalFor(
    userId: string,
    role: string,
    tenantId: string | undefined,
  ): Promise<DevicePolicyPrincipal> {
    const principals = (await getUserPrincipals({
      userId,
      role: role.length > 0 ? role : null,
    })) as unknown;
    const groupIds: string[] = [];
    if (Array.isArray(principals)) {
      for (const entry of principals) {
        if (!isPlainRecord(entry) || entry.principalType !== 'group') {
          continue;
        }
        const id = entry.principalId;
        if (typeof id === 'string' && id.trim().length > 0) {
          groupIds.push(id.trim());
        } else if (id !== null && id !== undefined && typeof id.toString === 'function') {
          groupIds.push(id.toString());
        }
      }
    }
    return { userId, role, groupIds, ...(tenantId === undefined ? {} : { tenantId }) };
  }

  /**
   * THE RESOLUTION, live, from current documents (GM-78 rule 1). Every read below is
   * server-scoped and server-loaded; nothing in it comes from the request except the identity the
   * server itself established.
   */
  async function resolveFor(
    principal: DevicePolicyPrincipal,
    tenantId: string | undefined,
  ): Promise<DevicePolicyResolution> {
    const [assignmentsRaw, tenantDefaultRaw] = await Promise.all([
      listAssignments(tenantId === undefined ? {} : { tenantId }) as Promise<unknown>,
      getTenantDefault(tenantId === undefined ? {} : { tenantId }) as Promise<unknown>,
    ]);
    const assignments = Array.isArray(assignmentsRaw) ? assignmentsRaw : [];

    // Preload exactly the scopes the policy documents point at. Loading is id-precise rather than a
    // paginated list so a tenant with more scopes than one page still resolves from the real row;
    // an id that is not in the data stays absent from the map and the resolver reports it as
    // `scope-missing`, which fails closed instead of falling through to a wider level.
    const referenced = new Set<string>();
    for (const entry of assignments) {
      const record = recordOf(entry);
      const id = record === null ? null : asTrimmedString(record.toolScopeId);
      if (id !== null) {
        referenced.add(id);
      }
    }
    const tenantRecord = recordOf(tenantDefaultRaw);
    const tenantScopeId = tenantRecord === null ? null : asTrimmedString(tenantRecord.defaultToolScopeId);
    if (tenantScopeId !== null) {
      referenced.add(tenantScopeId);
    }
    const ids = [...referenced];
    if (ids.length > MAX_SCOPE_PRELOAD) {
      logger.warn(
        `[adminDevicePolicy] ${ids.length} referenced scopes exceeds the preload bound ` +
          `(${MAX_SCOPE_PRELOAD}); the excess resolve as missing and fail closed`,
      );
    }
    const loaded = await Promise.all(
      ids.slice(0, MAX_SCOPE_PRELOAD).map(async (id) => {
        const scope = await (getToolScope(id, tenantId === undefined ? {} : { tenantId }) as Promise<
          unknown
        >);
        return [id, scope] as const;
      }),
    );
    const scopeById = new Map<string, unknown>(loaded);

    return resolveDevicePolicy({
      principal,
      tenantDefault: tenantRecord as unknown as IDeviceTenantPolicyDefault | null,
      assignments: assignments as unknown as IDevicePolicyAssignment[],
      getScope: (id) => scopeById.get(id) as unknown as IDeviceToolScope | undefined,
      serverStage: deps.serverStage,
      ...(deps.pilot === undefined ? {} : { pilot: deps.pilot }),
      primitives: deps.primitives,
    });
  }

  /** The one place a 500 is produced, so the log line format is identical everywhere. */
  function failure(res: Response, context: string, error: unknown, message: string): Response {
    logger.error(`[adminDevicePolicy] ${context} error:`, error);
    return res.status(500).json({ error: message });
  }

  /**
   * A seam refusal is a 503 (the audit path or the storage layer is unwired, or the audit write
   * itself failed), everything else is the caller's 500. Returns `null` when the error is not a
   * seam refusal, so the caller can answer 500 with its own message.
   */
  function seamRefusal(res: Response, context: string, error: unknown): Response | null {
    if (error instanceof DevicePolicyStorageUnavailableError) {
      logger.error(`[adminDevicePolicy] ${context} refused: ${error.method} is not wired`);
      return res.status(503).json({
        error:
          'Device-policy storage is not wired in this build, so the request was refused rather than ' +
          'answered from a partial store.',
      });
    }
    if (error instanceof DevicePolicyAuditUnavailableError) {
      logger.error(`[adminDevicePolicy] ${context} refused: the audit path is unavailable`);
      return res.status(503).json({
        error:
          'Policy changes require the admin audit path, and this build could not write to it. The ' +
          'change was refused rather than applied without an audit record.',
      });
    }
    return null;
  }

  /** A resolution wiring defect is the server's own fault, never the caller's. */
  function resolutionFailure(res: Response, context: string, error: unknown): Response {
    if (error instanceof DevicePolicyError) {
      logger.error(`[adminDevicePolicy] ${context} primitives error:`, error.code);
      return res.status(500).json({ error: 'Device-policy enforcement primitives are unavailable' });
    }
    return failure(res, context, error, 'Failed to resolve device policy');
  }

  // ── scopes ──────────────────────────────────────────────────────────────────────────────────

  async function listScopesHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req).name;
      guardedReadQuery(req, actor);
      const { limit, offset } = parsePagination(req.query as { limit?: string; offset?: string });
      const tenantId = tenantOf(req);
      const options = { limit, offset, ...(tenantId === undefined ? {} : { tenantId }) };
      const [rows, total] = await Promise.all([
        listScopes(options) as Promise<unknown>,
        countScopes(tenantId === undefined ? {} : { tenantId }) as Promise<number>,
      ]);
      const scopes = (Array.isArray(rows) ? rows : [])
        .map((row) => toScopeResponse(row))
        .filter((row): row is AdminDeviceToolScope => row !== null);
      return res.status(200).json({ scopes, total, limit, offset });
    } catch (error) {
      return (
        seamRefusal(res, 'listScopes', error) ?? failure(res, 'listScopes', error, 'Failed to list tool scopes')
      );
    }
  }

  async function getScopeHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req).name;
      guardedReadQuery(req, actor);
      const { scopeId } = req.params as ScopeIdParams;
      const idError = validateDeviceToolScopeId(scopeId);
      if (idError !== null) {
        return res.status(400).json({ error: idError });
      }
      const tenantId = tenantOf(req);
      const scope = await (getToolScope(
        scopeId as string,
        tenantId === undefined ? {} : { tenantId },
      ) as Promise<unknown>);
      const response = toScopeResponse(scope);
      if (response === null) {
        return res.status(404).json({ error: 'Tool scope not found' });
      }
      return res.status(200).json({ scope: response });
    } catch (error) {
      return (
        seamRefusal(res, 'getScope', error) ?? failure(res, 'getScope', error, 'Failed to get tool scope')
      );
    }
  }

  async function createScopeHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req);
      const { body } = guardedWriteBody(req, SCOPE_WRITE_FIELDS, actor.name);
      const validation = validateDeviceToolScopeBody(body, { requireId: true, requireName: true });
      if (!validation.ok) {
        return res.status(400).json({ error: firstError(validation, 'createScope') });
      }
      const refused = auditUnavailable(actor.name);
      if (refused !== null) {
        return res.status(refused.status).json(refused.body);
      }

      const input = body as { id: string; name: string; description?: string; tools: string[]; stage: string; isActive?: boolean };
      const id = input.id.trim();
      const tenantId = tenantOf(req);
      const existing = await (getToolScope(
        id,
        tenantId === undefined ? {} : { tenantId },
      ) as Promise<unknown>);
      if (toScopeResponse(existing) !== null) {
        return res.status(409).json({ error: `Tool scope "${id}" already exists` });
      }

      const document = {
        id,
        name: input.name.trim(),
        description: input.description ?? '',
        tools: input.tools.map((tool) => tool.trim()),
        stage: input.stage,
        isActive: input.isActive ?? true,
        version: 1,
        ...(tenantId === undefined ? {} : { tenantId }),
      };

      const entry = await recordPolicyChange({
        action: DEVICE_POLICY_AUDIT_ACTIONS.SCOPE_CREATED,
        actor,
        target: auditTarget(id, document.name),
        before: snapshot(null, SNAPSHOT_TYPES.scope, id),
        after: snapshot(document, SNAPSHOT_TYPES.scope, id),
        ...(tenantId === undefined ? {} : { tenantId }),
      });
      const saved = await (upsertToolScope(
        document,
        tenantId === undefined ? {} : { tenantId },
      ) as Promise<unknown>);
      logger.info(
        `[adminDevicePolicy] ${entry.action} "${id}" by ${actor.name} (policyVersion input v${document.version})`,
      );
      return res.status(201).json({ scope: toScopeResponse(saved) ?? toScopeResponse(document) });
    } catch (error) {
      return (
        seamRefusal(res, 'createScope', error) ?? failure(res, 'createScope', error, 'Failed to create tool scope')
      );
    }
  }

  /**
   * A scope update is a FULL REPLACEMENT of the policy fields. The storage layer's own validator
   * (`validateDeviceToolScopeBody`) requires `tools` and `stage` on every write, and that is the
   * right shape: a partial update could silently retain a tool the admin meant to remove. `name`,
   * `description` and `isActive` fall back to the stored values when omitted.
   */
  async function updateScopeHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req);
      const { body } = guardedWriteBody(req, SCOPE_WRITE_FIELDS, actor.name);
      const validation = validateDeviceToolScopeBody(body, { requireId: false, requireName: false });
      if (!validation.ok) {
        return res.status(400).json({ error: firstError(validation, 'updateScope') });
      }
      const { scopeId } = req.params as ScopeIdParams;
      const idError = validateDeviceToolScopeId(scopeId);
      if (idError !== null) {
        return res.status(400).json({ error: idError });
      }
      const refused = auditUnavailable(actor.name);
      if (refused !== null) {
        return res.status(refused.status).json(refused.body);
      }

      const input = body as { name?: string; description?: string; tools: string[]; stage: string; isActive?: boolean };
      const id = scopeId as string;
      const tenantId = tenantOf(req);
      const options = tenantId === undefined ? {} : { tenantId };
      const existingRaw = await (getToolScope(id, options) as Promise<unknown>);
      const existing = toScopeResponse(existingRaw);
      if (existing === null) {
        return res.status(404).json({ error: 'Tool scope not found' });
      }

      const document = {
        id,
        name: input.name === undefined ? existing.name : input.name.trim(),
        description: input.description === undefined ? existing.description : input.description,
        tools: input.tools.map((tool) => tool.trim()),
        stage: input.stage,
        isActive: input.isActive ?? existing.isActive,
        // Bumped on every accepted content change, so the content-derived policyVersion a device
        // pins (GM-78 rule 4) changes with it — including when a scope is retired.
        version: existing.version + 1,
        ...(tenantId === undefined ? {} : { tenantId }),
      };

      const entry = await recordPolicyChange({
        action: DEVICE_POLICY_AUDIT_ACTIONS.SCOPE_UPDATED,
        actor,
        target: auditTarget(id, document.name),
        before: snapshot(existingRaw, SNAPSHOT_TYPES.scope, id),
        after: snapshot(document, SNAPSHOT_TYPES.scope, id),
        ...(tenantId === undefined ? {} : { tenantId }),
      });
      const saved = await (upsertToolScope(document, options) as Promise<unknown>);
      logger.info(`[adminDevicePolicy] ${entry.action} "${id}" by ${actor.name} (v${document.version})`);
      return res.status(200).json({ scope: toScopeResponse(saved) ?? toScopeResponse(document) });
    } catch (error) {
      return (
        seamRefusal(res, 'updateScope', error) ?? failure(res, 'updateScope', error, 'Failed to update tool scope')
      );
    }
  }

  /**
   * Deleting a scope that anything still points at is a 409: the assignments and the tenant default
   * are separately administered records, and removing their target would leave dangling references
   * that fail closed at resolution time — a silent outage for exactly the people the scope covered.
   */
  async function deleteScopeHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req);
      const { scopeId } = req.params as ScopeIdParams;
      const idError = validateDeviceToolScopeId(scopeId);
      if (idError !== null) {
        return res.status(400).json({ error: idError });
      }
      const refused = auditUnavailable(actor.name);
      if (refused !== null) {
        return res.status(refused.status).json(refused.body);
      }

      const id = scopeId as string;
      const tenantId = tenantOf(req);
      const options = tenantId === undefined ? {} : { tenantId };
      const existingRaw = await (getToolScope(id, options) as Promise<unknown>);
      const existing = toScopeResponse(existingRaw);
      if (existing === null) {
        return res.status(404).json({ error: 'Tool scope not found' });
      }

      const [assignmentsRaw, tenantDefaultRaw] = await Promise.all([
        listAssignments(tenantId === undefined ? {} : { tenantId }) as Promise<unknown>,
        getTenantDefault(tenantId === undefined ? {} : { tenantId }) as Promise<unknown>,
      ]);
      const referencing = (Array.isArray(assignmentsRaw) ? assignmentsRaw : [])
        .map((row) => toAssignmentResponse(row))
        .filter((row): row is AdminDevicePolicyAssignment => row !== null && row.toolScopeId === id);
      const tenantDefault = toTenantDefaultResponse(tenantDefaultRaw);
      if (referencing.length > 0 || tenantDefault?.defaultToolScopeId === id) {
        const where =
          tenantDefault?.defaultToolScopeId === id
            ? 'the tenant default'
            : `${referencing.length} assignment${referencing.length === 1 ? '' : 's'}`;
        return res.status(409).json({
          error: `Tool scope "${id}" is still referenced by ${where}; reassign or remove those references first`,
        });
      }

      const entry = await recordPolicyChange({
        action: DEVICE_POLICY_AUDIT_ACTIONS.SCOPE_DELETED,
        actor,
        target: auditTarget(id, existing.name),
        before: snapshot(existingRaw, SNAPSHOT_TYPES.scope, id),
        after: snapshot(null, SNAPSHOT_TYPES.scope, id),
        ...(tenantId === undefined ? {} : { tenantId }),
      });
      const deleted = await (deleteToolScope(id, options) as Promise<unknown>);
      if (deleted === null || deleted === undefined) {
        // The row vanished between the read and the delete. The audit entry records the intent;
        // the caller is told the truth.
        logger.warn(`[adminDevicePolicy] ${entry.action} "${id}" found nothing to delete (race)`);
        return res.status(404).json({ error: 'Tool scope not found' });
      }
      logger.info(`[adminDevicePolicy] ${entry.action} "${id}" by ${actor.name}`);
      return res.status(200).json({ success: true });
    } catch (error) {
      return (
        seamRefusal(res, 'deleteScope', error) ?? failure(res, 'deleteScope', error, 'Failed to delete tool scope')
      );
    }
  }

  // ── assignments ─────────────────────────────────────────────────────────────────────────────

  async function listAssignmentsHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req).name;
      const { query } = guardedReadQuery(req, actor);
      const tenantId = tenantOf(req);
      const filter: Record<string, unknown> = {};
      if (tenantId !== undefined) {
        filter.tenantId = tenantId;
      }
      const principalType = asTrimmedString(query.principalType);
      if (principalType !== null) {
        if (!(DEVICE_POLICY_PRINCIPAL_TYPES as readonly string[]).includes(principalType)) {
          return res.status(400).json({
            error: `principalType must be one of ${DEVICE_POLICY_PRINCIPAL_TYPES.join(', ')}`,
          });
        }
        filter.principalType = principalType;
      }
      const principalId = asTrimmedString(query.principalId);
      if (principalId !== null) {
        filter.principalId = principalId;
      }
      const rows = await (listAssignments(filter) as Promise<unknown>);
      const assignments = (Array.isArray(rows) ? rows : [])
        .map((row) => toAssignmentResponse(row))
        .filter((row): row is AdminDevicePolicyAssignment => row !== null);
      return res.status(200).json({ assignments, total: assignments.length });
    } catch (error) {
      return (
        seamRefusal(res, 'listAssignments', error) ??
        failure(res, 'listAssignments', error, 'Failed to list policy assignments')
      );
    }
  }

  /**
   * Upserts one assignment (PUT semantics: the body IS the assignment). The scope it names must
   * exist and the principal must exist — a dangling reference here would resolve nowhere and fail
   * closed for that principal, so it is refused (404) rather than stored.
   */
  async function setAssignmentHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req);
      const { body } = guardedWriteBody(req, ASSIGNMENT_WRITE_FIELDS, actor.name);
      const validation = validateDevicePolicyAssignmentBody(body);
      if (!validation.ok) {
        return res.status(400).json({ error: firstError(validation, 'setAssignment') });
      }
      const refused = auditUnavailable(actor.name);
      if (refused !== null) {
        return res.status(refused.status).json(refused.body);
      }

      const input = body as {
        principalType: string;
        principalId: string;
        toolScopeId: string;
        priority?: number;
        isActive?: boolean;
      };
      const principalType = input.principalType;
      const principalId = input.principalId.trim();
      if (
        (principalType === 'user' || principalType === 'group') &&
        !isValidObjectIdString(principalId)
      ) {
        return res.status(400).json({ error: 'Invalid principal ID format' });
      }

      const tenantId = tenantOf(req);
      const options = tenantId === undefined ? {} : { tenantId };

      const scope = toScopeResponse(await (getToolScope(input.toolScopeId, options) as Promise<unknown>));
      if (scope === null) {
        return res.status(404).json({ error: `Tool scope "${input.toolScopeId}" not found` });
      }
      const principalExists = await principalExistsFor(principalType, principalId);
      if (!principalExists) {
        return res.status(404).json({
          error: principalType === 'role' ? 'Role not found' : principalType === 'group' ? 'Group not found' : 'User not found',
        });
      }

      const existingRaw = await (getAssignment(principalType, principalId, options) as Promise<unknown>);
      const existing = toAssignmentResponse(existingRaw);

      const document = {
        principalType,
        principalId,
        toolScopeId: input.toolScopeId,
        priority: input.priority ?? 0,
        isActive: input.isActive ?? true,
        ...(tenantId === undefined ? {} : { tenantId }),
      };

      const entry = await recordPolicyChange({
        action: DEVICE_POLICY_AUDIT_ACTIONS.ASSIGNMENT_SET,
        actor,
        target: auditTarget(`${principalType}:${principalId}`, `${principalType}:${principalId}`),
        before: snapshot(existingRaw, SNAPSHOT_TYPES.assignment, `${principalType}:${principalId}`),
        after: snapshot(document, SNAPSHOT_TYPES.assignment, `${principalType}:${principalId}`),
        ...(tenantId === undefined ? {} : { tenantId }),
        note: { toolScopeId: input.toolScopeId },
      });
      const saved = await (upsertAssignment(document, options) as Promise<unknown>);
      logger.info(
        `[adminDevicePolicy] ${entry.action} ${principalType}:${principalId} -> ${input.toolScopeId} by ${actor.name}`,
      );
      return res
        .status(existing === null ? 201 : 200)
        .json({
          assignment: toAssignmentResponse(saved) ?? toAssignmentResponse(document),
          created: existing === null,
        });
    } catch (error) {
      return (
        seamRefusal(res, 'setAssignment', error) ??
        failure(res, 'setAssignment', error, 'Failed to set policy assignment')
      );
    }
  }

  /** True when the role, group or user the assignment names exists. */
  async function principalExistsFor(principalType: string, principalId: string): Promise<boolean> {
    if (principalType === 'role') {
      return recordOf(await (getRoleByName(principalId) as Promise<unknown>)) !== null;
    }
    if (principalType === 'group') {
      return recordOf(await (findGroupById(principalId) as Promise<unknown>)) !== null;
    }
    return recordOf(await (findUser({ _id: principalId }) as Promise<unknown>)) !== null;
  }

  async function removeAssignmentHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req);
      const { principalType, principalId } = req.params as AssignmentParams;
      if (
        typeof principalType !== 'string' ||
        !(DEVICE_POLICY_PRINCIPAL_TYPES as readonly string[]).includes(principalType)
      ) {
        return res.status(400).json({
          error: `principalType must be one of ${DEVICE_POLICY_PRINCIPAL_TYPES.join(', ')}`,
        });
      }
      if (typeof principalId !== 'string' || principalId.trim().length === 0) {
        return res.status(400).json({ error: 'principalId is required' });
      }
      const refused = auditUnavailable(actor.name);
      if (refused !== null) {
        return res.status(refused.status).json(refused.body);
      }

      const id = principalId.trim();
      const tenantId = tenantOf(req);
      const options = tenantId === undefined ? {} : { tenantId };
      const existingRaw = await (getAssignment(principalType, id, options) as Promise<unknown>);
      if (toAssignmentResponse(existingRaw) === null) {
        return res.status(404).json({ error: 'Policy assignment not found' });
      }

      const entry = await recordPolicyChange({
        action: DEVICE_POLICY_AUDIT_ACTIONS.ASSIGNMENT_REMOVED,
        actor,
        target: auditTarget(`${principalType}:${id}`, `${principalType}:${id}`),
        before: snapshot(existingRaw, SNAPSHOT_TYPES.assignment, `${principalType}:${id}`),
        after: snapshot(null, SNAPSHOT_TYPES.assignment, `${principalType}:${id}`),
        ...(tenantId === undefined ? {} : { tenantId }),
      });
      const removed = await (deleteAssignment(principalType, id, options) as Promise<unknown>);
      if (removed === null || removed === undefined) {
        logger.warn(`[adminDevicePolicy] ${entry.action} ${principalType}:${id} found nothing to remove (race)`);
        return res.status(404).json({ error: 'Policy assignment not found' });
      }
      logger.info(`[adminDevicePolicy] ${entry.action} ${principalType}:${id} by ${actor.name}`);
      return res.status(200).json({ success: true });
    } catch (error) {
      return (
        seamRefusal(res, 'removeAssignment', error) ??
        failure(res, 'removeAssignment', error, 'Failed to remove policy assignment')
      );
    }
  }

  // ── tenant default ──────────────────────────────────────────────────────────────────────────

  async function getTenantDefaultHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req).name;
      guardedReadQuery(req, actor);
      const tenantId = tenantOf(req);
      const raw = await (getTenantDefault(
        tenantId === undefined ? {} : { tenantId },
      ) as Promise<unknown>);
      return res.status(200).json({ tenantDefault: toTenantDefaultResponse(raw) });
    } catch (error) {
      return (
        seamRefusal(res, 'getTenantDefault', error) ??
        failure(res, 'getTenantDefault', error, 'Failed to get the tenant device-policy default')
      );
    }
  }

  async function setTenantDefaultHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req);
      const { body } = guardedWriteBody(req, TENANT_DEFAULT_WRITE_FIELDS, actor.name);
      const validation = validateDeviceTenantDefaultBody(body);
      if (!validation.ok) {
        return res.status(400).json({ error: firstError(validation, 'setTenantDefault') });
      }
      const refused = auditUnavailable(actor.name);
      if (refused !== null) {
        return res.status(refused.status).json(refused.body);
      }

      const input = body as { defaultToolScopeId: string };
      const tenantId = tenantOf(req);
      const options = tenantId === undefined ? {} : { tenantId };
      const scope = toScopeResponse(
        await (getToolScope(input.defaultToolScopeId, options) as Promise<unknown>),
      );
      if (scope === null) {
        return res.status(404).json({ error: `Tool scope "${input.defaultToolScopeId}" not found` });
      }
      const existingRaw = await (getTenantDefault(options) as Promise<unknown>);
      const existing = toTenantDefaultResponse(existingRaw);

      const document = {
        defaultToolScopeId: input.defaultToolScopeId,
        version: (existing?.version ?? 0) + 1,
        ...(tenantId === undefined ? {} : { tenantId }),
      };

      const entry = await recordPolicyChange({
        action: DEVICE_POLICY_AUDIT_ACTIONS.TENANT_DEFAULT_SET,
        actor,
        target: auditTarget(tenantId ?? 'platform', 'tenant-device-policy-default'),
        before: snapshot(existingRaw, SNAPSHOT_TYPES.tenantDefault, tenantId ?? 'platform'),
        after: snapshot(document, SNAPSHOT_TYPES.tenantDefault, tenantId ?? 'platform'),
        ...(tenantId === undefined ? {} : { tenantId }),
      });
      const saved = await (upsertTenantDefault({ defaultToolScopeId: input.defaultToolScopeId }, options) as Promise<unknown>);
      logger.info(
        `[adminDevicePolicy] ${entry.action} -> ${input.defaultToolScopeId} by ${actor.name} (v${document.version})`,
      );
      return res
        .status(200)
        .json({ tenantDefault: toTenantDefaultResponse(saved) ?? toTenantDefaultResponse(document) });
    } catch (error) {
      return (
        seamRefusal(res, 'setTenantDefault', error) ??
        failure(res, 'setTenantDefault', error, 'Failed to set the tenant device-policy default')
      );
    }
  }

  // ── resolution ──────────────────────────────────────────────────────────────────────────────

  /**
   * THE SELF-SERVICE READ (GM-79 rule 3). Any authenticated user may read their OWN effective set,
   * and only their own: the identity comes from the session, so a `userId` in the query is stripped
   * by the read guard and changes nothing.
   */
  async function resolveSelfHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req);
      const { attempts } = guardedReadQuery(req, actor.name);
      const user = req.user as { id?: string; _id?: { toString(): string }; role?: string } | undefined;
      const userId = user?.id ?? (user?._id === undefined ? null : String(user._id));
      if (userId === null) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      const tenantId = tenantOf(req);
      const principal = await principalFor(userId, asTrimmedString(user?.role) ?? '', tenantId);
      const resolution = await resolveFor(principal, tenantId);
      return res.status(200).json({
        resolution: serializeResolution(resolution),
        ...(attempts.length === 0 ? {} : { ignoredFields: attempts.map((row) => row.field).sort() }),
      });
    } catch (error) {
      if (error instanceof DevicePolicyStorageUnavailableError) {
        return seamRefusal(res, 'resolveSelf', error) as Response;
      }
      return resolutionFailure(res, 'resolveSelf', error);
    }
  }

  /**
   * THE ADMIN INSPECTION. Resolves a principal the admin names, from the database — never from the
   * request's claims about that principal. A principal in another tenant is a 403: the device-policy
   * documents this API administers are tenant-scoped, so resolving across tenants would leak one
   * tenant's policy shape to another's admin.
   */
  async function resolveForPrincipalHandler(req: ServerRequest, res: Response) {
    try {
      const actor = actorFrom(req);
      const { query } = guardedReadQuery(req, actor.name);
      const params = req.params as PrincipalParams;
      const userId = asTrimmedString(params.userId) ?? asTrimmedString(query.userId);
      if (userId === null) {
        return res.status(400).json({ error: 'userId is required' });
      }
      if (!isValidObjectIdString(userId)) {
        return res.status(400).json({ error: 'Invalid user ID format' });
      }
      const targetRaw = await (findUser({ _id: userId }) as Promise<unknown>);
      const target = recordOf(targetRaw);
      if (target === null) {
        return res.status(404).json({ error: 'User not found' });
      }
      const tenantId = tenantOf(req);
      const targetTenant = asTrimmedString(target.tenantId);
      if (tenantId !== undefined && targetTenant !== null && targetTenant !== tenantId) {
        return res.status(403).json({ error: 'Cannot resolve device policy for a principal in another tenant' });
      }

      const principal = await principalFor(
        userId,
        asTrimmedString(target.role) ?? '',
        targetTenant ?? tenantId,
      );
      const resolution = await resolveFor(principal, tenantId);
      return res.status(200).json({
        userId,
        resolution: serializeResolution(resolution),
      });
    } catch (error) {
      if (error instanceof DevicePolicyStorageUnavailableError) {
        return seamRefusal(res, 'resolveForPrincipal', error) as Response;
      }
      return resolutionFailure(res, 'resolveForPrincipal', error);
    }
  }

  return {
    listScopes: listScopesHandler,
    getScope: getScopeHandler,
    createScope: createScopeHandler,
    updateScope: updateScopeHandler,
    deleteScope: deleteScopeHandler,
    listAssignments: listAssignmentsHandler,
    setAssignment: setAssignmentHandler,
    removeAssignment: removeAssignmentHandler,
    getTenantDefault: getTenantDefaultHandler,
    setTenantDefault: setTenantDefaultHandler,
    resolveSelf: resolveSelfHandler,
    resolveForPrincipal: resolveForPrincipalHandler,
  };
}
/**
 * W10b — THE DEVICE-POLICY PERSISTENCE LAYER: the eleven functions W10's storage seam names.
 *
 * `packages/api/src/admin/devicePolicy/storage.ts` declares fifteen methods and binds every one that
 * `~/models` does not expose to a NAMED REFUSAL, which the route turns into a 503. In this branch:
 *
 *   ALREADY PRESENT (they are pre-existing methods, bound through the seam unchanged, NOT reimplemented
 *   here — W10b's whole point is to supply what is missing rather than fork what works):
 *     getRoleByName, findGroupById, findUser, getUserPrincipals
 *
 *   SUPPLIED HERE (the eleven that were absent):
 *     listScopes, countScopes, getToolScope, upsertToolScope, deleteToolScope,
 *     listAssignments, getAssignment, upsertAssignment, deleteAssignment,
 *     getTenantDefault, upsertTenantDefault
 *
 * Signatures are the seam's own (`AdminDevicePolicyDeps` in
 * `packages/api/src/admin/devicePolicy/types.ts`), not invented: `getToolScope(id, { tenantId })`,
 * `upsertAssignment(document, { tenantId })`, and so on. `options.tenantId` is the tenant the write
 * or read is scoped to, and it is the ONLY source of tenancy on the write path.
 *
 * THE TWO RULES THIS FILE ENFORCES
 *
 * 1. TENANT COERCION ON EVERY WRITE. A caller-supplied document may carry a `tenantId` of its own —
 *    the guards strip the request spelling, but a data-layer function must not rely on a caller
 *    having been careful. Every write here takes the tenant from `options.tenantId` and DISCARDS any
 *    tenant on the document, so the only tenant a document can land in is the one the caller is
 *    already scoped to. Without this, a platform-context caller could plant a policy inside a tenant
 *    it cannot read back — a write the 403/404 surface would never show.
 *
 * 2. `tenantId` IS ALWAYS STORED, AS A STRING OR AN EXPLICIT `null`. Never absent. The uniqueness
 *    constraints and every lookup filter include `tenantId`, and a missing field and a null field are
 *    not the same thing to a filter. One canonical spelling means a platform install
 *    (`options` omitted -> `null`) and a tenant install (`options.tenantId = 't1'`) each have exactly
 *    one namespace, and there is no third "unset" spelling that could defeat a unique index.
 *
 * WHAT A READ REFUSES TO DO. `getToolScope(id, { tenantId })` filters on the tenant, it does not
 * merely "prefer" it: a scope that exists in another tenant is NOT FOUND here rather than returned.
 * A policy API that answers across tenants is worse than one that refuses, which is the same rule the
 * seam applies to a missing function.
 */

import type { Model, FilterQuery } from 'mongoose';
import { createDevicePolicyAssignmentModel } from '~/models/devicePolicyAssignment';
import { createDeviceTenantPolicyDefaultModel } from '~/models/deviceTenantPolicyDefault';
import { createDeviceToolScopeModel } from '~/models/deviceToolScope';
import type { IDeviceToolScopeDocument } from '~/schema/deviceToolScope';
import type { IDevicePolicyAssignmentDocument } from '~/schema/devicePolicyAssignment';
import type { IDeviceTenantPolicyDefaultDocument } from '~/schema/deviceTenantPolicyDefault';

/** The options every storage function accepts: the tenant the operation is scoped to. */
export interface DevicePolicyStorageOptions {
  tenantId?: string;
  limit?: number;
  offset?: number;
  principalType?: string;
  principalId?: string;
}

export interface DevicePolicyStorageMethods {
  listScopes: (options?: DevicePolicyStorageOptions) => Promise<IDeviceToolScopeDocument[]>;
  countScopes: (options?: DevicePolicyStorageOptions) => Promise<number>;
  getToolScope: (
    id: string,
    options?: DevicePolicyStorageOptions,
  ) => Promise<IDeviceToolScopeDocument | null>;
  upsertToolScope: (
    scope: Partial<IDeviceToolScopeDocument> & { id: string },
    options?: DevicePolicyStorageOptions,
  ) => Promise<IDeviceToolScopeDocument | null>;
  deleteToolScope: (
    id: string,
    options?: DevicePolicyStorageOptions,
  ) => Promise<IDeviceToolScopeDocument | null>;
  listAssignments: (
    options?: DevicePolicyStorageOptions,
  ) => Promise<IDevicePolicyAssignmentDocument[]>;
  getAssignment: (
    principalType: string,
    principalId: string,
    options?: DevicePolicyStorageOptions,
  ) => Promise<IDevicePolicyAssignmentDocument | null>;
  upsertAssignment: (
    assignment: Partial<IDevicePolicyAssignmentDocument>,
    options?: DevicePolicyStorageOptions,
  ) => Promise<IDevicePolicyAssignmentDocument | null>;
  deleteAssignment: (
    principalType: string,
    principalId: string,
    options?: DevicePolicyStorageOptions,
  ) => Promise<IDevicePolicyAssignmentDocument | null>;
  getTenantDefault: (
    options?: DevicePolicyStorageOptions,
  ) => Promise<IDeviceTenantPolicyDefaultDocument | null>;
  upsertTenantDefault: (
    input: { defaultToolScopeId: string },
    options?: DevicePolicyStorageOptions,
  ) => Promise<IDeviceTenantPolicyDefaultDocument | null>;
}

/**
 * The stored spelling of a tenant: a non-empty string, or `null` for the platform tenant.
 *
 * One function, used by every filter and every document, so the platform tenant cannot be spelled two
 * ways (`undefined` in a filter, `null` in a document) — the mismatch that would let a scope be
 * written once and then not found by the read that just wrote it.
 */
function tenantKey(options?: DevicePolicyStorageOptions): string | null {
  const tenantId = options?.tenantId;
  if (typeof tenantId !== 'string') {
    return null;
  }
  const trimmed = tenantId.trim();
  return trimmed.length === 0 ? null : trimmed;
}

/** A non-empty string, or `undefined` for anything else. Used to normalise ids off a caller's object. */
function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

/** True for a value that can be a Mongoose `$set` member (i.e. not `undefined`). */
function defined(value: unknown): boolean {
  return value !== undefined;
}

/**
 * Drops `undefined` members so `$set` never carries one. Mongoose would ignore them, but an explicit
 * strip keeps the update document readable in a log or a debugger, which matters for a policy store.
 */
function compact(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (defined(value)) {
      out[key] = value;
    }
  }
  return out;
}

export function createDevicePolicyMethods(
  mongoose: typeof import('mongoose'),
): DevicePolicyStorageMethods {
  const DeviceToolScope: Model<IDeviceToolScopeDocument> = createDeviceToolScopeModel(mongoose);
  const DevicePolicyAssignment: Model<IDevicePolicyAssignmentDocument> =
    createDevicePolicyAssignmentModel(mongoose);
  const DeviceTenantPolicyDefault: Model<IDeviceTenantPolicyDefaultDocument> =
    createDeviceTenantPolicyDefaultModel(mongoose);

  // ── tool scopes ─────────────────────────────────────────────────────────────────────────────

  /**
   * The admin list. Paged (`{ limit, offset }` from `parsePagination`) and ordered by slug, which is
   * the same order `id` is unique in, so a caller paging through sees a stable sequence.
   */
  async function listScopes(
    options?: DevicePolicyStorageOptions,
  ): Promise<IDeviceToolScopeDocument[]> {
    const filter: FilterQuery<IDeviceToolScopeDocument> = { tenantId: tenantKey(options) };
    let query = DeviceToolScope.find(filter).sort({ id: 1 });
    if (typeof options?.offset === 'number' && options.offset > 0) {
      query = query.skip(options.offset);
    }
    if (typeof options?.limit === 'number' && options.limit > 0) {
      query = query.limit(options.limit);
    }
    return (await query.lean()) as unknown as IDeviceToolScopeDocument[];
  }

  /** The list route's `total`: the count that belongs with the page, never the page's length. */
  async function countScopes(options?: DevicePolicyStorageOptions): Promise<number> {
    return DeviceToolScope.countDocuments({ tenantId: tenantKey(options) });
  }

  /**
   * One scope by slug, WITHIN the tenant. A scope in another tenant is not found — see the header.
   *
   * `findOne(...).lean()` rather than the handler's own unwrapping: the seam's contract is a stored
   * record, and a lean document is what the handlers' `recordOf()` and the resolver both read.
   */
  async function getToolScope(
    id: string,
    options?: DevicePolicyStorageOptions,
  ): Promise<IDeviceToolScopeDocument | null> {
    const scopeId = nonEmptyString(id);
    if (scopeId === undefined) {
      return null;
    }
    const doc = await DeviceToolScope.findOne({
      id: scopeId,
      tenantId: tenantKey(options),
    }).lean();
    return (doc as unknown as IDeviceToolScopeDocument) ?? null;
  }

  /**
   * Create or replace a scope (the route's PUT semantics, used by both POST and PUT).
   *
   * The document's POLICY fields are written from the caller; its TENANT is not (rule 1 above). The
   * caller's `tenantId`, if any, is dropped rather than merged.
   */
  async function upsertToolScope(
    scope: Partial<IDeviceToolScopeDocument> & { id: string },
    options?: DevicePolicyStorageOptions,
  ): Promise<IDeviceToolScopeDocument | null> {
    const scopeId = nonEmptyString(scope?.id);
    if (scopeId === undefined) {
      throw new Error('upsertToolScope requires a scope id');
    }
    const tenantId = tenantKey(options);
    const filter: FilterQuery<IDeviceToolScopeDocument> = { id: scopeId, tenantId };

    const policyFields = compact({
      // Only usable values become `$set` members: a non-string `name` is DROPPED (so it can neither
      // overwrite the stored name nor reach the schema's cast as a number), never coerced.
      name: nonEmptyString(scope.name),
      description: typeof scope.description === 'string' ? scope.description : undefined,
      tools: Array.isArray(scope.tools)
        ? scope.tools.filter((tool): tool is string => typeof tool === 'string')
        : undefined,
      stage: nonEmptyString(scope.stage),
      isActive: typeof scope.isActive === 'boolean' ? scope.isActive : undefined,
      version: typeof scope.version === 'number' ? scope.version : undefined,
    });

    const doc = await DeviceToolScope.findOneAndUpdate(
      filter,
      {
        // A field the caller omitted is left alone on an existing row and takes its SCHEMA DEFAULT on
        // an insert (`setDefaultsOnInsert`), which is how a scope created without a `version` still
        // starts at 1 — without a second `$setOnInsert` on the same path, which MongoDB rejects as a
        // conflict. A caller-supplied `version` (the admin handler bumps it) wins on both paths.
        $set: { ...policyFields, id: scopeId, tenantId },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    ).lean();
    return (doc as unknown as IDeviceToolScopeDocument) ?? null;
  }

  /**
   * Delete a scope, returning the row that was removed (or `null` when there was nothing to remove).
   *
   * The route relies on exactly that distinction: a `null` here is a 404 rather than a silent 200, so
   * a delete of an already-deleted scope tells the truth. The reference check that refuses to delete a
   * scope still named by an assignment or the tenant default is the HANDLER's (it can answer 409 with
   * a message); this function's job is only to remove the row atomically and say what it removed.
   */
  async function deleteToolScope(
    id: string,
    options?: DevicePolicyStorageOptions,
  ): Promise<IDeviceToolScopeDocument | null> {
    const scopeId = nonEmptyString(id);
    if (scopeId === undefined) {
      return null;
    }
    const doc = await DeviceToolScope.findOneAndDelete({
      id: scopeId,
      tenantId: tenantKey(options),
    }).lean();
    return (doc as unknown as IDeviceToolScopeDocument) ?? null;
  }

  // ── assignments ─────────────────────────────────────────────────────────────────────────────

  /**
   * Every assignment in the tenant, optionally narrowed by principal. The resolution walk calls this
   * with only `{ tenantId }` and filters the three levels itself; the admin list route may narrow by
   * `principalType`/`principalId`.
   *
   * Ordered by `principalType` then `principalId` so two reads of unchanged data return the same
   * sequence. The resolver does its own priority tie-break, so this order is for the LIST route and
   * for readable diffs, not for the resolution result.
   */
  async function listAssignments(
    options?: DevicePolicyStorageOptions,
  ): Promise<IDevicePolicyAssignmentDocument[]> {
    const filter: FilterQuery<IDevicePolicyAssignmentDocument> = {
      tenantId: tenantKey(options),
    };
    const principalType = nonEmptyString(options?.principalType);
    if (principalType !== undefined) {
      filter.principalType = principalType;
    }
    const principalId = nonEmptyString(options?.principalId);
    if (principalId !== undefined) {
      filter.principalId = principalId;
    }
    return (await DevicePolicyAssignment.find(filter)
      .sort({ principalType: 1, principalId: 1 })
      .lean()) as unknown as IDevicePolicyAssignmentDocument[];
  }

  /** The one assignment a principal holds in this tenant (`null` when it holds none). */
  async function getAssignment(
    principalType: string,
    principalId: string,
    options?: DevicePolicyStorageOptions,
  ): Promise<IDevicePolicyAssignmentDocument | null> {
    const type = nonEmptyString(principalType);
    const id = nonEmptyString(principalId);
    if (type === undefined || id === undefined) {
      return null;
    }
    const doc = await DevicePolicyAssignment.findOne({
      tenantId: tenantKey(options),
      principalType: type,
      principalId: id,
    }).lean();
    return (doc as unknown as IDevicePolicyAssignmentDocument) ?? null;
  }

  /**
   * Create or replace the assignment for a principal (the route's `PUT /assignments`).
   *
   * `tenantId` again comes from `options` and not from the document (rule 1). `priority` and
   * `isActive` fall back to the schema defaults when the caller omits them, which is what the
   * handler expects: it sends them explicitly, and a caller that does not still gets a usable row.
   */
  async function upsertAssignment(
    assignment: Partial<IDevicePolicyAssignmentDocument>,
    options?: DevicePolicyStorageOptions,
  ): Promise<IDevicePolicyAssignmentDocument | null> {
    const principalType = nonEmptyString(assignment?.principalType);
    const principalId = nonEmptyString(assignment?.principalId);
    if (principalType === undefined || principalId === undefined) {
      throw new Error('upsertAssignment requires principalType and principalId');
    }
    const toolScopeId = nonEmptyString(assignment.toolScopeId);
    if (toolScopeId === undefined) {
      throw new Error('upsertAssignment requires toolScopeId');
    }
    const tenantId = tenantKey(options);
    const filter: FilterQuery<IDevicePolicyAssignmentDocument> = {
      tenantId,
      principalType,
      principalId,
    };

    const policyFields = compact({
      toolScopeId,
      priority: typeof assignment.priority === 'number' ? assignment.priority : undefined,
      isActive: typeof assignment.isActive === 'boolean' ? assignment.isActive : undefined,
    });

    const doc = await DevicePolicyAssignment.findOneAndUpdate(
      filter,
      {
        // Same rule as `upsertToolScope`: omitted fields take their schema default (0 / true) on
        // insert and are left untouched on update, with no conflicting `$setOnInsert` path.
        $set: { ...policyFields, tenantId, principalType, principalId },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    ).lean();
    return (doc as unknown as IDevicePolicyAssignmentDocument) ?? null;
  }

  /** Remove a principal's assignment, returning the row that was removed (or `null`). */
  async function deleteAssignment(
    principalType: string,
    principalId: string,
    options?: DevicePolicyStorageOptions,
  ): Promise<IDevicePolicyAssignmentDocument | null> {
    const type = nonEmptyString(principalType);
    const id = nonEmptyString(principalId);
    if (type === undefined || id === undefined) {
      return null;
    }
    const doc = await DevicePolicyAssignment.findOneAndDelete({
      tenantId: tenantKey(options),
      principalType: type,
      principalId: id,
    }).lean();
    return (doc as unknown as IDevicePolicyAssignmentDocument) ?? null;
  }

  // ── the tenant default ──────────────────────────────────────────────────────────────────────

  /**
   * The tenant's default scope, or `null`.
   *
   * `null` is the fail-closed answer, not an error: a tenant with no default document enables
   * nothing at the tenant level, which is what GM-74/GM-76 require ("an absent value at every level
   * enables nothing"). This function therefore has NO code-side fallback default — inventing one here
   * would be exactly the hardcoded policy GM-76 rule 4 forbids.
   */
  async function getTenantDefault(
    options?: DevicePolicyStorageOptions,
  ): Promise<IDeviceTenantPolicyDefaultDocument | null> {
    const doc = await DeviceTenantPolicyDefault.findOne({ tenantId: tenantKey(options) }).lean();
    return (doc as unknown as IDeviceTenantPolicyDefaultDocument) ?? null;
  }

  /**
   * Set the tenant default. `version` is incremented ATOMICALLY (`$inc`) on every accepted write, and
   * starts at 1 on insert, so the stored counter counts writes without a read-then-write race — and a
   * device pinning an older version can tell that it did (GM-78 rule 4).
   */
  async function upsertTenantDefault(
    input: { defaultToolScopeId: string },
    options?: DevicePolicyStorageOptions,
  ): Promise<IDeviceTenantPolicyDefaultDocument | null> {
    const defaultToolScopeId = nonEmptyString(input?.defaultToolScopeId);
    if (defaultToolScopeId === undefined) {
      throw new Error('upsertTenantDefault requires defaultToolScopeId');
    }
    const tenantId = tenantKey(options);
    const doc = await DeviceTenantPolicyDefault.findOneAndUpdate(
      { tenantId },
      {
        $set: { defaultToolScopeId, tenantId },
        // `$inc` on a missing field yields 1 on insert, so the create and the update paths agree on
        // what "version 1" means without a second write. `setDefaultsOnInsert` is OFF here on
        // purpose: the schema's `version` default would land in `$setOnInsert` and collide with this
        // `$inc` on the same path, which MongoDB rejects as a conflict.
        $inc: { version: 1 },
      },
      { upsert: true, new: true, setDefaultsOnInsert: false },
    ).lean();
    return (doc as unknown as IDeviceTenantPolicyDefaultDocument) ?? null;
  }

  return {
    listScopes,
    countScopes,
    getToolScope,
    upsertToolScope,
    deleteToolScope,
    listAssignments,
    getAssignment,
    upsertAssignment,
    deleteAssignment,
    getTenantDefault,
    upsertTenantDefault,
  };
}
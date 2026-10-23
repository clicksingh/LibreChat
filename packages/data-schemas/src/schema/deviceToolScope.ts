/**
 * W10b — TOOL SCOPE: the stored shape (GM-76 rule 2, "the policy is data in the database").
 *
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3 (GM-76),
 * `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §2 (W10),
 * `docs/GM-RULING-ABSOLUTE-ADMIN-POLICY-AND-AUDIT-SEAM-20261023.md` §5 (W10b supplies the seam).
 *
 * This is the PERSISTENCE shape of a scope. The API-facing shape is `IDeviceToolScope` in
 * `~/admin/devicePolicy` (W10's file, not touched here); the two differ in exactly one place and
 * the difference is deliberate:
 *
 *   IDeviceToolScope.tenantId?: string      absent means "the platform default tenant"
 *   IDeviceToolScopeDocument.tenantId: string | null
 *                                           STORED as an explicit null, never absent
 *
 * `null` rather than "absent" is load-bearing. Both uniqueness constraints and every lookup filter
 * on `tenantId`, and MongoDB's unique index treats a MISSING field as null but will not match an
 * explicit `{ tenantId: null }` filter against a missing field in every index path. Storing one
 * canonical spelling means "the platform tenant" has exactly one representation, so the fail-closed
 * read (`getToolScope(id, {})` in a platform install) can never silently miss a row, and the unique
 * index can never be defeated by writing the same scope twice with two different spellings of
 * "no tenant".
 *
 * UNIQUENESS: `id` is globally unique, and that is the instruction W10b was given ("toolScopeId
 * unique") as well as the property the resolver depends on. A scope id is a URL path segment
 * (`/api/admin/device-policy/scopes/:scopeId`) and the resolution preload builds a map keyed by
 * scope id, so one slug must mean one scope platform-wide. The tenant is still enforced
 * independently: every read and write filters on `tenantId`, so a tenant-A admin cannot read,
 * delete or affect a tenant-B scope even though the slug space is shared. `(tenantId, id)` is
 * indexed as well, because that is the compound every tenant-scoped lookup uses.
 *
 * NOT HERE: the tool catalog. `tools` is a list of catalog names and membership is NOT validated at
 * write time — the catalog belongs to `api/server/services/Device/deviceCapabilityPolicy`, and an
 * unknown name is refused by the enforcement path with a reason instead of being rejected at write
 * time, so a catalog that later gains a tool needs no data migration. That is GM-76 rule 1: the
 * catalog is data, and this file does not restate it.
 */

import { Schema, Document } from 'mongoose';
import { DEVICE_POLICY_STAGES, type DevicePolicyStage } from '~/admin/devicePolicy';

/** The stored scope. Mirrors `IDeviceToolScope`, with `tenantId` canonicalised to `null`. */
export interface IDeviceToolScopeDocument extends Document {
  /** Stable slug: lowercase, digits and single hyphens. The resolver keys off this. */
  id: string;
  name: string;
  description: string;
  /** Catalog tool names this scope enables. No wildcard semantics of any kind. */
  tools: string[];
  /** The stage this scope narrows to; the resolved stage is the stricter of this and the server's. */
  stage: DevicePolicyStage;
  /** Retired scopes keep their history and their assignments but enable nothing. */
  isActive: boolean;
  /** Bumped by the admin API on every content change; feeds the device-pinned policy version. */
  version: number;
  /** The owning tenant, or `null` for the platform tenant. Always present. */
  tenantId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

const deviceToolScopeSchema: Schema<IDeviceToolScopeDocument> =
  new Schema<IDeviceToolScopeDocument>(
    {
      id: {
        type: String,
        required: true,
      },
      name: {
        type: String,
        required: true,
      },
      description: {
        type: String,
        default: '',
      },
      tools: {
        type: [String],
        default: [],
      },
      stage: {
        type: String,
        enum: [...DEVICE_POLICY_STAGES],
        required: true,
      },
      isActive: {
        type: Boolean,
        default: true,
      },
      version: {
        type: Number,
        default: 1,
        min: 1,
      },
      tenantId: {
        type: String,
        default: null,
      },
    },
    { timestamps: true },
  );

/** One scope per slug, platform-wide: see the header for why this is global and not per-tenant. */
deviceToolScopeSchema.index({ id: 1 }, { unique: true });

/** The resolution walk's scope load, and every tenant-scoped read: `getToolScope(id, {tenantId})`. */
deviceToolScopeSchema.index({ tenantId: 1, id: 1 });

/** The admin list: `listScopes({ tenantId, limit, offset })` in slug order. */
deviceToolScopeSchema.index({ tenantId: 1, isActive: 1, id: 1 });

export default deviceToolScopeSchema;
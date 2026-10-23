/**
 * W10b — POLICY ASSIGNMENT: the stored shape (GM-76 rule 3, the resolution order's three data levels).
 *
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3 (GM-76),
 * `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §2 (W10).
 *
 * An assignment is ITS OWN RECORD rather than a `toolScopeId` field on a role, group or user
 * document. That was W10's design decision, preserved here, and the reason is a write-scope one that
 * still holds: `api/models/role.ts`, `group.ts` and `user.ts` are shared, high-traffic surfaces, and
 * a policy record that lives beside them can be administered and audited today without editing them.
 * The resolver reads an identity plus a policy document, so it does not care which collection
 * produced them — W10b therefore does NOT have to touch the role/group/user documents, and the
 * storage seam's `getRoleByName` / `findGroupById` / `findUser` bind to the EXISTING implementations
 * unchanged.
 *
 * The three levels the resolution order reads, most specific first:
 *
 *     user  -> principalId is a user id
 *     group -> principalId is a group id
 *     role  -> principalId is a role NAME (the spelling the existing role surface stores)
 *
 * UNIQUENESS: `(tenantId, principalType, principalId)` is unique. One principal has at most one
 * assignment per tenant, so resolution is a lookup and not a tie-break problem: a principal cannot
 * end up holding two policies at the same level, which is the state that makes "which one wins?"
 * depend on write order. The `priority` field is kept and indexed because the resolver documents how
 * it breaks a match across DIFFERENT principals at the same level (a user in two groups, or holding
 * two roles), and that tie-break needs a deterministic stored value.
 *
 * TENANT COERCION: `tenantId` is always written from the caller's explicit `options.tenantId`
 * (normalised to `null` for the platform tenant), NEVER from the assignment object handed in. A
 * document that carried its own tenant would let a caller with a platform session plant a policy in
 * another tenant; the method drops it, so the only tenant an assignment can land in is the one the
 * caller is already scoped to.
 */

import { Schema, Document } from 'mongoose';
import {
  DEVICE_POLICY_PRINCIPAL_TYPES,
  type DevicePolicyPrincipalType,
} from '~/admin/devicePolicy';

/** The stored assignment. Mirrors `IDevicePolicyAssignment`, with `tenantId` canonicalised. */
export interface IDevicePolicyAssignmentDocument extends Document {
  principalType: DevicePolicyPrincipalType;
  /** The role NAME, the group id, or the user id — matching the existing admin surfaces. */
  principalId: string;
  toolScopeId: string;
  /** Higher wins when a principal matches more than one assignment at the same level. */
  priority: number;
  isActive: boolean;
  /** The owning tenant, or `null` for the platform tenant. Always present. */
  tenantId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

const devicePolicyAssignmentSchema: Schema<IDevicePolicyAssignmentDocument> =
  new Schema<IDevicePolicyAssignmentDocument>(
    {
      principalType: {
        type: String,
        enum: [...DEVICE_POLICY_PRINCIPAL_TYPES],
        required: true,
      },
      principalId: {
        type: String,
        required: true,
      },
      toolScopeId: {
        type: String,
        required: true,
      },
      priority: {
        type: Number,
        default: 0,
        min: 0,
      },
      isActive: {
        type: Boolean,
        default: true,
      },
      tenantId: {
        type: String,
        default: null,
      },
    },
    { timestamps: true },
  );

/**
 * One policy per principal per tenant — the constraint the route's PUT semantics assume (`setAssignment`
 * says "the body IS the assignment", which is only sound if there is exactly one row to replace).
 */
devicePolicyAssignmentSchema.index(
  { tenantId: 1, principalType: 1, principalId: 1 },
  { unique: true },
);

/** The resolution walk: load every assignment in the tenant, in a deterministic order. */
devicePolicyAssignmentSchema.index({ tenantId: 1, priority: -1, toolScopeId: 1 });

/** The delete-scope reference check (`409` when a scope is still assigned) and the audit target walk. */
devicePolicyAssignmentSchema.index({ tenantId: 1, toolScopeId: 1 });

export default devicePolicyAssignmentSchema;
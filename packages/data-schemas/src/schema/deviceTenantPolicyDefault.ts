/**
 * W10b — THE TENANT DEFAULT: the stored shape (GM-76 rule 4, "configurable, not baked into code").
 *
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3 (GM-76 rules 3 and 4):
 * "The default policy for a new user is configurable, not baked into code. A fresh install must not
 * require a code change to alter what a new employee gets."
 *
 * ONE DOCUMENT PER TENANT. `defaultToolScopeId` is the scope the resolution order falls back to when
 * no user, group or role assignment applies. A tenant with NO default document resolves to nothing,
 * which is the fail-closed floor GM-74/GM-76 require — the absence of data enables nothing, and this
 * collection has no code-side default to fall back on precisely so that "no policy" cannot quietly
 * become "some policy".
 *
 * UNIQUENESS ON `tenantId` ALONE is what makes "one document per tenant" true. The platform tenant is
 * stored as an explicit `null` (see `deviceToolScope.ts` for why null rather than absent), and a
 * unique index treats null as a value — so the platform default is a single document too, and two
 * concurrent admin writes cannot produce two competing platform defaults.
 *
 * `version` is incremented by the storage method on every accepted write (`$inc`), so a device
 * holding an older default can detect that it did (GM-78 rule 4). The admin handler also computes a
 * version for its log line and its response fallback; the two agree because both count writes.
 */

import { Schema, Document } from 'mongoose';

/** The stored tenant default. Mirrors `IDeviceTenantPolicyDefault`, with `tenantId` canonicalised. */
export interface IDeviceTenantPolicyDefaultDocument extends Document {
  /** The owning tenant, or `null` for the platform default. Always present. */
  tenantId: string | null;
  /** The scope a principal resolves to when no user, group or role assignment applies. */
  defaultToolScopeId: string;
  /** Incremented on every accepted write, so a stale reader is detectable. */
  version: number;
  createdAt: Date;
  updatedAt: Date;
}

const deviceTenantPolicyDefaultSchema: Schema<IDeviceTenantPolicyDefaultDocument> =
  new Schema<IDeviceTenantPolicyDefaultDocument>(
    {
      tenantId: {
        type: String,
        default: null,
      },
      defaultToolScopeId: {
        type: String,
        required: true,
      },
      version: {
        type: Number,
        default: 1,
        min: 1,
      },
    },
    { timestamps: true },
  );

/** One default per tenant (the platform tenant included, as an explicit null). */
deviceTenantPolicyDefaultSchema.index({ tenantId: 1 }, { unique: true });

export default deviceTenantPolicyDefaultSchema;
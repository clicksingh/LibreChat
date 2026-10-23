/**
 * W10 — admin device-policy public surface (GM-76, GM-78, GM-79, GM-81).
 *
 * The one place the route file (`api/server/routes/admin/devicePolicy.js`) imports from. Everything
 * below is deliberately exposed:
 *
 *   createAdminDevicePolicyHandlers  the 12 handlers, dependencies injected
 *   resolveDevicePolicy              the resolution order, pure and directly testable
 *   authorizeResolvedTool            the dispatch gate for a resolved policy (W12)
 *   resolveDevicePolicyStorage       the fail-closed storage port (503 until the data layer lands)
 *   DEVICE_POLICY_AUDIT_ACTION_NAMES the frozen `device_policy.*` list the rebase registers
 *   guards / codes / shapes          the widening guards, the refusal codes, the audit actions
 */

export {
  createAdminDevicePolicyHandlers,
  type AdminDevicePolicyHandlerDeps,
  type AdminDevicePolicyHandlers,
} from './handlers';
export { authorizeResolvedTool, describeResolution, DevicePolicyError, resolveDevicePolicy } from './resolver';
export {
  DevicePolicyStorageUnavailableError,
  DEVICE_POLICY_STORAGE_METHODS,
  isStorageUnavailableError,
  resolveDevicePolicyStorage,
  type DevicePolicyStorageMethod,
} from './storage';
export {
  buildDevicePolicyAuditEntry,
  changedFieldsBetween,
  createDevicePolicyAuditWriter,
  DEVICE_POLICY_AUDIT_ACTION_NAMES,
  DEVICE_POLICY_AUDIT_CATEGORY,
  DEVICE_POLICY_AUDIT_TARGET_TYPE,
  DevicePolicyAuditUnavailableError,
  fingerprintOf,
  snapshotPolicyDocument,
  type AuditActorInput,
  type AuditTargetInput,
  type DevicePolicyAuditEntry,
  type DevicePolicyAuditWriter,
  type PolicySnapshot,
  type RecordAuditEntry,
  type RecordAuditEntryInput,
} from './audit';
export {
  ASSIGNMENT_WRITE_FIELDS,
  DEVICE_CLAIM_FIELDS,
  PRIVILEGE_FIELDS,
  REQUEST_WIDENING_FIELDS,
  SCOPE_WRITE_FIELDS,
  TENANT_DEFAULT_WRITE_FIELDS,
  TOKEN_CLAIM_FIELDS,
  WRITE_SHAPE_FIELDS,
  deviceClaimFieldNames,
  privilegeFieldNames,
  requestWideningFieldNames,
  stripRequestWideningFields,
  tokenClaimFieldNames,
  type GuardMode,
  type StripResult,
  type WideningAttempt,
} from './guards';
export {
  DEVICE_POLICY_CODES,
  DEVICE_POLICY_DENIED_BY,
  DEVICE_POLICY_DETAILS,
  DEVICE_POLICY_AUDIT_ACTIONS,
  DEVICE_POLICY_RESOLUTION_SCHEMA,
  type AdminDevicePolicyAssignment,
  type AdminDevicePolicyDeps,
  type AdminDeviceTenantDefault,
  type AdminDeviceToolScope,
  type DevicePolicyLevel,
  type DevicePolicyLevelTrace,
  type DevicePolicyPrincipal,
  type DevicePolicyProvenance,
  type DevicePolicyResolution,
  type DevicePolicyResolutionInput,
  type DevicePolicyStage,
  type DevicePolicyToolDecision,
  type DevicePolicyValidation,
  type ToolEffectiveReport,
  type ToolExclusion,
  type ToolRegistryPrimitives,
} from './types';
export type {
  DeviceCapabilityPolicyPrimitives,
  DevicePolicyPrimitives,
  DeviceToolFloorEnvelope,
  DeviceToolRegistryPrimitives,
} from './primitives';
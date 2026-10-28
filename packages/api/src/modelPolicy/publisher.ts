import { extractEnvVariable } from 'librechat-data-provider';
import type { ClientSession } from 'mongoose';
import { buildModelPolicyCommitPlan } from './projection';

type Endpoint = {
  name: string;
  default?: boolean;
  apiKey?: string;
  baseURL?: string;
  models?: { default?: string[]; fetch?: boolean };
  customParams?: Record<string, unknown>;
  [field: string]: unknown;
};

type RoleConfig = {
  priority?: number;
  isActive?: boolean;
  tombstones?: string[];
  overrides?: {
    interface?: { modelSelect?: boolean };
    endpoints?: { custom?: Endpoint[] };
  };
};

type RoleProjection = {
  roles: Record<
    string,
    { interface?: { modelSelect?: boolean }; endpoints?: { custom?: Endpoint[] } }
  >;
};

type BaseAppConfig = { endpoints?: { custom?: Endpoint[] } };
type RoleConfigs = Record<string, RoleConfig | null>;
type ProjectionWrite = { principalId: string; fields: string[] };
type ModelPolicyCommitResult = {
  policyVersion: number;
  transition: 'advance' | 'noop' | 'create';
  policyNoop: boolean;
  refreshConfigCaches: boolean;
  writes: ProjectionWrite[];
  noop: boolean;
};

export interface ModelPolicyCommitDeps {
  listActiveNonRoleConfigsForTenant: (
    tenantId: string,
    session: ClientSession,
  ) => Promise<RoleConfig[]>;
  findConfigByPrincipal: (
    type: string,
    id: string,
    options: { includeInactive: boolean; tenantId: string },
    session: ClientSession,
  ) => Promise<RoleConfig | null>;
  patchConfigFields: (
    type: string,
    id: string,
    model: string,
    fields: Record<string, unknown>,
    priority: number,
    session: ClientSession,
    tenantId: string,
  ) => Promise<unknown>;
  commitModelPolicyRevision: (
    candidate: unknown,
    options: { expectedVersion: number; tenantId: string; actor: string; source: string },
    session: ClientSession,
  ) => Promise<{ version: number; noop: boolean }>;
  invalidateConfigCaches: (tenantId: string) => Promise<unknown>;
  startSession: () => Promise<ClientSession>;
  tenantId: string;
  baseAppConfig: BaseAppConfig;
}

const ROLE = 'role';
const ROLE_MODEL = 'Role';
const DEFAULT_PRIORITY: Record<string, number> = { __base__: 10, USER: 20, ADMIN: 20 };

function clone<T>(value: T): T {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function mergeEndpointList(
  current: Endpoint[] | null | undefined,
  endpointPatch: Endpoint,
): Endpoint[] {
  const list = Array.isArray(current) ? clone(current) : [];
  const index = list.findIndex((item: Endpoint) => item && item.name === endpointPatch.name);
  if (index < 0) return [...list, clone(endpointPatch)];
  const existing = list[index] || {};
  list[index] = {
    ...existing,
    ...clone(endpointPatch),
    models: endpointPatch.models
      ? { ...(existing.models || {}), ...clone(endpointPatch.models) }
      : existing.models,
    customParams: endpointPatch.customParams
      ? { ...(existing.customParams || {}), ...clone(endpointPatch.customParams) }
      : existing.customParams,
  };
  return list;
}

function rejectDuplicateEndpointNames(entries: Endpoint[] | undefined, label: string): void {
  if (!entries) return;
  const names = entries.map((ep) => ep?.name);
  if (
    names.some((name) => typeof name !== 'string' || !name) ||
    new Set(names).size !== names.length
  ) {
    invalidFundedEndpoint('Ambiguous or duplicate endpoint names in ' + label);
  }
}

function rejectNullEndpointContainers(config: RoleConfig | null, label: string): void {
  const overrides = config?.overrides;
  if (!overrides || !Object.prototype.hasOwnProperty.call(overrides, 'endpoints')) return;
  const endpoints = overrides.endpoints;
  if (endpoints == null || typeof endpoints !== 'object' || Array.isArray(endpoints)) {
    invalidFundedEndpoint('Invalid endpoint container in ' + label);
  }
  if (
    Object.prototype.hasOwnProperty.call(endpoints, 'custom') &&
    !Array.isArray(endpoints.custom)
  ) {
    invalidFundedEndpoint('Invalid custom endpoint container in ' + label);
  }
}

function validateNonRoleConfigs(configs: RoleConfig[], endpointName: string): void {
  for (const config of configs) {
    rejectNullEndpointContainers(config, 'user/group Config');
    const tombstones = config.tombstones;
    if (
      tombstones != null &&
      (!Array.isArray(tombstones) ||
        tombstones.some(
          (path) =>
            typeof path !== 'string' ||
            path === 'endpoints' ||
            path === 'endpoints.custom' ||
            path.startsWith('endpoints.custom.'),
        ))
    ) {
      invalidFundedEndpoint('User or group Config can suppress the managed endpoint');
    }
    const custom = config.overrides?.endpoints?.custom;
    if (custom != null) {
      if (!Array.isArray(custom)) {
        invalidFundedEndpoint('Invalid user or group endpoint overrides');
      }
      rejectDuplicateEndpointNames(custom, 'user/group Config');
      if (custom.some((ep) => ep.name === endpointName || ep.default === true)) {
        invalidFundedEndpoint('User or group Config can supersede the managed default');
      }
    }
  }
}

function reasoningProfileMap(endpoint: Endpoint | undefined): Record<string, unknown> {
  const value = endpoint?.customParams?.reasoningProfiles;
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

// Runtime Config resolution deep-merges nested reasoningProfiles across YAML
// and role documents. An empty projection map cannot remove older profiles.
// Null overlays neutralize stale capabilities while retaining unrelated params.
function reconcileAdminReasoningProfiles(
  existing: RoleConfigs,
  projection: RoleProjection,
  baseAppConfig: BaseAppConfig,
): void {
  const managedName = projection.roles.__base__?.endpoints?.custom?.[0]?.name;
  const adminPatch = projection.roles.ADMIN?.endpoints?.custom?.[0];
  if (!managedName || !adminPatch) return;
  const active = reasoningProfileMap(adminPatch);
  const cleared: Record<string, unknown> = Object.create(null);
  const sources = [
    ...(baseAppConfig.endpoints?.custom || []),
    ...(existing.__base__?.overrides?.endpoints?.custom || []),
    ...(existing.ADMIN?.overrides?.endpoints?.custom || []),
  ];
  for (const endpoint of sources) {
    if (endpoint?.name !== managedName) continue;
    for (const model of Object.keys(reasoningProfileMap(endpoint))) {
      if (!Object.prototype.hasOwnProperty.call(active, model)) {
        cleared[model] = null;
      }
    }
  }
  adminPatch.customParams = {
    ...adminPatch.customParams,
    reasoningProfiles: { ...cleared, ...active },
  };
}

function hasForbiddenModelParameter(endpoint: Endpoint): boolean {
  const extra = endpoint.addParams;
  if (extra != null && (typeof extra !== 'object' || Array.isArray(extra))) return true;
  if (extra && Object.prototype.hasOwnProperty.call(extra, 'model')) return true;
  const dropped = endpoint.dropParams;
  return Array.isArray(dropped) && dropped.includes('model');
}

function invalidFundedEndpoint(message: string): never {
  const error = new Error(message);
  throw Object.assign(error, { code: 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID', status: 422 });
}

function validateFundedEndpoint(
  existing: RoleConfigs,
  projection: RoleProjection,
  baseAppConfig: BaseAppConfig,
): void {
  const managedPatch = projection.roles.__base__?.endpoints?.custom?.[0];
  if (!managedPatch?.models?.default?.length) {
    invalidFundedEndpoint('Managed base projection has no default model');
  }
  const basePriority = existing.__base__?.priority ?? DEFAULT_PRIORITY.__base__;
  const userPriority = existing.USER?.priority ?? DEFAULT_PRIORITY.USER;
  const adminPriority = existing.ADMIN?.priority ?? DEFAULT_PRIORITY.ADMIN;
  // Runtime sorts Config documents by ascending priority. Both role
  // catalogues must override __base__, never be replaced by it.
  if (
    !Number.isSafeInteger(basePriority) ||
    !Number.isSafeInteger(userPriority) ||
    !Number.isSafeInteger(adminPriority) ||
    basePriority >= userPriority ||
    basePriority >= adminPriority
  ) {
    invalidFundedEndpoint('Managed role Config priority order is incompatible');
  }
  // Credentials are owned by the validated server/YAML base configuration.
  // The Config projection need not (and must not) duplicate the API key.
  const configured: Endpoint[] = Array.isArray(baseAppConfig?.endpoints?.custom)
    ? baseAppConfig.endpoints.custom
    : [];
  rejectDuplicateEndpointNames(configured, 'validated base configuration');
  const trusted = configured.filter((ep: Endpoint) => ep?.name === managedPatch.name);
  if (trusted.length !== 1) {
    invalidFundedEndpoint('Managed endpoint must exist in validated server configuration');
  }
  // The runtime deep-merges addParams. A role override with addParams: {}
  // cannot remove a model parameter inherited from YAML. Fail closed here.
  if (hasForbiddenModelParameter(trusted[0])) {
    invalidFundedEndpoint('Validated server endpoint can override the funded model');
  }

  // The resolver applies role tombstones before merging overrides. If a
  // tombstone deletes the funded endpoint, a matching model list alone is
  // insufficient evidence that USER chat can actually resolve that model.
  for (const id of ['__base__', 'USER', 'ADMIN']) {
    const tombstones = existing[id]?.tombstones;
    if (
      tombstones != null &&
      (!Array.isArray(tombstones) ||
        tombstones.some(
          (path: string) =>
            typeof path !== 'string' ||
            path === 'endpoints' ||
            path === 'endpoints.custom' ||
            path.startsWith('endpoints.custom.'),
        ))
    ) {
      invalidFundedEndpoint('Owned Config tombstone suppresses the managed endpoint');
    }
  }

  for (const id of ['__base__', 'USER', 'ADMIN']) {
    rejectNullEndpointContainers(existing[id], id);
  }

  const baseEntries = existing.__base__?.overrides?.endpoints?.custom;
  const userEntries = existing.USER?.overrides?.endpoints?.custom;
  for (const entries of [baseEntries, userEntries]) {
    if (
      entries != null &&
      (!Array.isArray(entries) ||
        entries.some(
          (ep: Endpoint) => !ep || typeof ep !== 'object' || typeof ep.name !== 'string',
        ))
    ) {
      invalidFundedEndpoint('Invalid role endpoint overrides');
    }
  }

  // Mixed Config fields can carry explicit nulls. The real Config resolver
  // treats these as replacements rather than the keyed merge helper's fallback.
  // Reject them before canonical CAS instead of certifying an unusable model.
  for (const [label, entries] of [
    ['__base__', baseEntries],
    ['USER', userEntries],
    ['ADMIN', existing.ADMIN?.overrides?.endpoints?.custom],
  ] as const) {
    const managed = entries?.filter((ep: Endpoint) => ep?.name === managedPatch.name) || [];
    if (
      managed.some(
        (ep: Endpoint) =>
          hasForbiddenModelParameter(ep) ||
          (Object.prototype.hasOwnProperty.call(ep, 'models') &&
            (ep.models === null || typeof ep.models !== 'object' || Array.isArray(ep.models))) ||
          (ep.models &&
            Object.prototype.hasOwnProperty.call(ep.models, 'default') &&
            !Array.isArray(ep.models.default)),
      )
    ) {
      invalidFundedEndpoint('Invalid explicit managed model override in ' + label);
    }
  }

  for (const [label, role] of [
    ['__base__', baseEntries],
    ['USER', userEntries],
    ['ADMIN', existing.ADMIN?.overrides?.endpoints?.custom],
  ] as const) {
    if (role != null && !Array.isArray(role)) {
      invalidFundedEndpoint('Invalid role endpoint array: ' + label);
    }
    rejectDuplicateEndpointNames(role || undefined, label);
  }

  // Use the same keyed merge precedence as the actual Config resolver:
  // validated YAML -> __base__ role -> V2 base patch -> USER role.
  const mergedBase = (baseEntries || []).reduce(
    (entries: Endpoint[], override: Endpoint) => mergeEndpointList(entries, override),
    configured,
  );
  const projectedBase = mergeEndpointList(mergedBase, managedPatch);
  const effective = (userEntries || []).reduce(
    (entries: Endpoint[], override: Endpoint) => mergeEndpointList(entries, override),
    projectedBase,
  );
  const defaults = effective.filter((ep: Endpoint) => ep?.default === true);
  if (defaults.length !== 1 || defaults[0].name !== managedPatch.name) {
    invalidFundedEndpoint('Managed USER default endpoint is ambiguous or overridden');
  }

  const selected = defaults[0];
  if (hasForbiddenModelParameter(selected)) {
    invalidFundedEndpoint('Managed USER endpoint parameters override the published model');
  }
  const requiredModel = managedPatch.models.default[0];
  if (
    !Array.isArray(selected.models?.default) ||
    selected.models.default.length !== 1 ||
    selected.models.default[0] !== requiredModel
  ) {
    invalidFundedEndpoint('USER override conflicts with published managed model');
  }

  const configuredEndpoint = trusted[0];
  const resolvedKey = extractEnvVariable(configuredEndpoint.apiKey || '');
  const resolvedURL = extractEnvVariable(configuredEndpoint.baseURL || '');
  if (
    typeof resolvedKey !== 'string' ||
    !resolvedKey.trim() ||
    resolvedKey === 'user_provided' ||
    resolvedKey.includes(String.fromCharCode(36, 123)) ||
    typeof resolvedURL !== 'string' ||
    !resolvedURL.trim() ||
    resolvedURL === 'user_provided' ||
    resolvedURL.includes(String.fromCharCode(36, 123)) ||
    selected.apiKey !== configuredEndpoint.apiKey ||
    selected.baseURL !== configuredEndpoint.baseURL
  ) {
    invalidFundedEndpoint('Managed endpoint requires unchanged server-owned credentials');
  }
  try {
    const url = new URL(resolvedURL);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
      invalidFundedEndpoint('Managed endpoint URL is invalid');
    }
  } catch (error) {
    if ((error as { code?: string } | null)?.code === 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID')
      throw error;
    invalidFundedEndpoint('Managed endpoint URL is invalid');
  }

  // Verify the actual ADMIN catalogue after applying its higher-priority
  // overrides and the proposed publication patch. It must keep the trusted
  // company credential destination and the published active model list.
  const adminPatch = projection.roles.ADMIN?.endpoints?.custom?.[0];
  const adminEntries = existing.ADMIN?.overrides?.endpoints?.custom;
  if (
    !adminPatch ||
    !Array.isArray(adminPatch.models?.default) ||
    (adminEntries != null && !Array.isArray(adminEntries))
  ) {
    invalidFundedEndpoint('Managed ADMIN endpoint projection is invalid');
  }
  if (
    Array.isArray(adminEntries) &&
    adminEntries.some(
      (ep: Endpoint) => !ep || typeof ep !== 'object' || typeof ep.name !== 'string',
    )
  ) {
    invalidFundedEndpoint('Managed ADMIN endpoint overrides are malformed');
  }
  const adminEffective = (adminEntries || []).reduce(
    (entries: Endpoint[], override: Endpoint) => mergeEndpointList(entries, override),
    projectedBase,
  );
  const adminProjected = mergeEndpointList(adminEffective, adminPatch);
  const adminSelected = adminProjected.filter((ep: Endpoint) => ep?.name === managedPatch.name);
  if (
    adminSelected.length !== 1 ||
    adminSelected[0].default !== true ||
    hasForbiddenModelParameter(adminSelected[0]) ||
    adminSelected[0].apiKey !== configuredEndpoint.apiKey ||
    adminSelected[0].baseURL !== configuredEndpoint.baseURL ||
    !Array.isArray(adminSelected[0].models?.default) ||
    JSON.stringify(adminSelected[0].models.default) !== JSON.stringify(adminPatch.models.default)
  ) {
    invalidFundedEndpoint('ADMIN catalogue would override trusted managed endpoint');
  }
}

export async function applyProjectionInSession(
  projection: RoleProjection,
  deps: ModelPolicyCommitDeps,
  session: ClientSession,
): Promise<ProjectionWrite[]> {
  const {
    findConfigByPrincipal,
    listActiveNonRoleConfigsForTenant,
    patchConfigFields,
    tenantId,
    baseAppConfig,
  } = deps;
  const ids = ['__base__', 'USER', 'ADMIN'];
  // Mongoose forbids concurrent operations sharing a transaction session.
  const existing: RoleConfigs = {};
  for (const id of ids) {
    existing[id] = await findConfigByPrincipal(
      ROLE,
      id,
      { includeInactive: true, tenantId },
      session,
    );
  }
  const nonRoleConfigs = await listActiveNonRoleConfigsForTenant(tenantId, session);
  validateNonRoleConfigs(
    nonRoleConfigs,
    projection.roles.__base__?.endpoints?.custom?.[0]?.name || '',
  );
  const writes = [];

  // Validate the *effective* USER endpoint before the transaction can
  // advance the canonical revision, not only the new base projection.
  reconcileAdminReasoningProfiles(existing, projection, baseAppConfig);
  validateFundedEndpoint(existing, projection, baseAppConfig);

  for (const id of ids) {
    const current = existing[id];
    // Do not advance the canonical policy when an owned effective Config is disabled.
    if (current?.isActive === false) {
      throw Object.assign(new Error('Managed-model projection is inactive'), {
        code: 'MODEL_POLICY_INACTIVE_PROJECTION',
        status: 409,
      });
    }
    const fields: Record<string, unknown> = {};
    const rolePatch = projection.roles[id];

    if (
      rolePatch.interface &&
      current?.overrides?.interface?.modelSelect !== rolePatch.interface.modelSelect
    ) {
      fields['interface.modelSelect'] = rolePatch.interface.modelSelect;
    }

    const endpointPatch = rolePatch.endpoints?.custom?.[0];
    if (endpointPatch) {
      const next = mergeEndpointList(current?.overrides?.endpoints?.custom, endpointPatch);
      if (!same(current?.overrides?.endpoints?.custom || [], next)) {
        fields['endpoints.custom'] = next;
      }
    }

    if (Object.keys(fields).length === 0) continue;
    await patchConfigFields(
      ROLE,
      id,
      ROLE_MODEL,
      fields,
      current?.priority ?? DEFAULT_PRIORITY[id],
      session,
      tenantId,
    );
    writes.push({ principalId: id, fields: Object.keys(fields) });
  }

  return writes;
}

export async function commitManagedModelPolicy(
  input: unknown,
  deps: ModelPolicyCommitDeps,
): Promise<ModelPolicyCommitResult> {
  const {
    findConfigByPrincipal,
    listActiveNonRoleConfigsForTenant,
    patchConfigFields,
    commitModelPolicyRevision,
    invalidateConfigCaches,
    startSession,
    tenantId,
  } = deps || {};

  if (
    typeof findConfigByPrincipal !== 'function' ||
    typeof listActiveNonRoleConfigsForTenant !== 'function' ||
    typeof patchConfigFields !== 'function' ||
    typeof commitModelPolicyRevision !== 'function' ||
    typeof invalidateConfigCaches !== 'function' ||
    typeof startSession !== 'function'
  ) {
    throw new TypeError('model-policy commit dependencies are required');
  }

  // The bearer token is an instance-level service identity. It must be bound
  // to one explicitly configured tenant, never to the caller's request body.
  if (typeof tenantId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(tenantId)) {
    throw Object.assign(new Error('Model policy tenant is not configured'), {
      code: 'MODEL_POLICY_TENANT_REQUIRED',
      status: 503,
    });
  }
  const plan = buildModelPolicyCommitPlan(input);
  const session = await startSession();
  let result: ModelPolicyCommitResult | undefined;

  try {
    await session.withTransaction(async () => {
      const canonical = await commitModelPolicyRevision(
        plan.candidate,
        {
          expectedVersion: plan.expectedVersion,
          tenantId,
          actor: plan.actor,
          source: plan.source,
        },
        session,
      );

      const writes = await applyProjectionInSession(plan.projection, deps, session);
      let transition: ModelPolicyCommitResult['transition'] = 'advance';
      if (canonical.noop) {
        transition = 'noop';
      } else if (plan.expectedVersion === 0) {
        transition = 'create';
      }

      result = {
        policyVersion: canonical.version,
        transition,
        policyNoop: canonical.noop,
        refreshConfigCaches: plan.refreshConfigCaches,
        writes,
        noop: canonical.noop && writes.length === 0,
      };
    });
  } finally {
    await session.endSession();
  }

  if (!result) throw new Error('Model policy transaction completed without a result');
  if (result.writes.length > 0 || result.refreshConfigCaches === true)
    await invalidateConfigCaches(tenantId);
  return result;
}

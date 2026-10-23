/**
 * W10 — the STORAGE SEAM: a fail-closed port for device-policy persistence.
 *
 * `docs/GM-RULING-ABSOLUTE-ADMIN-POLICY-AND-AUDIT-SEAM-20261023.md` §5: the W10 builder's
 * persistence functions (`listScopes`, `getToolScope`, `upsertToolScope`, …) are OWED by the data
 * layer (W10b / the rebase) and do not exist in this branch yet. The admin API route
 * (`api/server/routes/admin/devicePolicy.js`) asks `~/models` for them; whatever it cannot find is
 * not left `undefined` (an accidental 500 at dispatch time) and is not silently stubbed (an
 * unauditable write path). It is bound to a NAMED port that refuses with a typed wiring error.
 *
 * Both seaming failures use the same HTTP semantics for the same reason:
 *
 *   audit seam    (GM-81) .......... 503 SERVICE UNAVAILABLE, and the write changes nothing
 *   storage seam  (this module) .... 503 SERVICE UNAVAILABLE, and the write changes nothing
 *
 * Fail-open is never an answer for policy data. Until the persistence layer lands, every write
 * throws before touching anything, and every read throws instead of returning an incomplete
 * answer. Reads that refuse are honest: a policy API that answers from a partial store is worse
 * than one that refuses.
 *
 * THE REBASE WIRING (planned, W10b): add the persistence functions to the data layer, and the
 * route's `resolveDevicePolicyStorage(db)` starts returning the real functions instead of refused
 * ports. No handler changes; no test changes.
 */

import { logger } from '@librechat/data-schemas';

/**
 * The names the route expects on the data layer. Assignments are their own records here
 * (GM-PLAN §2: separate records, not edits to role/group/user documents), and the tenant default
 * is a single document per tenant.
 */
export type DevicePolicyStorageMethod =
  | 'listScopes'
  | 'countScopes'
  | 'getToolScope'
  | 'upsertToolScope'
  | 'deleteToolScope'
  | 'listAssignments'
  | 'getAssignment'
  | 'upsertAssignment'
  | 'deleteAssignment'
  | 'getTenantDefault'
  | 'upsertTenantDefault'
  | 'getRoleByName'
  | 'findGroupById'
  | 'findUser'
  | 'getUserPrincipals';

/** The same list as data, so the port can be iterated and a future method cannot be forgotten. */
export const DEVICE_POLICY_STORAGE_METHODS: readonly DevicePolicyStorageMethod[] = Object.freeze([
  'listScopes',
  'countScopes',
  'getToolScope',
  'upsertToolScope',
  'deleteToolScope',
  'listAssignments',
  'getAssignment',
  'upsertAssignment',
  'deleteAssignment',
  'getTenantDefault',
  'upsertTenantDefault',
  'getRoleByName',
  'findGroupById',
  'findUser',
  'getUserPrincipals',
]);

/**
 * A data-layer function that is absent in this build. Thrown when CALLED, not when bound, so the
 * route file always loads and the failure is named at the exact operation that needs it.
 */
export class DevicePolicyStorageUnavailableError extends Error {
  code = 'DEVICE_POLICY_STORAGE_UNAVAILABLE';
  /** Which storage operation was attempted. */
  method: string;

  constructor(method: string) {
    super(
      `Device-policy storage is not wired in this build: the data layer exposes no ${method}. ` +
        'The request was refused rather than answered from a partial store (W10 storage seam).',
    );
    this.name = 'DevicePolicyStorageUnavailableError';
    this.method = method;
  }
}

/** One bound data-layer operation: argument and result shapes are the data layer's own. */
export type DevicePolicyStorageFunction = (...args: any[]) => Promise<any>;

/** The bound port: one function per method, present or refusing. */
export type DevicePolicyStoragePort = Record<DevicePolicyStorageMethod, DevicePolicyStorageFunction>;

/**
 * Binds the storage port. Every present function is passed through; every absent one becomes a
 * named refusal. Pure: safe to call in a spec without a database.
 *
 * @param db the data layer (`~/models` on the server); may omit any or all of the methods
 */
export function resolveDevicePolicyStorage(
  db: Record<string, unknown> | null | undefined,
): DevicePolicyStoragePort {
  const source = db ?? {};
  const bound = {} as Record<string, unknown>;
  for (const method of DEVICE_POLICY_STORAGE_METHODS) {
    const candidate = source[method];
    if (typeof candidate === 'function') {
      bound[method] = candidate;
      continue;
    }
    const refused = (..._args: unknown[]): Promise<never> => {
      logger.warn(`[adminDevicePolicy] storage refused: no ${method} in this build`);
      return Promise.reject(new DevicePolicyStorageUnavailableError(method));
    };
    bound[method] = refused;
  }
  return bound as DevicePolicyStoragePort;
}

/** True when an error is a storage-seam refusal rather than a domain or database failure. */
export function isStorageUnavailableError(error: unknown): error is DevicePolicyStorageUnavailableError {
  return error instanceof DevicePolicyStorageUnavailableError;
}

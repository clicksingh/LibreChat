/**
 * W10 — GM-79 ESCALATION GUARDS (rule 3): no request field, token claim or device claim can raise
 * a resolved policy.
 *
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §6.3: "The policy resolution is
 * server-side; there is no request field, token claim or device claim that can raise it."
 *
 * The deep guarantee is architectural: `resolveDevicePolicy()` takes NO request, session, token or
 * device value — its inputs are a server-resolved identity and server-loaded documents. There is
 * therefore no parameter through which a caller could widen the answer. This module makes that
 * property checkable rather than merely asserted:
 *
 *   1. REQUEST. `stripRequestWideningFields` removes every key that would widen a policy if a
 *      handler honoured it. It runs in two modes, because the two families of route legitimately
 *      carry different fields:
 *        - `read`  (GET /resolve, GET /effective): none of the guarded spellings is part of any
 *          read shape, so all of them are stripped. A client sending `tools`, `grant` or
 *          `capabilities` to a read route gets nothing for it.
 *        - `write` (scope/assignment/tenant-default writes): the body shape's OWN fields are kept
 *          (`tools` and `stage` are how an admin edits a scope — they are the policy, not a
 *          privilege claim), and every PRIVILEGE field is stripped and reported. The write shapes
 *          are separately validated against `devicePolicy.ts` in data-schemas, which honours no
 *          field outside the documented shape.
 *   2. TOKEN. Self-asserted principal fields (`role`, `groups`, `tenantId`, `toolScopeId`,
 *      `capabilities`) are never read from a claim body: the resolver's identity is built from the
 *      DATABASE (the user document's role, its group memberships, its tenant). A forged claim
 *      naming a privileged role changes nothing.
 *   3. DEVICE. Device-supplied policy hints (`enabled`, `deviceFloor`, `policyVersion`, `ceiling`)
 *      have no parameter into the RESOLUTION path at all. A device asserts its floor only to the
 *      DISPATCH path, where it can narrow and never widen; and because `policyVersion` is
 *      content-derived, a device re-fetching an old policy receives the current one and can detect
 *      that it did.
 *
 * A widening attempt is LOGGED and then DISCARDED. Field NAMES and the actor are logged; values
 * never are, because the value of a widening attempt is itself an attacker-chosen privilege claim
 * and has no business in a log. Discarding rather than erroring is deliberate on the read paths:
 * the guard must not become an oracle that tells a caller which spelling came closest.
 */

import { logger } from '@librechat/data-schemas';

/** The family of route a strip is running for. */
export type GuardMode = 'read' | 'write';

/**
 * Request-body keys that must never be honoured as authority on the device-policy READ routes.
 * None of these is part of any read shape.
 */
export const REQUEST_WIDENING_FIELDS: ReadonlySet<string> = new Set([
  'tools',
  'granted',
  'grant',
  'capabilities',
  'capability',
  'permissions',
  'scope',
  'toolScope',
  'toolScopeId',
  'devicePolicy',
  'policy',
  'policyVersion',
  'version',
  'enabled',
  'enabledTools',
  'admin',
  'isAdmin',
  'role',
  'roles',
  'groups',
  'groupIds',
  'tenantId',
  'deviceId',
  'ceiling',
  'stage',
  'pilot',
]);

/**
 * PRIVILEGE keys: never part of ANY device-policy shape, read or write. These are the escalation
 * spellings — a caller asserting capabilities, a grant, an admin flag, or a different identity.
 *
 * `tools` and `stage` are absent on purpose: they are legitimate members of the SCOPE write shape
 * (they ARE the policy an admin edits). Stripping them on a write would make the write shapes
 * impossible; the write shapes are closed and validated, so they cannot carry authority beyond the
 * documented fields, and a read route still strips them (see `REQUEST_WIDENING_FIELDS`).
 */
export const PRIVILEGE_FIELDS: ReadonlySet<string> = new Set([
  'granted',
  'grant',
  'grants',
  'capabilities',
  'capability',
  'permissions',
  'scope',
  'toolScope',
  'toolScopeId',
  'devicePolicy',
  'policy',
  'policyVersion',
  'enabled',
  'enabledTools',
  'admin',
  'isAdmin',
  'role',
  'roles',
  'groups',
  'groupIds',
  'deviceId',
  'ceiling',
  'pilot',
  'allow',
]);

/** Explicit allow-lists: the only fields each write shape may honour. Used to REPORT extras. */
export const SCOPE_WRITE_FIELDS: ReadonlySet<string> = new Set([
  'id',
  'name',
  'description',
  'tools',
  'stage',
  'isActive',
]);

export const ASSIGNMENT_WRITE_FIELDS: ReadonlySet<string> = new Set([
  'principalType',
  'principalId',
  'toolScopeId',
  'priority',
  'isActive',
]);

export const TENANT_DEFAULT_WRITE_FIELDS: ReadonlySet<string> = new Set(['defaultToolScopeId']);

/** The allow-list for a write shape, so the guard knows what is legitimate for that body. */
export const WRITE_SHAPE_FIELDS: Readonly<Record<string, ReadonlySet<string>>> = Object.freeze({
  scope: SCOPE_WRITE_FIELDS,
  assignment: ASSIGNMENT_WRITE_FIELDS,
  'tenant-default': TENANT_DEFAULT_WRITE_FIELDS,
});

/**
 * Self-asserted identity fields a bearer/JWT claim body might carry. The resolver builds its
 * principal from server-looked-up membership rows, never from these.
 */
export const TOKEN_CLAIM_FIELDS: ReadonlySet<string> = new Set([
  'role',
  'roles',
  'groups',
  'groupIds',
  'tenantId',
  'toolScopeId',
  'toolScope',
  'capabilities',
  'permissions',
  'admin',
  'isAdmin',
]);

/**
 * Device-supplied policy hints. The RESOLUTION path has no device parameter; these are documented
 * here so the serve-current test asserts every one of them is without effect on the returned
 * policy.
 */
export const DEVICE_CLAIM_FIELDS: ReadonlySet<string> = new Set([
  'tools',
  'enabled',
  'deviceFloor',
  'policy',
  'policyVersion',
  'toolScope',
  'toolScopeId',
  'ceiling',
  'stage',
  'pilot',
  'allow',
  'grants',
]);

/** The fields a widening attempt probed, for tests and logs. */
export type WideningAttempt = {
  field: string;
  source: 'body' | 'query' | 'token' | 'device';
  /** `stripped` = removed and ignored; `rejected` = refused by the shape's allow-list. */
  disposition: 'stripped' | 'rejected';
};

export type StripResult<T> = {
  body: T;
  attempts: WideningAttempt[];
};

/**
 * Strips widening fields from a body in place and reports what was probed.
 *
 * `mode: 'read'` strips every guarded spelling. `mode: 'write'` strips every PRIVILEGE field, keeps
 * the shape's own `keep` fields, and reports any key that is neither — so an unrecognised field on
 * a write is visible rather than silently accepted.
 *
 * The same object is returned for handler convenience. Field names and the actor are logged; values
 * are not.
 */
export function stripRequestWideningFields<T extends Record<string, unknown>>(
  body: T,
  options?: {
    mode?: GuardMode;
    source?: 'body' | 'query' | 'token' | 'device';
    actor?: string;
    /** The write shape whose allow-list applies (`scope` | `assignment` | `tenant-default`). */
    keep?: ReadonlySet<string>;
  },
): StripResult<T> {
  const mode = options?.mode ?? 'read';
  const source = options?.source ?? 'body';
  const attempts: WideningAttempt[] = [];

  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { body, attempts };
  }

  const record = body as Record<string, unknown>;

  if (mode === 'read') {
    for (const field of REQUEST_WIDENING_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(record, field)) {
        attempts.push({ field, source, disposition: 'stripped' });
        delete record[field];
      }
    }
  } else {
    const keep = options?.keep;
    for (const field of Object.keys(record)) {
      if (keep !== undefined && keep.has(field)) {
        continue;
      }
      if (PRIVILEGE_FIELDS.has(field)) {
        attempts.push({ field, source, disposition: 'stripped' });
        delete record[field];
        continue;
      }
      if (keep !== undefined) {
        // Neither a shape field nor a known privilege spelling: not honoured, and not silent.
        attempts.push({ field, source, disposition: 'rejected' });
      }
    }
  }

  if (attempts.length > 0) {
    logger.warn(
      `[devicePolicy] widening attempt ignored (${options?.actor ?? 'unknown actor'}): ` +
        attempts.map((attempt) => `${attempt.source}:${attempt.field}`).join(', '),
    );
  }

  return { body, attempts };
}

/** Every guarded spelling, so a spec iterating a list covers a future addition without an edit. */
export function requestWideningFieldNames(): string[] {
  return [...REQUEST_WIDENING_FIELDS].sort();
}

export function privilegeFieldNames(): string[] {
  return [...PRIVILEGE_FIELDS].sort();
}

export function tokenClaimFieldNames(): string[] {
  return [...TOKEN_CLAIM_FIELDS].sort();
}

export function deviceClaimFieldNames(): string[] {
  return [...DEVICE_CLAIM_FIELDS].sort();
}
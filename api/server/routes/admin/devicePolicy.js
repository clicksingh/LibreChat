/**
 * W10 — admin device-policy API surface (GM-76, GM-79, GM-81).
 *
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3 and §6,
 * `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §2/§3 (W10).
 *
 * Mirrors `admin/roles.js` and `admin/quotaPolicy.js` exactly: the same authentication pair
 * (`requireJwtAuth` then the capability gate from `~/server/middleware/roles/capabilities`), the
 * same `~/models` data layer, and the handlers from `@librechat/api`.
 *
 * WHAT THIS BOUNDARY OWNS, AND WHY IT IS HERE
 *   1. The capability gates. GM-79 rule 1 requires the EXISTING admin authorisation pattern, not a
 *      bespoke check, and there is no device-policy capability in `SystemCapabilities` — so the
 *      surface uses the capabilities that already describe policy data: `access:admin` for the
 *      router, `read:configs` for reads and `manage:configs` for writes. `MANAGE_CONFIGS` implies
 *      `READ_CONFIGS` through `CapabilityImplications`, so a managing admin can always read.
 *   2. The enforcement primitives, taken from the REAL modules — `deviceCapabilityPolicy.js` (the
 *      tier-1 ceiling, the stage ladder, the hard denies, the approval gate) and
 *      `deviceToolRegistry.js` (the intersection law and the dispatch gate). They are handed to
 *      `@librechat/api` as a port here, so the package never imports `api/server/**` and there is
 *      exactly one implementation of the law.
 *   3. The storage port, bound fail-closed: `resolveDevicePolicyStorage(db)` names every persistence
 *      function the data layer does not yet expose (W10b / the rebase owes them), and a named
 *      refusal is a 503 rather than an accidental 500 or a partial answer.
 *
 * ONE ROUTER, TWO AUDIENCES
 * `GET /resolve-self` is the ONLY route a non-admin may call — GM-76 gives every employee the right
 * to SEE their own effective set, read-only. It is registered BEFORE the `router.use` admin gate, so
 * the admin gate applies to the admin surface and the self route carries only `requireJwtAuth`. That
 * ordering is load-bearing in Express (middleware applies to routes registered after it), so it is
 * stated here rather than left to be inferred, and it is tested both ways: a non-admin gets 200 from
 * `/resolve-self` and 403 from every other route.
 *
 * THE STAGE IS SERVER-OWNED
 * `serverStage` is read from the environment, never from a request — the read guard strips `stage`,
 * `pilot` and `ceiling` from every query, so a caller cannot sharpen the ladder. The default is the
 * NARROWEST stage (`A`): a wrong default must never be the wide one, and a scope may only narrow it.
 *
 * MOUNTING IS OWED (out of this change's write scope): `api/server/routes/index.js` and
 * `api/server/index.js` are hot files with live branches in them, so the router is not mounted here.
 * The spec mounts it inside its own Express app instead.
 */

const express = require('express');
const { createAdminDevicePolicyHandlers, resolveDevicePolicyStorage } = require('@librechat/api');
const { SystemCapabilities } = require('@librechat/data-schemas');
const { requireCapability } = require('~/server/middleware/roles/capabilities');
const { requireJwtAuth } = require('~/server/middleware');
const deviceCapabilityPolicy = require('~/server/services/Device/deviceCapabilityPolicy');
const deviceToolRegistry = require('~/server/services/Device/deviceToolRegistry');
const db = require('~/models');

const router = express.Router();

const requireAdminAccess = requireCapability(SystemCapabilities.ACCESS_ADMIN);
const requireReadPolicy = requireCapability(SystemCapabilities.READ_CONFIGS);
const requireManagePolicy = requireCapability(SystemCapabilities.MANAGE_CONFIGS);

/**
 * The stage the SERVER is currently at. Advanced by an operator, never by a request; the narrowest
 * stage is the default and every scope may only narrow it further (`stricterStage` in the resolver).
 */
const DEFAULT_SERVER_STAGE = 'A';

function resolveServerStage() {
  const configured = process.env.CBHR_DEVICE_CAPABILITY_STAGE;
  if (configured === undefined || configured === '') {
    return DEFAULT_SERVER_STAGE;
  }
  if (deviceCapabilityPolicy.CAPABILITY_STAGES.includes(configured)) {
    return configured;
  }
  // An unrecognised stage is a configuration fault, not licence to widen: keep the narrow default.
  console.warn(
    `[adminDevicePolicy] ignoring unknown CBHR_DEVICE_CAPABILITY_STAGE="${configured}"; ` +
      `using "${DEFAULT_SERVER_STAGE}"`,
  );
  return DEFAULT_SERVER_STAGE;
}

/** The pilot deny-list overlay (tier-1 law). On unless an operator turns it off explicitly. */
function resolvePilot() {
  return process.env.CBHR_DEVICE_PILOT !== 'false';
}

/**
 * THE PRIMITIVES PORT. Declared as a function so a caller can see exactly which two modules the
 * enforcement path reuses, and so a test can supply its own port without touching the route.
 *
 * `stageRank` now comes from `deviceCapabilityPolicy.STAGE_RANK` — the authoritative map. It used to
 * be DERIVED here from the order of `CAPABILITY_STAGES`, because the policy module exported the ladder
 * but not its rank. That inference happened to agree, but it was an assumption about a module's
 * internals rather than the source of truth, and its absence once made stage narrowing silently do
 * nothing, which would have let a scope declaring stage A enable stage B/C tools it named. The map is
 * exported now, so the assumption is gone.
 */
const STAGE_RANK = deviceCapabilityPolicy.STAGE_RANK;

function requireDevicePolicyPrimitives() {
  return {
    capabilityPolicy: {
      capabilityStages: deviceCapabilityPolicy.CAPABILITY_STAGES,
      stageRank: STAGE_RANK,
      catalogToolNames: deviceCapabilityPolicy.TOOL_CATALOG.map((tool) => tool.name),
      getToolDefinition: (name) => deviceCapabilityPolicy.getToolDefinition(name),
      capabilityCeiling: (stage) => deviceCapabilityPolicy.ceilingForStage(stage),
    },
    toolRegistry: {
      effectiveTools: (params) => deviceToolRegistry.effectiveTools(params),
      authorizeDispatch: (toolName, params) => deviceToolRegistry.authorizeDispatch(toolName, params),
      assertDispatchAllowed: (toolName, params) =>
        deviceToolRegistry.assertDispatchAllowed(toolName, params),
    },
  };
}

const handlers = createAdminDevicePolicyHandlers({
  // The persistence port, bound fail-closed: every function `~/models` exposes is passed through,
  // and every one it does not yet expose (W10b / the rebase owes them) becomes a named refusal
  // rather than an accidental 500 or a partial answer. Identity lookups (`getRoleByName`,
  // `findGroupById`, `findUser`, `getUserPrincipals`) come through the same port.
  ...resolveDevicePolicyStorage(db),
  // The audit recorder is INJECTED and absent in this branch (GM-81): the write routes below then
  // refuse with 503 rather than change policy without a durable audit record. The rebase maps
  // `db.recordAuditEntry` here in one line.
  recordAuditEntry: db.recordAuditEntry,
  primitives: requireDevicePolicyPrimitives(),
  serverStage: resolveServerStage(),
  pilot: resolvePilot(),
});

/**
 * The self-service read: any AUTHENTICATED user, their own effective set, read-only. Registered
 * before the admin gate on purpose (see the header).
 */
router.get('/resolve-self', requireJwtAuth, handlers.resolveSelf);

// Everything below is admin-only: the existing admin authorisation pattern, applied once.
router.use(requireJwtAuth, requireAdminAccess);

// ── tool scopes ───────────────────────────────────────────────────────────────────────────────
router.get('/scopes', requireReadPolicy, handlers.listScopes);
router.post('/scopes', requireManagePolicy, handlers.createScope);
router.get('/scopes/:scopeId', requireReadPolicy, handlers.getScope);
router.put('/scopes/:scopeId', requireManagePolicy, handlers.updateScope);
router.delete('/scopes/:scopeId', requireManagePolicy, handlers.deleteScope);

// ── assignments ───────────────────────────────────────────────────────────────────────────────
router.get('/assignments', requireReadPolicy, handlers.listAssignments);
router.put('/assignments', requireManagePolicy, handlers.setAssignment);
router.delete('/assignments/:principalType/:principalId', requireManagePolicy, handlers.removeAssignment);

// ── tenant default ────────────────────────────────────────────────────────────────────────────
router.get('/tenant-default', requireReadPolicy, handlers.getTenantDefault);
router.put('/tenant-default', requireManagePolicy, handlers.setTenantDefault);

// ── resolution (inspection) ───────────────────────────────────────────────────────────────────
// Express 5 dropped the `:param?` optional-segment suffix, so the two spellings share one handler
// rather than relying on a syntax that no longer behaves the same way (see admin/quotaPolicy.js).
router.get('/resolve-for-principal', requireReadPolicy, handlers.resolveForPrincipal);
router.get('/resolve-for-principal/:userId', requireReadPolicy, handlers.resolveForPrincipal);

module.exports = router;
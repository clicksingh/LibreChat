/**
 * 8S3C.2 — RUN_CODE.USE authority-ceiling regression tests (Blocker 1).
 *
 * These tests pin the effective authorization resolution for the document
 * workstation to canonical checkAccess semantics:
 *
 *     effectiveCodeEnvAvailable = globalCodeCapability && userRunCodeAllowed
 *
 * RUN_CODE.USE is the authority ceiling — a client-forged
 * `ephemeralAgent.execute_code` / `document_visual_qa` flag is NEVER treated
 * as authorization, and a user whose role lacks RUN_CODE.USE cannot obtain a
 * code environment no matter what the global `endpoints.agents.capabilities`
 * set contains. The helper is exercised against the REAL
 * `checkAccessWithRequestCache` from `@librechat/api` (only `~/models`
 * role lookup is mocked), so these tests verify the actual canonical access
 * path, not a local re-implementation.
 */
const { PermissionTypes, Permissions } = require('librechat-data-provider');

const mockGetRoleByName = jest.fn();
jest.mock('~/models', () => ({
  getRoleByName: (...args) => mockGetRoleByName(...args),
}));

const { isRunCodeUseAllowed, resolveEffectiveCodeEnv } = require('../authorization');

function runCodeAllowedRole() {
  return { permissions: { [PermissionTypes.RUN_CODE]: { [Permissions.USE]: true } } };
}

function runCodeDeniedRole() {
  return { permissions: {} };
}

function makeReq(user = { id: 'user_1', role: 'USER' }) {
  return { user };
}

describe('authorization.js — RUN_CODE.USE ceiling (8S3C.2)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('isRunCodeUseAllowed', () => {
    it('returns true for a user whose role grants RUN_CODE.USE', async () => {
      mockGetRoleByName.mockResolvedValue(runCodeAllowedRole());
      await expect(isRunCodeUseAllowed(makeReq())).resolves.toBe(true);
    });

    it('returns false for a user whose role LACKS RUN_CODE.USE', async () => {
      mockGetRoleByName.mockResolvedValue(runCodeDeniedRole());
      await expect(isRunCodeUseAllowed(makeReq())).resolves.toBe(false);
    });

    it('returns false (fail-closed) when the user has no role', async () => {
      await expect(isRunCodeUseAllowed(makeReq({ id: 'user_1' }))).resolves.toBe(false);
      expect(mockGetRoleByName).not.toHaveBeenCalled();
    });

    it('returns false (fail-closed) when there is no user', async () => {
      await expect(isRunCodeUseAllowed({})).resolves.toBe(false);
      expect(mockGetRoleByName).not.toHaveBeenCalled();
    });

    it('resolves once per request via the canonical request cache', async () => {
      mockGetRoleByName.mockResolvedValue(runCodeAllowedRole());
      const req = makeReq();
      await isRunCodeUseAllowed(req);
      await isRunCodeUseAllowed(req);
      await isRunCodeUseAllowed(req);
      // Three call sites, one role lookup — satisfies the "one request-scoped
      // effective authorization resolution" requirement.
      expect(mockGetRoleByName).toHaveBeenCalledTimes(1);
    });
  });

  describe('resolveEffectiveCodeEnv', () => {
    it('global capability ON + allowed user → true', async () => {
      mockGetRoleByName.mockResolvedValue(runCodeAllowedRole());
      await expect(resolveEffectiveCodeEnv(makeReq(), true)).resolves.toBe(true);
    });

    it('global capability ON + denied user → false (user permission is the ceiling)', async () => {
      mockGetRoleByName.mockResolvedValue(runCodeDeniedRole());
      await expect(resolveEffectiveCodeEnv(makeReq(), true)).resolves.toBe(false);
    });

    it('global capability OFF + allowed user → false (capability AND)', async () => {
      mockGetRoleByName.mockResolvedValue(runCodeAllowedRole());
      await expect(resolveEffectiveCodeEnv(makeReq(), false)).resolves.toBe(false);
    });

    it('global capability OFF + denied user → false', async () => {
      mockGetRoleByName.mockResolvedValue(runCodeDeniedRole());
      await expect(resolveEffectiveCodeEnv(makeReq(), false)).resolves.toBe(false);
    });

    it('never consults the role resolver when the global capability is off', async () => {
      mockGetRoleByName.mockResolvedValue(runCodeDeniedRole());
      await resolveEffectiveCodeEnv(makeReq(), false);
      expect(mockGetRoleByName).not.toHaveBeenCalled();
    });
  });
});

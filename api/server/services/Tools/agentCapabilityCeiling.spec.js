const { Tools, Permissions, PermissionTypes } = require('librechat-data-provider');

const mockCheckAccessWithRequestCache = jest.fn();
jest.mock('@librechat/api', () => ({
  checkAccessWithRequestCache: (...args) => mockCheckAccessWithRequestCache(...args),
}));

const mockGetRoleByName = jest.fn();
jest.mock('~/models', () => ({
  getRoleByName: (...args) => mockGetRoleByName(...args),
}));

const { assertToolCapabilityCeiling, RUN_CODE_GATED_TOOLS } = require('./agentCapabilityCeiling');

describe('assertToolCapabilityCeiling (8S5 capability-ceiling defense-in-depth)', () => {
  const req = { user: { id: 'user_1', role: 'USER' } };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('exposes exactly execute_code and bash_tool as RUN_CODE-gated', () => {
    expect([...RUN_CODE_GATED_TOOLS].sort()).toEqual(['bash_tool', 'execute_code'].sort());
  });

  it('is a no-op when tools is not an array', async () => {
    await expect(assertToolCapabilityCeiling(undefined, req)).resolves.toBeUndefined();
    await expect(assertToolCapabilityCeiling(null, req)).resolves.toBeUndefined();
    expect(mockCheckAccessWithRequestCache).not.toHaveBeenCalled();
  });

  it('is a no-op when tools is empty', async () => {
    await expect(assertToolCapabilityCeiling([], req)).resolves.toBeUndefined();
    expect(mockCheckAccessWithRequestCache).not.toHaveBeenCalled();
  });

  it('is a no-op when tools contains no RUN_CODE-gated entry (never checks access)', async () => {
    await expect(
      assertToolCapabilityCeiling(['web_search', 'file_search', Tools.agent_management], req),
    ).resolves.toBeUndefined();
    expect(mockCheckAccessWithRequestCache).not.toHaveBeenCalled();
  });

  it('passes for execute_code when the user has RUN_CODE.USE', async () => {
    mockCheckAccessWithRequestCache.mockResolvedValue(true);
    await expect(
      assertToolCapabilityCeiling(['web_search', Tools.execute_code], req),
    ).resolves.toBeUndefined();
    expect(mockCheckAccessWithRequestCache).toHaveBeenCalledWith(
      expect.objectContaining({
        req,
        user: req.user,
        permissionType: PermissionTypes.RUN_CODE,
        permissions: [Permissions.USE],
      }),
    );
  });

  it('passes for bash_tool when the user has RUN_CODE.USE', async () => {
    mockCheckAccessWithRequestCache.mockResolvedValue(true);
    await expect(assertToolCapabilityCeiling([Tools.bash_tool], req)).resolves.toBeUndefined();
  });

  it('throws AGENT_CAPABILITY_NOT_ALLOWED (403) for execute_code when the user lacks RUN_CODE.USE', async () => {
    mockCheckAccessWithRequestCache.mockResolvedValue(false);
    await expect(assertToolCapabilityCeiling([Tools.execute_code], req)).rejects.toMatchObject({
      code: 'AGENT_CAPABILITY_NOT_ALLOWED',
      status: 403,
    });
  });

  it('throws AGENT_CAPABILITY_NOT_ALLOWED (403) for bash_tool when the user lacks RUN_CODE.USE', async () => {
    mockCheckAccessWithRequestCache.mockResolvedValue(false);
    await expect(assertToolCapabilityCeiling([Tools.bash_tool], req)).rejects.toMatchObject({
      code: 'AGENT_CAPABILITY_NOT_ALLOWED',
      status: 403,
    });
  });

  it('rejects a mixed tool list containing even one RUN_CODE-gated tool when denied', async () => {
    mockCheckAccessWithRequestCache.mockResolvedValue(false);
    await expect(
      assertToolCapabilityCeiling(['web_search', Tools.execute_code, 'file_search'], req),
    ).rejects.toMatchObject({ code: 'AGENT_CAPABILITY_NOT_ALLOWED' });
  });
});

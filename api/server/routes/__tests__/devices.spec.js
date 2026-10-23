const express = require('express');
const request = require('supertest');

const mockRetireHandler = jest.fn((req, res) =>
  res.status(200).json({
    ok: true,
    authenticated: req.authenticatedByJwt === true,
    userId: req.user?.id ?? null,
  }),
);
const mockRequireJwtAuth = jest.fn((req, _res, next) => {
  req.authenticatedByJwt = true;
  req.user = { id: 'route-user', tenantId: 'tenant-route' };
  req.authStrategy = 'jwt';
  next();
});

// Track handler creation calls
let handlerCreationCalls = [];
const mockCreateHandler = jest.fn((deps) => {
  handlerCreationCalls.push(deps);
  return mockRetireHandler;
});

jest.mock('@librechat/data-schemas', () => ({
  getTenantId: jest.fn(() => 'tenant-route'),
}));

jest.mock('~/server/middleware/requireJwtAuth', () => (req, res, next) =>
  mockRequireJwtAuth(req, res, next),
);

jest.mock('~/db/models', () => ({
  DeviceAuthority: {},
  AuditEvent: {},
}));

// Mock must return the handler factory inline
jest.mock('~/server/services/Device/ownerCurrentRetireHandler', () => ({
  createOwnerCurrentRetireHandler: jest.fn((deps) => {
    handlerCreationCalls.push(deps);
    return mockRetireHandler;
  }),
}));

const devicesRouter = require('../devices');

function createApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/devices', devicesRouter);
  return app;
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe('Device owner routes', () => {
  it('runs JWT auth before POST /current/retire handler', async () => {
    const res = await request(createApp()).post('/api/devices/current/retire').send({});
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      ok: true,
      authenticated: true,
      userId: 'route-user',
    });
    expect(mockRequireJwtAuth).toHaveBeenCalledTimes(1);
    expect(mockRetireHandler).toHaveBeenCalledTimes(1);
  });

  it('rejects unauthenticated requests before the retire handler runs', async () => {
    // A denying auth middleware stands in for an expired/invalid token.
    mockRequireJwtAuth.mockImplementationOnce((_req, res) =>
      res.status(401).json({ ok: false, code: 'UNAUTHORIZED' }),
    );
    const res = await request(createApp()).post('/api/devices/current/retire').send({});
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ ok: false, code: 'UNAUTHORIZED' });
    expect(mockRetireHandler).not.toHaveBeenCalled();
  });

  it('exposes only POST /current/retire and no other verb or device endpoint', async () => {
    const app = createApp();
    for (const method of ['get', 'put', 'patch', 'delete']) {
      const res = await request(app)[method]('/api/devices/current/retire');
      expect(res.status).toBe(404);
    }
    expect(mockRetireHandler).not.toHaveBeenCalled();

    const unknown = await request(app).post('/api/devices/currentregister').send({});
    expect(unknown.status).toBe(404);
    expect(mockRetireHandler).not.toHaveBeenCalled();
  });

  it('does not expose GET /current/retire', async () => {
    const res = await request(createApp()).get('/api/devices/current/retire');
    expect(res.status).toBe(404);
    expect(mockRetireHandler).not.toHaveBeenCalled();
  });

  it('constructs the handler once with server-owned dependencies', () => {
    expect(handlerCreationCalls).toHaveLength(1);
    const deps = handlerCreationCalls[0];
    expect(deps).toHaveProperty('db');
    expect(deps).toHaveProperty('tenantContext');
    expect(typeof deps.tenantContext.getActiveTenantId).toBe('function');
    expect(deps.tenantContext.alsAbsencePermitted).toBe(false);
  });
});

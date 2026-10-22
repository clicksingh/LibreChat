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
const mockCreateHandler = jest.fn(() => mockRetireHandler);

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

jest.mock('~/server/services/Device/ownerCurrentRetireHandler', () => ({
  createOwnerCurrentRetireHandler: (...args) => mockCreateHandler(...args),
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

  it('does not expose GET /current/retire', async () => {
    const res = await request(createApp()).get('/api/devices/current/retire');
    expect(res.status).toBe(404);
    expect(mockRetireHandler).not.toHaveBeenCalled();
  });

  it('constructs the handler once with server-owned dependencies', () => {
    expect(mockCreateHandler).toHaveBeenCalledTimes(1);
    const deps = mockCreateHandler.mock.calls[0][0];
    expect(deps).toHaveProperty('db');
    expect(deps).toHaveProperty('tenantContext');
    expect(typeof deps.tenantContext.getActiveTenantId).toBe('function');
    expect(deps.tenantContext.alsAbsencePermitted).toBe(false);
  });
});

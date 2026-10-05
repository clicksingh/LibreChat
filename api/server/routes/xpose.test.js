const express = require('express');
const request = require('supertest');

const mockClaimDevice = jest.fn((_req, res) =>
  res.status(200).json({ ok: true, state: 'claimed' }),
);

jest.mock('@librechat/api', () => ({
  createToolFavoritesHandlers: () => ({
    listToolFavorites: (_req, res) => res.status(200).json([]),
    addToolFavorite: (_req, res) => res.status(200).json({ ok: true }),
    removeToolFavorite: (_req, res) => res.status(200).json({ ok: true }),
  }),
  createXposePairingHandlers: () => ({ claimDevice: mockClaimDevice }),
}));

jest.mock('~/server/middleware', () => ({
  requireJwtAuth: (req, res, next) => {
    if (req.headers.authorization !== 'Bearer test-token') {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    req.user = { email: 'user@example.com' };
    return next();
  },
}));

jest.mock('~/server/controllers/FavoritesController', () => ({
  updateFavoritesController: (_req, res) => res.status(200).json({}),
  getFavoritesController: (_req, res) => res.status(200).json({}),
}));

jest.mock('~/server/controllers/SkillStatesController', () => ({
  getSkillStatesController: (_req, res) => res.status(200).json({}),
  updateSkillStatesController: (_req, res) => res.status(200).json({}),
}));

jest.mock('~/models', () => ({
  getToolFavorites: jest.fn(),
  addToolFavorite: jest.fn(),
  removeToolFavorite: jest.fn(),
}));

const router = require('./settings');

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/user/settings', router);
  return app;
}

describe('POST /api/user/settings/xpose/devices/claim', () => {
  beforeEach(() => {
    mockClaimDevice.mockClear();
  });

  it('rejects unauthenticated requests before reaching the xpose handler', async () => {
    const res = await request(buildApp())
      .post('/api/user/settings/xpose/devices/claim')
      .send({ code: 'ABC-123' });

    expect(res.status).toBe(401);
    expect(mockClaimDevice).not.toHaveBeenCalled();
  });

  it('routes authenticated requests to the xpose claim handler', async () => {
    const res = await request(buildApp())
      .post('/api/user/settings/xpose/devices/claim')
      .set('Authorization', 'Bearer test-token')
      .send({ code: 'ABC-123' });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true, state: 'claimed' });
    expect(mockClaimDevice).toHaveBeenCalledTimes(1);
  });
});

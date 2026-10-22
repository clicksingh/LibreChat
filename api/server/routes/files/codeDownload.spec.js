'use strict';

const express = require('express');
const request = require('supertest');
const { Readable } = require('stream');

jest.mock('~/server/services/Files/strategies', () => ({
  getStrategyFunctions: jest.fn(),
}));
jest.mock('~/server/services/Endpoints/agents/authorization', () => ({
  resolveWorkspaceContextExplicit: jest.fn(),
}));

const { FileSources } = require('librechat-data-provider');
const { getStrategyFunctions } = require('~/server/services/Files/strategies');
const {
  resolveWorkspaceContextExplicit,
} = require('~/server/services/Endpoints/agents/authorization');
const { signProjectFallback } = require('~/server/services/Files/Code/fallbackGrant');
const filesRouter = require('./files');

const SESSION = 'abcdefghijklmnopqrstu';
const FILE = 'ABCDEFGHIJKLMNOPQRSTU';
const PROJECT = 'project-test-a';
const DOWNLOAD_PATH = `/api/files/code/download/${SESSION}/${FILE}`;

describe('CodeAPI fallback HTTP route authorization (synthetic)', () => {
  const priorSecret = process.env.JWT_SECRET;
  const getDownloadStream = jest.fn();
  const app = express();
  app.use((req, _res, next) => {
    req.user = {
      id: req.get('x-qa-user') || 'member-a',
      tenantId: req.get('x-qa-tenant') || 'tenant-a',
      role: 'USER',
    };
    next();
  });
  app.use('/api/files', filesRouter);

  const grant = () =>
    signProjectFallback({
      req: { user: { id: 'member-a', tenantId: 'tenant-a' } },
      outputScope: { kind: 'project', id: PROJECT },
      sessionId: SESSION,
      fileId: FILE,
      expiresAt: Date.now() + 60_000,
    });

  beforeEach(() => {
    process.env.JWT_SECRET = 'synthetic-pr35-route-testing-only-not-a-real-secret';
    jest.clearAllMocks();
    getStrategyFunctions.mockImplementation((source) => {
      if (source !== FileSources.execute_code) {
        throw new Error('Unexpected synthetic download strategy');
      }
      return { getDownloadStream };
    });
    getDownloadStream.mockImplementation(async () => ({
      headers: { 'content-type': 'application/octet-stream' },
      data: Readable.from([Buffer.from('isolated-test-output')]),
    }));
    resolveWorkspaceContextExplicit.mockResolvedValue({
      kind: 'project',
      workspaceId: PROJECT,
    });
  });

  afterAll(() => {
    if (priorSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = priorSecret;
  });

  test('legacy personal fallback stays personal, even with forged project query', async () => {
    const response = await request(app).get(DOWNLOAD_PATH + '?kind=project&id=' + PROJECT);
    expect(response.status).toBe(200);
    expect(response.body.toString()).toBe('isolated-test-output');
    expect(getDownloadStream).toHaveBeenCalledWith(
      SESSION + '/' + FILE,
      { kind: 'user', id: 'member-a' },
      expect.objectContaining({ user: expect.objectContaining({ id: 'member-a' }) }),
    );
    expect(resolveWorkspaceContextExplicit).not.toHaveBeenCalled();
  });

  test('valid scoped grant checks live project access before streaming bytes', async () => {
    const response = await request(app).get(DOWNLOAD_PATH).query({ grant: grant() });
    expect(response.status).toBe(200);
    expect(response.body.toString()).toBe('isolated-test-output');
    expect(response.headers['cache-control']).toBe('private, no-store');
    expect(response.headers['referrer-policy']).toBe('no-referrer');
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(resolveWorkspaceContextExplicit).toHaveBeenCalledTimes(1);
    expect(resolveWorkspaceContextExplicit).toHaveBeenCalledWith(
      expect.objectContaining({ user: expect.objectContaining({ id: 'member-a' }) }),
      PROJECT,
    );
    expect(getDownloadStream).toHaveBeenCalledWith(
      SESSION + '/' + FILE,
      { kind: 'project', id: PROJECT },
      expect.objectContaining({
        workspaceContext: { kind: 'project', workspaceId: PROJECT },
      }),
    );
  });

  test('tampered or foreign-owner grants do not reach CodeAPI', async () => {
    const token = grant();
    const [body, signature] = token.split('.');
    const bad = body + '.' + (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
    const tampered = await request(app).get(DOWNLOAD_PATH).query({ grant: bad });
    expect(tampered.status).toBe(403);
    const foreign = await request(app)
      .get(DOWNLOAD_PATH)
      .set('x-qa-user', 'foreign-user')
      .query({ grant: token });
    expect(foreign.status).toBe(403);
    const tenant = await request(app)
      .get(DOWNLOAD_PATH)
      .set('x-qa-tenant', 'tenant-b')
      .query({ grant: token });
    expect(tenant.status).toBe(403);
    expect(getDownloadStream).not.toHaveBeenCalled();
  });

  test.each([
    [403, 'revoked'],
    [404, 'archived'],
  ])('denies a %s live project, no CodeAPI byte stream (%s)', async (status) => {
    resolveWorkspaceContextExplicit.mockRejectedValueOnce(
      Object.assign(new Error('Workspace permission denied'), { status }),
    );
    const response = await request(app).get(DOWNLOAD_PATH).query({ grant: grant() });
    expect(response.status).toBe(status);
    expect(getDownloadStream).not.toHaveBeenCalled();
  });

  test.each([
    [401, 403],
    [403, 403],
    [404, 404],
  ])('propagates intentional workspace status %s as HTTP %s', async (upstream, expected) => {
    resolveWorkspaceContextExplicit.mockRejectedValueOnce(
      Object.assign(new Error('Access check denied'), { status: upstream }),
    );
    const response = await request(app).get(DOWNLOAD_PATH).query({ grant: grant() });
    expect(response.status).toBe(expected);
    expect(getDownloadStream).not.toHaveBeenCalled();
  });

  test('unexpected workspace database failure returns 500, not misleading 403', async () => {
    resolveWorkspaceContextExplicit.mockRejectedValueOnce(new Error('synthetic MongoDB outage'));
    const response = await request(app).get(DOWNLOAD_PATH).query({ grant: grant() });
    expect(response.status).toBe(500);
    expect(response.text).toBe('Error downloading file');
    expect(getDownloadStream).not.toHaveBeenCalled();
  });

  test('missing fallback signing configuration returns 500 without streaming', async () => {
    const token = grant();
    delete process.env.JWT_SECRET;
    try {
      const response = await request(app).get(DOWNLOAD_PATH).query({ grant: token });
      expect(response.status).toBe(500);
      expect(getDownloadStream).not.toHaveBeenCalled();
    } finally {
      process.env.JWT_SECRET = 'synthetic-pr35-route-testing-only-not-a-real-secret';
    }
  });

  test('a resolver returning another project cannot authorize the download', async () => {
    resolveWorkspaceContextExplicit.mockResolvedValueOnce({
      kind: 'project',
      workspaceId: 'another-project',
    });
    const response = await request(app).get(DOWNLOAD_PATH).query({ grant: grant() });
    expect(response.status).toBe(403);
    expect(getDownloadStream).not.toHaveBeenCalled();
  });
});

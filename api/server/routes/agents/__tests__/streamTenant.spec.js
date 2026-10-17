const express = require('express');
const request = require('supertest');

const mockGenerationJobManager = {
  getJob: jest.fn(),
  subscribe: jest.fn(),
  subscribeWithResume: jest.fn(),
  getResumeState: jest.fn(),
  abortJob: jest.fn(),
  getActiveJobIdsForUser: jest.fn().mockResolvedValue([]),
};

jest.mock('@librechat/data-schemas', () => ({
  ...jest.requireActual('@librechat/data-schemas'),
  logger: {
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
  },
}));

jest.mock('@librechat/api', () => ({
  ...jest.requireActual('@librechat/api'),
  isEnabled: jest.fn().mockReturnValue(false),
  GenerationJobManager: mockGenerationJobManager,
}));

jest.mock('~/models', () => ({
  saveMessage: jest.fn(),
}));

let mockUserId = 'user-123';
let mockTenantId;

jest.mock('~/server/middleware', () => ({
  uaParser: (req, res, next) => next(),
  checkBan: (req, res, next) => next(),
  requireJwtAuth: (req, res, next) => {
    req.user = { id: mockUserId, tenantId: mockTenantId };
    next();
  },
  messageIpLimiter: (req, res, next) => next(),
  configMiddleware: (req, res, next) => next(),
  messageUserLimiter: (req, res, next) => next(),
}));

jest.mock('~/server/routes/agents/chat', () => require('express').Router());
jest.mock('~/server/routes/agents/v1', () => {
  const router = require('express').Router();
  router.use((req, res) => res.status(418).json({ error: 'v1 caught stream route' }));
  return { v1: router };
});
jest.mock('~/server/routes/agents/openai', () => require('express').Router());
jest.mock('~/server/routes/agents/responses', () => require('express').Router());

const agentsRouter = require('../index');
const app = express();
app.use(express.json());
app.use('/agents', agentsRouter);

function mockSubscribeSuccess() {
  mockGenerationJobManager.subscribe.mockImplementation((_streamId, _writeEvent, onDone) => {
    process.nextTick(() => onDone({ done: true }));
    return { unsubscribe: jest.fn() };
  });
}

describe('SSE stream tenant isolation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockUserId = 'user-123';
    mockTenantId = undefined;
  });

  describe('GET /chat/stream/:streamId', () => {
    it('returns 403 when a user from a different tenant accesses a stream', async () => {
      mockUserId = 'user-456';
      mockTenantId = 'tenant-b';

      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: { userId: 'user-456', tenantId: 'tenant-a' },
        status: 'running',
      });

      const res = await request(app).get('/agents/chat/stream/stream-123');
      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Unauthorized');
    });

    it('returns 404 when stream does not exist', async () => {
      mockGenerationJobManager.getJob.mockResolvedValue(null);

      const res = await request(app).get('/agents/chat/stream/nonexistent');
      expect(res.status).toBe(404);
    });

    it('proceeds past tenant guard when tenant matches', async () => {
      mockUserId = 'user-123';
      mockTenantId = 'tenant-a';
      mockSubscribeSuccess();

      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: { userId: 'user-123', tenantId: 'tenant-a' },
        status: 'running',
      });

      const res = await request(app).get('/agents/chat/stream/stream-123');
      expect(res.status).toBe(200);
      expect(mockGenerationJobManager.subscribe).toHaveBeenCalledTimes(1);
    });

    it('proceeds past tenant guard when job has no tenantId (single-tenant mode)', async () => {
      mockUserId = 'user-123';
      mockTenantId = undefined;
      mockSubscribeSuccess();

      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: { userId: 'user-123' },
        status: 'running',
      });

      const res = await request(app).get('/agents/chat/stream/stream-123');
      expect(res.status).toBe(200);
      expect(mockGenerationJobManager.subscribe).toHaveBeenCalledTimes(1);
    });

    it('returns 403 when job has tenantId but user has no tenantId', async () => {
      mockUserId = 'user-123';
      mockTenantId = undefined;

      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: { userId: 'user-123', tenantId: 'some-tenant' },
        status: 'running',
      });

      const res = await request(app).get('/agents/chat/stream/stream-123');
      expect(res.status).toBe(403);
    });
  });

  describe('fail-closed authenticated stream ownership (synthetic jobs)', () => {
    for (const metadata of [undefined, {}, { tenantId: 'tenant-a' }]) {
      it('refuses SSE subscribe and resume when job owner missing: ' + JSON.stringify(metadata), async () => {
        mockUserId = 'user-123';
        mockTenantId = 'tenant-a';
        mockGenerationJobManager.getJob.mockResolvedValue({ metadata, status: 'running' });
        for (const suffix of ['', '?resume=true']) {
          const res = await request(app).get('/agents/chat/stream/opaque-stream-id' + suffix);
          expect(res.status).toBe(403);
          expect(mockGenerationJobManager.subscribe).not.toHaveBeenCalled();
          expect(mockGenerationJobManager.subscribeWithResume).not.toHaveBeenCalled();
        }
      });
      it('refuses aborted job without owner: ' + JSON.stringify(metadata), async () => {
        mockUserId = 'user-123';
        mockTenantId = 'tenant-a';
        mockGenerationJobManager.getJob.mockResolvedValue({ metadata, status: 'running' });
        const res = await request(app).post('/agents/chat/abort').send({streamId:'opaque-stream-id'});
        expect(res.status).toBe(403);
        expect(mockGenerationJobManager.abortJob).not.toHaveBeenCalled();
      });
      it('refuses status endpoint without owner: ' + JSON.stringify(metadata), async () => {
        mockUserId = 'user-123';
        mockTenantId = 'tenant-a';
        mockGenerationJobManager.getJob.mockResolvedValue({ metadata, status: 'running' });
        const res = await request(app).get('/agents/chat/status/opaque-stream-id');
        expect(res.status).toBe(403);
        expect(mockGenerationJobManager.getResumeState).not.toHaveBeenCalled();
      });
    }
    it('refuses a job with no owner even if the request identity is also malformed', async () => {
      mockUserId = undefined;
      mockTenantId = undefined;
      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: {}, status: 'running',
      });
      expect((await request(app).get('/agents/chat/stream/opaque-stream-id')).status).toBe(403);
      expect((await request(app).get('/agents/chat/status/opaque-stream-id')).status).toBe(403);
      expect((await request(app).post('/agents/chat/abort').send({streamId:'opaque-stream-id'})).status).toBe(403);
      expect(mockGenerationJobManager.subscribe).not.toHaveBeenCalled();
    });

    it('denies other user in same tenant before delivering SSE events', async () => {
      mockUserId = 'other-user';
      mockTenantId = 'tenant-a';
      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: { userId:'user-123', tenantId:'tenant-a' }, status:'running'
      });
      const res = await request(app).get('/agents/chat/stream/opaque-stream-id?resume=true');
      expect(res.status).toBe(403);
      expect(mockGenerationJobManager.subscribeWithResume).not.toHaveBeenCalled();
    });
  });

  describe('synthetic user-facing SSE resume envelope', () => {
    it('replays an authorized published-file receipt in the sync envelope and ends cleanly', async () => {
      mockUserId = 'owner-a';
      mockTenantId = 'tenant-a';
      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: { userId:'owner-a', tenantId:'tenant-a' }, status:'running',
      });
      const reference = {
        file_id: 'out-0123456789abcdef0123',
        storage_session_id: 'legacy-synthetic',
        name: 'Final.pdf',
        role: 'output',
      };
      const resumeState = {runSteps:[],aggregatedContent:[],lastUpdate:1};
      const pendingEvents = [{type:'file',files:[reference]}];
      mockGenerationJobManager.subscribeWithResume.mockImplementation(
        (_streamId, _writeEvent, onDone) => {
          process.nextTick(() => onDone({ done:true }));
          return {
            subscription: {unsubscribe:jest.fn()}, resumeState, pendingEvents,
          };
        },
      );
      const res = await request(app).get('/agents/chat/stream/opaque-stream-id?resume=true');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/^text\/event-stream/);
      expect(res.text).toContain('event: message');
      expect(res.text).toContain('"sync":true');
      expect(res.text).toContain('"pendingEvents"');
      expect(res.text).toContain(reference.file_id);
      expect(res.text).toContain('"done":true');
      expect(mockGenerationJobManager.subscribeWithResume).toHaveBeenCalledTimes(1);
    });
  });

  describe('GET /chat/status/:conversationId', () => {
    it('returns 403 when tenant does not match', async () => {
      mockUserId = 'user-123';
      mockTenantId = 'tenant-b';

      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: { userId: 'user-123', tenantId: 'tenant-a' },
        status: 'running',
      });

      const res = await request(app).get('/agents/chat/status/conv-123');
      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Unauthorized');
    });

    it('returns status when tenant matches', async () => {
      mockUserId = 'user-123';
      mockTenantId = 'tenant-a';

      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: { userId: 'user-123', tenantId: 'tenant-a' },
        status: 'running',
        createdAt: Date.now(),
      });
      mockGenerationJobManager.getResumeState.mockResolvedValue(null);

      const res = await request(app).get('/agents/chat/status/conv-123');
      expect(res.status).toBe(200);
      expect(res.body.active).toBe(true);
    });
  });

  describe('POST /chat/abort', () => {
    it('returns 403 when tenant does not match', async () => {
      mockUserId = 'user-123';
      mockTenantId = 'tenant-b';

      mockGenerationJobManager.getJob.mockResolvedValue({
        metadata: { userId: 'user-123', tenantId: 'tenant-a' },
        status: 'running',
      });

      const res = await request(app).post('/agents/chat/abort').send({ streamId: 'stream-123' });
      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Unauthorized');
    });
  });
});

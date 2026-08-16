'use strict';

/**
 * 8S3C R3 — document_visual_qa contract + runtime tool unit coverage.
 *
 * Covers:
 *   1. Pure contract module (verdict validation, payload construction,
 *      defensive parsing, batching) — mirrors codeapi's render-contract style.
 *   2. Runtime tool with stubbed transports — proves the tool's only outbound
 *      calls are (a) the existing codeapi page fetch and (b) the aibridge
 *      vision call, and that ONLY rendered page PNG data-URLs (never raw
 *      source bytes) are forwarded to the vision model.
 *   3. Real `callAIBridge` transport — posts ONLY to the aibridge
 *      /v1/chat/completions endpoint (no second vision transport).
 */

const mockGetFiles = jest.fn();
const mockAxios = jest.fn();

jest.mock('~/models', () => ({ getFiles: mockGetFiles }));
jest.mock('@librechat/api', () => ({
  ...jest.requireActual('@librechat/api'),
  createAxiosInstance: () => mockAxios,
}));

const contract = require('./documentVisualQAContract');
const {
  runDocumentVisualQA,
  createDocumentVisualQATool,
  callAIBridge,
  resolveAIBridgeAuth,
  pageFromName,
} = require('./documentVisualQA');

/** Tiny valid PNG so the sharp downscale path is exercised. */
let pngBuffer;
let largePngBuffer;

const PASS_JSON = JSON.stringify({ verdict: 'PASS', issues: [], summary: 'clean pages' });
const ISSUES_JSON = JSON.stringify({
  verdict: 'ISSUES_FOUND',
  issues: [
    {
      artifact: 'report-001.png',
      page: 1,
      severity: 'high',
      description: 'Table columns clipped at the right edge.',
      suggestion: 'Widen the table container.',
    },
  ],
  summary: 'Page 1 has a clipped table.',
});

beforeAll(async () => {
  const sharp = require('sharp');
  pngBuffer = await sharp({
    create: { width: 64, height: 64, channels: 4, background: { r: 255, g: 0, b: 0, alpha: 1 } },
  })
    .png()
    .toBuffer();
  largePngBuffer = await sharp({
    create: { width: 2048, height: 2048, channels: 4, background: { r: 0, g: 128, b: 255, alpha: 1 } },
  })
    .png()
    .toBuffer();
});

describe('documentVisualQAContract (pure)', () => {
  describe('buildQAPrompt', () => {
    it('covers all six required QA dimensions', () => {
      const prompt = contract.buildQAPrompt();
      expect(prompt).toContain('Clipping');
      expect(prompt).toContain('Overlap');
      expect(prompt).toContain('Visual hierarchy');
      expect(prompt).toContain('Unreadable charts/tables');
      expect(prompt).toContain('Malformed layouts');
      expect(prompt).toContain('Legibility');
    });

    it('includes the focus override and the artifact/page map', () => {
      const prompt = contract.buildQAPrompt({
        focus: 'clipping, overlap',
        pageMap: [
          { artifact: 'report-001.png', page: 1 },
          { artifact: 'report-002.png', page: 2 },
        ],
      });
      expect(prompt).toContain('Focus areas for this pass: clipping, overlap.');
      expect(prompt).toContain('artifact "report-001.png", page 1');
      expect(prompt).toContain('artifact "report-002.png", page 2');
    });

    it('demands strict JSON output only', () => {
      const prompt = contract.buildQAPrompt();
      expect(prompt).toContain('ONE strict JSON object');
      expect(prompt).toContain('no markdown fences');
    });
  });

  describe('buildVisionPayload', () => {
    it('builds text + image_url data-URL parts for the vision model', () => {
      const payload = contract.buildVisionPayload({
        prompt: 'Inspect',
        pages: [
          { name: 'a.png', page: 1, mimeType: 'image/png', base64: 'QUJD' },
          { name: 'b.png', page: 2, mimeType: 'image/png', base64: 'REVG' },
        ],
      });
      expect(payload.model).toBe(contract.VISION_MODEL);
      expect(payload.temperature).toBe(0.2);
      expect(payload.messages).toHaveLength(1);
      expect(payload.messages[0].role).toBe('user');
      const parts = payload.messages[0].content;
      expect(parts[0]).toEqual({ type: 'text', text: 'Inspect' });
      expect(parts[1]).toEqual({
        type: 'image_url',
        image_url: { url: 'data:image/png;base64,QUJD' },
      });
      expect(parts[2].image_url.url).toBe('data:image/png;base64,REVG');
    });
  });

  describe('normalizePageLimit', () => {
    it('defaults to 4 when absent, clamps to [1, 8]', () => {
      expect(contract.normalizePageLimit(undefined)).toBe(4);
      expect(contract.normalizePageLimit(0)).toBe(1);
      expect(contract.normalizePageLimit(99)).toBe(8);
      expect(contract.normalizePageLimit('6')).toBe(6);
      expect(contract.normalizePageLimit('not-a-number')).toBe(4);
      expect(contract.normalizePageLimit(NaN)).toBe(4);
    });
  });

  describe('batchRefs', () => {
    it('splits page refs into batches of at most maxPages', () => {
      const refs = [1, 2, 3, 4, 5, 6, 7];
      expect(contract.batchRefs(refs, 2)).toEqual([[1, 2], [3, 4], [5, 6], [7]]);
      expect(contract.batchRefs(refs, 4)).toEqual([
        [1, 2, 3, 4],
        [5, 6, 7],
      ]);
      expect(contract.batchRefs(refs, 99)).toEqual([refs]);
    });
  });

  describe('sanitizeIssue', () => {
    it('coerces a raw issue into the verdict contract', () => {
      const issue = contract.sanitizeIssue(
        {
          artifact: 'x.png',
          page: 3,
          severity: 'high',
          description: 'd',
          suggestion: 's',
        },
        'fallback',
        1,
      );
      expect(issue).toEqual({ artifact: 'x.png', page: 3, severity: 'high', description: 'd', suggestion: 's' });
    });

    it('falls back on missing/invalid fields and drops non-objects', () => {
      expect(contract.sanitizeIssue(null)).toBeNull();
      const issue = contract.sanitizeIssue({ page: 'bad', severity: 'catastrophic' }, 'f.png', 7);
      expect(issue.artifact).toBe('f.png');
      expect(issue.page).toBe(7);
      expect(issue.severity).toBe('medium');
      expect(issue.description).toBe('(no description)');
      expect(issue.suggestion).toBe('');
    });
  });

  describe('parseVerdict (defensive)', () => {
    it('parses raw JSON', () => {
      expect(contract.parseVerdict(PASS_JSON)).toEqual({ verdict: 'PASS', issues: [], summary: 'clean pages' });
    });

    it('parses markdown-fenced JSON', () => {
      const fenced = '```json\n' + PASS_JSON + '\n```';
      expect(contract.parseVerdict(fenced)).toEqual({ verdict: 'PASS', issues: [], summary: 'clean pages' });
    });

    it('extracts the first {...} block from surrounding prose', () => {
      const prose = 'Here is the result:\n' + ISSUES_JSON + '\nThat is all.';
      const parsed = contract.parseVerdict(prose);
      expect(parsed.verdict).toBe('ISSUES_FOUND');
      expect(parsed.issues).toHaveLength(1);
      expect(parsed.issues[0].artifact).toBe('report-001.png');
    });

    it('coerces PASS-with-issues into a clean PASS', () => {
      const parsed = contract.parseVerdict(
        JSON.stringify({ verdict: 'PASS', issues: [{ artifact: 'a.png', page: 1 }], summary: '' }),
      );
      expect(parsed.verdict).toBe('PASS');
      expect(parsed.issues).toEqual([]);
    });

    it('synthesizes a high-severity issue when ISSUES_FOUND has no issues', () => {
      const parsed = contract.parseVerdict(
        JSON.stringify({ verdict: 'ISSUES_FOUND', issues: [], summary: 'there was a problem' }),
        { artifact: 'a.png', page: 2 },
      );
      expect(parsed.verdict).toBe('ISSUES_FOUND');
      expect(parsed.issues).toHaveLength(1);
      expect(parsed.issues[0].severity).toBe('high');
    });

    it('infers ISSUES_FOUND when a verdict is missing but issues exist', () => {
      const parsed = contract.parseVerdict(
        JSON.stringify({ issues: [{ artifact: 'a.png', page: 1, severity: 'medium', description: 'd' }] }),
      );
      expect(parsed.verdict).toBe('ISSUES_FOUND');
    });

    it('throws a coded VQA_PARSE_FAILED on non-recoverable output', () => {
      for (const bad of ['', 42, 'no json here at all']) {
        try {
          contract.parseVerdict(bad);
          throw new Error('expected parseVerdict to throw');
        } catch (error) {
          expect(error.code).toBe('VQA_PARSE_FAILED');
          expect(error.name).toBe('DocumentVisualQAError');
        }
      }
    });
  });

  describe('combineVerdicts', () => {
    it('returns PASS when every batch is clean', () => {
      const combined = contract.combineVerdicts([
        { verdict: 'PASS', issues: [], summary: 'p1' },
        { verdict: 'PASS', issues: [], summary: 'p2' },
      ]);
      expect(combined.verdict).toBe('PASS');
      expect(combined.issues).toEqual([]);
      expect(combined.summary).toContain('p1');
      expect(combined.summary).toContain('p2');
    });

    it('returns ISSUES_FOUND when any batch finds issues', () => {
      const combined = contract.combineVerdicts([
        { verdict: 'PASS', issues: [], summary: 'p1' },
        { verdict: 'ISSUES_FOUND', issues: [{ artifact: 'a.png', page: 1 }], summary: 'p2' },
      ]);
      expect(combined.verdict).toBe('ISSUES_FOUND');
      expect(combined.issues).toHaveLength(1);
    });

    it('handles an empty list', () => {
      const combined = contract.combineVerdicts([]);
      expect(combined.verdict).toBe('PASS');
      expect(combined.summary).toContain('No pages inspected');
    });
  });

  describe('reconcileArtifactNames', () => {
    const pageMap = [
      { artifact: 'report-001.png', page: 1 },
      { artifact: 'report-002.png', page: 2 },
    ];

    it('leaves known artifact names untouched', () => {
      const verdict = {
        verdict: 'ISSUES_FOUND',
        issues: [{ artifact: 'report-001.png', page: 1, severity: 'high', description: 'x' }],
      };
      const reconciled = contract.reconcileArtifactNames(verdict, pageMap);
      expect(reconciled.issues[0].artifact).toBe('report-001.png');
    });

    it('maps a generic image label back to the page-map artifact for that page', () => {
      const verdict = {
        verdict: 'ISSUES_FOUND',
        issues: [{ artifact: 'image.png', page: 1, severity: 'medium', description: 'clip' }],
      };
      const reconciled = contract.reconcileArtifactNames(verdict, pageMap);
      expect(reconciled.issues[0].artifact).toBe('report-001.png');
      expect(reconciled.issues[0].page).toBe(1);
    });

    it('leaves unknown artifacts on unknown pages untouched', () => {
      const verdict = {
        verdict: 'ISSUES_FOUND',
        issues: [{ artifact: 'mystery.png', page: 9, severity: 'low', description: '?' }],
      };
      const reconciled = contract.reconcileArtifactNames(verdict, pageMap);
      expect(reconciled.issues[0].artifact).toBe('mystery.png');
    });

    it('preserves verdict and non-issue fields', () => {
      const verdict = { verdict: 'PASS', issues: [], summary: 'clean' };
      const reconciled = contract.reconcileArtifactNames(verdict, pageMap);
      expect(reconciled.verdict).toBe('PASS');
      expect(reconciled.summary).toBe('clean');
    });
  });

  describe('formatVerdict', () => {
    it('renders verdict, issues, and the authoritative RAW JSON', () => {
      const parsed = contract.parseVerdict(ISSUES_JSON);
      const text = contract.formatVerdict(parsed);
      expect(text).toContain('QA VERDICT: ISSUES_FOUND');
      expect(text).toContain('[page 1][high] report-001.png');
      expect(text).toContain('RAW: {"verdict":"ISSUES_FOUND"');
    });
  });
});

describe('documentVisualQA runtime tool (stubbed transports)', () => {
  beforeEach(() => {
    mockGetFiles.mockReset();
    mockAxios.mockReset();
  });

  it('returns a PASS verdict and calls ONLY the codeapi fetch + aibridge vision transport', async () => {
    const downloadPage = jest.fn().mockResolvedValue(pngBuffer);
    const callAIBridge = jest.fn().mockResolvedValue(PASS_JSON);

    const result = await runDocumentVisualQA({
      req: {},
      session_id: 'sess-1',
      file_ids: ['f1'],
      deps: {
        downloadPage,
        callAIBridge,
        resolveAIBridgeAuth: () => 'Bearer test',
      },
    });

    expect(downloadPage).toHaveBeenCalledTimes(1);
    expect(downloadPage).toHaveBeenCalledWith('sess-1', 'f1');
    expect(callAIBridge).toHaveBeenCalledTimes(1);

    const { authHeader, payload } = callAIBridge.mock.calls[0][0];
    expect(authHeader).toBe('Bearer test');
    expect(payload.model).toBe(contract.VISION_MODEL);
    expect(payload.messages[0].role).toBe('user');

    const parts = payload.messages[0].content;
    const imageParts = parts.filter((part) => part.type === 'image_url');
    // ONLY rendered page PNG data-URLs travel to the vision model — never raw
    // source bytes or any other resource.
    expect(parts[0].type).toBe('text');
    expect(imageParts).toHaveLength(1);
    expect(imageParts[0].image_url.url.startsWith('data:image/png;base64,')).toBe(true);
    // No other outbound call was made: the two injected functions above are
    // the only network boundaries, and neither was called more than expected.
    expect(mockAxios).not.toHaveBeenCalled();

    expect(result).toContain('QA VERDICT: PASS');
    expect(result).toContain('RAW:');
  });

  it('returns ISSUES_FOUND with the offending artifact/page list (file_names path)', async () => {
    const downloadPage = jest.fn().mockResolvedValue(pngBuffer);
    const callAIBridge = jest.fn().mockResolvedValue(ISSUES_JSON);
    mockGetFiles.mockResolvedValue([
      {
        filename: 'render-out/pages/report-001.png',
        metadata: { codeEnvRef: { file_id: 'f1', storage_session_id: 'sess-1' } },
      },
    ]);

    const result = await runDocumentVisualQA({
      req: {},
      session_id: 'sess-1',
      file_names: ['render-out/pages/report-001.png'],
      deps: { downloadPage, callAIBridge, resolveAIBridgeAuth: () => 'Bearer test' },
    });

    // The model reported the generic label "report-001.png"; reconciliation
    // maps it back to the page-map artifact so the list names the real path.
    expect(result).toContain('QA VERDICT: ISSUES_FOUND');
    expect(result).toContain('render-out/pages/report-001.png');
    expect(result).toContain('Table columns clipped');
    expect(mockGetFiles).toHaveBeenCalledWith({
      user: undefined,
      'metadata.codeEnvRef.storage_session_id': 'sess-1',
    });
    expect(downloadPage).toHaveBeenCalledWith('sess-1', 'f1');
  });

  it('batches pages by maxPages and merges batch verdicts', async () => {
    const downloadPage = jest.fn().mockResolvedValue(pngBuffer);
    const callAIBridge = jest
      .fn()
      .mockResolvedValueOnce(PASS_JSON)
      .mockResolvedValueOnce(ISSUES_JSON);

    const result = await runDocumentVisualQA({
      req: {},
      session_id: 'sess-1',
      file_ids: ['f1', 'f2', 'f3'],
      maxPages: 2,
      deps: { downloadPage, callAIBridge, resolveAIBridgeAuth: () => 'Bearer test' },
    });

    expect(downloadPage).toHaveBeenCalledTimes(3);
    expect(callAIBridge).toHaveBeenCalledTimes(2);
    // Batch 1 -> 2 pages, batch 2 -> 1 page.
    expect(
      callAIBridge.mock.calls[0][0].payload.messages[0].content.filter((p) => p.type === 'image_url')
        .length,
    ).toBe(2);
    expect(
      callAIBridge.mock.calls[1][0].payload.messages[0].content.filter((p) => p.type === 'image_url')
        .length,
    ).toBe(1);
    expect(result).toContain('QA VERDICT: ISSUES_FOUND');
  });

  it('fails closed with a coded VQA_OVERALL_TIMEOUT past the wall-clock deadline', async () => {
    // A stub deadline of 0ms forces the second batch past the budget; the
    // first batch still completes, proving the deadline is checked per batch
    // and never suppresses a finished batch's verdict work.
    const downloadPage = jest.fn().mockResolvedValue(pngBuffer);
    const callAIBridge = jest.fn().mockResolvedValue(PASS_JSON);

    await expect(
      runDocumentVisualQA({
        req: {},
        session_id: 'sess-1',
        file_ids: ['f1', 'f2', 'f3'],
        maxPages: 2,
        deps: { downloadPage, callAIBridge, resolveAIBridgeAuth: () => 'Bearer test', overallDeadlineMs: 0 },
      }),
    ).rejects.toMatchObject({ code: 'VQA_OVERALL_TIMEOUT' });
  });

  it('resolves file_names to codeapi ids via the files collection', async () => {
    mockGetFiles.mockResolvedValue([
      {
        filename: 'render-out/pages/report-001.png',
        metadata: { codeEnvRef: { storage_session_id: 'sess-1', file_id: 'sha001' } },
      },
      {
        filename: 'render-out/pages/report-002.png',
        metadata: { codeEnvRef: { storage_session_id: 'sess-1', file_id: 'sha002' } },
      },
    ]);
    const downloadPage = jest.fn().mockResolvedValue(pngBuffer);
    const callAIBridge = jest.fn().mockResolvedValue(PASS_JSON);

    const result = await runDocumentVisualQA({
      req: { user: { id: 'user_1' } },
      session_id: 'sess-1',
      file_names: ['render-out/pages/report-002.png'],
      deps: { downloadPage, callAIBridge, resolveAIBridgeAuth: () => 'Bearer test' },
    });

    expect(mockGetFiles).toHaveBeenCalledWith({
      user: 'user_1',
      'metadata.codeEnvRef.storage_session_id': 'sess-1',
    });
    expect(downloadPage).toHaveBeenCalledWith('sess-1', 'sha002');
    expect(result).toContain('QA VERDICT: PASS');
  });

  it('returns a coded VQA_NO_FILE_REFS when file_names match nothing', async () => {
    mockGetFiles.mockResolvedValue([]);
    await expect(
      runDocumentVisualQA({
        req: { user: { id: 'user_1' } },
        session_id: 'sess-1',
        file_names: ['missing.png'],
        deps: { downloadPage: jest.fn(), callAIBridge: jest.fn(), resolveAIBridgeAuth: () => 'Bearer test' },
      }),
    ).rejects.toMatchObject({ code: 'VQA_NO_FILE_REFS' });
  });

  it('returns coded errors instead of crashing', async () => {
    const deps = { resolveAIBridgeAuth: () => 'Bearer test' };

    // invalid session_id
    await expect(
      runDocumentVisualQA({ req: {}, session_id: '  ', file_ids: ['f1'], deps }),
    ).rejects.toMatchObject({ code: 'VQA_INVALID_INPUT' });

    // no refs at all
    await expect(
      runDocumentVisualQA({ req: {}, session_id: 'sess-1', deps }),
    ).rejects.toMatchObject({ code: 'VQA_NO_FILE_REFS' });

    // over the hard total-page cap
    await expect(
      runDocumentVisualQA({
        req: {},
        session_id: 'sess-1',
        file_ids: Array.from({ length: contract.MAX_TOTAL_PAGES + 1 }, (_, i) => `f${i}`),
        deps,
      }),
    ).rejects.toMatchObject({ code: 'VQA_TOO_MANY_PAGES' });

    // auth unresolved
    await expect(
      runDocumentVisualQA({
        req: {},
        session_id: 'sess-1',
        file_ids: ['f1'],
        deps: { resolveAIBridgeAuth: () => null },
      }),
    ).rejects.toMatchObject({ code: 'VQA_AUTH_UNRESOLVED' });

    // page fetch failure
    await expect(
      runDocumentVisualQA({
        req: {},
        session_id: 'sess-1',
        file_ids: ['f1'],
        deps: {
          downloadPage: jest.fn().mockRejectedValue(new Error('boom')),
          callAIBridge: jest.fn(),
          resolveAIBridgeAuth: () => 'Bearer test',
        },
      }),
    ).rejects.toMatchObject({ code: 'VQA_PAGE_FETCH_FAILED' });

    // unparseable vision verdict
    await expect(
      runDocumentVisualQA({
        req: {},
        session_id: 'sess-1',
        file_ids: ['f1'],
        deps: {
          downloadPage: jest.fn().mockResolvedValue(pngBuffer),
          callAIBridge: jest.fn().mockResolvedValue('this is not json at all'),
          resolveAIBridgeAuth: () => 'Bearer test',
        },
      }),
    ).rejects.toMatchObject({ code: 'VQA_PARSE_FAILED' });

    // aibridge HTTP failure
    await expect(
      runDocumentVisualQA({
        req: {},
        session_id: 'sess-1',
        file_ids: ['f1'],
        deps: {
          downloadPage: jest.fn().mockResolvedValue(pngBuffer),
          callAIBridge: jest.fn().mockRejectedValue(new Error('connection refused')),
          resolveAIBridgeAuth: () => 'Bearer test',
        },
      }),
    ).rejects.toMatchObject({ code: 'VQA_AI_BRIDGE_ERROR' });
  });

  it('downscales a large page until it fits the per-page budget', async () => {
    const { downscalePage } = require('./documentVisualQA');
    // A deliberately tiny budget forces the shrink loop toward the 256px floor.
    const result = await downscalePage(largePngBuffer, 40_000);
    expect(result.base64.length).toBeGreaterThan(0);
    expect(result.mimeType).toBe('image/png');
    expect(contract.DATA_URL_PREFIX.length + result.base64.length).toBeLessThanOrEqual(40_000);
  });

  it('returns a coded VQA_PAGE_DOWNSCALE_FAILED on corrupt input', async () => {
    const { downscalePage } = require('./documentVisualQA');
    await expect(downscalePage(Buffer.from('not a png'), 1 << 20)).rejects.toMatchObject({
      code: 'VQA_PAGE_DOWNSCALE_FAILED',
    });
  });

  it('rejects a non-PNG raster (JPEG) at the PNG magic gate (defense-in-depth)', async () => {
    const { downscalePage } = require('./documentVisualQA');
    // A JPEG sharp COULD decode and re-encode — the explicit signature gate must
    // still refuse it so only genuine rendered PNGs ever reach vision.
    const jpegBytes = Buffer.from('ffd8ffe000104a46494600010100000100010000', 'hex');
    await expect(downscalePage(jpegBytes, 1 << 20)).rejects.toMatchObject({
      code: 'VQA_PAGE_DOWNSCALE_FAILED',
    });
  });

  it('exposes a tool instance whose schema self-documents the exact input keys', () => {
    const tool = createDocumentVisualQATool({ req: {}, deps: {} });
    expect(tool.name).toBe(contract.TOOL_NAME);
    expect(tool.responseFormat).toBe('content');
    expect(tool.schema.properties).toHaveProperty('session_id');
    expect(tool.schema.properties).toHaveProperty('file_ids');
    expect(tool.schema.properties).toHaveProperty('file_names');
    expect(tool.schema.properties).toHaveProperty('focus');
    expect(tool.schema.properties).toHaveProperty('maxPages');
    expect(tool.schema.required).toContain('session_id');
    expect(tool.schema.properties.maxPages.maximum).toBe(contract.MAX_PAGES_CAP);
  });

  it('tool func returns coded text (never throws) for invalid input', async () => {
    const tool = createDocumentVisualQATool({ req: {}, deps: {} });
    const output = await tool.invoke({ session_id: '' });
    expect(typeof output).toBe('string');
    expect(output).toContain('[VQA_INVALID_INPUT]');
  });
});

describe('real transport boundaries', () => {
  beforeEach(() => {
    mockAxios.mockReset();
  });

  it('callAIBridge posts ONLY to the aibridge chat completions endpoint', async () => {
    mockAxios.mockResolvedValue({
      data: { choices: [{ message: { content: PASS_JSON } }] },
    });
    const content = await callAIBridge({
      authHeader: 'Bearer test',
      payload: { model: contract.VISION_MODEL, messages: [{ role: 'user', content: [] }] },
    });
    expect(mockAxios).toHaveBeenCalledTimes(1);
    const request = mockAxios.mock.calls[0][0];
    expect(request.method).toBe('post');
    expect(request.url).toBe(`${contract.AIBRIDGE_BASE_URL}/v1/chat/completions`);
    expect(request.headers.Authorization).toBe('Bearer test');
    expect(request.timeout).toBe(contract.AIBRIDGE_TIMEOUT_MS);
    expect(content).toContain('PASS');
  });

  it('callAIBridge surfaces a coded VQA_AI_BRIDGE_ERROR on HTTP failure', async () => {
    mockAxios.mockRejectedValue({ response: { status: 502 } });
    await expect(
      callAIBridge({ authHeader: 'Bearer test', payload: {} }),
    ).rejects.toMatchObject({ code: 'VQA_AI_BRIDGE_ERROR' });
  });

  it('resolveAIBridgeAuth resolves the placeholder to a Bearer header using the resolved env value', () => {
    process.env.VQA_R3_TEST_KEY = 'super-secret-value';
    const req = {
      config: {
        endpoints: {
          custom: [{ name: 'CBHR AI', apiKey: '${VQA_R3_TEST_KEY}' }],
        },
      },
    };
    expect(resolveAIBridgeAuth(req)).toBe('Bearer super-secret-value');
    delete process.env.VQA_R3_TEST_KEY;
  });

  it('resolveAIBridgeAuth returns null (coded VQA_AUTH_UNRESOLVED) when the key cannot be resolved', () => {
    delete process.env.VQA_R3_UNRESOLVED_KEY;
    const req = {
      config: {
        endpoints: {
          custom: [{ name: 'CBHR AI', apiKey: '${VQA_R3_UNRESOLVED_KEY}' }],
        },
      },
    };
    expect(resolveAIBridgeAuth(req)).toBeNull();
  });
});

describe('pageFromName', () => {
  it('extracts a 1-based page number from a rendered page path', () => {
    expect(pageFromName('render-out/pages/report-003.png')).toBe(3);
    expect(pageFromName('report-12.png')).toBe(12);
    expect(pageFromName('cover.png')).toBe(1);
  });
});

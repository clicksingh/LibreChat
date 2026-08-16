'use strict';

/**
 * 8S3C R3 — `document_visual_qa` runtime tool (issue #8).
 *
 * Renders-then-describes ONLY. The tool fetches already-rendered PNG pages
 * from the codeapi session workspace through the EXISTING CodeAPI client
 * (`getCodeApiAuthHeaders` -> `GET {codeapi}/download/{session}/{file}?kind=&id=`),
 * downscales them, and sends them through the EXISTING aibridge vision path
 * (`POST http://aibridge:4103/v1/chat/completions`, model `glm-5v-turbo`).
 *
 * Isolation contract (unchanged — nothing here weakens codeapi/aibridge):
 *   - Child sandbox network isolation is untouched; no new egress is opened.
 *   - Raw source documents are NEVER sent to the vision model — only rendered
 *     page bitmaps, downscaled and re-encoded to PNG.
 *   - Auth for aibridge uses the RESOLVED custom-endpoint key value only
 *     (dotenv-order-safe); the key is never logged or printed.
 *
 * Testability: `createDocumentVisualQATool({ req, deps })` accepts a deps
 * overrides map (`downloadPage`, `callAIBridge`, `getFiles`, `downscalePage`)
 * so the unit suite can stub every transport and prove the tool's only
 * outbound call is to aibridge.
 */

const sharp = require('sharp');
const { DynamicStructuredTool } = require('@librechat/agents/langchain/tools');
const { getCodeBaseURL } = require('@librechat/agents');
const {
  createAxiosInstance,
  codeServerHttpAgent,
  codeServerHttpsAgent,
  buildCodeEnvDownloadQuery,
  getCodeApiAuthHeaders,
  getCustomEndpointConfig,
} = require('@librechat/api');
const { extractEnvVariable } = require('librechat-data-provider');
const { getFiles } = require('~/models');
const contract = require('./documentVisualQAContract');

const axios = createAxiosInstance();

/** PNG signature bytes — the bitmap gate (see contract.PNG_MAGIC). */
const PNG_MAGIC_BYTES = Buffer.from(contract.PNG_MAGIC, 'hex');

const TOOL_DESCRIPTION = `Inspect rendered document page PNGs (render-out/pages/*.png from a prior render/exec step) for layout defects and return a strict pass/issues verdict.

Input keys (exact):
- session_id (required): codeapi session id of the render step holding the PNG pages.
- file_ids (optional): codeapi file ids of the PNG pages to QA.
- file_names (optional): sandbox paths of the PNG pages, e.g. "render-out/pages/report-001.png". Use exactly one of the two.
- focus (optional): comma-separated: clipping, overlap, hierarchy, charts, legibility, layout.
- maxPages (optional, default 4, hard cap 8): pages per vision pass.

Checks: clipping, overlap, visual hierarchy, unreadable charts/tables, malformed layouts, legibility.

Return ONE strict JSON object:
{"verdict":"PASS"|"ISSUES_FOUND","issues":[{"artifact":"<png name>","page":<1-based page>,"severity":"low|medium|high","description":"...","suggestion":"..."}],"summary":"..."}
On ISSUES_FOUND, list the offending artifact/pages. Only rendered bitmaps reach vision.`;

/**
 * Resolves the aibridge auth header from the CBHR AI custom endpoint config.
 * Uses the RESOLVED key value (dotenv-order-safe) — never the raw
 * placeholder, and never logged.
 * @returns {string|null} `Bearer <resolved>` or null when unresolved.
 */
function resolveAIBridgeAuth(req) {
  let endpointConfig = null;
  try {
    endpointConfig = getCustomEndpointConfig({ endpoint: 'CBHR AI', appConfig: req?.config });
  } catch {
    endpointConfig = null;
  }
  const apiKey = endpointConfig?.apiKey;
  if (typeof apiKey === 'string' && apiKey.trim()) {
    const trimmedKey = apiKey.trim();
    const resolved = extractEnvVariable(trimmedKey);
    if (typeof resolved === 'string' && resolved.trim() && resolved !== trimmedKey) {
      return `Bearer ${resolved.trim()}`;
    }
  }
  return null;
}

/**
 * Downloads one rendered page from the codeapi session workspace using the
 * EXISTING codeapi client (same auth/transport as Files/Code/crud.js).
 */
async function downloadCodePage(req, sessionId, fileId) {
  try {
    const baseURL = getCodeBaseURL();
    const query = buildCodeEnvDownloadQuery({ kind: 'user', id: req?.user?.id });
    const authHeaders = await getCodeApiAuthHeaders(req);
    const response = await axios({
      method: 'get',
      url: `${baseURL}/download/${sessionId}/${fileId}${query}`,
      responseType: 'arraybuffer',
      headers: {
        'User-Agent': 'LibreChat/1.0',
        ...authHeaders,
      },
      httpAgent: codeServerHttpAgent,
      httpsAgent: codeServerHttpsAgent,
      timeout: 15000,
    });
    return Buffer.from(response.data);
  } catch (error) {
    throw new contract.DocumentVisualQAError(
      contract.ERR.VQA_PAGE_FETCH_FAILED,
      error?.message ?? String(error),
    );
  }
}

/**
 * Downscales a rendered page so its base64 data URL fits the per-page body
 * budget. Longest-edge target starts at PAGE_MAX_DIM and shrinks until the
 * data URL is under budget (or the 256px floor is reached).
 */
async function downscalePage(buffer, budget) {
  // Defense-in-depth (security review finding #3): only genuine PNG bitmaps are
  // ever forwarded to the vision model. sharp already fails closed on office
  // formats, but the explicit signature check makes the guarantee fail-fast and
  // independent of the codec, so raw source documents and non-PNG rasters never
  // reach vision.
  if (
    !Buffer.isBuffer(buffer) ||
    buffer.length < PNG_MAGIC_BYTES.length ||
    !buffer.subarray(0, PNG_MAGIC_BYTES.length).equals(PNG_MAGIC_BYTES)
  ) {
    throw new contract.DocumentVisualQAError(
      contract.ERR.VQA_PAGE_DOWNSCALE_FAILED,
      'page is not a PNG bitmap (only rendered PNG pages reach vision)',
    );
  }
  try {
    let dim = contract.PAGE_MAX_DIM;
    for (;;) {
      const resized = await sharp(buffer, { limitInputPixels: 40 << 20 })
        .rotate()
        .resize({ width: dim, height: dim, fit: 'inside', withoutEnlargement: true })
        .png({ compressionLevel: 6, adaptiveFiltering: true })
        .toBuffer();
      const base64 = resized.toString('base64');
      const size = contract.DATA_URL_PREFIX.length + base64.length;
      if (size <= budget || dim <= 256) {
        return { buffer: resized, base64, mimeType: 'image/png', dim };
      }
      dim = Math.floor(dim * 0.75);
    }
  } catch (error) {
    throw new contract.DocumentVisualQAError(
      contract.ERR.VQA_PAGE_DOWNSCALE_FAILED,
      error?.message ?? String(error),
    );
  }
}

/**
 * POSTs a vision payload to the EXISTING aibridge proxy
 * (`POST {AIBRIDGE_BASE_URL}/v1/chat/completions`). Returns the raw
 * completion text. The transport timeout is set ABOVE aibridge's
 * VISION_TIMEOUT_MS (120s) so aibridge's coded timeout surfaces instead of a
 * generic transport failure.
 */
async function callAIBridge({ authHeader, payload }) {
  try {
    const response = await axios({
      method: 'post',
      url: `${contract.AIBRIDGE_BASE_URL}/v1/chat/completions`,
      data: payload,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'LibreChat/1.0',
        ...(authHeader ? { Authorization: authHeader } : {}),
      },
      timeout: contract.AIBRIDGE_TIMEOUT_MS,
    });
    const content = response?.data?.choices?.[0]?.message?.content;
    if (typeof content !== 'string' || !content.trim()) {
      throw new contract.DocumentVisualQAError(
        contract.ERR.VQA_AI_BRIDGE_ERROR,
        'empty vision model content',
      );
    }
    return content;
  } catch (error) {
    if (error instanceof contract.DocumentVisualQAError) {
      throw error;
    }
    const status = error?.response?.status;
    throw new contract.DocumentVisualQAError(
      contract.ERR.VQA_AI_BRIDGE_ERROR,
      status ? `HTTP ${status}` : (error?.message ?? String(error)),
    );
  }
}

/** Extracts a 1-based page number from a rendered page path (e.g. "...-003.png" -> 3). */
function pageFromName(name) {
  const match = String(name).match(/(\d+)\.\w+$/);
  const num = match ? Number(match[1]) : NaN;
  return Number.isInteger(num) && num >= 1 ? num : 1;
}

/**
 * Resolves the page refs to inspect.
 * Primary: `file_ids` (codeapi ids). Fallback: `file_names` resolved to
 * codeapi ids via the LibreChat files collection (`metadata.codeEnvRef`).
 */
async function resolveFileRefs({ req, sessionId, fileIds, fileNames, getFilesImpl }) {
  if (Array.isArray(fileIds) && fileIds.length > 0) {
    return fileIds.map((fileId, idx) => ({
      sessionId,
      fileId: String(fileId),
      name: String(fileId),
      page: idx + 1,
    }));
  }

  if (Array.isArray(fileNames) && fileNames.length > 0) {
    const docs = await getFilesImpl({
      user: req?.user?.id,
      'metadata.codeEnvRef.storage_session_id': sessionId,
    });
    const fileIdByName = new Map();
    for (const file of docs ?? []) {
      const ref = file?.metadata?.codeEnvRef;
      if (ref?.file_id && typeof file?.filename === 'string' && !fileIdByName.has(file.filename)) {
        fileIdByName.set(file.filename, ref.file_id);
      }
    }
    const refs = [];
    const missing = [];
    for (const name of fileNames) {
      const fileName = String(name);
      const fileId = fileIdByName.get(fileName);
      if (fileId) {
        refs.push({ sessionId, fileId, name: fileName, page: pageFromName(fileName) });
      } else {
        missing.push(fileName);
      }
    }
    if (refs.length === 0) {
      throw new contract.DocumentVisualQAError(
        contract.ERR.VQA_NO_FILE_REFS,
        `no file in session ${sessionId} matched ${JSON.stringify(missing.slice(0, 5))}`,
      );
    }
    return refs;
  }

  throw new contract.DocumentVisualQAError(contract.ERR.VQA_NO_FILE_REFS);
}

/**
 * Core tool logic. Transport functions come from `deps` (real by default) so
 * the unit suite can stub every network boundary.
 *
 * @returns {Promise<string>} formatted verdict text (or a coded error string).
 */
async function runDocumentVisualQA({ req, session_id, file_ids, file_names, focus, maxPages, deps = {} }) {
  const downloadPageImpl = deps.downloadPage ?? ((sessionId, fileId) => downloadCodePage(req, sessionId, fileId));
  const callAIBridgeImpl = deps.callAIBridge ?? ((params) => callAIBridge(params));
  const getFilesImpl = deps.getFiles ?? getFiles;
  const downscaleImpl = deps.downscalePage ?? downscalePage;
  const resolveAuthImpl = deps.resolveAIBridgeAuth ?? (() => resolveAIBridgeAuth(req));

  if (typeof session_id !== 'string' || !session_id.trim()) {
    throw new contract.DocumentVisualQAError(contract.ERR.VQA_INVALID_INPUT, 'session_id is required');
  }
  const sessionId = session_id.trim();

  const refs = await resolveFileRefs({
    req,
    sessionId,
    fileIds: file_ids,
    fileNames: file_names,
    getFilesImpl,
  });
  if (refs.length === 0) {
    throw new contract.DocumentVisualQAError(contract.ERR.VQA_NO_FILE_REFS);
  }
  if (refs.length > contract.MAX_TOTAL_PAGES) {
    throw new contract.DocumentVisualQAError(
      contract.ERR.VQA_TOO_MANY_PAGES,
      `requested ${refs.length} pages (cap ${contract.MAX_TOTAL_PAGES})`,
    );
  }

  const authHeader = resolveAuthImpl();
  if (!authHeader) {
    throw new contract.DocumentVisualQAError(contract.ERR.VQA_AUTH_UNRESOLVED);
  }

  const batchSize = contract.normalizePageLimit(maxPages);
  const batchBudget = Math.floor(
    (contract.MAX_BODY_BYTES / batchSize) * contract.BODY_BUDGET_SAFETY,
  );

  const batches = contract.batchRefs(refs, batchSize);
  const overallDeadlineMs = deps.overallDeadlineMs ?? contract.QA_OVERALL_DEADLINE_MS;
  const deadline = Date.now() + overallDeadlineMs;
  const verdicts = [];
  for (const batch of batches) {
    if (Date.now() > deadline) {
      throw new contract.DocumentVisualQAError(
        contract.ERR.VQA_OVERALL_TIMEOUT,
        `QA wall-clock budget of ${Math.round(overallDeadlineMs / 1000)}s exceeded`,
      );
    }
    const pages = [];
    for (const ref of batch) {
      // Defensive wrapping at the tool boundary: a transport that leaks a raw
      // error must surface as a coded error, never crash the tool call.
      let raw;
      try {
        raw = await downloadPageImpl(ref.sessionId, ref.fileId);
      } catch (error) {
        if (error instanceof contract.DocumentVisualQAError) {
          throw error;
        }
        throw new contract.DocumentVisualQAError(
          contract.ERR.VQA_PAGE_FETCH_FAILED,
          error?.message ?? String(error),
        );
      }
      let resized;
      try {
        resized = await downscaleImpl(raw, batchBudget);
      } catch (error) {
        if (error instanceof contract.DocumentVisualQAError) {
          throw error;
        }
        throw new contract.DocumentVisualQAError(
          contract.ERR.VQA_PAGE_DOWNSCALE_FAILED,
          error?.message ?? String(error),
        );
      }
      pages.push({
        name: ref.name,
        page: ref.page,
        mimeType: 'image/png',
        base64: resized.base64,
      });
    }
    const pageMap = pages.map((p) => ({ artifact: p.name, page: p.page }));
    const prompt = contract.buildQAPrompt({ focus, pageMap });
    const payload = contract.buildVisionPayload({ prompt, pages });
    let content;
    try {
      content = await callAIBridgeImpl({ authHeader, payload });
    } catch (error) {
      if (error instanceof contract.DocumentVisualQAError) {
        throw error;
      }
      throw new contract.DocumentVisualQAError(
        contract.ERR.VQA_AI_BRIDGE_ERROR,
        error?.message ?? String(error),
      );
    }
    const verdict = contract.parseVerdict(content, {
      artifact: pages[0]?.name,
      page: pages[0]?.page,
    });
    // Vision models sometimes echo a generic image label (e.g. "image.png")
    // instead of the artifact name from the page map; reconcile so the
    // offending-artifact list always points at the real rendered file.
    verdicts.push(contract.reconcileArtifactNames(verdict, pageMap));
  }

  const overall = contract.combineVerdicts(verdicts);
  return contract.formatVerdict(overall);
}

/**
 * Factory for the runtime tool instance used by ToolService.
 * @param {{req: object, deps?: object}} params
 */
function createDocumentVisualQATool({ req, deps }) {
  // Deep-clone the frozen canonical schema: langchain's @cfworker/json-schema
  // validation dereferences the schema IN PLACE (mutating nodes with
  // `__absolute_uri__`), which throws on a frozen object. The contract module
  // stays frozen/self-documenting; the runtime tool gets a mutable working copy.
  const schema = JSON.parse(JSON.stringify(contract.TOOL_PARAMETERS));
  return new DynamicStructuredTool({
    name: contract.TOOL_NAME,
    description: TOOL_DESCRIPTION,
    schema,
    responseFormat: 'content',
    func: async (args) => {
      try {
        return await runDocumentVisualQA({ req, deps, ...args });
      } catch (error) {
        if (error instanceof contract.DocumentVisualQAError) {
          // Clean coded failure — the model sees `[CODE] message` and can
          // self-correct (e.g. re-call with valid refs) instead of the run
          // crashing.
          return `[${error.code}] ${error.message}`;
        }
        throw error;
      }
    },
  });
}

module.exports = {
  createDocumentVisualQATool,
  runDocumentVisualQA,
  resolveAIBridgeAuth,
  downloadCodePage,
  downscalePage,
  callAIBridge,
  resolveFileRefs,
  pageFromName,
  TOOL_DESCRIPTION,
};

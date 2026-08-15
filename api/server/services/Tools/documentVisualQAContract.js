'use strict';

/**
 * 8S3C R3 — document_visual_qa contract (issue #8).
 *
 * Dependency-free, pure source of truth for the machine-readable Vision QA
 * contract spoken by the `document_visual_qa` tool. The runtime tool
 * (`./documentVisualQA.js`) composes this module with the CodeAPI + aibridge
 * transports; the unit tests (`./documentVisualQA.spec.js`) exercise only the
 * pure logic here (verdict validation, payload construction, defensive
 * parsing, batching). The model-facing tool definition in
 * `packages/api/src/agents/tools.ts` mirrors `TOOL_PARAMETERS` exactly.
 *
 * Stable contract — do not rename input keys or verdict fields without
 * bumping CONTRACT_VERSION and updating `docs/r3-vision-qa.md`.
 */

const CONTRACT_VERSION = 'document_visual_qa/1';

/** Tool name — must match the `Tools` enum value in librechat-data-provider. */
const TOOL_NAME = 'document_visual_qa';

/** Vision model routed through the EXISTING aibridge vision path. */
const VISION_MODEL = 'glm-5v-turbo';

/**
 * aibridge base URL as seen from the LibreChat api container. The api
 * container and aibridge share the default compose network, so the service
 * name resolves directly. Overridable via env for test/local runs.
 */
const AIBRIDGE_BASE_URL = process.env.AIBRIDGE_BASE_URL || 'http://aibridge:4103';

/** Hard cap on the aibridge request body (mirrors aibridge MAX_BODY_BYTES). */
const MAX_BODY_BYTES = 32 << 20; // 32 MiB

/**
 * Per-batch upstream timeout, kept well under aibridge VISION_TIMEOUT_MS
 * (120s) so a hung vision call fails inside the tool's own budget instead of
 * tripping an outer step timeout.
 */
const AIBRIDGE_TIMEOUT_MS = 90_000;

/** Page batching defaults/caps (see TOOL_PARAMETERS). */
const DEFAULT_MAX_PAGES = 4;
const MAX_PAGES_CAP = 8;
/** Absolute cap on pages inspected per single tool call (3 batches of 8). */
const MAX_TOTAL_PAGES = 24;

/** Longest-edge target when downscaling a rendered page before base64. */
const PAGE_MAX_DIM = 1024;

/** Data-URL prefix for the image parts. */
const DATA_URL_PREFIX = 'data:image/png;base64,';

/**
 * Fraction of the per-batch body budget reserved for JSON framing overhead
 * (prompt text, message envelope, multi-byte chars in base64) so a batch
 * never drifts past MAX_BODY_BYTES.
 */
const BODY_BUDGET_SAFETY = 0.75;

/** Coded errors. `.code` is stable — the model and tests match on it. */
const ERR = Object.freeze({
  VQA_INVALID_INPUT: {
    code: 'VQA_INVALID_INPUT',
    message: 'tool inputs failed validation',
  },
  VQA_NO_FILE_REFS: {
    code: 'VQA_NO_FILE_REFS',
    message: 'no file_ids or file_names supplied, or none matched the session',
  },
  VQA_TOO_MANY_PAGES: {
    code: 'VQA_TOO_MANY_PAGES',
    message: `page count exceeds the hard cap of ${MAX_TOTAL_PAGES} per tool call`,
  },
  VQA_PAGE_FETCH_FAILED: {
    code: 'VQA_PAGE_FETCH_FAILED',
    message: 'could not fetch a rendered page from the sandbox workspace',
  },
  VQA_PAGE_DOWNSCALE_FAILED: {
    code: 'VQA_PAGE_DOWNSCALE_FAILED',
    message: 'could not downscale a rendered page',
  },
  VQA_PAGE_TOO_LARGE: {
    code: 'VQA_PAGE_TOO_LARGE',
    message: 'a rendered page could not be sized under the body budget',
  },
  VQA_AUTH_UNRESOLVED: {
    code: 'VQA_AUTH_UNRESOLVED',
    message: 'aibridge auth key could not be resolved',
  },
  VQA_AI_BRIDGE_ERROR: {
    code: 'VQA_AI_BRIDGE_ERROR',
    message: 'aibridge vision call failed',
  },
  VQA_PARSE_FAILED: {
    code: 'VQA_PARSE_FAILED',
    message: 'vision model verdict could not be parsed',
  },
});

class DocumentVisualQAError extends Error {
  constructor(codedError, detail) {
    super(detail ? `${codedError.message}: ${detail}` : codedError.message);
    this.name = 'DocumentVisualQAError';
    this.code = codedError.code;
    this.coded = codedError;
  }
}

/**
 * Model-facing JSON Schema — self-documenting exact input keys. The tool
 * function validates defensively (DynamicStructuredTool does not enforce
 * `required`), but this schema is what the model plans against.
 */
const TOOL_PARAMETERS = Object.freeze({
  type: 'object',
  properties: {
    session_id: {
      type: 'string',
      description:
        'CodeAPI execution session id returned by the render/exec step whose sandbox workspace contains the rendered PNG pages. Do not invent this value; take it verbatim from the render step output.',
    },
    file_ids: {
      type: 'array',
      items: { type: 'string' },
      description:
        'CodeAPI file ids of the rendered PNG pages to QA (the .png entries in the render/exec step artifact refs). Provide exactly one of file_ids or file_names.',
    },
    file_names: {
      type: 'array',
      items: { type: 'string' },
      description:
        'Relative sandbox workspace paths of the rendered PNG pages, e.g. "render-out/pages/report-001.png" as listed in the render manifest outputs[].path. Used when only the names are known; the tool resolves them to codeapi file ids for the given session.',
    },
    focus: {
      type: 'string',
      description:
        'Optional comma-separated QA focus areas. Supported: clipping, overlap, hierarchy, charts, legibility, layout. Defaults to all six.',
    },
    maxPages: {
      type: 'integer',
      minimum: 1,
      maximum: 8,
      default: 4,
      description:
        'Maximum pages to inspect per vision pass. Pages are sent to the vision model in batches of at most this size (hard cap 8, default 4). Documents with more pages than this should be QA\'d in multiple calls.',
    },
  },
  required: ['session_id'],
});

/**
 * Builds the QA instruction text sent as the user text part of the vision
 * message (the page images travel as image_url parts alongside it).
 *
 * `pageMap` is an ordered array of `{ artifact, page }` for the attached
 * images; the vision model reports absolute document page numbers (and
 * artifact names) from this map instead of guessing by image position.
 */
function buildQAPrompt({ focus, pageMap } = {}) {
  const focusLine =
    typeof focus === 'string' && focus.trim()
      ? `\nFocus areas for this pass: ${focus.trim()}.`
      : '';
  const mapLine =
    Array.isArray(pageMap) && pageMap.length > 0
      ? `\nThe attached images correspond to these artifacts and absolute document page numbers, in order:\n${pageMap
          .map((p) => `- image ${p.index ?? p.artifact}: artifact "${p.artifact}", page ${p.page}`)
          .join('\n')}\nReport "artifact" as the listed file name and "page" as the listed absolute page number (never image position).`
      : '';
  return [
    'You are a professional document layout QA inspector. Examine the rendered page image(s) attached to this message.',
    'Check each page for:',
    '- Clipping: text, shapes, or table columns cut off at page/slide edges or overlapping container boundaries.',
    '- Overlap: text boxes, shapes, or table cells overlapping when they should be separated.',
    '- Visual hierarchy: headings not visually distinct from body text, or inconsistent alignment/spacing.',
    '- Unreadable charts/tables: tiny fonts, legend cut off, axis labels overlapping, data bars clipped.',
    '- Malformed layouts: elements off-canvas, broken tables, images spilling outside their containers.',
    '- Legibility: low-contrast text, text overflowing its box, truncated labels.',
    focusLine,
    mapLine,
    '',
    'Respond with ONE strict JSON object and nothing else — no markdown fences, no commentary, no trailing prose. Schema:',
    '{"verdict":"PASS"|"ISSUES_FOUND","issues":[{"artifact":"<png file name>","page":<1-based page number>,"severity":"low"|"medium"|"high","description":"<what is wrong>","suggestion":"<how to fix it>"}],"summary":"<one or two sentence overall assessment>"}',
    '',
    'Rules:',
    '- verdict is "PASS" only when every inspected page has no clipping/overlap/hierarchy/legibility/layout problems.',
    '- Report every distinct problem found; up to a handful of issues per page is fine.',
    '- "page" is the 1-based page number of the artifact within the rendered document.',
    '- "severity": high = visually broken/unreadable, medium = clearly noticeable defect, low = minor polish.',
    '- If the image(s) cannot be read at all, set verdict "ISSUES_FOUND" with one high-severity issue and description "page image unreadable".',
  ].join('\n');
}

/**
 * Builds the aibridge chat-completions body.
 * @param {{prompt: string, pages: Array<{name: string, page: number, mimeType?: string, base64: string}>, model?: string}} args
 */
function buildVisionPayload({ prompt, pages, model = VISION_MODEL }) {
  const content = [{ type: 'text', text: prompt }];
  for (const page of pages) {
    content.push({
      type: 'image_url',
      image_url: {
        url: `data:${page.mimeType || 'image/png'};base64,${page.base64}`,
      },
    });
  }
  return {
    model,
    temperature: 0.2,
    max_tokens: 4096,
    messages: [{ role: 'user', content }],
  };
}

/**
 * Clamps a requested `maxPages` into [1, MAX_PAGES_CAP]. Numeric strings
 * (e.g. "4" from a lax model) are coerced; anything else falls back to
 * DEFAULT_MAX_PAGES.
 */
function normalizePageLimit(value) {
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) {
    value = Number(value);
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return DEFAULT_MAX_PAGES;
  }
  return Math.max(1, Math.min(MAX_PAGES_CAP, Math.floor(value)));
}

/** Splits a page-ref array into batches of at most `batchSize`. */
function batchRefs(refs, batchSize) {
  const size = normalizePageLimit(batchSize);
  const batches = [];
  for (let i = 0; i < refs.length; i += size) {
    batches.push(refs.slice(i, i + size));
  }
  return batches;
}

const SEVERITIES = new Set(['low', 'medium', 'high']);

/**
 * Coerces one raw issue object into the verdict contract shape. Non-objects
 * are dropped; missing/invalid fields fall back to safe defaults so a model
 * with slightly-off output still yields a usable verdict.
 */
function sanitizeIssue(raw, fallbackArtifact = '(unknown)', fallbackPage = 1) {
  if (!raw || typeof raw !== 'object') {
    return null;
  }
  const artifact =
    typeof raw.artifact === 'string' && raw.artifact.trim()
      ? raw.artifact.trim()
      : fallbackArtifact;
  const page = Number.isInteger(raw.page) && raw.page >= 1 ? raw.page : fallbackPage;
  const severity = SEVERITIES.has(raw.severity) ? raw.severity : 'medium';
  const description =
    typeof raw.description === 'string' && raw.description.trim()
      ? raw.description.trim()
      : '(no description)';
  const suggestion = typeof raw.suggestion === 'string' ? raw.suggestion.trim() : '';
  return { artifact, page, severity, description, suggestion };
}

/**
 * Defensively parses a vision-model response into the verdict contract.
 * Tries, in order: raw JSON.parse, markdown-fence-stripped JSON, then the
 * first {...} block. Throws DocumentVisualQAError(VQA_PARSE_FAILED) when no
 * object can be recovered.
 */
function parseVerdict(text, fallback = {}) {
  if (typeof text !== 'string') {
    throw new DocumentVisualQAError(ERR.VQA_PARSE_FAILED, 'non-string content');
  }
  const trimmed = text.trim();
  if (!trimmed) {
    throw new DocumentVisualQAError(ERR.VQA_PARSE_FAILED, 'empty content');
  }

  const stripFences = (s) => s.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

  const candidates = [stripFences(trimmed)];
  const braceMatch = trimmed.match(/\{[\s\S]*\}/);
  if (braceMatch) {
    candidates.push(stripFences(braceMatch[0]));
  }

  let obj = null;
  for (const candidate of candidates) {
    try {
      obj = JSON.parse(candidate);
      break;
    } catch {
      /* try next candidate */
    }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new DocumentVisualQAError(ERR.VQA_PARSE_FAILED, 'no JSON object found in model output');
  }

  const fallbackArtifact = typeof fallback.artifact === 'string' ? fallback.artifact : '(unknown)';
  const fallbackPage = Number.isInteger(fallback.page) && fallback.page >= 1 ? fallback.page : 1;

  let verdict = obj.verdict;
  if (verdict !== 'PASS' && verdict !== 'ISSUES_FOUND') {
    verdict = Array.isArray(obj.issues) && obj.issues.length > 0 ? 'ISSUES_FOUND' : 'PASS';
  }
  const issues = Array.isArray(obj.issues)
    ? obj.issues
        .map((i) => sanitizeIssue(i, fallbackArtifact, fallbackPage))
        .filter(Boolean)
    : [];
  const summary =
    typeof obj.summary === 'string' && obj.summary.trim() ? obj.summary.trim() : '';

  // A model that says PASS must not carry issues; a model that says
  // ISSUES_FOUND must carry at least one.
  if (verdict === 'PASS') {
    return { verdict, issues: [], summary };
  }
  if (issues.length === 0) {
    return {
      verdict,
      issues: [
        {
          artifact: fallbackArtifact,
          page: fallbackPage,
          severity: 'high',
          description: 'Vision model reported ISSUES_FOUND but returned no structured issues.',
          suggestion: '',
        },
      ],
      summary,
    };
  }
  return { verdict, issues, summary };
}

/**
 * Reconciles issue artifact names against the page map. Vision models
 * sometimes report a generic image label (e.g. "image.png") instead of echoing
 * the artifact name the page map tells them to use. When an issue's artifact is
 * not one of the known page-map artifacts, substitute the mapped artifact for
 * the issue's (1-based) page so the offending-artifact list stays actionable.
 * Unknown artifacts on unknown pages are left untouched.
 */
function reconcileArtifactNames(verdict, pageMap = []) {
  const map = new Map();
  for (const entry of pageMap) {
    if (typeof entry.artifact === 'string' && Number.isInteger(entry.page)) {
      map.set(entry.page, entry.artifact);
    }
  }
  const known = new Set(map.values());
  const issues = (verdict?.issues ?? []).map((issue) => {
    if (!issue || (typeof issue.artifact === 'string' && known.has(issue.artifact))) {
      return issue;
    }
    const mapped = Number.isInteger(issue?.page) ? map.get(issue.page) : undefined;
    return mapped ? { ...issue, artifact: mapped } : issue;
  });
  return { ...verdict, issues };
}

/**
 * Merges per-batch verdicts into one overall verdict. Any batch that is
 * ISSUES_FOUND makes the overall verdict ISSUES_FOUND; summaries are joined.
 */
function combineVerdicts(verdicts) {
  const all = verdicts.filter(Boolean);
  if (all.length === 0) {
    return {
      verdict: 'PASS',
      issues: [],
      summary: 'No pages inspected.',
    };
  }
  const issues = all.flatMap((v) => v.issues ?? []);
  const summaries = all.map((v) => (v.summary ? v.summary.trim() : '')).filter(Boolean);
  const hasIssues = all.some((v) => v.verdict === 'ISSUES_FOUND') || issues.length > 0;
  return {
    verdict: hasIssues ? 'ISSUES_FOUND' : 'PASS',
    issues: hasIssues ? issues : [],
    summary:
      summaries.length > 0
        ? summaries.join(' | ')
        : hasIssues
          ? 'Issues were found across the inspected pages.'
          : 'No clipping, overlap, hierarchy, chart, layout, or legibility problems detected.',
  };
}

/**
 * Human-readable tool output text. Always ends with the authoritative verdict
 * JSON so the model can re-derive structured facts without re-calling.
 */
function formatVerdict(verdict) {
  const lines = [];
  lines.push(`QA VERDICT: ${verdict.verdict}`);
  if (verdict.summary) {
    lines.push(`Summary: ${verdict.summary}`);
  }
  if (verdict.issues && verdict.issues.length > 0) {
    lines.push('Issues:');
    for (const issue of verdict.issues) {
      lines.push(
        `- [page ${issue.page}][${issue.severity}] ${issue.artifact}: ${issue.description}` +
          (issue.suggestion ? ` (suggestion: ${issue.suggestion})` : ''),
      );
    }
  }
  lines.push(`RAW: ${JSON.stringify(verdict)}`);
  return lines.join('\n');
}

module.exports = {
  CONTRACT_VERSION,
  TOOL_NAME,
  VISION_MODEL,
  AIBRIDGE_BASE_URL,
  MAX_BODY_BYTES,
  AIBRIDGE_TIMEOUT_MS,
  DEFAULT_MAX_PAGES,
  MAX_PAGES_CAP,
  MAX_TOTAL_PAGES,
  PAGE_MAX_DIM,
  DATA_URL_PREFIX,
  BODY_BUDGET_SAFETY,
  ERR,
  DocumentVisualQAError,
  TOOL_PARAMETERS,
  buildQAPrompt,
  buildVisionPayload,
  normalizePageLimit,
  batchRefs,
  sanitizeIssue,
  parseVerdict,
  reconcileArtifactNames,
  combineVerdicts,
  formatVerdict,
};

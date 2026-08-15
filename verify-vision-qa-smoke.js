#!/usr/bin/env node
'use strict';

/**
 * 8S3C R3 — live Vision QA smoke (issue #8).
 *
 * Proves the EXISTING aibridge vision path end-to-end WITHOUT the LibreChat api
 * process:
 *
 *   1. RENDER — starts a THROWAWAY `cbhr-codeapi:d9dba74e8066` container on a
 *      different host port, with the SAME seccomp profile and env shape as
 *      production (no isolation weakened), generates a GROUND-TRUTH MALFORMED
 *      pptx with pptxgenjs (text box clipped past the right slide edge + a
 *      bright overlapping box on top of a table), and renders it to PNG inside
 *      the EXACT child context the /exec path uses (runuser -> unshare -Urn,
 *      loopback-only netns) via the R2 renderer (`render-doc.sh`).
 *   2. VISION — from the HOST, POSTs the real QA prompt (the tool's
 *      `buildQAPrompt`, including the artifact/page map) plus the rendered page
 *      as a PNG data URL to `http://127.0.0.1:4103/v1/chat/completions`
 *      (aibridge -> LiteLLM -> z.ai glm-5v-turbo) with the RESOLVED aibridge
 *      auth key, then parses the strict-JSON verdict with the tool's
 *      `parseVerdict`/`formatVerdict`.
 *   3. ASSERT — the planted clipping/overlap defects are reported
 *      (verdict ISSUES_FOUND).
 *
 * The aibridge key is resolved exactly the way the runtime tool resolves it:
 * `extractEnvVariable` over `dotenv`-loaded `process.env` (dotenv-order-safe).
 * The key/Authorization header is NEVER printed, logged, or written to disk.
 *
 * This smoke exercises the SAME shipped contract module
 * (`api/server/services/Tools/documentVisualQAContract.js`) used by the tool,
 * so the QA prompt text, payload shape and verdict parser under test are
 * byte-identical to production.
 *
 * Isolation: the throwaway container is removed on exit; production containers
 * (`codeapi`, `aibridge`, `LibreChat`, `litellm`) are never touched; no
 * production key material is generated here (a fresh disposable ed25519 pair is
 * used for the throwaway codeapi JWT).
 *
 * Usage:
 *   node verify-vision-qa-smoke.js
 *   VQA_SMOKE_PORT=4222 node verify-vision-qa-smoke.js   # different throwaway port
 *
 * Exit code 0 = smoke passed; non-zero = failed (diagnostic printed).
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const IMAGE = process.env.VQA_SMOKE_IMAGE || 'cbhr-codeapi:d9dba74e8066';
const HOST_PORT = process.env.VQA_SMOKE_PORT || '4221';
const CONTAINER = 'r3-vqa-smoke';
const R2_REPO = '/opt/cbhr-ai/codeapi-wt-r2';
const SECCOMP = path.join(R2_REPO, 'seccomp-codeapi.json');
const CHILD_RUNNER = path.join(R2_REPO, 'scripts', 'r2-child-runner.sh');
const LIBRECHAT_ENV = '/opt/cbhr-ai/LibreChat/.env';
const AIBRIDGE_URL = (process.env.AIBRIDGE_URL || 'http://127.0.0.1:4103').replace(/\/+$/, '');

if (HOST_PORT === '4101' || HOST_PORT === '4103' || HOST_PORT === '4220') {
  console.error(`FATAL: VQA_SMOKE_PORT ${HOST_PORT} collides with a production/verify port.`);
  process.exit(2);
}

// ---- tiny harness ----------------------------------------------------------
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'vqa-smoke-'));
const KEYDIR = path.join(TMP, 'keys');
fs.mkdirSync(KEYDIR, { recursive: true });
let failed = 0;
let passed = 0;

function ok(label) { passed++; console.log(`  PASS  ${label}`); }
function bad(label) { failed++; console.log(`  FAIL  ${label}`); }

function sh(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', ...opts }).trim();
}

function shTry(cmd, args) {
  try {
    return { ok: true, out: sh(cmd, args) };
  } catch (e) {
    return { ok: false, out: String(e.stdout || '').trim(), err: String(e.stderr || e.message).trim() };
  }
}

/** Runs docker; returns {ok, out, err}. */
function docker(args) { return shTry('docker', args); }
function dockerOk(args) { const r = docker(args); if (!r.ok) throw new Error(`docker ${args[0]} failed: ${r.err} ${r.out}`); return r.out; }

const cleanup = () => {
  docker(['rm', '-f', CONTAINER]);
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* best effort */ }
};
function cleanupExit(code = 1) { cleanup(); process.exit(code); }

async function main() {
// ---- 0) preconditions ------------------------------------------------------
console.log(`== preconditions`);
if (!fs.existsSync(SECCOMP)) { console.error(`FATAL: seccomp profile missing: ${SECCOMP}`); process.exit(2); }
if (!fs.existsSync(CHILD_RUNNER)) { console.error(`FATAL: child runner missing: ${CHILD_RUNNER}`); process.exit(2); }
if (!fs.existsSync(LIBRECHAT_ENV)) { console.error(`FATAL: LibreChat env missing: ${LIBRECHAT_ENV}`); process.exit(2); }

const img = docker(['image', 'inspect', IMAGE]);
if (!img.ok) { bad(`${IMAGE} not present (run the R2 renderer build first)`); cleanupExit(); }
else ok(`throwaway image present: ${IMAGE}`);

const aiCheck = dockerOk(['ps', '--filter', 'name=aibridge', '--format', '{{.Names}}']).trim();
if (aiCheck !== 'aibridge') { bad('aibridge container not running'); cleanupExit(); }
else ok('aibridge running');

const keyCheck = shTry('node', ['-e', "require('dotenv').config({path:process.argv[1]});const v=process.env.LITELLM_MASTER_KEY;console.log(v&&v.trim()&&v!=='${LITELLM_MASTER_KEY}'?'RESOLVED':'UNRESOLVED')", LIBRECHAT_ENV]);
if (keyCheck.ok && keyCheck.out === 'RESOLVED') ok('aibridge auth key resolves (value never printed)');
else { bad(`aibridge auth key UNRESOLVED (${keyCheck.err || keyCheck.out})`); cleanupExit(); }

// ---- 1) render the ground-truth malformed fixture --------------------------
console.log(`== throwaway codeapi render (${IMAGE})`);
dockerOk(['rm', '-f', CONTAINER]);

try {
  sh('openssl', ['genpkey', '-algorithm', 'ed25519', '-out', path.join(KEYDIR, 'private.pem')]);
  sh('openssl', ['pkey', '-in', path.join(KEYDIR, 'private.pem'), '-pubout', '-out', path.join(KEYDIR, 'test.pub.pem')]);
} catch (e) {
  bad(`keypair generation failed: ${e.message}`);
  cleanupExit();
}

const run = docker([
  'run', '-d', '--rm', '--name', CONTAINER,
  '--security-opt', `seccomp:${SECCOMP}`,
  '-p', `127.0.0.1:${HOST_PORT}:4100`,
  '-e', 'CODEAPI_JWT_PUBLIC_KEY_DIR=/run/secrets/keys',
  '-e', `BUILD_COMMIT=${IMAGE.split(':')[1] || 'unknown'}`,
  '-v', `${KEYDIR}:/run/secrets/keys:ro`,
  '-v', `${R2_REPO}:/repo:ro`,
  IMAGE,
]);
if (!run.ok) { bad(`throwaway container start failed: ${run.err} ${run.out}`); cleanupExit(); }
ok('throwaway codeapi container started');

let healthy = false;
for (let i = 0; i < 60; i++) {
  const h = shTry('curl', ['-fsS', `http://127.0.0.1:${HOST_PORT}/health`]);
  if (h.ok) { healthy = true; break; }
  require('child_process').spawnSync('sleep', ['1']);
}
if (!healthy) {
  bad(`throwaway container did not become healthy`);
  const logs = docker(['logs', CONTAINER]).out;
  console.error(logs.slice(0, 2000));
  cleanupExit();
}
ok(`throwaway /health up on 127.0.0.1:${HOST_PORT}`);

// stage a workdir + the pptxgenjs fixture generator
const stageScript = `
set -e
useradd -m r2tester 2>/dev/null || true
WORK=/home/r2tester/work
rm -rf "$WORK"; mkdir -p "$WORK"
cp /repo/scripts/r2-child-runner.sh /home/r2tester/r2-child-runner.sh
chown r2tester:r2tester /home/r2tester/r2-child-runner.sh
chown -R r2tester:r2tester "$WORK"
`;
const stage = docker(['exec', CONTAINER, 'bash', '-c', stageScript]);
if (!stage.ok) { bad(`fixture staging failed: ${stage.err} ${stage.out}`); cleanupExit(); }

// the GROUND-TRUTH MALFORMED fixture: clipping past the right slide edge + a
// bright overlapping box drawn on top of a table (two unmissable defects).
const genSource = `'use strict';
const pptxgen = require('pptxgenjs');
(async () => {
  const pptx = new pptxgen();
  pptx.defineLayout({ name: 'WIDE', width: 10, height: 7.5 });
  pptx.layout = 'WIDE';
  const slide = pptx.addSlide();
  slide.background = { color: 'FFFFFF' };
  slide.addText('MALFORMED QA FIXTURE', { x: 0.4, y: 0.3, w: 9, h: 0.7, fontSize: 30, bold: true, color: '1F3864', fontFace: 'Arial' });
  // DEFECT 1 — CLIPPING: text box begins at x=6.2in and is 5.5in wide, so it
  // extends past the 10in slide edge; words after the boundary are physically
  // cut off at the right edge of the rendered page.
  slide.addText(
    'RIGHT-EDGE CLIPPING FIXTURE: this long paragraph is placed in a text box that starts at x=6.2 inches and is 5.5 inches wide, so it runs well past the 10 inch right edge of the slide. Every word after the page boundary is physically cut off and must not be readable.',
    { x: 6.2, y: 1.6, w: 5.5, h: 2.2, fontSize: 18, color: 'C00000', fontFace: 'Arial' }
  );
  // A normal table (added first so the overlap box renders ON TOP).
  slide.addTable(
    [
      [{ text: 'Item', options: { bold: true, fill: { color: 'D9E2F3' } } }, { text: 'Qty', options: { bold: true, fill: { color: 'D9E2F3' } } }, { text: 'Price', options: { bold: true, fill: { color: 'D9E2F3' } } }],
      ['Widget A', '3', '$12.00'],
      ['Widget B', '7', '$4.50'],
    ],
    { x: 0.5, y: 4.1, w: 6.0, h: 1.6, border: { type: 'solid', pt: 1, color: '404040' }, fontSize: 14 }
  );
  // DEFECT 2 — OVERLAP: bright yellow box drawn on top of the table's header row.
  slide.addText('OVERLAP DEFECT', {
    x: 0.6, y: 4.15, w: 2.6, h: 0.5, fontSize: 14, bold: true, color: '7F6000',
    fill: { color: 'FFE699' }, align: 'center',
  });
  slide.addText('This is a ground-truth malformed fixture for the vision QA smoke test.', { x: 0.5, y: 6.4, w: 9, h: 0.5, fontSize: 12, color: '595959' });
  await pptx.writeFile({ fileName: '/home/r2tester/work/malformed.pptx' });
  console.log('fixture written');
})();
`;
const genFile = path.join(TMP, 'gen-fixture.js');
fs.writeFileSync(genFile, genSource);
dockerOk(['cp', genFile, `${CONTAINER}:/home/r2tester/gen-fixture.js`]);
dockerOk(['exec', CONTAINER, 'chown', 'r2tester:r2tester', '/home/r2tester/gen-fixture.js']);

const gen = docker(['exec', CONTAINER, 'node', '/home/r2tester/gen-fixture.js']);
if (!gen.ok) { bad(`pptxgenjs fixture generation failed: ${gen.err} ${gen.out}`); cleanupExit(); }
else ok('ground-truth malformed pptx generated (pptxgenjs)');

// render in the EXACT child context (runuser -> unshare -Urn -> seccomp)
const child = docker(['exec', CONTAINER, 'bash', '-c',
  'cd /home/r2tester/work && runuser -u r2tester -- /usr/bin/unshare -Urn -- /bin/bash /home/r2tester/r2-child-runner.sh render-out malformed.pptx']);
const childOut = child.ok ? child.out : `${child.err}\n${child.out}`;
const rc = (childOut.match(/^RC=(\d+)/m) || [])[1];
const mfLine = (childOut.match(/^MFJSON=(\{.*\})/m) || [])[1];
if (rc !== '0' || !mfLine) {
  bad(`render-doc.sh rc=${rc || '?'} (output below)`);
  console.error(childOut.slice(0, 2000));
  cleanupExit();
}
let manifest;
try { manifest = JSON.parse(mfLine); } catch { bad(`manifest parse failed`); cleanupExit(); }
if (manifest.status === 'ok' && manifest.pageCount >= 1 && (manifest.outputs || []).some((o) => o.kind === 'png')) {
  ok(`render ok: pageCount=${manifest.pageCount} outputs=${manifest.outputs.map((o) => o.kind).join(',')}`);
} else {
  bad(`render not ok: status=${manifest.status} pageCount=${manifest.pageCount}`);
  cleanupExit();
}

const pngPath = (manifest.outputs.find((o) => o.kind === 'png') || {}).path;
if (!pngPath) { bad('no png in manifest outputs'); cleanupExit(); }
// outputs[].path is relative to the render outdir (render-out).
dockerOk(['cp', `${CONTAINER}:/home/r2tester/work/render-out/${pngPath}`, path.join(TMP, 'page.png')]);
const pngBuf = fs.readFileSync(path.join(TMP, 'page.png'));
ok(`rendered page fetched from sandbox: ${pngPath} (${pngBuf.length} bytes)`);

// ---- 2) vision via the EXISTING aibridge path ------------------------------
console.log('== vision QA via aibridge (127.0.0.1:4103)');
process.env.AIBRIDGE_BASE_URL = AIBRIDGE_URL;
const contract = require('./api/server/services/Tools/documentVisualQAContract.js');
const sharp = require('sharp');

let dim = contract.PAGE_MAX_DIM;
let downscaled = await sharp(pngBuf, { limitInputPixels: 40 << 20 })
  .resize({ width: dim, height: dim, fit: 'inside', withoutEnlargement: true })
  .png({ compressionLevel: 6, adaptiveFiltering: true })
  .toBuffer();
const base64 = downscaled.toString('base64');
const bodyBytes = contract.DATA_URL_PREFIX.length + base64.length;
if (bodyBytes <= contract.MAX_BODY_BYTES) ok(`page downscaled to <= ${dim}px, body ${bodyBytes} bytes (aibridge cap ${contract.MAX_BODY_BYTES})`);
else { bad(`page too large for aibridge: ${bodyBytes} bytes`); cleanupExit(); }

// resolve the key exactly like the tool: dotenv-order-safe + extractEnvVariable
require('dotenv').config({ path: LIBRECHAT_ENV });
const { extractEnvVariable } = require('librechat-data-provider');
const apiKey = '${LITELLM_MASTER_KEY}';
const resolved = extractEnvVariable(apiKey);
if (typeof resolved !== 'string' || !resolved.trim() || resolved === apiKey) {
  bad('aibridge auth key could not be resolved');
  cleanupExit();
}
const authHeader = `Bearer ${resolved.trim()}`; // NEVER printed

const prompt = contract.buildQAPrompt({ focus: 'clipping, overlap, layout' });
const pages = [{ name: path.basename(pngPath), page: 1, mimeType: 'image/png', base64 }];
const payload = contract.buildVisionPayload({ prompt, pages });
console.log('   payload: model=%s parts=%s', payload.model, payload.messages[0].content.length);

const axios = require('axios');
let content;
try {
  const response = await axios({
    method: 'post',
    url: `${AIBRIDGE_URL}/v1/chat/completions`,
    data: payload,
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'LibreChat/1.0', Authorization: authHeader },
    timeout: contract.AIBRIDGE_TIMEOUT_MS,
  });
  content = response?.data?.choices?.[0]?.message?.content;
  if (typeof content !== 'string' || !content.trim()) throw new Error('empty vision content');
  ok('aibridge vision call returned content');
} catch (e) {
  const status = e?.response?.status;
  bad(`aibridge vision call failed: ${status ? `HTTP ${status}` : e.message}`);
  cleanupExit();
}

// ---- 3) assert the planted defect is reported ------------------------------
let verdict;
try {
  verdict = contract.parseVerdict(content, { artifact: path.basename(pngPath), page: 1 });
  // Same post-parse reconciliation the runtime tool applies: a generic model
  // image label ("image.png") is mapped back to the real rendered artifact.
  verdict = contract.reconcileArtifactNames(verdict, [{ artifact: path.basename(pngPath), page: 1 }]);
} catch (e) {
  bad(`verdict parse failed (${e.message}); raw tail: ${String(content).slice(0, 200)}`);
  cleanupExit();
}
console.log('--- model verdict ---');
console.log(contract.formatVerdict(verdict));
console.log('---------------------');

if (verdict.verdict === 'ISSUES_FOUND') {
  ok('verdict ISSUES_FOUND — planted clipping/overlap defects were reported');
  const joined = verdict.issues
    .map((i) => `${i.description} ${i.suggestion}`.toLowerCase())
    .join(' | ');
  if (/(clip|overflow|overlap|cut\s?off|boundary|edge|truncat|spill|malform|off.?canvas|right)/.test(joined)) {
    ok('issue text references the planted defect (clip/overlap/edge)');
  } else {
    bad(`ISSUES_FOUND but issue text does not clearly name the planted defect: ${joined}`);
  }
} else {
  bad('verdict PASS — the planted clipping/overlap defects were NOT reported');
}

cleanupExit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

'use strict';

/**
 * CBHR ENDPOINT AGENT — test fixtures (workstream W7).
 *
 * NOT a test file. Everything a spec needs to build a frame, and deliberately built the OPPOSITE way
 * round from the agent:
 *
 *   - `canonicalFor()` joins the sixteen-field body with a LITERAL `\u001f` and the field order WRITTEN
 *     OUT as an array literal here. It does not import the agent's `layout.js` and it does not import
 *     the backend's `envelopeCore.js`. So when a spec signs a frame with `canonicalFor()` and the agent
 *     accepts it, that is evidence the two independent readings of the frozen contract agree — not
 *     evidence that a module agrees with itself.
 *
 *   - `WORKED_EXAMPLE_CANONICAL` is the PUBLISHED worked example from the frozen contract
 *     (`evidence/gate-closure-002/v24/V24-C-signed-grants.md` F-V24C-4) with its published Ed25519
 *     signature, so the layout and the crypto path are pinned against the contract rather than against
 *     any implementation in this repository.
 *
 * The keypairs here exist only inside a test process. Nothing in this file is a deployment key, and
 * nothing here reads or writes the owner's real key store.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const nodeCrypto = require('node:crypto');

/**
 * The 15 signed fields, in the frozen order, as a literal. `argsDigestHex` is the contract's
 * `sha256(args)`; `tag` is the versioned domain separator.
 */
const FROZEN_FIELD_ORDER = Object.freeze([
  'tag',
  'requestId',
  'nonce',
  'issuedAt',
  'deadlineMs',
  'epoch',
  'grantId',
  'ownerPrincipalId',
  'tenantId',
  'deviceId',
  'deviceKeyId',
  'toolName',
  'opKind',
  'audience',
  'argsDigestHex',
]);

const V2_TAG = 'CBHR-RPC-V2';
const RESULT_TAG = 'CBHR-RPC-RESULT-V2';
const SEPARATOR = '\u001f';

/**
 * The contract's worked example, every value a literal so the golden bytes are reproducible anywhere.
 * These are the same public test values the backend's own spec publishes.
 */
const WORKED_EXAMPLE = Object.freeze({
  tag: V2_TAG,
  requestId: '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
  nonce: 'AAECAwQFBgcICQoLDA0ODw',
  issuedAt: '1761200000000',
  deadlineMs: '1761200060000',
  epoch: '7',
  grantId: 'EBESExQVFhcYGRobHB0eHw',
  ownerPrincipalId: '64f0a1b2c3d4e5f60718293a',
  tenantId: 'tenant-kelowna',
  deviceId: '65a1b2c3d4e5f60718293b4c',
  deviceKeyId: 'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw',
  toolName: 'read_file',
  opKind: 'command',
  audience: 'endpoint',
  argsDigestHex: '3795b53e4665398f141a5fafb3b006777f9f15f56423821f3e88795a8b972d14',
});

/** The exact canonical bytes of `WORKED_EXAMPLE`, with each 0x1F written as `\u001f`. */
const WORKED_EXAMPLE_CANONICAL =
  'CBHR-RPC-V2\u001f' +
  '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93\u001f' +
  'AAECAwQFBgcICQoLDA0ODw\u001f' +
  '1761200000000\u001f' +
  '1761200060000\u001f' +
  '7\u001f' +
  'EBESExQVFhcYGRobHB0eHw\u001f' +
  '64f0a1b2c3d4e5f60718293a\u001f' +
  'tenant-kelowna\u001f' +
  '65a1b2c3d4e5f60718293b4c\u001f' +
  'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw\u001f' +
  'read_file\u001f' +
  'command\u001f' +
  'endpoint\u001f' +
  '3795b53e4665398f141a5fafb3b006777f9f15f56423821f3e88795a8b972d14';

/** The contract's T0 for the worked example. */
const T0 = 1761200000000;

/** The published fixed-seed key's SPKI, and the published signature over the worked example. */
const GOLDEN_PUBLIC_KEY_SPKI_B64U =
  'MCowBQYDK2VwAyEAebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ';
const GOLDEN_SIGNATURE_B64U =
  'Zq8MZuROHEygKRQQmiXTWU80omRN4zPfaMYGt2NIBQot3pApk4_v92ljRvsblHar0nyGhoD2dsKrks20hsonAw';

/**
 * The independent canonical join: literal 0x1F, literal field order, no shared code.
 * @param {object} core a core carrying all 15 frozen fields
 * @returns {Buffer}
 */
function canonicalFor(core) {
  const parts = FROZEN_FIELD_ORDER.map((property) => {
    const value = core[property];
    if (typeof value !== 'string') {
      throw new TypeError(`fixture core.${property} must be a string`);
    }
    if (value.includes(SEPARATOR)) {
      throw new TypeError(`fixture core.${property} must not contain 0x1F`);
    }
    return value;
  });
  return Buffer.from(parts.join(SEPARATOR), 'utf8');
}

/** The independent result-core join (twelve fields, own tag). */
const FROZEN_RESULT_FIELD_ORDER = Object.freeze([
  'tag',
  'requestId',
  'callId',
  'nonce',
  'issuedAt',
  'deadlineMs',
  'grantId',
  'epoch',
  'deviceId',
  'deviceKeyId',
  'outcome',
  'argsDigestHex',
]);

/** @param {object} core */
function resultCanonicalFor(core) {
  const parts = FROZEN_RESULT_FIELD_ORDER.map((property) => String(core[property]));
  return Buffer.from(parts.join(SEPARATOR), 'utf8');
}

/** A throwaway Ed25519 keypair with a signing helper. Test-process only. */
function makeKeypair() {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
  const publicKeySpkiB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    publicKeySpkiB64u,
    keyId: nodeCrypto.createHash('sha256').update(Buffer.from(publicKeySpkiB64u, 'base64url')).digest('base64url'),
    sign: (bytes) => nodeCrypto.sign(null, bytes, privateKey).toString('base64url'),
    privateKeyPkcs8B64u: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url'),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/** The contract's fixed-seed keypair, reconstructed, so the golden signature can be reproduced. */
function makeGoldenKeypair() {
  const seed = Buffer.from(Array.from({ length: 32 }, (_unused, index) => index + 1));
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const publicKey = nodeCrypto.createPublicKey(privateKey);
  return {
    publicKeySpkiB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    sign: (bytes) => nodeCrypto.sign(null, bytes, privateKey).toString('base64url'),
  };
}

function sha256Hex(bytes) {
  return nodeCrypto.createHash('sha256').update(bytes).digest('hex');
}

function b64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * Builds a flat wire frame.
 *
 * The core is built from literal values, the digest is computed over the exact args bytes, and the
 * signature is produced through the CALLER-supplied signer over `canonicalFor(core)` — so a frame is
 * only ever signed by the key the test says signed it.
 *
 * @param {object} params
 * @param {(bytes: Buffer) => string} params.sign signer for the frame's own key
 * @param {string} params.keyId the `keyId` transport label
 * @param {object} [params.core] core field overrides
 * @param {object|string} [params.args] args payload; JSON-stringified unless a string is given
 * @param {string} [params.argsB64u] override for the transported args bytes (tampering tests)
 * @param {string} [params.signatureB64u] override the signature (forgery tests)
 * @param {object} [params.extra] additional transport fields (callId, idempotencyKey, seq)
 * @returns {{frame: object, core: object, canonical: Buffer, argsBytes: Buffer}}
 */
function buildFrame(params) {
  const argsBytes =
    params.argsBytes !== undefined
      ? Buffer.from(params.argsBytes)
      : params.args === undefined
        ? Buffer.from('{"path":"."}', 'utf8')
        : Buffer.from(typeof params.args === 'string' ? params.args : JSON.stringify(params.args), 'utf8');
  const core = {
    tag: V2_TAG,
    ...WORKED_EXAMPLE,
    ...params.core,
    argsDigestHex: params.core?.argsDigestHex ?? sha256Hex(argsBytes),
  };
  const canonical = canonicalFor(core);
  const frame = {
    ...core,
    signatureB64u: params.signatureB64u ?? params.sign(canonical),
    keyId: params.keyId,
    argsB64u: params.argsB64u ?? b64u(argsBytes),
    ...(typeof params.extra?.callId === 'string' ? { callId: params.extra.callId } : { callId: 'call-fixture-1' }),
    ...(typeof params.extra?.idempotencyKey === 'string' ? { idempotencyKey: params.extra.idempotencyKey } : {}),
    ...(params.extra?.seq === undefined ? {} : { seq: params.extra.seq }),
  };
  return { frame: Object.freeze(frame), core, canonical, argsBytes };
}

/** A temporary agent root, cleaned up by the caller (each one is unique). */
function makeTempRoot(prefix = 'cbhr-endpoint-test-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return dir;
}

function removeTempRoot(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
  } catch {
    // Best effort: a locked file left in the OS temp directory is not a test failure.
  }
}

module.exports = {
  FROZEN_FIELD_ORDER,
  FROZEN_RESULT_FIELD_ORDER,
  V2_TAG,
  RESULT_TAG,
  SEPARATOR,
  WORKED_EXAMPLE,
  WORKED_EXAMPLE_CANONICAL,
  T0,
  GOLDEN_PUBLIC_KEY_SPKI_B64U,
  GOLDEN_SIGNATURE_B64U,
  canonicalFor,
  resultCanonicalFor,
  makeKeypair,
  makeGoldenKeypair,
  sha256Hex,
  b64u,
  buildFrame,
  makeTempRoot,
  removeTempRoot,
};
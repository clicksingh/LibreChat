'use strict';

/**
 * Shared fixtures for the CBHR-RPC-V2 relay specs.
 *
 * NOT a spec file: the `.cjs` extension keeps it out of jest's `__tests__/**\/*.js` testMatch.
 *
 * The Ed25519 keypair generated here exists ONLY inside a test process. It is never written to disk,
 * never read from the environment and never asserted to be a deployment key: it stands in for the
 * owner's undecided custody choice so the seam can be exercised end to end.
 */

const nodeCrypto = require('node:crypto');
const relay = require('..');
const deviceCrypto = require('../../crypto');

/** The frozen worked example. Every value is a literal so the golden bytes are reproducible. */
const WORKED_EXAMPLE_CORE = Object.freeze({
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

/** The exact canonical bytes of `WORKED_EXAMPLE_CORE`, with each 0x1F written as `\u001f`. */
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

const WORKED_EXAMPLE_CANONICAL_BYTES = 325;

/** The `issuedAt` of the worked example, as an epoch-ms number. */
const T0 = 1761200000000;

/**
 * The published golden vector: the fixed-seed key's SPKI, and the exact Ed25519 signature over
 * `WORKED_EXAMPLE_CANONICAL`. Reproducible on any machine; see `makeDeterministicKeypair`.
 */
const GOLDEN_PUBLIC_KEY_SPKI_B64U =
  'MCowBQYDK2VwAyEAebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ';
const GOLDEN_SIGNATURE_B64U =
  'Zq8MZuROHEygKRQQmiXTWU80omRN4zPfaMYGt2NIBQot3pApk4_v92ljRvsblHar0nyGhoD2dsKrks20hsonAw';

/** A trusted authority projection, as `trustedAuthorityFromDeviceRow` would produce it. */
const AUTHORITY = Object.freeze({
  tenantId: 'tenant-kelowna',
  ownerPrincipalId: '64f0a1b2c3d4e5f60718293a',
  deviceId: '65a1b2c3d4e5f60718293b4c',
  deviceKeyId: 'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw',
  grantId: 'EBESExQVFhcYGRobHB0eHw',
  epoch: 7,
});

/**
 * Generates a throwaway Ed25519 keypair for one test process.
 * @returns {{publicKeySpkiB64u: string, privateKeyPkcs8B64u: string, privateKeyPem: string,
 *   signBytes: (bytes: Buffer) => string}}
 */
function makeTestKeypair() {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
  return {
    publicKeySpkiB64u: Buffer.from(spki).toString('base64url'),
    privateKeyPkcs8B64u: Buffer.from(pkcs8).toString('base64url'),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    signBytes: (bytes) => nodeCrypto.sign(null, bytes, privateKey).toString('base64url'),
  };
}

/**
 * A FIXED-SEED Ed25519 keypair, so the golden signature below is reproducible on any machine and by
 * any verifier. The seed is the 32 bytes 0x01..0x20 wrapped in a PKCS#8 DER envelope. This is a
 * published test vector, NOT a deployment key and NOT a custody choice: it exists only so a reader
 * can recompute the worked example byte for byte.
 * @returns {{publicKeySpkiB64u: string, privateKeyPkcs8B64u: string, privateKeyPem: string,
 *   signBytes: (bytes: Buffer) => string}}
 */
function makeDeterministicKeypair() {
  const seed = Buffer.from(Array.from({ length: 32 }, (_unused, index) => index + 1));
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const publicKey = nodeCrypto.createPublicKey(privateKey);
  return {
    publicKeySpkiB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    privateKeyPkcs8B64u: pkcs8.toString('base64url'),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    signBytes: (bytes) => nodeCrypto.sign(null, bytes, privateKey).toString('base64url'),
  };
}

/**
 * Builds the injected custody seam exactly as a real deployment would: the two-key surface only.
 * @param {object} keypair from `makeTestKeypair`
 * @param {string} [keyId]
 * @returns {{sign: Function, keyId: string}}
 */
function makeCustodySeam(keypair, keyId = 'test-custody-key-1') {
  return { sign: async (canonicalBytes) => keypair.signBytes(canonicalBytes), keyId };
}

/**
 * A dispatch transport that records calls and returns a scripted answer. The answer may be a value
 * or a function of the request; passing `undefined` explicitly yields `undefined` (an unusable
 * answer), which is a case the outcome law must classify rather than hide.
 * @param {object|Function} [response]
 * @returns {{transport: Function, calls: object[]}}
 */
function makeTransport(response) {
  const scripted =
    arguments.length === 0 ? { status: 200, body: { accepted: true } } : response;
  const calls = [];
  return {
    calls,
    transport: async (request) => {
      calls.push(request);
      return typeof scripted === 'function' ? scripted(request) : scripted;
    },
  };
}

/**
 * Flattens any value into a searchable string without JSON-serializing Buffers away.
 * @param {unknown} value
 * @returns {string}
 */
function deepText(value) {
  const nodeUtil = require('node:util');
  const parts = [];
  const walk = (item, depth) => {
    if (depth > 6 || item === null || item === undefined) {
      return;
    }
    if (typeof item === 'string') {
      parts.push(item);
      return;
    }
    if (Buffer.isBuffer(item)) {
      parts.push(item.toString('base64'));
      parts.push(item.toString('hex'));
      parts.push(item.toString('utf8'));
      return;
    }
    if (typeof item !== 'object') {
      parts.push(String(item));
      return;
    }
    parts.push(nodeUtil.inspect(item, { depth: 6, showHidden: true, getters: true }));
    for (const key of Object.keys(item)) {
      parts.push(key);
      walk(item[key], depth + 1);
    }
  };
  walk(value, 0);
  return parts.join('\n');
}

/**
 * Builds a jest-side stand-in for the future endpoint agent: it authenticates reply frames with a
 * throwaway device keypair, through the one audited signing primitive plus the named GM-56 opt-in
 * that exists for exactly this caller (the endpoint-side reply path). The device signs; nothing on
 * the backend path ever reaches `allowRelayAudience`.
 *
 * The verifier the sink must pin is built from the same throwaway keypair, so a test that witnesses a
 * sink-accepted success has witnessed the device's own authentication, not the test's.
 * @param {object} relayModule the relay layer (`..`)
 * @param {object} [options]
 * @param {string} [options.keyId] opaque device signing-key label
 * @param {() => number} [options.now] injected clock (epoch-ms)
 * @returns {{keypair, keyId, minter, deviceAuthority: (overrides) => object}}
 */
function makeDeviceResultMinter(relayModule, { keyId = 'test-device-key-1', now = () => Date.now() } = {}) {
  const keypair = makeTestKeypair();
  const signer = relayModule.createEnvelopeSigner(
    { sign: async (canonicalBytes) => keypair.signBytes(canonicalBytes), keyId },
    { allowRelayAudience: true },
  );

  /**
   * The device's own identity as the backend observed it: the frozen fixture authority with the
   * deviceKeyId of THIS throwaway keypair. Ledger reservations and reply frames both use it, so the
   * sink's binding check compares like with like — the signer and the named key are the same key.
   */
  const deviceAuthority = Object.freeze({
    ...AUTHORITY,
    deviceKeyId: relayModule.keyIdForPublicKey(keypair.publicKeySpkiB64u),
  });

  /**
   * Mints a result frame for one call: the result DOCUMENT bytes travel in `argsB64u`, and their
   * sha256 is the signed field 15, so the outcome is bound by the device's own Ed25519 authentication.
   * @param {object} params
   * @param {string} params.callId
   * @param {string} params.outcome one of the device-reported outcome words
   * @param {string} [params.toolName]
   * @param {Buffer} [params.bytes] exact result bytes; defaults to the document JSON
   * @param {object} [params.core] per-field overrides for hostile cases (a different device, audience, epoch...)
   * @param {string} [params.argsB64u] transported-bytes override (a digest disagreement, hostile case)
   * @param {string} [params.frameCallId] the frame's own transport callId override (hostile case)
   * @param {string} [params.nonce] fixed nonce override (replay cases)
   * @returns {Promise<{payload: string, frame: object, bytes: Buffer, document: object|null}>}
   */
  async function mintResultFrame({ callId, outcome, toolName = 'read_file', bytes = null, core = {}, argsB64u, frameCallId, nonce = null }) {
    const document = bytes === null ? { callId, outcome, toolName } : null;
    const resultBytes = bytes === null ? Buffer.from(JSON.stringify(document), 'utf8') : bytes;
    const issuedAt = now();
    const signed = await signer.signCore({
      requestId: nodeCrypto.randomUUID(),
      nonce: nonce ?? nodeCrypto.randomBytes(16).toString('base64url'),
      issuedAt: String(issuedAt),
      deadlineMs: String(issuedAt + 120000),
      epoch: String(deviceAuthority.epoch),
      grantId: deviceAuthority.grantId,
      ownerPrincipalId: deviceAuthority.ownerPrincipalId,
      tenantId: deviceAuthority.tenantId,
      deviceId: deviceAuthority.deviceId,
      deviceKeyId: deviceAuthority.deviceKeyId,
      toolName,
      opKind: 'command',
      audience: 'relay',
      argsDigestHex: nodeCrypto.createHash('sha256').update(resultBytes).digest('hex'),
      ...core,
    });
    const frame = relayModule.toWireFrame({
      signed,
      argsB64u: argsB64u !== undefined ? argsB64u : resultBytes.toString('base64url'),
      callId: frameCallId !== undefined ? frameCallId : callId,
    });
    return { payload: JSON.stringify(frame), frame, bytes: resultBytes, document };
  }

  return { keypair, keyId, minter: { mintResultFrame }, signer, deviceAuthority };
}

module.exports = {
  relay,
  nodeCrypto,
  deviceCrypto,
  WORKED_EXAMPLE_CORE,
  WORKED_EXAMPLE_CANONICAL,
  WORKED_EXAMPLE_CANONICAL_BYTES,
  T0,
  GOLDEN_PUBLIC_KEY_SPKI_B64U,
  GOLDEN_SIGNATURE_B64U,
  AUTHORITY,
  makeTestKeypair,
  makeDeterministicKeypair,
  makeCustodySeam,
  makeTransport,
  makeDeviceResultMinter,
  deepText,
};


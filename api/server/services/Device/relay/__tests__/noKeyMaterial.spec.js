'use strict';

/**
 * W2 spec — PROOF that no private key material is logged, serialized or even reachable.
 *
 * Three independent proofs, because "we do not log the key" is not a testable claim on its own:
 *
 *   A. RUNTIME — run a full sign + dispatch cycle with a real (throwaway) Ed25519 keypair, force both
 *      the success and the failure paths, capture every console call and every injected-logger call,
 *      and assert that no 20-character window of the private key's encodings appears in any of them.
 *   B. SERIALIZATION — assert the same for `JSON.stringify` and `util.inspect` of every object this
 *      layer produces (signed envelope, wire frame, dispatch outcome, error, signer, client).
 *   C. SOURCE — scan the production relay modules for key-generating, key-reading and signing
 *      primitives, and for `process.env`/`fs` access. None may exist: the module cannot read a key
 *      even if someone wanted it to. Key-material vocabulary may appear ONLY in comments.
 *
 * The keypair exists only inside this test process. Nothing here is a deployment key.
 */

const fs = require('node:fs');
const path = require('node:path');
const nodeUtil = require('node:util');

const {
  relay,
  nodeCrypto,
  AUTHORITY,
  T0,
  makeTestKeypair,
  makeCustodySeam,
  makeTransport,
  deepText,
} = require('./_fixtures.cjs');

const keypair = makeTestKeypair();
const ARGS_BYTES = Buffer.from('{"path":"C:/notes/today.txt"}', 'utf8');

/**
 * Every encoding of the private key this test knows how to look for, plus a sliding-window set that
 * catches a PARTIAL leak (a log that prints, say, the first 24 characters of the key).
 */
function keyMaterialNeedles(key) {
  const pkcs8Der = Buffer.from(key.privateKeyPkcs8B64u, 'base64url');
  const base64Std = pkcs8Der.toString('base64');
  const base64Url = pkcs8Der.toString('base64url');
  const hex = pkcs8Der.toString('hex');
  const pemBody = key.privateKeyPem
    .replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '')
    .replace(/\s+/g, '');

  const needles = new Set([
    key.privateKeyPkcs8B64u,
    base64Std,
    base64Url,
    hex,
    key.privateKeyPem,
    pemBody,
    pkcs8Der.toString('latin1'),
  ]);

  const windowed = [base64Std, base64Url, hex, pemBody];
  for (const encoding of windowed) {
    for (let index = 0; index + 20 <= encoding.length; index++) {
      needles.add(encoding.slice(index, index + 20));
    }
  }
  return [...needles];
}

const NEEDLES = keyMaterialNeedles(keypair);

/** Returns every needle found in `text`, so a failure names the leak. */
function findKeyMaterial(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return [];
  }
  return NEEDLES.filter((needle) => text.includes(needle));
}

function buildCycle({ logger, response }) {
  const signer = relay.createEnvelopeSigner(makeCustodySeam(keypair));
  const verifier = relay.createEnvelopeVerifier({ publicKeySpkiB64u: keypair.publicKeySpkiB64u });
  const { transport, calls } = makeTransport(response);
  const client = relay.createRelayDispatchClient({
    transport,
    signer,
    verifier,
    logger,
    clock: { now: () => T0 },
    nonceFactory: () => 'AAECAwQFBgcICQoLDA0ODw',
    requestIdFactory: () => '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
  });
  return { signer, verifier, client, calls };
}

describe('A. no private key material is logged', () => {
  let consoleSpies;
  let consoleCalls;

  beforeEach(() => {
    consoleCalls = [];
    consoleSpies = ['log', 'info', 'warn', 'error', 'debug', 'trace'].map((method) =>
      jest.spyOn(console, method).mockImplementation((...args) => {
        consoleCalls.push({ method, args });
      }),
    );
  });

  afterEach(() => {
    for (const spy of consoleSpies) {
      spy.mockRestore();
    }
  });

  it('emits nothing to the console across the success and failure paths', async () => {
    const loggerCalls = [];
    const logger = {
      warn: (...args) => loggerCalls.push(args),
      info: (...args) => loggerCalls.push(args),
      error: (...args) => loggerCalls.push(args),
    };

    const ok = buildCycle({ logger, response: { status: 200, body: { accepted: true } } });
    await ok.client.dispatchCommand({ authority: AUTHORITY, toolName: 'read_file', argsBytes: ARGS_BYTES });

    const refused = buildCycle({ logger, response: { status: 400 } });
    await refused.client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    const uncertain = buildCycle({ logger, response: { status: 500 } });
    await uncertain.client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    const thrown = buildCycle({
      logger,
      response: () => {
        throw new Error('socket hang up');
      },
    });
    await thrown.client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    // This layer writes nothing to the console at all.
    expect(consoleCalls).toEqual([]);

    // The injected logger received only fixed, payload-free notices.
    expect(loggerCalls.length).toBeGreaterThan(0);
    const logged = deepText(loggerCalls);
    expect(findKeyMaterial(logged)).toEqual([]);
    for (const args of loggerCalls) {
      expect(args).toHaveLength(1);
      expect(typeof args[0]).toBe('string');
      expect(args[0]).toMatch(/^relay dispatch (transport failure|outcome uncertain)$/);
    }
  });

  it('never logs the nonce, the signature, the args digest or an owner id either', async () => {
    const loggerCalls = [];
    const logger = { warn: (...args) => loggerCalls.push(args) };
    const cycle = buildCycle({ logger, response: { status: 503 } });
    const outcome = await cycle.client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    const frame = cycle.calls[0].frame;
    const logged = deepText(loggerCalls);
    for (const secretish of [
      frame.nonce,
      frame.signatureB64u,
      frame.argsDigestHex,
      frame.grantId,
      frame.ownerPrincipalId,
      frame.deviceId,
      frame.deviceKeyId,
    ]) {
      expect(logged).not.toContain(secretish);
    }
    // The outcome object itself carries no envelope material.
    expect(findKeyMaterial(deepText(outcome))).toEqual([]);
    expect(deepText(outcome)).not.toContain(frame.signatureB64u);
    expect(deepText(outcome)).not.toContain(frame.nonce);
  });

  it('survives a logger that throws, without leaking or masking the outcome', async () => {
    const logger = {
      warn: () => {
        throw new Error('logger exploded');
      },
    };
    const cycle = buildCycle({ logger, response: { status: 500 } });

    const outcome = await cycle.client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.delivered).toBe('unknown');
  });
});

describe('B. no private key material is serialized', () => {
  async function everyProducedObject() {
    const signer = relay.createEnvelopeSigner(makeCustodySeam(keypair));
    const verifier = relay.createEnvelopeVerifier({ publicKeySpkiB64u: keypair.publicKeySpkiB64u });
    const { transport, calls } = makeTransport({ status: 200, body: { accepted: true } });
    const client = relay.createRelayDispatchClient({
      transport,
      signer,
      verifier,
      clock: { now: () => T0 },
      nonceFactory: () => 'AAECAwQFBgcICQoLDA0ODw',
      requestIdFactory: () => '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
    });

    const signed = await signer.signCore({
      requestId: '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
      nonce: 'AAECAwQFBgcICQoLDA0ODw',
      issuedAt: String(T0),
      deadlineMs: String(T0 + 60000),
      epoch: String(AUTHORITY.epoch),
      grantId: AUTHORITY.grantId,
      ownerPrincipalId: AUTHORITY.ownerPrincipalId,
      tenantId: AUTHORITY.tenantId,
      deviceId: AUTHORITY.deviceId,
      deviceKeyId: AUTHORITY.deviceKeyId,
      toolName: 'read_file',
      opKind: 'command',
      audience: 'endpoint',
      argsDigestHex: nodeCrypto.createHash('sha256').update(ARGS_BYTES).digest('hex'),
    });
    const frame = relay.toWireFrame({ signed, seq: 1, idempotencyKey: 'idem-1', callId: 'call-1' });
    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    let failure;
    try {
      relay.buildEnvelopeCore({ tag: 'CBHR-RPC-V2' });
    } catch (err) {
      failure = err;
    }

    return { signer, verifier, client, signed, frame, outcome, failure, call: calls[0] };
  }

  it('serializes none of them with JSON.stringify, util.inspect or Object.keys', async () => {
    const produced = await everyProducedObject();

    for (const [label, value] of Object.entries(produced)) {
      expect({ label, leaks: findKeyMaterial(JSON.stringify(value) ?? '') }).toEqual({
        label,
        leaks: [],
      });
      expect({ label, leaks: findKeyMaterial(nodeUtil.inspect(value, { depth: 8, showHidden: true })) })
        .toEqual({ label, leaks: [] });
      expect({ label, leaks: findKeyMaterial(deepText(value)) }).toEqual({ label, leaks: [] });
      expect({ label, leaks: findKeyMaterial(Object.keys(value ?? {}).join(' ')) }).toEqual({
        label,
        leaks: [],
      });
    }
  });

  it('never puts key material on the wire frame or the signed envelope', async () => {
    const { signed, frame } = await everyProducedObject();

    expect(Object.keys(frame)).toEqual([...relay.RPC_FRAME_KEYS.slice(0, 15), 'signatureB64u', 'keyId', 'seq', 'idempotencyKey', 'callId']);
    expect(Object.keys(signed).sort()).toEqual(['core', 'keyId', 'signatureB64u']);
    expect(Object.isFrozen(frame)).toBe(true);
    expect(Object.isFrozen(signed)).toBe(true);
    expect(Object.isFrozen(signed.core)).toBe(true);

    // The only key-derived value anywhere is the public key label the custody surface supplied.
    expect(frame.keyId).toBe('test-custody-key-1');
    expect(JSON.stringify(frame)).not.toContain(keypair.publicKeySpkiB64u);
    expect(JSON.stringify(frame)).not.toContain(keypair.privateKeyPkcs8B64u);
  });

  it('keeps the diagnostic field and cause out of every serialized error', async () => {
    const { failure } = await everyProducedObject();

    expect(failure).toBeInstanceOf(relay.RelayError);
    expect(failure.code).toBe('ENVELOPE_SHAPE_INVALID');
    expect(failure.field).toBe('requestId');
    // `field` is server-side only.
    expect(failure.toJSON()).toEqual({
      name: 'RelayError',
      code: 'ENVELOPE_SHAPE_INVALID',
      httpStatus: 400,
      message: failure.message,
      retryable: false,
    });
    expect(JSON.parse(JSON.stringify(failure))).not.toHaveProperty('field');
    expect(Object.keys(failure)).not.toContain('field');
    expect(failure.message).not.toContain('CBHR-RPC-V2');
  });
});

describe('C. no key material is even reachable from the production modules', () => {
  const relayDir = path.resolve(__dirname, '..');
  const productionFiles = fs
    .readdirSync(relayDir)
    .filter((name) => name.endsWith('.js'))
    .map((name) => ({ name, text: fs.readFileSync(path.join(relayDir, name), 'utf8') }));

  it('has production modules to scan', () => {
    expect(productionFiles.length).toBeGreaterThanOrEqual(8);
  });

  it.each([
    ['keypair generation', /\bgenerateKeyPair(Sync)?\s*\(/],
    ['private-key construction', /\bcreatePrivateKey\s*\(/],
    ['a signing primitive', /\b(createSign|createHmacSign|crypto\.sign|nodeCrypto\.sign|deviceCrypto\.sign)\s*\(/],
    ['KeyObject handling', /\bKeyObject\b/],
    ['filesystem access', /require\(\s*['"](node:)?fs(\/promises)?['"]\s*\)/],
    ['environment access', /process\.env/],
    ['a PEM header', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ])('contains no %s', (_label, pattern) => {
    const offenders = productionFiles
      .filter((file) => pattern.test(file.text))
      .map((file) => file.name);
    expect(offenders).toEqual([]);
  });

  it('mentions private-key vocabulary only inside comments', () => {
    const offenders = [];
    for (const file of productionFiles) {
      const lines = file.text.split('\n');
      lines.forEach((line, index) => {
        if (/\bprivateKey\b/.test(line)) {
          const trimmed = line.trim();
          const isComment =
            trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*');
          if (!isComment) {
            offenders.push(`${file.name}:${index + 1}`);
          }
        }
      });
    }
    expect(offenders).toEqual([]);
  });

  it('imports only the accepted crypto module and node built-ins', () => {
    const requires = [];
    for (const file of productionFiles) {
      const matches = file.text.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g);
      for (const match of matches) {
        requires.push({ file: file.name, specifier: match[1] });
      }
    }
    const allowed = new Set([
      'node:crypto',
      './errors',
      './envelopeCore',
      './envelopeSigner',
      './envelopeVerifier',
      './freshness',
      './replayWindow',
      './argsDigest',
      './relayDispatchClient',
      '../crypto',
    ]);
    const unexpected = requires.filter((entry) => !allowed.has(entry.specifier));
    expect(unexpected).toEqual([]);
    // No new dependency was added to reach the crypto primitives.
    expect(requires.filter((entry) => entry.specifier === 'node:crypto').map((e) => e.file)).toEqual(
      expect.arrayContaining(['argsDigest.js', 'relayDispatchClient.js']),
    );
  });

  it('reuses the accepted Device crypto module rather than reimplementing canonicalisation', () => {
    const core = productionFiles.find((file) => file.name === 'envelopeCore.js');
    expect(core.text).toContain("require('../crypto')");
    expect(core.text).toContain('canonicalEncode');
    // No hand-rolled 0x1F join: the separator must not be joined with a literal in production code.
    expect(core.text).not.toMatch(/join\(\s*['"]\\u001f['"]\s*\)/);
    const signer = productionFiles.find((file) => file.name === 'envelopeSigner.js');
    expect(signer.text).toContain('verifyEd25519');
    expect(signer.text).toContain('thumbprintB64u');
  });
});

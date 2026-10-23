'use strict';

/**
 * GM-48 / GM-49 defect-fix proofs.
 *
 * One describe block per finding. Every test here FAILS against the pre-fix bytes and PASSES after
 * the fix, so the suite is a regression proof rather than a description:
 *
 *   GM-47 (M1)  args bytes travel in the frame as `argsB64u`, outside the signature, and the
 *               endpoint re-hashes what it received -> ARGS_DIGEST_MISMATCH.
 *   m2          the replay ring never forgets a nonce while an envelope bearing it could still be
 *               fresh (strict prune + freshness-horizon-pinned retention).
 *   m3          the SIGNING PRIMITIVE refuses `audience: 'relay'`, not only the dispatch path.
 *   m4          a failing-field error carries a generic external message; the field detail is
 *               server-side only.
 *   m5          a custody/transport `cause` cannot print key material.
 *   GM-49       a real dispatch refuses a null replay window.
 */

const nodeUtil = require('node:util');

const {
  relay,
  nodeCrypto,
  AUTHORITY,
  T0,
  WORKED_EXAMPLE_CORE,
  GOLDEN_SIGNATURE_B64U,
  GOLDEN_PUBLIC_KEY_SPKI_B64U,
  makeTestKeypair,
  makeDeterministicKeypair,
  makeCustodySeam,
  makeTransport,
  deepText,
} = require('./_fixtures.cjs');

const keypair = makeTestKeypair();
const signer = relay.createEnvelopeSigner(makeCustodySeam(keypair));
const verifier = relay.createEnvelopeVerifier({ publicKeySpkiB64u: keypair.publicKeySpkiB64u });

const ARGS_BYTES = Buffer.from('{"path":"C:/notes/today.txt"}', 'utf8');
const ARGS_DIGEST_HEX = nodeCrypto.createHash('sha256').update(ARGS_BYTES).digest('hex');
const REQUEST_ID = '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93';
const NONCE = 'AAECAwQFBgcICQoLDA0ODw';

/** Dispatches one command and returns the frame the relay would have forwarded. */
async function dispatchFrame({ argsBytes = ARGS_BYTES } = {}) {
  const { transport, calls } = makeTransport({ status: 200, body: { accepted: true } });
  const client = relay.createRelayDispatchClient({
    transport,
    signer,
    verifier,
    clock: { now: () => T0 },
    nonceFactory: () => NONCE,
    requestIdFactory: () => REQUEST_ID,
    replayWindow: relay.createReplayWindow({ now: () => T0 }),
  });
  const outcome = await client.dispatchCommand({
    authority: AUTHORITY,
    toolName: 'read_file',
    argsBytes,
  });
  return { outcome, frame: calls[0].frame };
}

describe('GM-47 (M1) — the args bytes travel in the frame and the endpoint re-hashes them', () => {
  it('exposes argsB64u as a permitted frame key and refuses it as a core key', () => {
    // Pre-fix: `RPC_FRAME_KEYS` refused any extra key, so this key did not exist and the assertion
    // failed; a frame carrying it was rejected as `not a permitted wire-frame key`.
    expect(relay.RPC_FRAME_KEYS).toContain('argsB64u');
    expect(relay.ARGS_B64U_FIELD).toBe('argsB64u');
    expect(relay.RPC_FRAME_TRANSPORT_FIELDS).toEqual([
      'signatureB64u',
      'keyId',
      'argsB64u',
      'seq',
      'idempotencyKey',
      'callId',
    ]);
    // Outside the signature: it is NOT one of the 15 signed fields.
    expect(relay.RPC_ENVELOPE_FIELD_ORDER).not.toContain('argsB64u');
    expect(relay.RPC_ENVELOPE_FIELD_ORDER).toHaveLength(15);
    expect(relay.RPC_ENVELOPE_FIELD_ORDER[14]).toBe('argsDigestHex');
    expect(() => relay.buildEnvelopeCore({ ...WORKED_EXAMPLE_CORE, argsB64u: 'AAAA' })).toThrow(
      expect.objectContaining({ code: 'ENVELOPE_SHAPE_INVALID' }),
    );
  });

  it('carries the exact bytes on a dispatched frame and round-trips them to field 15', async () => {
    const { outcome, frame } = await dispatchFrame();

    expect(outcome.ok).toBe(true);
    expect(frame.argsB64u).toBe(ARGS_BYTES.toString('base64url'));
    expect(frame.argsDigestHex).toBe(ARGS_DIGEST_HEX);

    // 1. decode exactly what travelled
    const decoded = relay.decodeArgsB64u(frame.argsB64u);
    expect(Buffer.isBuffer(decoded)).toBe(true);
    expect(decoded.equals(ARGS_BYTES)).toBe(true);

    // 2. recompute sha256 over the received bytes and require equality with field 15
    const check = relay.verifyArgsBytes({ frame });
    expect(check.ok).toBe(true);
    expect(check.argsBytes.equals(ARGS_BYTES)).toBe(true);
    expect(check.argsDigestHex).toBe(frame.argsDigestHex);

    // 3. the signature still covers exactly the 15-field canonical string (argsB64u excluded)
    const signedFromFrame = relay.signedFromWireFrame(frame);
    expect(Object.keys(signedFromFrame.core)).toHaveLength(15);
    expect(signedFromFrame.core).not.toHaveProperty('argsB64u');
    expect(verifier.verifySignature(signedFromFrame).ok).toBe(true);
    expect(
      relay.canonicalRpcBytes(signedFromFrame.core).toString('utf8'),
    ).toBe(
      [
        'CBHR-RPC-V2',
        REQUEST_ID,
        NONCE,
        String(T0),
        String(T0 + 60000),
        '7',
        AUTHORITY.grantId,
        AUTHORITY.ownerPrincipalId,
        AUTHORITY.tenantId,
        AUTHORITY.deviceId,
        AUTHORITY.deviceKeyId,
        'read_file',
        'command',
        'endpoint',
        ARGS_DIGEST_HEX,
      ].join('\u001f'),
    );
  });

  it('proves the golden signature is unchanged by the frame extension', async () => {
    // `argsB64u` is transport data: adding it must not move the published signed bytes.
    const deterministic = makeDeterministicKeypair();
    const deterministicSigner = relay.createEnvelopeSigner(
      makeCustodySeam(deterministic, 'golden'),
    );
    const signed = await deterministicSigner.signCore(WORKED_EXAMPLE_CORE);
    const frame = relay.toWireFrame({ signed, argsB64u: ARGS_BYTES.toString('base64url') });

    expect(frame.argsB64u).toBe(ARGS_BYTES.toString('base64url'));
    expect(signed.signatureB64u).toBe(GOLDEN_SIGNATURE_B64U);
    expect(relay.canonicalRpcBytes(signed.core)).toHaveLength(325);
    expect(
      relay.createEnvelopeVerifier({ publicKeySpkiB64u: GOLDEN_PUBLIC_KEY_SPKI_B64U })
        .verifySignature(relay.signedFromWireFrame(frame)).ok,
    ).toBe(true);
  });

  it('fails closed with ARGS_DIGEST_MISMATCH when the transported bytes were swapped', async () => {
    const { frame } = await dispatchFrame();
    const swapped = {
      ...frame,
      argsB64u: Buffer.from('{"path":"C:/etc/passwd"}', 'utf8').toString('base64url'),
    };

    // The signature is still valid: argsB64u is outside it. Only the digest check catches this.
    expect(verifier.verifySignature(relay.signedFromWireFrame(swapped)).ok).toBe(true);

    const check = relay.verifyArgsBytes({ frame: swapped });
    expect(check.ok).toBe(false);
    expect(check.error.code).toBe('ARGS_DIGEST_MISMATCH');

    const admission = await relay.verifyEnvelope({
      signed: swapped,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
    });
    expect(admission.ok).toBe(false);
    expect(admission.error.code).toBe('ARGS_DIGEST_MISMATCH');
  });

  it('refuses a frame that carries no args bytes, and a non-canonical encoding', async () => {
    const { frame } = await dispatchFrame();

    const { argsB64u: _dropped, ...withoutArgs } = frame;
    expect(() => relay.signedFromWireFrame(withoutArgs)).toThrow(
      expect.objectContaining({ code: 'ENVELOPE_SHAPE_INVALID' }),
    );
    expect(() => relay.toWireFrame({ signed: relay.signedFromWireFrame(frame) })).toThrow(
      expect.objectContaining({ code: 'ENVELOPE_SHAPE_INVALID' }),
    );
    // Padded / foreign alphabet is not canonical unpadded base64url.
    for (const bad of ['AAECAw==', 'not base64url!!', 42, null, undefined]) {
      const result = relay.verifyArgsBytes({ argsB64u: bad, argsDigestHex: ARGS_DIGEST_HEX });
      expect({ bad, code: result.ok ? null : result.error.code }).toEqual({
        bad,
        code: 'ARGS_DIGEST_MISMATCH',
      });
    }
  });

  it('round-trips empty args (sha256 of the empty byte string) without canonicalisation', async () => {
    const empty = Buffer.alloc(0);
    const { frame } = await dispatchFrame({ argsBytes: empty });

    expect(frame.argsB64u).toBe('');
    expect(frame.argsDigestHex).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    const check = relay.verifyArgsBytes({ frame });
    expect(check.ok).toBe(true);
    expect(check.argsBytes).toHaveLength(0);
  });

  it('does not canonicalise: byte-identical args hash identically, any byte change does not', async () => {
    const one = Buffer.from([0x00, 0x01, 0xfe, 0xff, 0x20]);
    const two = Buffer.from([0x00, 0x01, 0xfe, 0xff, 0x21]);

    const first = await dispatchFrame({ argsBytes: one });
    expect(relay.verifyArgsBytes({ frame: first.frame }).ok).toBe(true);
    expect(
      relay.verifyArgsBytes({ argsB64u: two.toString('base64url'), argsDigestHex: first.frame.argsDigestHex })
        .ok,
    ).toBe(false);
    // Whitespace is NOT normalised away: the bytes are the bytes (GM-29).
    expect(
      relay.verifyArgsBytes({
        argsB64u: Buffer.from(' {"path":"x"} ', 'utf8').toString('base64url'),
        argsDigestHex: nodeCrypto.createHash('sha256').update('{"path":"x"}', 'utf8').digest('hex'),
      }).ok,
    ).toBe(false);
  });
});

describe('m2 — a nonce is never forgotten while an envelope bearing it could still be fresh', () => {
  const MIN = relay.MIN_REPLAY_RETENTION_MS;

  it('retains a nonce at exactly the widest freshness window under the minimum retention', async () => {
    // Pre-fix: prune used `expiresAt <= atMs`, so at `seenAt + 120000` the entry was already gone
    // while `evaluateFreshness` still accepted `ageMs == 120000` — the replay below was ACCEPTED.
    let now = T0;
    const replayWindow = relay.createReplayWindow({ now: () => now, retentionMs: MIN });
    const params = { grantId: AUTHORITY.grantId, nonce: NONCE };

    expect(MIN).toBe(relay.MAX_FRESHNESS_WINDOW_MS);
    expect((await replayWindow.checkAndRemember(params)).ok).toBe(true);

    now = T0 + MIN;
    // The envelope is STILL ADMISSIBLE at this instant (freshness is inclusive at `ageMs == windowMs`).
    expect(
      relay.evaluateFreshness({
        audience: 'relay',
        issuedAt: T0,
        deadlineMs: T0 + 120000,
        now,
      }).ok,
    ).toBe(true);

    // Therefore the nonce must still be remembered, and the replay must be REJECTED.
    const replay = await replayWindow.checkAndRemember(params);
    expect({ ok: replay.ok, code: replay.error?.code }).toEqual({
      ok: false,
      code: 'REPLAY_DETECTED',
    });
    expect(replayWindow.has(params)).toBe(true);
  });

  it('is still enforcing one millisecond past the window, and only then forgets', async () => {
    let now = T0;
    const replayWindow = relay.createReplayWindow({ now: () => now, retentionMs: MIN });
    const params = { grantId: AUTHORITY.grantId, nonce: NONCE };

    await replayWindow.checkAndRemember(params);
    now = T0 + MIN + 1;
    expect(replayWindow.has(params)).toBe(false);
    // Safe to forget: no envelope with this nonce can pass freshness any more.
    expect(
      relay.evaluateFreshness({
        audience: 'relay',
        issuedAt: T0,
        deadlineMs: T0 + 120000,
        now,
      }).ok,
    ).toBe(false);
  });

  it('pins retention to the envelope freshness horizon, not to the admission instant', async () => {
    // An envelope admitted while future-dated stays fresh past `seenAt + retentionMs`.
    let now = T0 - 60000;
    const replayWindow = relay.createReplayWindow({ now: () => now, retentionMs: MIN });
    const params = { grantId: AUTHORITY.grantId, nonce: NONCE, freshUntilMs: T0 + 60000 };

    expect((await replayWindow.checkAndRemember(params)).ok).toBe(true);
    now = T0 + 60000;
    const replay = await replayWindow.checkAndRemember({
      grantId: AUTHORITY.grantId,
      nonce: NONCE,
    });
    expect(replay.ok).toBe(false);
    expect(replay.error.code).toBe('REPLAY_DETECTED');
  });
});

describe('m3 — the audience policy lives in the signing primitive', () => {
  const relayCore = () => ({ ...WORKED_EXAMPLE_CORE, audience: 'relay', deadlineMs: String(T0 + 120000) });

  it('refuses to sign a relay-audience core without an explicit opt-in', async () => {
    // Pre-fix: `signCore` signed this happily; only `parseDispatchRequest` refused it, so any
    // caller of the exported primitive could mint the endpoint's half of the protocol.
    const primitive = relay.createEnvelopeSigner(makeCustodySeam(keypair));

    await expect(primitive.signCore(relayCore())).rejects.toMatchObject({
      code: 'ENVELOPE_AUDIENCE_NOT_DISPATCHABLE',
    });
  });

  it('refuses before custody is touched, so no signature is ever produced', async () => {
    const signed = [];
    const primitive = relay.createEnvelopeSigner({
      keyId: 'probe',
      sign: (bytes) => {
        signed.push(bytes);
        return keypair.signBytes(bytes);
      },
    });

    await expect(primitive.signCore(relayCore())).rejects.toMatchObject({
      code: 'ENVELOPE_AUDIENCE_NOT_DISPATCHABLE',
    });
    expect(signed).toHaveLength(0);
  });

  it('still signs endpoint-audience cores, and exposes the policy as reviewable data', async () => {
    const primitive = relay.createEnvelopeSigner(makeCustodySeam(keypair));
    const signed = await primitive.signCore(WORKED_EXAMPLE_CORE);

    expect(verifier.verifySignature(signed).ok).toBe(true);
    expect(relay.SIGNER_AUDIENCE_POLICY.REFUSE_RELAY_BY_DEFAULT).toBe(true);
    expect(relay.SIGNER_AUDIENCE_POLICY.RELAY_AUDIENCE_OPT_IN).toBe('allowRelayAudience');
  });

  it('honours the explicit, named opt-in for the endpoint-side reply path only', async () => {
    const optedIn = relay.createEnvelopeSigner(makeCustodySeam(keypair), {
      allowRelayAudience: true,
    });
    const signed = await optedIn.signCore(relayCore());

    expect(signed.core.audience).toBe('relay');
    expect(verifier.verifySignature(signed).ok).toBe(true);
    // Anything other than the literal `true` is not an opt-in.
    for (const value of [false, 0, 1, 'true', {}, null]) {
      const notOptedIn = relay.createEnvelopeSigner(makeCustodySeam(keypair), {
        allowRelayAudience: value,
      });
      await expect(notOptedIn.signCore(relayCore())).rejects.toMatchObject({
        code: 'ENVELOPE_AUDIENCE_NOT_DISPATCHABLE',
      });
    }
  });
});

describe('m4 — a failing-field error never discloses which field failed', () => {
  function failingError() {
    try {
      relay.buildEnvelopeCore({ ...WORKED_EXAMPLE_CORE, requestId: 'not-a-uuid' });
    } catch (err) {
      return err;
    }
    throw new Error('expected a refusal');
  }

  it('carries a generic external message and keeps the field server-side only', () => {
    // Pre-fix: `message` was `envelope field "requestId" must be ...`, and `message` is in
    // `toJSON()`, so serializing the error disclosed the failing field (invariant 3).
    const err = failingError();

    expect(err.code).toBe('ENVELOPE_SHAPE_INVALID');
    expect(err.message).toBe(relay.GENERIC_FIELD_MESSAGE);
    expect(err.message).toBe('envelope field is invalid');
    expect(err.message).not.toContain('requestId');

    // Server-side detail is available, and is non-enumerable.
    expect(err.field).toBe('requestId');
    expect(err.detail).toContain('requestId');
    expect(Object.keys(err)).not.toContain('field');
    expect(Object.keys(err)).not.toContain('detail');
    expect(Object.getOwnPropertyDescriptor(err, 'field').enumerable).toBe(false);
    expect(Object.getOwnPropertyDescriptor(err, 'detail').enumerable).toBe(false);
  });

  it('serializes nothing that names the field', () => {
    const err = failingError();
    const external = [JSON.stringify(err), JSON.stringify(err.toJSON()), err.toJSON().message, nodeUtil.inspect(err)];

    for (const text of external) {
      expect(text).not.toContain('requestId');
      expect(text).not.toContain('must be a canonical');
    }
    expect(err.toJSON()).toEqual({
      name: 'RelayError',
      code: 'ENVELOPE_SHAPE_INVALID',
      httpStatus: 400,
      message: 'envelope field is invalid',
      retryable: false,
    });
  });

  it('applies to every field-named refusal, including args and replay failures', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    await replayWindow.checkAndRemember({ grantId: AUTHORITY.grantId, nonce: NONCE });
    const replay = await replayWindow.checkAndRemember({ grantId: AUTHORITY.grantId, nonce: NONCE });
    const args = relay.verifyArgsBytes({ argsB64u: 'AAAA', argsDigestHex: ARGS_DIGEST_HEX });

    for (const err of [replay.error, args.error]) {
      expect(err.message).toBe('envelope field is invalid');
      expect(err.field).toBeTruthy();
      expect(err.detail.length).toBeGreaterThan(0);
      expect(JSON.stringify(err)).not.toContain(err.field);
    }
  });
});

describe('m5 — a cause chain can never print key material', () => {
  const KEY_MATERIAL = keypair.privateKeyPem;

  it('replaces a custody error carrying key material with a code-only stand-in', async () => {
    const leaking = relay.createEnvelopeSigner({
      keyId: 'leaky-custody',
      sign: async () => {
        throw new Error(`HSM refused; loaded key:\n${KEY_MATERIAL}`);
      },
    });

    // Pre-fix: the raw error was forwarded as `cause`, so `util.inspect`/`console.error` printed it.
    const err = await leaking.signCore(WORKED_EXAMPLE_CORE).catch((failure) => failure);

    expect(err.code).toBe('SIGNER_SEAM_INVALID');
    expect(err.cause).toBeInstanceOf(Error);
    expect(err.cause.name).toBe('RelayCause');
    expect(err.cause.message).toBe('relay cause');
    expect(err.cause.stack ?? '').not.toContain(KEY_MATERIAL);

    for (const text of [
      nodeUtil.inspect(err, { depth: 8 }),
      nodeUtil.inspect(err, { depth: 8, showHidden: true }),
      JSON.stringify(err),
      deepText(err),
      String(err.stack ?? ''),
    ]) {
      expect(text).not.toContain('BEGIN PRIVATE KEY');
      expect(text).not.toContain(KEY_MATERIAL);
      expect(text).not.toContain(keypair.privateKeyPkcs8B64u);
    }
  });

  it('preserves only the code, so classification still works', () => {
    const err = relay.relayFailure('RELAY_DISPATCH_UNCERTAIN', 'hop failed', {
      cause: Object.assign(new Error(`key=${keypair.privateKeyPkcs8B64u}`), {
        code: 'ECONNRESET',
      }),
    });

    expect(err.cause.code).toBe('ECONNRESET');
    expect(err.cause.message).toBe('relay cause');
    expect(nodeUtil.inspect(err)).not.toContain(keypair.privateKeyPkcs8B64u);
  });

  it('drops a primitive cause rather than forwarding its text', () => {
    const err = relay.relayFailure('RELAY_REJECTED', 'refused', { cause: KEY_MATERIAL });

    expect(err.cause).toBeUndefined();
    expect(nodeUtil.inspect(err)).not.toContain('BEGIN PRIVATE KEY');
  });

  it('sanitizes the transport failure on the dispatch path', async () => {
    const { transport } = makeTransport(() => {
      throw new Error(`socket closed; key ${KEY_MATERIAL}`);
    });
    const client = relay.createRelayDispatchClient({
      transport,
      signer,
      clock: { now: () => T0 },
      nonceFactory: () => NONCE,
      requestIdFactory: () => REQUEST_ID,
      replayWindow: relay.createReplayWindow({ now: () => T0 }),
    });

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    expect(outcome.code).toBe('RELAY_DISPATCH_UNCERTAIN');
    expect(deepText(outcome)).not.toContain(KEY_MATERIAL);
    expect(nodeUtil.inspect(outcome.error, { depth: 8 })).not.toContain('BEGIN PRIVATE KEY');
  });
});

describe('GM-49 — a real dispatch requires a replay window', () => {
  it('refuses to construct a dispatch client without one', () => {
    // Pre-fix: `replayWindow: null` meant replay was accepted, silently.
    for (const replayWindow of [undefined, null]) {
      expect(() =>
        relay.createRelayDispatchClient({
          transport: async () => ({ status: 200 }),
          signer,
          ...(replayWindow === undefined ? {} : { replayWindow }),
        }),
      ).toThrow(expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }));
    }
  });

  it('still permits a null window for non-dispatch verification use', async () => {
    const signed = await signer.signCore(WORKED_EXAMPLE_CORE);
    const result = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
    });

    expect(result.ok).toBe(true);
  });

  it('refuses a replay at the dispatch path once the window is enforced', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    const { transport, calls } = makeTransport({ status: 200, body: { accepted: true } });
    const client = relay.createRelayDispatchClient({
      transport,
      signer,
      clock: { now: () => T0 },
      nonceFactory: () => NONCE,
      requestIdFactory: () => REQUEST_ID,
      replayWindow,
    });

    const first = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });
    const second = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    expect(first.ok).toBe(true);
    expect(second.code).toBe('REPLAY_DETECTED');
    expect(calls).toHaveLength(1);
  });
});

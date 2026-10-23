'use strict';

/**
 * W7 spec — REFUSE BEFORE EXECUTING ANYTHING (the verification chain and its distinct codes).
 *
 * Every case here is one of the acceptance tests the workstream names, and each one asserts TWO
 * things, because either alone is weak:
 *
 *   1. the exact refusal CODE (a distinct code per step, so a local operator can tell a rotation
 *      mistake from a forgery from a stale clock); and
 *   2. that NOTHING EXECUTED — `executed: false` on the agent's own report, plus a tool that would
 *      leave a trace (a listing of the workspace root) is never reached.
 *
 * The frames are built by `test/_fixtures.js`, whose canonical join shares no code with the agent's
 * layout (see the golden-vector spec). So "the agent accepted a fixture frame" means the two
 * independent readings of the contract agree.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { describe, it, before, after } = require('node:test');

const fixtures = require('./_fixtures');
const { verifyCommandFrame } = require('../src/verify');
const { buildPinSet } = require('../src/pinnedKeys');
const { createDurableReplayWindow } = require('../src/replayWindow');
const { V2_TAG } = require('../src/layout');

const T = fixtures.T0;
const DEVICE_ID = fixtures.WORKED_EXAMPLE.deviceId;
const DEVICE_KEY_ID = fixtures.WORKED_EXAMPLE.deviceKeyId;

const backendKey = fixtures.makeKeypair();
const otherKey = fixtures.makeKeypair();
const PINS = buildPinSet([{ keyId: backendKey.keyId, publicKeySpkiB64u: backendKey.publicKeySpkiB64u }]);

let replaySeq = 0;
function freshNonce() {
  replaySeq += 1;
  return Buffer.alloc(16, replaySeq).toString('base64url');
}

/** A frame builder bound to the pinned backend key, with per-test overrides. */
function sign(overrides = {}) {
  const { core = {}, ...rest } = overrides;
  return fixtures.buildFrame({
    sign: backendKey.sign,
    keyId: backendKey.keyId,
    core: { nonce: freshNonce(), issuedAt: String(T), deadlineMs: String(T + 60000), ...core },
    ...rest,
  });
}

function verify(frame, options = {}) {
  const now = options.now ?? (() => T + 1000);
  return verifyCommandFrame({
    frame,
    pins: options.pins ?? PINS,
    deviceId: options.deviceId ?? DEVICE_ID,
    deviceKeyId: options.deviceKeyId ?? DEVICE_KEY_ID,
    now,
    replayWindow: options.replayWindow ?? createDurableReplayWindow({ persist: false, now }),
  });
}

describe('1. tampered args are refused before execution (GM-47)', () => {
  it('refuses when argsB64u is swapped for different bytes, with a distinct code', async () => {
    const { frame, argsBytes } = sign({ args: { path: 'notes.txt' } });
    const tampered = Object.freeze({
      ...frame,
      argsB64u: Buffer.from('{"path":"C:/Windows/System32/config/SAM"}', 'utf8').toString('base64url'),
    });
    assert.notEqual(tampered.argsB64u, frame.argsB64u);

    const verdict = await verify(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_ARGS_DIGEST_MISMATCH');
    // The signed digest is untouched, so the SWAP is what fails — not the signature.
    assert.equal(tampered.argsDigestHex, frame.argsDigestHex);
    assert.notEqual(argsBytes.toString('utf8'), Buffer.from(tampered.argsB64u, 'base64url').toString('utf8'));
  });

  it('refuses a frame that omits the args bytes entirely', async () => {
    const { frame } = sign();
    const withoutArgs = Object.fromEntries(Object.entries(frame).filter(([key]) => key !== 'argsB64u'));
    const verdict = await verify(withoutArgs);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_ARGS_DIGEST_MISMATCH');
  });

  it('refuses non-canonical base64url args bytes', async () => {
    const { frame } = sign();
    const verdict = await verify({ ...frame, argsB64u: `${frame.argsB64u}=` });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_ARGS_DIGEST_MISMATCH');
  });

  it('accepts the untouched frame, so the tamper test is not passing vacuously', async () => {
    const { frame, argsBytes } = sign({ args: { path: 'notes.txt' } });
    const verdict = await verify(frame);
    assert.equal(verdict.ok, true);
    assert.ok(verdict.argsBytes.equals(argsBytes));
  });
});

describe('2. a valid signature with the WRONG AUDIENCE is refused', () => {
  it("refuses audience 'relay' even though the signature over it is genuine", async () => {
    // This is the relay-signed-result shape presented to the endpoint: valid Ed25519 over a valid
    // canonical string, and still refused because field 14 says the frame is not for us.
    const { frame } = sign({ core: { audience: 'relay' } });
    const verdict = await verify(frame);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_AUDIENCE_MISMATCH');
  });

  it('refuses an audience outside the enum at the shape step', async () => {
    const { frame } = sign({ core: { audience: 'endpoint ' } });
    const verdict = await verify(frame);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_ENVELOPE_SHAPE_INVALID');
  });
});

describe('3. freshness: stale and future-dated frames are both refused', () => {
  it('refuses a frame older than the frozen 60 s endpoint window', async () => {
    const { frame } = sign({ core: { issuedAt: String(T), deadlineMs: String(T + 60000) } });
    const verdict = await verify(frame, { now: () => T + 61000 });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_FRESHNESS_EXPIRED');
  });

  it('accepts a frame exactly at the 60 s boundary (inclusive), then refuses one millisecond later', async () => {
    const first = sign({ core: { issuedAt: String(T), deadlineMs: String(T + 60000) } });
    const atBoundary = await verify(first.frame, { now: () => T + 60000 });
    assert.equal(atBoundary.ok, true, atBoundary.ok === false ? atBoundary.error.code : '');

    const second = sign({ core: { issuedAt: String(T), deadlineMs: String(T + 60000) } });
    const pastBoundary = await verify(second.frame, { now: () => T + 60001 });
    assert.equal(pastBoundary.ok, false);
    assert.equal(pastBoundary.error.code, 'ENDPOINT_FRESHNESS_EXPIRED');
  });

  it('refuses a future-dated frame beyond the window', async () => {
    const { frame } = sign({ core: { issuedAt: String(T + 61000), deadlineMs: String(T + 120000) } });
    const verdict = await verify(frame, { now: () => T });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_FRESHNESS_NOT_YET_VALID');
  });

  it('refuses a future-dated frame inside the window, but not before the window closes', async () => {
    const inside = sign({ core: { issuedAt: String(T + 30000), deadlineMs: String(T + 120000) } });
    // |now - issuedAt| <= 60 s BOTH ways: a frame from 30 s in the future is inside the window.
    const insideVerdict = await verify(inside.frame, { now: () => T });
    assert.equal(insideVerdict.ok, true, '30 s early must still be fresh');

    const { frame } = sign({ core: { issuedAt: String(T + 30000), deadlineMs: String(T + 120000) } });
    const outsideVerdict = await verify(frame, { now: () => T - 31001 });
    assert.equal(outsideVerdict.ok, false);
    assert.equal(outsideVerdict.error.code, 'ENDPOINT_FRESHNESS_NOT_YET_VALID');
  });
});

describe('4. deadlineMs is enforced independently of freshness', () => {
  it('refuses a frame whose deadline has passed', async () => {
    const { frame } = sign({ core: { issuedAt: String(T), deadlineMs: String(T + 20000) } });
    // Inside the 60 s freshness window (10 s old) but past its own deadline.
    const verdict = await verify(frame, { now: () => T + 30000 });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_DEADLINE_EXCEEDED');
  });

  it('refuses a deadline horizon beyond the frozen 120 s cap', async () => {
    const { frame } = sign({ core: { issuedAt: String(T), deadlineMs: String(T + 120001) } });
    const verdict = await verify(frame, { now: () => T });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_DEADLINE_EXCEEDED');
  });

  it('refuses a deadline that precedes its own issuance', async () => {
    const { frame } = sign({ core: { issuedAt: String(T), deadlineMs: String(T - 1) } });
    const verdict = await verify(frame, { now: () => T });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_ENVELOPE_SHAPE_INVALID');
  });
});

describe('5. replay: the same nonce is refused twice', () => {
  it('accepts the first use and refuses the second, with a distinct code', async () => {
    const window = createDurableReplayWindow({ persist: false, now: () => T + 1000 });
    const { frame } = sign();

    const first = await verify(frame, { replayWindow: window });
    assert.equal(first.ok, true, first.ok === false ? first.error.code : '');

    const second = await verify(frame, { replayWindow: window });
    assert.equal(second.ok, false);
    assert.equal(second.error.code, 'ENDPOINT_REPLAY_DETECTED');
  });

  it('binds the nonce to the grant: the same nonce under a DIFFERENT grantId is not a replay', async () => {
    const window = createDurableReplayWindow({ persist: false, now: () => T + 1000 });
    const nonce = freshNonce();
    const first = sign({ core: { nonce } });
    const second = sign({ core: { nonce, grantId: 'AQIDBAUGBwgJCgsMDQ4PEA' } });

    assert.equal((await verify(first.frame, { replayWindow: window })).ok, true);
    assert.equal((await verify(second.frame, { replayWindow: window })).ok, true);
  });

  it('a forged frame cannot burn a nonce and deny the genuine one that follows', async () => {
    const window = createDurableReplayWindow({ persist: false, now: () => T + 1000 });
    const nonce = freshNonce();
    const genuine = sign({ core: { nonce } });
    const forged = { ...genuine.frame, signatureB64u: otherKey.sign(genuine.canonical) };

    const forgedVerdict = await verify(forged, { replayWindow: window });
    assert.equal(forgedVerdict.ok, false);
    assert.equal(forgedVerdict.error.code, 'ENDPOINT_SIGNATURE_INVALID');

    const genuineVerdict = await verify(genuine.frame, { replayWindow: window });
    assert.equal(genuineVerdict.ok, true, 'the nonce must still be spendable by the real frame');
  });
});

describe('6. signature and key pinning', () => {
  it('refuses a frame signed by a key that is not pinned, without calling it a bad signature', async () => {
    const forged = fixtures.buildFrame({
      sign: otherKey.sign,
      keyId: otherKey.keyId,
      core: { nonce: freshNonce(), issuedAt: String(T), deadlineMs: String(T + 60000) },
    });
    const verdict = await verify(forged.frame);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_KEY_UNPINNED');
  });

  it('refuses a frame that names a PINNED keyId but is signed by another key', async () => {
    const { frame, canonical } = sign();
    const verdict = await verify({ ...frame, signatureB64u: otherKey.sign(canonical) });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_SIGNATURE_INVALID');
  });

  it('refuses a malformed signature before attempting verification', async () => {
    const { frame } = sign();
    const verdict = await verify({ ...frame, signatureB64u: 'not-a-signature' });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_SIGNATURE_INVALID');
  });

  it('refuses a frame carrying any field that is not part of the frozen document', async () => {
    const { frame } = sign();
    const verdict = await verify({ ...frame, ownerPrincipalIdClaim: 'someone-else' });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_FRAME_EXTRA_FIELD');
  });

  it('refuses a frame whose tag is not the frozen versioned separator', async () => {
    const { frame } = sign();
    const verdict = await verify({ ...frame, tag: 'CBHR-RPC-V1' });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_ENVELOPE_SHAPE_INVALID');
    assert.equal(V2_TAG, 'CBHR-RPC-V2');
  });
});

describe('7. the endpoint is the addressee', () => {
  it('refuses a valid backend-signed command addressed to another device', async () => {
    const { frame } = sign({ core: { deviceId: '65a1b2c3d4e5f60718293b4d' } });
    const verdict = await verify(frame);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_DEVICE_MISMATCH');
  });

  it('refuses a valid backend-signed command bound to another key generation', async () => {
    const { frame } = sign({
      core: { deviceKeyId: 'aBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw' },
    });
    const verdict = await verify(frame);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_DEVICE_KEY_MISMATCH');
  });
});

describe('8. opKind admission', () => {
  it('refuses a resync frame at this lab endpoint, with its own code', async () => {
    const { frame } = sign({ core: { opKind: 'resync' } });
    const verdict = await verify(frame);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_OPKIND_REFUSED');
  });

  it('refuses a cancel frame at this lab endpoint, with its own code', async () => {
    const { frame } = sign({ core: { opKind: 'cancel' } });
    const verdict = await verify(frame);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_OPKIND_REFUSED');
  });
});

describe('9. the refusal taxonomy is distinct and leak-free', () => {
  it('every step has its own code, and no two steps share one', async () => {
    const cases = [];
    cases.push((await verify({ ...sign().frame, argsB64u: 'AAAA' })).error.code);
    cases.push((await verify(sign({ core: { audience: 'relay' } }).frame)).error.code);
    cases.push((await verify(sign({ core: { issuedAt: String(T) } }).frame, { now: () => T + 90000 })).error.code);
    cases.push(
      (await verify(sign({ core: { issuedAt: String(T), deadlineMs: String(T + 1000) } }).frame, { now: () => T + 2000 }))
        .error.code,
    );
    cases.push((await verify(sign({ core: { deviceId: 'other' } }).frame)).error.code);
    cases.push((await verify(sign({ core: { deviceKeyId: 'aBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw' } }).frame)).error.code);
    cases.push((await verify(sign({ core: { opKind: 'cancel' } }).frame)).error.code);
    cases.push(
      (
        await verify(fixtures.buildFrame({ sign: otherKey.sign, keyId: otherKey.keyId, core: { nonce: freshNonce() } }).frame)
      ).error.code,
    );
    assert.equal(new Set(cases).size, cases.length, `codes must be distinct: ${cases.join(', ')}`);
    for (const code of cases) {
      assert.match(code, /^ENDPOINT_/);
    }
  });

  it('a refusal never names the failing field or its value in serialized form', async () => {
    const { frame } = sign({ core: { deviceId: 'device-that-is-not-me' } });
    const verdict = await verify(frame);
    assert.equal(verdict.ok, false);

    const error = verdict.error;
    assert.equal(error.name, 'EndpointRefusal');
    assert.equal(error.message, 'endpoint refused the frame');
    // `field` and `detail` are server-side only: real but NON-ENUMERABLE, so a
    // serialization or a JSON.stringify'd error never leaks which check failed.
    assert.equal(Object.getOwnPropertyDescriptor(error, 'field').enumerable, false);
    assert.equal(Object.getOwnPropertyDescriptor(error, 'detail').enumerable, false);
    assert.equal(error.field, 'deviceId');
    assert.ok(error.detail.includes('different device id'));

    const serialized = JSON.stringify(error);
    assert.ok(!serialized.includes('deviceId'), 'JSON.stringify must not carry the field name');
    assert.ok(!serialized.includes('device-that-is-not-me'), 'JSON.stringify must not carry the value');
    assert.ok(!serialized.includes('detail'));
    // Own enumerable data properties are the envelope: name/code/httpStatus/retryable. `message` and
    // `stack` live on the Error prototype, which is exactly why they stay fixed and generic while
    // `field`/`detail` are non-enumerable own properties.
    assert.deepEqual(new Set(Object.keys(error)), new Set(['name', 'code', 'httpStatus', 'retryable']));
    assert.equal(error.message, 'endpoint refused the frame');
    assert.equal(JSON.parse(serialized).code, 'ENDPOINT_DEVICE_MISMATCH');
  });

  it('a sanitized cause carries only an error code, never a message that could hold key material', async () => {
    const { refusal } = require('../src/errors');
    const inner = new Error('custody said: pkcs8=AAAA-secret-key-material');
    inner.code = 'CUSTODY_BROKE';
    const outer = refusal('ENDPOINT_DEVICE_KEY_UNAVAILABLE', 'the key could not be loaded', { cause: inner });
    const util = require('node:util');
    const printed = `${util.inspect(outer, { depth: 8 })} ${JSON.stringify(outer)} ${outer.message}`;
    assert.ok(!printed.includes('secret-key-material'));
    assert.equal(outer.cause.name, 'EndpointCause');
    assert.equal(outer.cause.code, 'CUSTODY_BROKE');
    assert.equal(outer.cause.message, 'endpoint cause');
  });
});
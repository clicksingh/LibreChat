'use strict';

/**
 * W7 spec — THE GOLDEN VECTOR: is the endpoint's signed byte layout the CONTRACT's, or merely its own?
 *
 * A verifier that shares its field order with the signer agrees with itself and proves nothing about
 * the frozen contract (GM-54). These assertions therefore come from three directions at once:
 *
 *   A. The contract's PUBLISHED worked example, byte for byte, against the endpoint's independent
 *      rebuild — including the literal count of 0x1F separators, and re-deriving the digest from the
 *      args bytes the contract says were hashed.
 *   B. The contract's PUBLISHED Ed25519 signature under its published fixed-seed key, verified by the
 *      endpoint's real verification chain. If the endpoint's field order, tag or encoding were wrong
 *      by one byte, this signature would not verify — no amount of self-consistency would save it.
 *   C. Negative controls on the vector itself: a reordered core, a changed tag and a changed field
 *      must NOT verify, so test A cannot pass vacuously.
 *
 * The backend's own copy of this vector lives in `api/server/services/Device/relay/__tests__`; the
 * literals below are duplicated on purpose, because a shared import would make the two sides agree by
 * construction and hide exactly the divergence this spec exists to catch.
 */

const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { describe, it } = require('node:test');

const fixtures = require('./_fixtures');
const layout = require('../src/layout');
const { verifyCommandFrame } = require('../src/verify');
const { buildPinSet } = require('../src/pinnedKeys');
const { createDurableReplayWindow } = require('../src/replayWindow');
const { sha256Hex } = require('../src/freshness');

const ARGS_BYTES = Buffer.from('{"path":"C:/notes/today.txt"}', 'utf8');

function keyIdOf(spkiB64u) {
  return nodeCrypto.createHash('sha256').update(Buffer.from(spkiB64u, 'base64url')).digest('base64url');
}

function memoryReplayWindow(now) {
  return createDurableReplayWindow({ persist: false, now });
}

describe('A. the endpoint rebuilds the contract worked example byte for byte', () => {
  it('produces the published canonical string, with 15 fields and 14 separators', () => {
    const fromAgent = layout.canonicalBytesFor(fixtures.WORKED_EXAMPLE);
    const fromFixture = fixtures.canonicalFor(fixtures.WORKED_EXAMPLE);

    assert.equal(fromAgent.toString('utf8'), fixtures.WORKED_EXAMPLE_CANONICAL);
    assert.equal(fromAgent.length, 325);
    assert.ok(fromAgent.equals(fromFixture), 'the agent layout and the independent fixture join must agree');
    assert.equal(fixtures.WORKED_EXAMPLE_CANONICAL.split(fixtures.SEPARATOR).length, 15);
    assert.equal(fixtures.WORKED_EXAMPLE_CANONICAL.split(fixtures.SEPARATOR)[0], 'CBHR-RPC-V2');
    assert.equal(
      fixtures.WORKED_EXAMPLE_CANONICAL.split(fixtures.SEPARATOR).length - 1,
      fromAgent.toString('utf8').split(fixtures.SEPARATOR).length - 1,
    );
  });

  it('pins the exact field ORDER rather than a set of names', () => {
    assert.deepEqual([...layout.FIELD_ORDER], [...fixtures.FROZEN_FIELD_ORDER]);
    const reordered = Object.fromEntries(
      Object.entries(fixtures.WORKED_EXAMPLE).reverse(),
    );
    // A reordered object must produce the SAME bytes: the order is the layout's, not the object's.
    assert.ok(layout.canonicalBytesFor(reordered).equals(layout.canonicalBytesFor(fixtures.WORKED_EXAMPLE)));
  });

  it('re-derives the published args digest from the args bytes, with no canonicalisation (GM-29)', () => {
    assert.equal(sha256Hex(ARGS_BYTES), fixtures.WORKED_EXAMPLE.argsDigestHex);
  });

  it('refuses a field carrying the 0x1F separator, and refuses an extra field', () => {
    assert.throws(
      () => layout.canonicalBytesFor({ ...fixtures.WORKED_EXAMPLE, tenantId: 'tenant\u001fkelowna' }),
      (err) => err.code === 'ENDPOINT_ENVELOPE_FIELD_NOT_CANONICAL',
    );
    assert.throws(
      () => layout.canonicalBytesFor({ ...fixtures.WORKED_EXAMPLE, extra: 'x' }),
      (err) => err.code === 'ENDPOINT_FRAME_EXTRA_FIELD',
    );
    assert.throws(
      () => layout.canonicalBytesFor({ ...fixtures.WORKED_EXAMPLE, sha256args: 'x' }),
      (err) => err.code === 'ENDPOINT_FRAME_EXTRA_FIELD',
    );
  });
});

describe('B. the contract published signature verifies through the real endpoint chain', () => {
  it('accepts the published golden signature over the worked example', async () => {
    const keyId = keyIdOf(fixtures.GOLDEN_PUBLIC_KEY_SPKI_B64U);
    const frame = Object.freeze({
      ...fixtures.WORKED_EXAMPLE,
      signatureB64u: fixtures.GOLDEN_SIGNATURE_B64U,
      keyId,
      argsB64u: ARGS_BYTES.toString('base64url'),
      callId: 'call-golden-1',
    });
    const verdict = await verifyCommandFrame({
      frame,
      pins: buildPinSet([{ keyId, publicKeySpkiB64u: fixtures.GOLDEN_PUBLIC_KEY_SPKI_B64U }]),
      deviceId: fixtures.WORKED_EXAMPLE.deviceId,
      deviceKeyId: fixtures.WORKED_EXAMPLE.deviceKeyId,
      now: () => fixtures.T0 + 1000,
      replayWindow: memoryReplayWindow(() => fixtures.T0 + 1000),
    });
    assert.equal(verdict.ok, true, verdict.ok === false ? verdict.error.code : '');
    assert.equal(verdict.core.toolName, 'read_file');
    assert.ok(verdict.argsBytes.equals(ARGS_BYTES));
  });

  it('still refuses the golden vector when the args bytes are swapped under it (the signature binds the digest)', async () => {
    const keyId = keyIdOf(fixtures.GOLDEN_PUBLIC_KEY_SPKI_B64U);
    const frame = Object.freeze({
      ...fixtures.WORKED_EXAMPLE,
      signatureB64u: fixtures.GOLDEN_SIGNATURE_B64U,
      keyId,
      argsB64u: Buffer.from('{"path":"C:/notes/SECRET.txt"}', 'utf8').toString('base64url'),
      callId: 'call-golden-2',
    });
    const verdict = await verifyCommandFrame({
      frame,
      pins: buildPinSet([{ keyId, publicKeySpkiB64u: fixtures.GOLDEN_PUBLIC_KEY_SPKI_B64U }]),
      deviceId: fixtures.WORKED_EXAMPLE.deviceId,
      deviceKeyId: fixtures.WORKED_EXAMPLE.deviceKeyId,
      now: () => fixtures.T0 + 1000,
      replayWindow: memoryReplayWindow(() => fixtures.T0 + 1000),
    });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.error.code, 'ENDPOINT_ARGS_DIGEST_MISMATCH');
  });
});

describe('C. negative controls: the vector is not passing vacuously', () => {
  it('rejects a recomputed signature over a REORDERED canonical string', () => {
    const golden = fixtures.makeGoldenKeypair();
    assert.equal(golden.publicKeySpkiB64u, fixtures.GOLDEN_PUBLIC_KEY_SPKI_B64U);

    const reordered = [
      'CBHR-RPC-V2',
      fixtures.WORKED_EXAMPLE.nonce,
      fixtures.WORKED_EXAMPLE.requestId,
      ...fixtures.FROZEN_FIELD_ORDER.slice(3).map((property) => fixtures.WORKED_EXAMPLE[property]),
    ].join(fixtures.SEPARATOR);
    const wrongOrderSignature = golden.sign(Buffer.from(reordered, 'utf8'));

    // A different byte string must give a different signature: the published one is over THIS order.
    assert.notEqual(wrongOrderSignature, fixtures.GOLDEN_SIGNATURE_B64U);
    assert.equal(golden.sign(Buffer.from(fixtures.WORKED_EXAMPLE_CANONICAL, 'utf8')), fixtures.GOLDEN_SIGNATURE_B64U);
  });

  it('rejects a recomputed signature over a different domain tag', () => {
    const golden = fixtures.makeGoldenKeypair();
    const v1 = fixtures.WORKED_EXAMPLE_CANONICAL.replace('CBHR-RPC-V2', 'CBHR-RPC-V1');
    assert.notEqual(golden.sign(Buffer.from(v1, 'utf8')), fixtures.GOLDEN_SIGNATURE_B64U);
  });

  it('the endpoint tag is one token and cannot be confused with the result tag', () => {
    assert.equal(layout.V2_TAG, 'CBHR-RPC-V2');
    assert.equal(layout.RESULT_TAG, 'CBHR-RPC-RESULT-V2');
    assert.notEqual(layout.V2_TAG, layout.RESULT_TAG);
    const resultBytes = require('../src/resultFrame').resultCanonicalBytes({
      tag: layout.RESULT_TAG,
      requestId: 'x',
      callId: 'y',
      nonce: 'AAECAwQFBgcICQoLDA0ODw',
      issuedAt: '1',
      deadlineMs: '2',
      grantId: 'EBESExQVFhcYGRobHB0eHw',
      epoch: '1',
      deviceId: 'd',
      deviceKeyId: 'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw',
      outcome: 'succeeded',
      argsDigestHex: fixtures.WORKED_EXAMPLE.argsDigestHex,
    });
    assert.ok(resultBytes.toString('utf8').startsWith('CBHR-RPC-RESULT-V2\u001f'));
    assert.equal(resultBytes.toString('utf8').split(fixtures.SEPARATOR).length, 12);
  });
});
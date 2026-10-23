'use strict';

/**
 * W2 spec — canonical string, signing determinism, tamper detection, and the custody seam.
 *
 * The frozen contract under test: `CBHR-RPC-V2` 15-field core, 0x1F-joined UTF-8, Ed25519
 * PureEdDSA over those exact bytes, no field reordering and no extra field inside the signature.
 */

const {
  relay,
  deviceCrypto,
  WORKED_EXAMPLE_CORE,
  WORKED_EXAMPLE_CANONICAL,
  WORKED_EXAMPLE_CANONICAL_BYTES,
  GOLDEN_PUBLIC_KEY_SPKI_B64U,
  GOLDEN_SIGNATURE_B64U,
  T0,
  makeTestKeypair,
  makeDeterministicKeypair,
  makeCustodySeam,
} = require('./_fixtures.cjs');

const keypair = makeTestKeypair();

/** Core with one field replaced, everything else identical. */
function coreWith(overrides) {
  return { ...WORKED_EXAMPLE_CORE, ...overrides };
}

describe('CBHR-RPC-V2 canonical string', () => {
  it('joins exactly 15 fields with a single 0x1F and reproduces the frozen worked example', () => {
    const bytes = relay.canonicalRpcBytes(relay.buildEnvelopeCore(WORKED_EXAMPLE_CORE));

    expect(bytes.toString('utf8')).toBe(WORKED_EXAMPLE_CANONICAL);
    expect(bytes.length).toBe(WORKED_EXAMPLE_CANONICAL_BYTES);
    expect(WORKED_EXAMPLE_CANONICAL.split('\u001f')).toHaveLength(15);
    expect(WORKED_EXAMPLE_CANONICAL.split('\u001f')[0]).toBe('CBHR-RPC-V2');
  });

  it('fixes the field order to the contract, independent of the input key order', () => {
    const reversed = Object.fromEntries(Object.entries(WORKED_EXAMPLE_CORE).reverse());
    const forward = relay.canonicalRpcBytes(relay.buildEnvelopeCore(WORKED_EXAMPLE_CORE));
    const backward = relay.canonicalRpcBytes(relay.buildEnvelopeCore(reversed));

    expect(backward.equals(forward)).toBe(true);
    expect(relay.RPC_ENVELOPE_FIELD_ORDER).toEqual([
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
    expect(relay.RPC_ENVELOPE_CONTRACT_NAMES).toHaveLength(15);
    expect(relay.RPC_ENVELOPE_CONTRACT_NAMES[14]).toBe('sha256(args)');
  });

  it('binds every one of the 15 fields: changing any single field changes the signed bytes', () => {
    const baseline = relay.canonicalRpcBytes(relay.buildEnvelopeCore(WORKED_EXAMPLE_CORE));
    const mutations = {
      requestId: '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c94',
      nonce: 'AAECAwQFBgcICQoLDA0OEQ',
      issuedAt: String(T0 + 1),
      deadlineMs: String(T0 + 60001),
      epoch: '8',
      grantId: 'EBESExQVFhcYGRobHB0eIA',
      ownerPrincipalId: '64f0a1b2c3d4e5f60718293b',
      tenantId: 'tenant-other',
      deviceId: '65a1b2c3d4e5f60718293b4d',
      deviceKeyId: 'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPA',
      toolName: 'write_file',
      opKind: 'cancel',
      audience: 'relay',
      argsDigestHex: '3795b53e4665398f141a5fafb3b006777f9f15f56423821f3e88795a8b972d15',
    };

    const mutated = Object.keys(mutations);
    expect(mutated).toHaveLength(14);
    for (const field of mutated) {
      const bytes = relay.canonicalRpcBytes(relay.buildEnvelopeCore(coreWith({ [field]: mutations[field] })));
      expect({ field, differs: !bytes.equals(baseline) }).toEqual({ field, differs: true });
    }
    // The tag is the 15th: bumping it changes the domain separator itself.
    expect(() => relay.buildEnvelopeCore(coreWith({ tag: 'CBHR-RPC-V1' }))).toThrow(
      expect.objectContaining({ code: 'ENVELOPE_SHAPE_INVALID' }),
    );
  });

  it('refuses to serialise a field containing the 0x1F separator (mint-side law)', () => {
    expect(() =>
      relay.canonicalRpcBytes(relay.buildEnvelopeCore(coreWith({ toolName: 'read\u001ffile' }))),
    ).toThrow(expect.objectContaining({ code: 'ENVELOPE_FIELD_NOT_CANONICAL' }));
  });

  it('refuses a transport field inside the signature', () => {
    expect(() =>
      relay.buildEnvelopeCore(coreWith({ seq: 12 })),
    ).toThrow(expect.objectContaining({ code: 'ENVELOPE_SHAPE_INVALID' }));
  });

  it('refuses a deadline horizon beyond the frozen 120 s bound and a negative horizon', () => {
    expect(() =>
      relay.buildEnvelopeCore(coreWith({ deadlineMs: String(T0 + 120001) })),
    ).toThrow(expect.objectContaining({ code: 'DEADLINE_OUT_OF_BOUND' }));
    expect(() =>
      relay.buildEnvelopeCore(coreWith({ deadlineMs: String(T0 - 1) })),
    ).toThrow(expect.objectContaining({ code: 'ENVELOPE_SHAPE_INVALID' }));
  });

  it.each([
    ['requestId', 'not-a-uuid'],
    ['nonce', 'AAECAwQFBgcICQoLDA0O'],
    ['issuedAt', '1761200000000.5'],
    ['epoch', '0'],
    ['grantId', 'EBESExQVFhcYGRobHB0e'],
    ['deviceKeyId', 'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS'],
    ['opKind', 'exec'],
    ['audience', 'device'],
    ['argsDigestHex', '3795B53E4665398F141A5FAFB3B006777F9F15F56423821F3E88795A8B972D14'],
  ])('refuses an out-of-domain %s', (field, value) => {
    expect(() => relay.buildEnvelopeCore(coreWith({ [field]: value }))).toThrow(
      expect.objectContaining({ code: 'ENVELOPE_SHAPE_INVALID' }),
    );
  });
});

describe('signing determinism', () => {
  it('produces byte-identical canonical bytes and an identical signature for the same core', async () => {
    const signer = relay.createEnvelopeSigner(makeCustodySeam(keypair));

    const first = await signer.signCore(WORKED_EXAMPLE_CORE);
    const second = await signer.signCore(WORKED_EXAMPLE_CORE);

    expect(first.signatureB64u).toBe(second.signatureB64u);
    expect(relay.canonicalRpcBytes(first.core).equals(relay.canonicalRpcBytes(second.core))).toBe(
      true,
    );
    // The signature is over the worked-example bytes, so it is stable across runs.
    expect(first.signatureB64u).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(first.keyId).toBe('test-custody-key-1');
  });

  it('signs the exact canonical bytes and nothing else', async () => {
    const seen = [];
    const signer = relay.createEnvelopeSigner({
      keyId: 'probe',
      sign: (bytes) => {
        seen.push(Buffer.from(bytes));
        return keypair.signBytes(bytes);
      },
    });

    await signer.signCore(WORKED_EXAMPLE_CORE);

    expect(seen).toHaveLength(1);
    expect(seen[0].toString('utf8')).toBe(WORKED_EXAMPLE_CANONICAL);
  });

  it('accepts an async custody implementation (HSM / KMS shape) without change', async () => {
    const signer = relay.createEnvelopeSigner({
      keyId: 'remote-custody',
      sign: async (bytes) => {
        await Promise.resolve();
        return keypair.signBytes(bytes);
      },
    });
    const signed = await signer.signCore(WORKED_EXAMPLE_CORE);
    const verifier = relay.createEnvelopeVerifier({
      publicKeySpkiB64u: keypair.publicKeySpkiB64u,
    });

    expect(verifier.verifySignature(signed).ok).toBe(true);
  });

  it('reproduces the published golden signature over the frozen worked example', async () => {
    const deterministic = makeDeterministicKeypair();
    expect(deterministic.publicKeySpkiB64u).toBe(GOLDEN_PUBLIC_KEY_SPKI_B64U);

    const signer = relay.createEnvelopeSigner(makeCustodySeam(deterministic, 'golden'));
    const signed = await signer.signCore(WORKED_EXAMPLE_CORE);

    expect(relay.canonicalRpcBytes(signed.core).toString('utf8')).toBe(WORKED_EXAMPLE_CANONICAL);
    expect(signed.signatureB64u).toBe(GOLDEN_SIGNATURE_B64U);
    expect(
      relay.createEnvelopeVerifier({ publicKeySpkiB64u: GOLDEN_PUBLIC_KEY_SPKI_B64U })
        .verifySignature(signed).ok,
    ).toBe(true);
  });
});

describe('tamper detection', () => {
  const verifier = relay.createEnvelopeVerifier({ publicKeySpkiB64u: keypair.publicKeySpkiB64u });

  async function signedExample() {
    const signer = relay.createEnvelopeSigner(makeCustodySeam(keypair));
    return signer.signCore(WORKED_EXAMPLE_CORE);
  }

  it('accepts the untampered envelope (control)', async () => {
    expect(verifier.verifySignature(await signedExample()).ok).toBe(true);
  });

  it('rejects a single flipped bit anywhere in the signed bytes (byte-level tamper)', async () => {
    const signed = await signedExample();
    const canonical = relay.canonicalRpcBytes(signed.core);

    // Flip exactly one bit in each byte position, one at a time: every position must fail.
    for (let index = 0; index < canonical.length; index++) {
      const mutated = Buffer.from(canonical);
      mutated[index] ^= 0x01;
      const verified = deviceCrypto.verifyEd25519({
        publicKeySpkiB64u: keypair.publicKeySpkiB64u,
        message: mutated,
        signatureB64u: signed.signatureB64u,
      });
      expect({ index, verified }).toEqual({ index, verified: false });
    }
    // Control: the unmutated bytes still verify.
    expect(
      deviceCrypto.verifyEd25519({
        publicKeySpkiB64u: keypair.publicKeySpkiB64u,
        message: canonical,
        signatureB64u: signed.signatureB64u,
      }),
    ).toBe(true);
  });

  it('rejects a flipped byte in the signature itself', async () => {
    const signed = await signedExample();
    const bytes = Buffer.from(signed.signatureB64u, 'base64url');
    bytes[0] ^= 0x01;
    const tampered = {
      core: signed.core,
      signatureB64u: bytes.toString('base64url'),
      keyId: signed.keyId,
    };

    const result = verifier.verifySignature(tampered);
    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('ENVELOPE_SIGNATURE_INVALID');
  });

  it.each([
    ['toolName', 'write_file'],
    ['argsDigestHex', '3795b53e4665398f141a5fafb3b006777f9f15f56423821f3e88795a8b972d15'],
    ['audience', 'relay'],
    ['grantId', 'EBESExQVFhcYGRobHB0eIA'],
    ['ownerPrincipalId', '64f0a1b2c3d4e5f60718293b'],
    ['epoch', '8'],
    ['deadlineMs', String(T0 + 60001)],
    ['nonce', 'AAECAwQFBgcICQoLDA0OEQ'],
  ])('rejects a flipped field value for %s', async (field, value) => {
    const signed = await signedExample();
    const tampered = {
      core: { ...signed.core, [field]: value },
      signatureB64u: signed.signatureB64u,
      keyId: signed.keyId,
    };

    const result = verifier.verifySignature(tampered);
    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('ENVELOPE_SIGNATURE_INVALID');
  });

  it('rejects an envelope re-signed by a different key', async () => {
    const otherKeypair = makeTestKeypair();
    const otherSigner = relay.createEnvelopeSigner(makeCustodySeam(otherKeypair, 'other-key'));
    const forged = await otherSigner.signCore(WORKED_EXAMPLE_CORE);

    const result = verifier.verifySignature(forged);
    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('ENVELOPE_SIGNATURE_INVALID');
  });

  it('rejects a signature with an unusable encoding rather than throwing', async () => {
    const signed = await signedExample();
    for (const signatureB64u of ['', 'not base64url!!', 'AAAA', null]) {
      const result = verifier.verifySignature({
        core: signed.core,
        signatureB64u,
        keyId: signed.keyId,
      });
      expect(result.ok).toBe(false);
    }
  });

  it('applies the pinned keyId label only after the signature verifies', async () => {
    const pinned = relay.createEnvelopeVerifier({
      publicKeySpkiB64u: keypair.publicKeySpkiB64u,
      expectedKeyId: 'expected-label',
    });
    const signed = await signedExample();

    const labelMismatch = pinned.verifySignature(signed);
    expect(labelMismatch.ok).toBe(false);
    expect(labelMismatch.error.code).toBe('ENVELOPE_KEY_MISMATCH');

    // A wrong key with a wrong label must report the cryptographic failure, never the label.
    const otherKeypair = makeTestKeypair();
    const otherSigner = relay.createEnvelopeSigner(makeCustodySeam(otherKeypair, 'expected-label'));
    const forged = otherSigner.signCore(WORKED_EXAMPLE_CORE);
    const forgedResult = pinned.verifySignature(await forged);
    expect(forgedResult.ok).toBe(false);
    expect(forgedResult.error.code).toBe('ENVELOPE_SIGNATURE_INVALID');
  });
});

describe('the injected custody seam', () => {
  it('accepts exactly { sign, keyId } and refuses any extra key, so key material cannot enter', () => {
    expect(relay.SIGNER_SEAM_KEYS).toEqual(['sign', 'keyId']);
    expect(() =>
      relay.createEnvelopeSigner({
        sign: async () => 'x',
        keyId: 'k',
        privateKey: keypair.privateKeyPem,
      }),
    ).toThrow(expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }));
    expect(() =>
      relay.createEnvelopeSigner({
        sign: async () => 'x',
        keyId: 'k',
        key: keypair.privateKeyPkcs8B64u,
      }),
    ).toThrow(expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }));
  });

  it('requires a sign function and a usable keyId', () => {
    expect(() => relay.createEnvelopeSigner(null)).toThrow(
      expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }),
    );
    expect(() => relay.createEnvelopeSigner({ keyId: 'k' })).toThrow(
      expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }),
    );
    expect(() => relay.createEnvelopeSigner({ sign: () => 'x' })).toThrow(
      expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }),
    );
    expect(() => relay.createEnvelopeSigner({ sign: () => 'x', keyId: '' })).toThrow(
      expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }),
    );
  });

  it('refuses a signer that returns a non-Ed25519-sized or non-canonical signature', async () => {
    for (const sign of [
      () => 'AAAA',
      () => 'not base64url!!',
      () => null,
      async () => {
        throw new Error('custody unavailable');
      },
    ]) {
      const signer = relay.createEnvelopeSigner({ sign, keyId: 'k' });
      await expect(signer.signCore(WORKED_EXAMPLE_CORE)).rejects.toMatchObject({
        code: 'SIGNER_SEAM_INVALID',
      });
    }
  });

  it('exposes no key-reading, key-generating or signing primitive on its surface', () => {
    const signer = relay.createEnvelopeSigner(makeCustodySeam(keypair));
    expect(Object.keys(signer).sort()).toEqual(['keyId', 'signBytes', 'signCore']);
    expect(Object.isFrozen(signer)).toBe(true);
    expect(signer.privateKey).toBeUndefined();
    expect(signer.key).toBeUndefined();
    expect(signer.publicKey).toBeUndefined();
  });
});



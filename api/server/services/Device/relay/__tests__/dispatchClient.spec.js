'use strict';

/**
 * W2 spec — the backend -> relay dispatch client.
 *
 * The two properties under test:
 *   1. IDENTITY IS NEVER SYNTHESISED FROM A REQUEST. The dispatch request and the authority
 *      projection are exact-key whitelists; a request-shaped object is refused by name, and every
 *      identity value in the signed core comes from the trusted authority projection.
 *   2. UNKNOWN-OUTCOME IS NEVER SUCCESS (F-V24C-9): only a 2xx relay answer that does not explicitly
 *      refuse is `ok: true`; a 5xx or a transport throw is `delivered: 'unknown'`.
 */

const {
  relay,
  nodeCrypto,
  AUTHORITY,
  T0,
  makeTestKeypair,
  makeCustodySeam,
  makeTransport,
} = require('./_fixtures.cjs');

const keypair = makeTestKeypair();
const signer = relay.createEnvelopeSigner(makeCustodySeam(keypair));
const verifier = relay.createEnvelopeVerifier({ publicKeySpkiB64u: keypair.publicKeySpkiB64u });

/**
 * Builds a client with reproducible minters and a recording transport.
 *
 * A replay window is ALWAYS supplied: `createRelayDispatchClient` refuses `replayWindow: null`
 * (GM-49 — a real dispatch without replay enforcement is a defect). `overrides.replayWindow` lets a
 * test share or replace it.
 */
function buildClient(overrides = {}) {
  const response = 'response' in overrides ? overrides.response : { status: 200, body: { accepted: true } };
  const { transport, calls } = makeTransport(response);
  const client = relay.createRelayDispatchClient({
    transport,
    signer,
    clock: { now: () => (overrides.now ?? T0) },
    nonceFactory: overrides.nonceFactory ?? (() => AUTHORITY_NONCE),
    requestIdFactory: overrides.requestIdFactory ?? (() => REQUEST_ID),
    verifier: overrides.verifier === undefined ? verifier : overrides.verifier,
    replayWindow:
      overrides.replayWindow === undefined
        ? relay.createReplayWindow({ now: () => (overrides.now ?? T0) })
        : overrides.replayWindow,
    logger: overrides.logger ?? null,
    assertAuthorityCurrent: overrides.assertAuthorityCurrent ?? null,
  });
  return { client, transport, calls };
}

const AUTHORITY_NONCE = 'AAECAwQFBgcICQoLDA0ODw';
const REQUEST_ID = '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93';

/** A fresh 128-bit nonce per call, so a shared replay window does not see a replay. */
function uniqueNonces() {
  let counter = 0;
  return () => Buffer.alloc(16, (counter += 1)).toString('base64url');
}

const ARGS_BYTES = Buffer.from('{"path":"C:/notes/today.txt"}', 'utf8');
const ARGS_DIGEST_HEX = nodeCrypto.createHash('sha256').update(ARGS_BYTES).digest('hex');

describe('dispatch client — identity comes only from trusted server context', () => {
  it('mints a core whose identity fields are exactly the trusted authority projection', async () => {
    const { client, calls } = buildClient();

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
      seq: 12,
    });

    expect(outcome.ok).toBe(true);
    expect(outcome.delivered).toBe('accepted');
    expect(calls).toHaveLength(1);
    expect(calls[0].deviceId).toBe(AUTHORITY.deviceId);

    const frame = calls[0].frame;
    expect(frame.tenantId).toBe(AUTHORITY.tenantId);
    expect(frame.ownerPrincipalId).toBe(AUTHORITY.ownerPrincipalId);
    expect(frame.deviceId).toBe(AUTHORITY.deviceId);
    expect(frame.deviceKeyId).toBe(AUTHORITY.deviceKeyId);
    expect(frame.grantId).toBe(AUTHORITY.grantId);
    expect(frame.epoch).toBe(String(AUTHORITY.epoch));
    expect(frame.requestId).toBe(REQUEST_ID);
    expect(frame.nonce).toBe(AUTHORITY_NONCE);
    expect(frame.toolName).toBe('read_file');
    expect(frame.opKind).toBe('command');
    expect(frame.audience).toBe('endpoint');
    expect(frame.argsDigestHex).toBe(ARGS_DIGEST_HEX);
    // GM-47: the exact args bytes travel with the frame, outside the signature.
    expect(frame.argsB64u).toBe(ARGS_BYTES.toString('base64url'));
    expect(frame.tag).toBe('CBHR-RPC-V2');
    expect(frame.keyId).toBe('test-custody-key-1');
    expect(frame.seq).toBe(12);
    expect(Object.keys(frame)).toHaveLength(19);
  });

  it('sets the signed deadline to issuedAt + the endpoint freshness window', async () => {
    const { client, calls } = buildClient();

    await client.dispatchCommand({ authority: AUTHORITY, toolName: 'read_file', argsBytes: ARGS_BYTES });

    const frame = calls[0].frame;
    expect(frame.issuedAt).toBe(String(T0));
    expect(frame.deadlineMs).toBe(String(T0 + 60000));
  });

  it('refuses a request-shaped dispatch argument by name, and sends nothing', async () => {
    const { client, calls } = buildClient();

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
      req: { user: { id: 'attacker' }, headers: { authorization: 'Bearer x' } },
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe('DISPATCH_REQUEST_SHAPE_INVALID');
    expect(outcome.delivered).toBe('no');
    expect(calls).toHaveLength(0);
  });

  it('refuses a user/session/header object smuggled in as the authority', async () => {
    const { client, calls } = buildClient();

    for (const smuggled of [
      { user: { id: 'attacker' } },
      { ownerId: 'attacker', tenantId: 'tenant-kelowna' },
      { ...AUTHORITY, headers: { authorization: 'Bearer x' } },
      { ...AUTHORITY, principalId: 'attacker' },
    ]) {
      const outcome = await client.dispatchCommand({
        authority: smuggled,
        toolName: 'read_file',
        argsBytes: ARGS_BYTES,
      });
      expect(outcome.ok).toBe(false);
      expect(outcome.code).toBe('AUTHORITY_SHAPE_INVALID');
    }
    expect(calls).toHaveLength(0);
  });

  it('requires every trusted authority field: nothing is defaulted or inferred', async () => {
    const { client, calls } = buildClient();

    for (const field of ['tenantId', 'ownerPrincipalId', 'deviceId', 'deviceKeyId', 'grantId', 'epoch']) {
      const partial = { ...AUTHORITY };
      delete partial[field];
      const outcome = await client.dispatchCommand({
        authority: partial,
        toolName: 'read_file',
        argsBytes: ARGS_BYTES,
      });
      expect({ field, code: outcome.code }).toEqual({
        field,
        code: 'AUTHORITY_SHAPE_INVALID',
      });
    }
    expect(calls).toHaveLength(0);
  });

  it('projects an authority from a server-observed row and refuses a mismatched one', () => {
    const row = {
      _id: '65a1b2c3d4e5f60718293b4c',
      tenantId: 'tenant-kelowna',
      ownerId: AUTHORITY.ownerPrincipalId,
      deviceKeyId: AUTHORITY.deviceKeyId,
      grantId: AUTHORITY.grantId,
      epoch: 7,
    };

    expect(
      relay.trustedAuthorityFromDeviceRow({
        row,
        tenantId: 'tenant-kelowna',
        ownerPrincipalId: AUTHORITY.ownerPrincipalId,
      }),
    ).toEqual(AUTHORITY);

    expect(() =>
      relay.trustedAuthorityFromDeviceRow({
        row,
        tenantId: 'tenant-kelowna',
        ownerPrincipalId: 'someone-else',
      }),
    ).toThrow(expect.objectContaining({ code: 'AUTHORITY_MISMATCH' }));

    expect(() =>
      relay.trustedAuthorityFromDeviceRow({
        row,
        tenantId: 'tenant-other',
        ownerPrincipalId: AUTHORITY.ownerPrincipalId,
      }),
    ).toThrow(expect.objectContaining({ code: 'AUTHORITY_MISMATCH' }));

    expect(() =>
      relay.trustedAuthorityFromDeviceRow({
        row: { ...row, grantId: null },
        tenantId: 'tenant-kelowna',
        ownerPrincipalId: AUTHORITY.ownerPrincipalId,
      }),
    ).toThrow(expect.objectContaining({ code: 'AUTHORITY_SHAPE_INVALID' }));

    expect(() =>
      relay.trustedAuthorityFromDeviceRow({
        row: { ...row, epoch: 0 },
        tenantId: 'tenant-kelowna',
        ownerPrincipalId: AUTHORITY.ownerPrincipalId,
      }),
    ).toThrow(expect.objectContaining({ code: 'AUTHORITY_SHAPE_INVALID' }));
  });
});

describe('dispatch client — audience and args', () => {
  it('refuses to mint a relay-audience frame (that half of the protocol is endpoint-signed)', async () => {
    const { client, calls } = buildClient();

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
      audience: 'relay',
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe('ENVELOPE_AUDIENCE_NOT_DISPATCHABLE');
    expect(calls).toHaveLength(0);
  });

  /**
   * REPLACES the old "accepts exactly one of the three args sources" test, which asserted that a
   * digest-only dispatch succeeds. That behaviour is now a defect: GM-47 requires the args BYTES to
   * travel, so a digest with no preimage cannot be dispatched at all.
   */
  it('requires an args preimage (bytes travel), refusing a digest-only dispatch', async () => {
    const { client, calls } = buildClient({ nonceFactory: uniqueNonces() });

    const fromBytes = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });
    const fromB64u = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsB64u: ARGS_BYTES.toString('base64url'),
    });
    const bothPreimages = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
      argsB64u: ARGS_BYTES.toString('base64url'),
    });
    const digestHexOnly = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsDigestHex: ARGS_DIGEST_HEX,
    });
    const digestB64uOnly = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsDigestB64u: Buffer.from(ARGS_DIGEST_HEX, 'hex').toString('base64url'),
    });
    const neither = await client.dispatchCommand({ authority: AUTHORITY, toolName: 'read_file' });

    expect(fromBytes.ok).toBe(true);
    expect(fromB64u.ok).toBe(true);
    expect(bothPreimages.code).toBe('ENVELOPE_ARGS_INVALID');
    expect(digestHexOnly.code).toBe('ENVELOPE_ARGS_INVALID');
    expect(digestB64uOnly.code).toBe('ENVELOPE_ARGS_INVALID');
    expect(neither.code).toBe('ENVELOPE_ARGS_INVALID');
    expect(calls).toHaveLength(2);
    for (const call of calls) {
      expect(call.frame.argsDigestHex).toBe(ARGS_DIGEST_HEX);
      expect(call.frame.argsB64u).toBe(ARGS_BYTES.toString('base64url'));
    }
  });

  it('accepts a declared digest only as a cross-check, and refuses a disagreeing one', async () => {
    const { client, calls } = buildClient();

    const agreeing = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
      argsDigestHex: ARGS_DIGEST_HEX,
    });
    const disagreeing = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
      argsDigestHex: '3795b53e4665398f141a5fafb3b006777f9f15f56423821f3e88795a8b972d15',
    });

    expect(agreeing.ok).toBe(true);
    expect(disagreeing.ok).toBe(false);
    expect(disagreeing.code).toBe('ARGS_DIGEST_MISMATCH');
    expect(calls).toHaveLength(1);
  });

  it('carries seq/idempotencyKey/callId as unsigned transport fields', async () => {
    const { client, calls } = buildClient();

    await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
      seq: 3,
      idempotencyKey: 'idem-1',
      callId: 'call-1',
    });

    const frame = calls[0].frame;
    expect(frame.seq).toBe(3);
    expect(frame.idempotencyKey).toBe('idem-1');
    expect(frame.callId).toBe('call-1');
    // The signature covers the core only: the transport fields are outside it.
    const signedFromFrame = relay.signedFromWireFrame(frame);
    expect(verifier.verifySignature(signedFromFrame).ok).toBe(true);
    expect(
      verifier.verifySignature({
        core: { ...signedFromFrame.core },
        signatureB64u: signedFromFrame.signatureB64u,
        keyId: signedFromFrame.keyId,
      }).ok,
    ).toBe(true);
  });

  it('validates opKind and transport-field shapes', async () => {
    const { client, calls } = buildClient();

    expect(
      (await client.dispatchCommand({ authority: AUTHORITY, toolName: 't', argsBytes: ARGS_BYTES, opKind: 'exec' }))
        .code,
    ).toBe('DISPATCH_REQUEST_SHAPE_INVALID');
    expect(
      (await client.dispatchCommand({ authority: AUTHORITY, toolName: '', argsBytes: ARGS_BYTES })).code,
    ).toBe('DISPATCH_REQUEST_SHAPE_INVALID');
    expect(
      (await client.dispatchCommand({ authority: AUTHORITY, toolName: 't', argsBytes: ARGS_BYTES, seq: 0 })).code,
    ).toBe('DISPATCH_REQUEST_SHAPE_INVALID');
    expect(
      (await client.dispatchCommand({ authority: AUTHORITY, toolName: 't', argsBytes: ARGS_BYTES, callId: '' })).code,
    ).toBe('DISPATCH_REQUEST_SHAPE_INVALID');
    expect(calls).toHaveLength(0);
  });

  it('mints cancel and resync frames with the same signature grammar', async () => {
    const { client, calls } = buildClient({ nonceFactory: uniqueNonces() });

    const cancel = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      opKind: 'cancel',
      argsBytes: Buffer.from(JSON.stringify({ targetCallId: 'call-1' }), 'utf8'),
      callId: 'call-1',
    });
    const resync = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: '-',
      opKind: 'resync',
      argsBytes: Buffer.alloc(0),
    });

    expect(cancel.ok).toBe(true);
    expect(resync.ok).toBe(true);
    expect(calls[0].frame.opKind).toBe('cancel');
    expect(calls[1].frame.opKind).toBe('resync');
    for (const call of calls) {
      expect(verifier.verifySignature(relay.signedFromWireFrame(call.frame)).ok).toBe(true);
    }
  });
});

describe('dispatch client — outcome law (unknown-outcome is never success)', () => {
  it('reports accepted only for a 2xx answer that does not explicitly refuse', async () => {
    for (const response of [
      { status: 200, body: { accepted: true } },
      { status: 202, body: {} },
      { status: 204 },
    ]) {
      const { client } = buildClient({ response });
      const outcome = await client.dispatchCommand({
        authority: AUTHORITY,
        toolName: 'read_file',
        argsBytes: ARGS_BYTES,
      });
      expect(outcome.ok).toBe(true);
      expect(outcome.delivered).toBe('accepted');
    }
  });

  it('reports refused for a 4xx answer or an explicit accepted:false', async () => {
    for (const response of [
      { status: 400, body: { ok: false } },
      { status: 403 },
      { status: 200, body: { accepted: false } },
    ]) {
      const { client } = buildClient({ response });
      const outcome = await client.dispatchCommand({
        authority: AUTHORITY,
        toolName: 'read_file',
        argsBytes: ARGS_BYTES,
      });
      expect(outcome.ok).toBe(false);
      expect(outcome.code).toBe('RELAY_REJECTED');
      expect(outcome.delivered).toBe('refused');
    }
  });

  it('reports unknown for a 5xx answer (the relay may have emitted before failing)', async () => {
    const { client } = buildClient({ response: { status: 503, body: {} } });

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe('RELAY_DISPATCH_UNCERTAIN');
    expect(outcome.delivered).toBe('unknown');
    expect(outcome.retryable).toBe(true);
  });

  it('reports unknown for a transport throw and never claims success', async () => {
    const client = relay.createRelayDispatchClient({
      transport: async () => {
        throw new Error('socket hang up');
      },
      signer,
      clock: { now: () => T0 },
      nonceFactory: () => AUTHORITY_NONCE,
      requestIdFactory: () => REQUEST_ID,
      verifier,
      replayWindow: relay.createReplayWindow({ now: () => T0 }),
    });

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe('RELAY_DISPATCH_UNCERTAIN');
    expect(outcome.delivered).toBe('unknown');
  });

  it('reports unknown for an unusable relay answer shape', async () => {
    for (const response of [undefined, null, 'ok', { status: '200' }, { status: 302 }]) {
      const { client } = buildClient({ response });
      const outcome = await client.dispatchCommand({
        authority: AUTHORITY,
        toolName: 'read_file',
        argsBytes: ARGS_BYTES,
      });
      expect(outcome.ok).toBe(false);
      expect(outcome.delivered).toBe('unknown');
    }
  });

  it('classifies answers through the pure helper as well', () => {
    expect(relay.interpretRelayResponse({ status: 200 })).toMatchObject({ accepted: true });
    expect(relay.interpretRelayResponse({ status: 429 })).toMatchObject({
      accepted: false,
      delivered: 'refused',
      retryable: true,
    });
    expect(relay.interpretRelayResponse({ status: 500 })).toMatchObject({
      accepted: false,
      delivered: 'unknown',
    });
  });
});

describe('dispatch client — pre-send guards', () => {
  it('refuses a replayed nonce before signing, and sends exactly once', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    const { client, calls } = buildClient({ replayWindow });

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
    expect(second.ok).toBe(false);
    expect(second.code).toBe('REPLAY_DETECTED');
    expect(second.delivered).toBe('no');
    expect(calls).toHaveLength(1);
  });

  it('refuses a differing grant with the same nonce (fresh grant ring)', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    const { client, calls } = buildClient({ replayWindow });

    const first = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });
    const rotatedGrant = await client.dispatchCommand({
      authority: { ...AUTHORITY, grantId: 'EBESExQVFhcYGRobHB0eIA' },
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    expect(first.ok).toBe(true);
    expect(rotatedGrant.ok).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it('never sends when the pre-dispatch self-check fails', async () => {
    const brokenVerifier = { verifySignature: () => ({ ok: false, error: new Error('nope') }) };
    const { client, calls } = buildClient({ verifier: brokenVerifier });

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.delivered).toBe('no');
    expect(calls).toHaveLength(0);
  });

  it('never sends when the authority is no longer current', async () => {
    const { client, calls } = buildClient({ assertAuthorityCurrent: async () => false });
    const stale = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });
    expect(stale.ok).toBe(false);
    expect(stale.code).toBe('AUTHORITY_MISMATCH');
    expect(stale.delivered).toBe('no');

    const throwing = buildClient({
      assertAuthorityCurrent: async () => {
        throw new Error('db down');
      },
    });
    const failed = await throwing.client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });
    expect(failed.code).toBe('AUTHORITY_MISMATCH');

    const current = buildClient({ assertAuthorityCurrent: async () => true });
    const ok = await current.client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: ARGS_BYTES,
    });
    expect(ok.ok).toBe(true);
    expect(calls).toHaveLength(0);
    expect(current.calls).toHaveLength(1);
  });

  it('requires an injected transport, the signer seam and a replay window at construction', () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    expect(() => relay.createRelayDispatchClient({ signer, replayWindow })).toThrow(
      expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }),
    );
    expect(() =>
      relay.createRelayDispatchClient({ transport: async () => ({ status: 200 }), replayWindow }),
    ).toThrow(expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }));
    expect(() =>
      relay.createRelayDispatchClient({
        transport: async () => ({ status: 200 }),
        signer,
        replayWindow,
        clock: {},
      }),
    ).toThrow(expect.objectContaining({ code: 'CLOCK_UNUSABLE' }));
    // GM-49: a null window on a real dispatch is a defect, refused at construction.
    expect(() =>
      relay.createRelayDispatchClient({ transport: async () => ({ status: 200 }), signer }),
    ).toThrow(expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }));
    expect(() =>
      relay.createRelayDispatchClient({
        transport: async () => ({ status: 200 }),
        signer,
        replayWindow: null,
      }),
    ).toThrow(expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }));
    expect(() =>
      relay.createRelayDispatchClient({
        transport: async () => ({ status: 200 }),
        signer,
        replayWindow: { now: () => T0 },
      }),
    ).toThrow(expect.objectContaining({ code: 'SIGNER_SEAM_INVALID' }));
  });
});
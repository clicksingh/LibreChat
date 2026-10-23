'use strict';

/**
 * CBHR-RPC-V2 backend signing and relay dispatch — public surface (workstream W2).
 *
 * LOCAL LAB ONLY. Production G0 remains BLOCKED; nothing here is mounted on a production host.
 *
 * GM RULING R2 / GM-9: the BACKEND signs; the relay's Durable Object is a mechanically keyless
 * forwarder. This package is the authority half. Key CUSTODY is an owner decision that has NOT been
 * made, so signing is reachable only through the injected `{ sign, keyId }` seam — there is no key
 * generation, no key read, no key store and no key log anywhere in this directory.
 *
 * TYPICAL WIRING (integration, workstream L):
 *
 *   const signer = createEnvelopeSigner({ sign, keyId });          // custody injected here
 *   const client = createRelayDispatchClient({ transport, signer, replayWindow });
 *   const authority = trustedAuthorityFromDeviceRow({
 *     row,                                    // server-observed DeviceAuthority document
 *     tenantId,                               // trusted ALS tenant
 *     ownerPrincipalId,                       // trusted authenticated session principal
 *   });
 *   const outcome = await client.dispatchCommand({
 *     authority,
 *     toolName: 'read_file',
 *     argsBytes,                              // raw argument bytes -> sha256(args)
 *     seq,                                    // relay ordering counter (transport field)
 *   });
 *   // outcome.delivered === 'unknown' means unknown-outcome: it is never a success, and the same
 *   // envelope must not be blindly retried (mint a fresh nonce instead).
 */

const errors = require('./errors');
const envelopeCore = require('./envelopeCore');
const envelopeSigner = require('./envelopeSigner');
const envelopeVerifier = require('./envelopeVerifier');
const freshness = require('./freshness');
const replayWindow = require('./replayWindow');
const argsDigest = require('./argsDigest');
const relayDispatchClient = require('./relayDispatchClient');

module.exports = {
  ...errors,
  ...envelopeCore,
  ...envelopeSigner,
  ...envelopeVerifier,
  ...freshness,
  ...replayWindow,
  ...argsDigest,
  ...relayDispatchClient,
};
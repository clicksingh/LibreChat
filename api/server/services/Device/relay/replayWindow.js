'use strict';

/**
 * REPLAY WINDOW — workstream W2 acceptance item 2 ("replay window (unseen nonce)").
 *
 * Frozen contract (F-V24C-7, endpoint invariant 8): the replay window is keyed `(grantId, nonce)` —
 * NOT by leaseId and not by nonce alone — so that a grant rotation starts a fresh ring and replay
 * state can never bridge two authorization generations. `grantId` is globally unique 128-bit CSPRNG
 * identity, and `nonce` is 128-bit CSPRNG, so the composite key is unambiguous: both components are
 * canonical unpadded base64url, whose alphabet excludes `:`, so the separator cannot be forged by a
 * component value.
 *
 * WHAT THIS WINDOW IS, AND IS NOT
 * - It is a fail-closed, in-process PRE-DISPATCH / pre-admission guard: the same nonce is never
 *   accepted twice by this process for the same grant, and it refuses BEFORE any signing or sending.
 * - It is NOT the durable replay authority. The contract places the durable window on the endpoint
 *   (fsynced, keyed `(grantId, nonce)`) and the nonce ring on the relay DO (per-frame storage
 *   re-read, GM-23). Those remain the authority; this guard is defence in depth on the authority
 *   side. An optional `store` seam is provided so a deployment can back it with durable storage
 *   without changing this module.
 * - Retention is enforced to be at least the widest freshness window (`MAX_FRESHNESS_WINDOW_MS`), so
 *   a nonce can never be forgotten while an envelope bearing it could still be fresh. A shorter
 *   retention is a construction-time refusal, not a runtime surprise.
 *
 * The reservation is inserted into memory BEFORE any `await`, so two concurrent calls in this process
 * cannot both accept the same nonce even when the durable store is asynchronous.
 */

const { decodeBase64UrlBytes } = require('./envelopeCore');
const { relayFailure } = require('./errors');
const { MAX_FRESHNESS_WINDOW_MS } = require('./freshness');

const COMPONENT_BYTES = 16;
const MIN_REPLAY_RETENTION_MS = MAX_FRESHNESS_WINDOW_MS;
const DEFAULT_REPLAY_RETENTION_MS = 300000;
const DEFAULT_MAX_ENTRIES = 100000;

function componentFailure(property) {
  return relayFailure(
    'ENVELOPE_SHAPE_INVALID',
    `replay ring component "${property}" must be canonical unpadded base64url of exactly ${COMPONENT_BYTES} bytes`,
    { field: property },
  );
}

function assertRingComponent(property, value) {
  const bytes = decodeBase64UrlBytes(value);
  if (bytes === null || bytes.length !== COMPONENT_BYTES) {
    throw componentFailure(property);
  }
  return value;
}

/**
 * The composite replay-ring key `grantId:nonce` (contract: `(grantId, nonce)`).
 * @param {{grantId: string, nonce: string}} params
 * @returns {string}
 */
function nonceRingKey({ grantId, nonce } = {}) {
  return `${assertRingComponent('grantId', grantId)}:${assertRingComponent('nonce', nonce)}`;
}

/**
 * A minimal in-memory implementation of the optional durable-store seam. Useful for a single-process
 * lab and for tests; it is NOT durable and must not be treated as the contract's fsynced window.
 * @returns {{has: Function, remember: Function, size: Function}}
 */
function createMapReplayStore() {
  const entries = new Map();
  return Object.freeze({
    has(key) {
      return entries.has(key);
    },
    remember(key, expiresAtMs) {
      entries.set(key, expiresAtMs);
    },
    size() {
      return entries.size;
    },
  });
}

/**
 * Creates a replay window.
 *
 * @param {object} [options]
 * @param {() => number} [options.now] injected clock (epoch-ms)
 * @param {number} [options.retentionMs] how long a spent nonce is remembered
 * @param {object} [options.store] optional durable seam: `{ has(key), remember(key, expiresAtMs) }`
 * @param {number} [options.maxEntries] hard memory bound; oldest reservations are evicted first
 * @returns {Readonly<{
 *   retentionMs: number,
 *   keyOf: Function,
 *   has: Function,
 *   size: Function,
 *   prune: Function,
 *   checkAndRemember: Function,
 * }>}
 */
function createReplayWindow(options = {}) {
  const clock = options.now ?? (() => Date.now());
  const retentionMs = options.retentionMs ?? DEFAULT_REPLAY_RETENTION_MS;
  const store = options.store ?? null;
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;

  if (typeof clock !== 'function') {
    throw relayFailure('CLOCK_UNUSABLE', 'the replay window requires a now() clock');
  }
  if (!Number.isSafeInteger(retentionMs) || retentionMs < MIN_REPLAY_RETENTION_MS) {
    throw relayFailure(
      'ENVELOPE_SHAPE_INVALID',
      `replay retention must be an integer >= the widest freshness window (${MIN_REPLAY_RETENTION_MS} ms)`,
      { field: 'retentionMs' },
    );
  }
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
    throw relayFailure('ENVELOPE_SHAPE_INVALID', 'replay maxEntries must be an integer >= 1', {
      field: 'maxEntries',
    });
  }
  if (store !== null) {
    if (
      typeof store !== 'object' ||
      typeof store.has !== 'function' ||
      typeof store.remember !== 'function'
    ) {
      throw relayFailure(
        'ENVELOPE_SHAPE_INVALID',
        'the replay store seam requires { has(key), remember(key, expiresAtMs) }',
        { field: 'store' },
      );
    }
  }

  /** key -> { seenAt, expiresAt } */
  const reservations = new Map();

  function nowMs() {
    const value = clock();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw relayFailure('CLOCK_UNUSABLE', 'the replay window clock did not return epoch milliseconds');
    }
    return value;
  }

  function pruneAt(atMs) {
    let removed = 0;
    for (const [key, entry] of reservations) {
      if (entry.expiresAt <= atMs) {
        reservations.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  function prune() {
    return pruneAt(nowMs());
  }

  function has(params) {
    const key = nonceRingKey(params);
    pruneAt(nowMs());
    return reservations.has(key);
  }

  function size() {
    return reservations.size;
  }

  /**
   * Accepts the nonce exactly once per grant. Fails closed with `REPLAY_DETECTED` when the nonce was
   * already spent inside the retention window.
   * @param {{grantId: string, nonce: string}} params
   * @returns {Promise<{ok: true, key: string, seenAt: number, expiresAt: number}
   *   | {ok: false, error: import('./errors').RelayError}>}
   */
  async function checkAndRemember(params) {
    const key = nonceRingKey(params);
    const atMs = nowMs();
    pruneAt(atMs);
    if (reservations.has(key)) {
      return {
        ok: false,
        error: relayFailure(
          'REPLAY_DETECTED',
          'envelope nonce was already seen for this grant inside the replay window',
          { field: 'nonce' },
        ),
      };
    }
    while (reservations.size >= maxEntries) {
      const oldestKey = reservations.keys().next().value;
      reservations.delete(oldestKey);
    }
    const entry = { seenAt: atMs, expiresAt: atMs + retentionMs };
    // Reserved before any await: in-process concurrency cannot double-accept.
    reservations.set(key, entry);
    if (store !== null) {
      try {
        await store.remember(key, entry.expiresAt);
      } catch (err) {
        reservations.delete(key);
        return {
          ok: false,
          error: relayFailure(
            'REPLAY_STORE_UNAVAILABLE',
            'the replay store seam failed; refusing the envelope rather than risking a replay',
            { field: 'store', cause: err },
          ),
        };
      }
    }
    return { ok: true, key, seenAt: entry.seenAt, expiresAt: entry.expiresAt };
  }

  return Object.freeze({
    retentionMs,
    keyOf: nonceRingKey,
    has,
    size,
    prune,
    checkAndRemember,
  });
}

module.exports = {
  MIN_REPLAY_RETENTION_MS,
  DEFAULT_REPLAY_RETENTION_MS,
  DEFAULT_MAX_ENTRIES,
  nonceRingKey,
  createMapReplayStore,
  createReplayWindow,
};
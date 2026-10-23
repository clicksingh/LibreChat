'use strict';

/**
 * CBHR ENDPOINT AGENT — DURABLE replay window (workstream W7).
 *
 * GM-34 assigns the durable replay authority to two places: the relay's DO ring and **the endpoint's
 * own persisted window**. This module is the endpoint's half. The distinction that matters is not
 * "we remember nonces" — it is that a nonce survives a PROCESS RESTART, so an attacker who captures a
 * frame cannot wait for the agent to be restarted (an update, a crash, a reboot) and replay it inside
 * the freshness window. An in-memory ring fails exactly there, and `tests/durability.js` proves the
 * difference by spending a nonce in one process and replaying it in another.
 *
 * KEY: `(grantId, nonce)` — the contract's composite key (F-V24C-7 / invariant 8), never nonce alone
 * and never `leaseId`. Both components are canonical unpadded base64url, whose alphabet excludes `:`,
 * so the separator cannot be forged by a component value.
 *
 * DURABILITY
 * The whole window is written with `atomicReplaceOwnerOnlyFile` (temp file + fsync + rename) inside an
 * owner-only directory, so a crash at any instant leaves either the previous window or the new one,
 * never a truncated file. The nonce is persisted BEFORE any execution is allowed to begin: if the
 * write fails, the frame is refused (`ENDPOINT_REPLAY_STORE_UNAVAILABLE`) rather than executed with
 * an unrecorded nonce.
 *
 * SAFETY PROPERTY (the same invariant the backend's in-process guard states)
 *   A nonce is NEVER forgotten while an envelope bearing it could still be fresh.
 * Pruning uses the STRICT comparison `expiresAt < atMs`: at `atMs === expiresAt` an envelope minted
 * when the nonce was first seen is still admissible (freshness is inclusive), so the entry must stay.
 */

const fs = require('node:fs');
const path = require('node:path');

const { refusal } = require('./errors');
const { decodeBase64UrlBytes, NONCE_BYTES, GRANT_ID_BYTES } = require('./layout');
const { atomicReplaceOwnerOnlyFile } = require('./permissions');
const { resolveRootDir } = require('./keystore');

/** The frozen endpoint freshness window (60 s); retention may never be shorter than this. */
const ENDPOINT_FRESHNESS_WINDOW_MS = 60000;
/** The widest window any audience may use (relay 120 s); retention covers both directions. */
const MAX_FRESHNESS_WINDOW_MS = 120000;
const MIN_RETENTION_MS = MAX_FRESHNESS_WINDOW_MS;
const DEFAULT_RETENTION_MS = 300000;

function replayRefusal(detail, cause) {
  return refusal('ENDPOINT_REPLAY_DETECTED', detail, { field: 'nonce', cause });
}

function storeRefusal(detail, cause) {
  return refusal('ENDPOINT_REPLAY_STORE_UNAVAILABLE', detail, { field: 'replayStore', cause });
}

function assertRingComponent(property, value, expectedBytes) {
  const bytes = decodeBase64UrlBytes(value);
  if (bytes === null || bytes.length !== expectedBytes) {
    throw refusal(
      'ENDPOINT_ENVELOPE_SHAPE_INVALID',
      `replay ring component "${property}" must be canonical unpadded base64url of exactly ${expectedBytes} bytes`,
      { field: property },
    );
  }
  return value;
}

/** The composite replay key `grantId:nonce`. */
function ringKey(grantId, nonce) {
  return `${assertRingComponent('grantId', grantId, GRANT_ID_BYTES)}:${assertRingComponent('nonce', nonce, NONCE_BYTES)}`;
}

/** The default replay file path under the agent root. */
function defaultReplayFile(rootDir) {
  return path.join(rootDir ?? resolveRootDir(), 'replay-window.json');
}

/**
 * Creates the durable window, loading any persisted entries first.
 *
 * @param {object} [options]
 * @param {string} [options.rootDir]
 * @param {string} [options.replayFile]
 * @param {() => number} [options.now] injected clock (epoch-ms)
 * @param {number} [options.retentionMs] how long a spent nonce is remembered
 * @param {boolean} [options.persist] set false ONLY for the in-memory reference tests
 * @returns {Readonly<object>}
 */
function createDurableReplayWindow(options = {}) {
  const now = options.now ?? (() => Date.now());
  const retentionMs = options.retentionMs ?? DEFAULT_RETENTION_MS;
  const persist = options.persist !== false;
  const replayFile = options.replayFile ?? defaultReplayFile(options.rootDir);

  if (typeof now !== 'function') {
    throw refusal('ENDPOINT_CLOCK_UNUSABLE', 'the replay window requires a now() clock');
  }
  if (!Number.isSafeInteger(retentionMs) || retentionMs < MIN_RETENTION_MS) {
    throw refusal(
      'ENDPOINT_ENVELOPE_SHAPE_INVALID',
      `replay retention must be an integer >= the widest freshness window (${MIN_RETENTION_MS} ms)`,
      { field: 'retentionMs' },
    );
  }

  /** key -> expiresAt (epoch-ms). Entries are only ever added or pruned, never rewritten in place. */
  const entries = new Map();

  function clock() {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw refusal('ENDPOINT_CLOCK_UNUSABLE', 'the replay window clock did not return epoch milliseconds');
    }
    return value;
  }

  function load() {
    if (!persist || !fs.existsSync(replayFile)) {
      return { loaded: 0 };
    }
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(replayFile, 'utf8'));
    } catch (err) {
      // A corrupt window must FAIL CLOSED: "I cannot read my replay state" is not "no nonce was
      // ever spent". Refusing to start is the only safe reading.
      throw storeRefusal('the persisted replay window could not be parsed', err);
    }
    if (parsed === null || typeof parsed !== 'object' || parsed.version !== 1 || !Array.isArray(parsed.entries)) {
      throw storeRefusal('the persisted replay window declares an unsupported version or shape');
    }
    const at = clock();
    for (const entry of parsed.entries) {
      if (entry === null || typeof entry !== 'object') {
        continue;
      }
      const { key, expiresAt } = entry;
      if (typeof key !== 'string' || !Number.isSafeInteger(expiresAt)) {
        continue;
      }
      if (expiresAt < at) {
        continue; // Strictly past: safe to forget (see the safety property above).
      }
      entries.set(key, expiresAt);
    }
    return { loaded: entries.size };
  }

  function serialized(at) {
    const live = [...entries.entries()]
      .filter(([, expiresAt]) => expiresAt >= at)
      .sort((left, right) => left[0].localeCompare(right[0]))
      .map(([key, expiresAt]) => ({ key, expiresAt }));
    return `${JSON.stringify({ version: 1, updatedAt: at, entries: live }, null, 2)}\n`;
  }

  function writeThrough(at) {
    if (!persist) {
      return;
    }
    try {
      atomicReplaceOwnerOnlyFile(replayFile, serialized(at));
    } catch (err) {
      throw storeRefusal(
        'the replay window could not be persisted; refusing the frame rather than executing with an unrecorded nonce',
        err,
      );
    }
  }

  function pruneAt(at) {
    let removed = 0;
    for (const [key, expiresAt] of entries) {
      if (expiresAt < at) {
        entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  const loaded = load();

  return Object.freeze({
    retentionMs,
    replayFile: () => replayFile,
    loadedEntries: loaded.loaded,
    size: () => entries.size,
    /** The composite `(grantId, nonce)` key this window uses, so the keying is inspectable. */
    keyOf: (params = {}) => ringKey(params.grantId, params.nonce),
    has: (grantId, nonce) => {
      const key = ringKey(grantId, nonce);
      pruneAt(clock());
      return entries.has(key);
    },
    /**
     * Accepts the nonce exactly once per grant and PERSISTS the reservation before returning.
     *
     * `freshUntilMs` is the last instant an envelope bearing this nonce can still satisfy the
     * freshness law; the reservation is extended to that horizon so the safety property holds even
     * for a frame admitted while future-dated.
     *
     * @param {object} params
     * @param {string} params.grantId
     * @param {string} params.nonce
     * @param {number} [params.freshUntilMs]
     * @returns {{ok: true, key: string, seenAt: number, expiresAt: number}
     *   | {ok: false, error: import('./errors').EndpointRefusal}}
     */
    checkAndRemember: (params = {}) => {
      let key;
      try {
        key = ringKey(params.grantId, params.nonce);
      } catch (err) {
        return { ok: false, error: err };
      }
      const at = clock();
      pruneAt(at);
      const { freshUntilMs } = params;
      if (
        freshUntilMs !== undefined &&
        freshUntilMs !== null &&
        (!Number.isSafeInteger(freshUntilMs) || freshUntilMs < 0)
      ) {
        return {
          ok: false,
          error: refusal(
            'ENDPOINT_ENVELOPE_SHAPE_INVALID',
            'the replay reservation freshness horizon must be non-negative epoch milliseconds',
            { field: 'freshUntilMs' },
          ),
        };
      }
      if (entries.has(key)) {
        return {
          ok: false,
          error: replayRefusal(
            'envelope nonce was already seen for this grant inside the durable replay window',
          ),
        };
      }
      const horizon = Number.isSafeInteger(freshUntilMs) ? freshUntilMs : 0;
      const expiresAt = Math.max(at + retentionMs, horizon);
      entries.set(key, expiresAt);
      try {
        writeThrough(at);
      } catch (err) {
        entries.delete(key);
        return { ok: false, error: err };
      }
      return { ok: true, key, seenAt: at, expiresAt };
    },
    /** Diagnostics only: prunes and persists. Safe to call at any time. */
    prune: () => {
      const at = clock();
      const removed = pruneAt(at);
      writeThrough(at);
      return removed;
    },
    /** The evidence a caller may store: counts, never nonce values beyond the ring keys. */
    describe: () => ({
      replayFile,
      retentionMs,
      entries: entries.size,
      loadedEntries: loaded.loaded,
    }),
  });
}

module.exports = {
  ENDPOINT_FRESHNESS_WINDOW_MS,
  MAX_FRESHNESS_WINDOW_MS,
  MIN_RETENTION_MS,
  DEFAULT_RETENTION_MS,
  ringKey,
  defaultReplayFile,
  createDurableReplayWindow,
};
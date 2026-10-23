'use strict';

/**
 * DISPATCH LEDGER — the authority-side record of calls that are ON THE WIRE (workstream W6, GM-43).
 *
 * WHY THIS EXISTS. A tool call is only half a protocol until its outcome comes back. The backend
 * mints and signs a command, the relay forwards it, the device executes it and reports a result —
 * and the platform can only believe that result if it can say WHICH CALL it belongs to. This ledger
 * is that memory: one entry per `callId` that the platform actually put on the wire.
 *
 * WHAT IT IS NOT
 * - It is not an authority and it never authorizes anything. It records what the trusted dispatch
 *   path already decided, and it answers two questions: "did we dispatch this call id?" and "has it
 *   already been completed?".
 * - It never reads a request, a session or a user object. The entry is an EXACT-KEY projection of
 *   server truth (`trustedAuthorityFromDeviceRow` supplies the identity), so a request-shaped object
 *   is refused by name before anything is recorded.
 * - It holds no key material, and it never sees a command payload. A `callId` is an opaque transport
 *   identity; it is copied, never parsed.
 *
 * CORRELATION LAW
 * - One `callId` identifies exactly ONE call. Re-using a live id is refused (`DISPATCH_CALL_ID_REUSED`),
 *   because two calls under one identity would make every later correlation a guess.
 * - A call completes exactly once (`complete()`); a second completion is refused with
 *   `DISPATCH_CALL_ALREADY_COMPLETED` and changes nothing. That is what makes a duplicated result
 *   harmless at the authority layer, independently of the relay's own retry handling.
 * - An unknown id is refused (`DISPATCH_CALL_UNKNOWN`), never invented and never completed on
 *   speculation: an outcome may only be recorded against a call that was dispatched.
 *
 * STORAGE. The default store is in-process and therefore NOT durable: a restart makes every call id
 * unknown, and the sink then REFUSES results instead of mis-attributing them (fail closed, never
 * wrong). A deployment injects a durable `store` seam — the natural one here is the device
 * collection or a dedicated dispatch collection — and must make `complete()` a CONDITIONAL update
 * (transition only from `dispatched`), which is what keeps "complete exactly once" true across
 * processes. This module cannot make that guarantee for a store it does not own; it says so here
 * rather than implying it.
 *
 * ATOMICITY IN PROCESS. The store seam is async by contract, so a read-check-write would let two
 * concurrent operations on one call id both observe the old state. The ledger therefore CLAIMS the
 * call id synchronously before its first `await` (and re-reads the state afterwards): the loser of a
 * concurrent pair fails closed with the same refusal code it would get afterwards. A durable store
 * still has to provide the conditional update — the claim closes the window inside one process, not
 * between processes.
 *
 * MEMORY BOUND (GM-57 precedent). The ledger is bounded and fails CLOSED: at capacity only a
 * COMPLETED entry may be forgotten (oldest first); if every tracked call is still live, the
 * reservation is refused (`DISPATCH_LEDGER_SATURATED`) rather than forgotten. A forgotten call would
 * become "unknown" — a refusal — so the trade is availability for correctness, deliberately.
 */

const { isRelayError, relayFailure } = require('./errors');

/** The exact keys a reservation may carry. Identity is server truth; nothing request-shaped. */
const DISPATCH_RESERVATION_KEYS = Object.freeze([
  'callId',
  'deviceId',
  'deviceKeyId',
  'tenantId',
  'grantId',
  'epoch',
  'requestId',
  'toolName',
  'opKind',
]);

/** The exact keys a completion may carry. */
const DISPATCH_COMPLETION_KEYS = Object.freeze(['outcome', 'resultSeq']);

/** The two states a call can be in. There is no third: uncertainty never becomes a state. */
const DISPATCH_CALL_STATES = Object.freeze({
  DISPATCHED: 'dispatched',
  COMPLETED: 'completed',
});

const DEFAULT_MAX_ENTRIES = 4096;
const TRANSPORT_TEXT_MAX_CHARS = 200;
const RESERVED_SEPARATOR = '\u001f';
const OUTCOME_TEXT_MAX_CHARS = 64;
const LEDGER_KIND = 'dispatch-ledger';

function ledgerFailure(code, message, options) {
  return relayFailure(code, message, options);
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOwn(record, key) {
  return Object.prototype.hasOwnProperty.call(record, key);
}

/**
 * Transport shape of a call id. Copied verbatim: the ledger never mints, normalises or rewrites one.
 * @param {unknown} value
 * @returns {boolean}
 */
function isTransportText(value) {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > TRANSPORT_TEXT_MAX_CHARS) return false;
  return !value.includes(RESERVED_SEPARATOR);
}

function shapeFailure(detail, field) {
  return ledgerFailure('DISPATCH_LEDGER_ENTRY_INVALID', `dispatch ledger entry invalid: ${detail}`, {
    field,
  });
}

/**
 * Validates and freezes a reservation. Exact-key whitelist; every failure names a field and never a
 * value, so a caller that logs the error cannot log a call identity or a tool argument.
 * @param {unknown} input
 * @returns {Readonly<object>} the projected reservation
 */
function projectReservation(input) {
  if (!isPlainRecord(input)) {
    throw shapeFailure('a reservation must be a plain object projected from server truth', 'callId');
  }
  for (const key of Object.keys(input)) {
    if (!DISPATCH_RESERVATION_KEYS.includes(key)) {
      throw shapeFailure(
        `the reservation refuses the key "${key}"; identity is never taken from a request`,
        key,
      );
    }
  }
  for (const key of DISPATCH_RESERVATION_KEYS) {
    if (!hasOwn(input, key)) {
      throw shapeFailure(`the reservation is missing "${key}"`, key);
    }
  }
  if (!isTransportText(input.callId)) {
    throw shapeFailure('"callId" must be a non-empty transport string of at most 200 characters', 'callId');
  }
  for (const key of ['deviceId', 'deviceKeyId', 'tenantId', 'grantId', 'requestId', 'toolName', 'opKind']) {
    if (typeof input[key] !== 'string' || input[key].length === 0) {
      throw shapeFailure(`"${key}" must be a non-empty string`, key);
    }
  }
  if (!Number.isInteger(input.epoch) || input.epoch < 1) {
    throw shapeFailure('"epoch" must be an integer >= 1', 'epoch');
  }
  return Object.freeze({
    callId: input.callId,
    deviceId: input.deviceId,
    deviceKeyId: input.deviceKeyId,
    tenantId: input.tenantId,
    grantId: input.grantId,
    epoch: input.epoch,
    requestId: input.requestId,
    toolName: input.toolName,
    opKind: input.opKind,
  });
}

/**
 * Validates a completion. The ledger records the OUTCOME WORD the sink derived from the device's own
 * authenticated bytes; it never invents one and never upgrades one.
 * @param {unknown} input
 * @returns {Readonly<{outcome: string, resultSeq: (number|null)}>}
 */
function projectCompletion(input) {
  if (!isPlainRecord(input)) {
    throw shapeFailure('a completion must be a plain object', 'outcome');
  }
  for (const key of Object.keys(input)) {
    if (!DISPATCH_COMPLETION_KEYS.includes(key)) {
      throw shapeFailure(`the completion refuses the key "${key}"`, key);
    }
  }
  if (typeof input.outcome !== 'string' || input.outcome.length === 0) {
    throw shapeFailure('"outcome" must be the non-empty word the device reported', 'outcome');
  }
  if (input.outcome.length > OUTCOME_TEXT_MAX_CHARS) {
    throw shapeFailure(`"outcome" must be at most ${OUTCOME_TEXT_MAX_CHARS} characters`, 'outcome');
  }
  const resultSeq = input.resultSeq ?? null;
  if (resultSeq !== null && (!Number.isInteger(resultSeq) || resultSeq < 1)) {
    throw shapeFailure('"resultSeq" must be an integer >= 1 or null', 'resultSeq');
  }
  return Object.freeze({ outcome: input.outcome, resultSeq });
}

/**
 * The default store: an in-process Map. NOT durable — see the module header. The seam is async so a
 * durable implementation never has to change this module.
 * @returns {Readonly<{kind: string, get: Function, set: Function, delete: Function, keys: Function, size: Function}>}
 */
function createMapDispatchStore() {
  const entries = new Map();
  return Object.freeze({
    kind: 'in-memory-dispatch-store',
    async get(key) {
      return entries.has(key) ? entries.get(key) : null;
    },
    async set(key, value) {
      entries.set(key, value);
    },
    async delete(key) {
      entries.delete(key);
    },
    async keys() {
      return [...entries.keys()];
    },
    async size() {
      return entries.size;
    },
  });
}

/**
 * Builds the dispatch ledger.
 *
 * @param {object} [options]
 * @param {() => number} [options.now] injected clock (epoch-ms)
 * @param {number} [options.maxEntries] hard memory bound; only completed entries are ever evicted
 * @param {object} [options.store] durable seam `{ get(key), set(key, value), delete(key), keys() }`
 * @returns {Readonly<object>} the ledger surface
 */
function createDispatchLedger(options = {}) {
  const clock = options.now ?? (() => Date.now());
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const store = options.store ?? createMapDispatchStore();

  if (typeof clock !== 'function') {
    throw ledgerFailure('CLOCK_UNUSABLE', 'the dispatch ledger requires a now() clock');
  }
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
    throw shapeFailure('"maxEntries" must be an integer >= 1', 'maxEntries');
  }
  if (
    store === null ||
    typeof store !== 'object' ||
    typeof store.get !== 'function' ||
    typeof store.set !== 'function' ||
    typeof store.delete !== 'function' ||
    typeof store.keys !== 'function'
  ) {
    throw shapeFailure('the store seam requires { get, set, delete, keys }', 'store');
  }

  function nowMs() {
    const value = clock();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw ledgerFailure('CLOCK_UNUSABLE', 'the dispatch ledger clock did not return epoch milliseconds');
    }
    return value;
  }

  /**
   * In-process mutex, taken SYNCHRONOUSLY before any `await`.
   *
   * Why it is needed: the store seam is async by contract (a durable store must be), so a plain
   * read-check-write would let two concurrent operations on the same call id both see the old state
   * and both "win" — two completions, or two reservations under one identity. Claiming the key before
   * the first await makes the loser fail closed instead. This is a single-process guarantee; a
   * durable store must additionally make `complete()` a conditional update (see the module header).
   */
  const claimed = new Set();

  function claim(kind, callId) {
    const key = `${kind}:${callId}`;
    if (claimed.has(key)) {
      return null;
    }
    claimed.add(key);
    return key;
  }

  function release_claim(key) {
    if (key !== null) {
      claimed.delete(key);
    }
  }

  function busyFailure(kind) {
    return ledgerFailure(
      kind === 'reserve' ? 'DISPATCH_CALL_ID_REUSED' : 'DISPATCH_CALL_ALREADY_COMPLETED',
      kind === 'reserve'
        ? 'this call id is already being recorded by the dispatch ledger'
        : 'this call is already being completed; a concurrent result must not complete it again',
      { field: 'callId' },
    );
  }

  /**
   * Records one call that is about to go on the wire.
   * @param {object} input see `DISPATCH_RESERVATION_KEYS`
   * @returns {Promise<object>} `{ok:true, entry}` or `{ok:false, error}`
   */
  async function reserve(input) {
    let projection;
    try {
      projection = projectReservation(input);
    } catch (err) {
      return { ok: false, error: isRelayError(err) ? err : ledgerFailure('DISPATCH_LEDGER_ENTRY_INVALID', 'the reservation is unusable', { cause: err }) };
    }
    const existing = await store.get(projection.callId);
    if (existing !== null && existing !== undefined) {
      return {
        ok: false,
        error: ledgerFailure(
          'DISPATCH_CALL_ID_REUSED',
          'this call id is already tracked by the dispatch ledger; one call id identifies exactly one call',
          { field: 'callId' },
        ),
      };
    }
    const claimKey = claim('reserve', projection.callId);
    if (claimKey === null) {
      return { ok: false, error: busyFailure('reserve') };
    }
    try {
      // Bounded, fail closed: forget a COMPLETED call (oldest first) or refuse — never a live one.
      if ((await store.keys()).length >= maxEntries) {
        const keys = await store.keys();
        let evicted = false;
        for (const key of keys) {
          const candidate = await store.get(key);
          if (candidate !== null && candidate !== undefined && candidate.state === DISPATCH_CALL_STATES.COMPLETED) {
            await store.delete(key);
            evicted = true;
            break;
          }
        }
        if (!evicted) {
          return {
            ok: false,
            error: ledgerFailure(
              'DISPATCH_LEDGER_SATURATED',
              'the dispatch ledger is full of calls that are still live; refusing rather than forgetting a call that a result could still complete',
              { field: 'maxEntries' },
            ),
          };
        }
      }
      const raced = await store.get(projection.callId);
      if (raced !== null && raced !== undefined) {
        return { ok: false, error: busyFailure('reserve') };
      }
      const entry = Object.freeze({
        ...projection,
        state: DISPATCH_CALL_STATES.DISPATCHED,
        reservedAt: nowMs(),
        completedAt: null,
        outcome: null,
        resultSeq: null,
      });
      await store.set(entry.callId, entry);
      return { ok: true, entry };
    } finally {
      release_claim(claimKey);
    }
  }

  /**
   * Withdraws a reservation for a call that was NOT put on the wire, so no result can ever be
   * correlated to it. Idempotent. A completed call can never be released.
   * @param {string} callId
   * @param {string} [reason]
   * @returns {Promise<object>}
   */
  async function release(callId, reason = 'not-sent') {
    if (!isTransportText(callId)) {
      return { ok: false, error: shapeFailure('"callId" must be a transport string', 'callId') };
    }
    const existing = await store.get(callId);
    if (existing === null || existing === undefined) {
      return { ok: true, released: false, reason: 'NOT_RESERVED', callId };
    }
    if (existing.state === DISPATCH_CALL_STATES.COMPLETED) {
      return {
        ok: false,
        error: ledgerFailure(
          'DISPATCH_CALL_ALREADY_COMPLETED',
          'a completed call cannot be released: its outcome is already recorded',
          { field: 'callId' },
        ),
      };
    }
    await store.delete(callId);
    return { ok: true, released: true, reason, callId };
  }

  /**
   * Completes one call with the outcome the DEVICE reported. Exactly once: a second completion is
   * refused and changes nothing.
   * @param {string} callId
   * @param {{outcome: string, resultSeq?: (number|null)}} completion
   * @returns {Promise<object>}
   */
  async function complete(callId, completion) {
    if (!isTransportText(callId)) {
      return { ok: false, error: shapeFailure('"callId" must be a transport string', 'callId') };
    }
    let projected;
    try {
      projected = projectCompletion(completion);
    } catch (err) {
      return { ok: false, error: isRelayError(err) ? err : ledgerFailure('DISPATCH_LEDGER_ENTRY_INVALID', 'the completion is unusable', { cause: err }) };
    }
    const existing = await store.get(callId);
    if (existing === null || existing === undefined) {
      return {
        ok: false,
        error: ledgerFailure(
          'DISPATCH_CALL_UNKNOWN',
          'no call with that id was dispatched by this ledger, so no outcome can be recorded against it',
          { field: 'callId' },
        ),
      };
    }
    if (existing.state !== DISPATCH_CALL_STATES.DISPATCHED) {
      return {
        ok: false,
        error: ledgerFailure(
          'DISPATCH_CALL_ALREADY_COMPLETED',
          'that call already has a recorded outcome; a second result must not complete it again',
          { field: 'callId' },
        ),
      };
    }
    // Synchronous claim BEFORE any await: two concurrent completions cannot both win.
    const claimKey = claim('complete', callId);
    if (claimKey === null) {
      return { ok: false, error: busyFailure('complete') };
    }
    try {
      const raced = await store.get(callId);
      if (raced === null || raced === undefined) {
        return {
          ok: false,
          error: ledgerFailure(
            'DISPATCH_CALL_UNKNOWN',
            'no call with that id was dispatched by this ledger, so no outcome can be recorded against it',
            { field: 'callId' },
          ),
        };
      }
      if (raced.state !== DISPATCH_CALL_STATES.DISPATCHED) {
        return { ok: false, error: busyFailure('complete') };
      }
      const completed = Object.freeze({
        ...raced,
        state: DISPATCH_CALL_STATES.COMPLETED,
        completedAt: nowMs(),
        outcome: projected.outcome,
        resultSeq: projected.resultSeq,
      });
      await store.set(callId, completed);
      return { ok: true, entry: completed };
    } finally {
      release_claim(claimKey);
    }
  }

  /**
   * @param {string} callId
   * @returns {Promise<object|null>} the entry, or null when the call was never dispatched
   */
  async function get(callId) {
    if (!isTransportText(callId)) {
      return null;
    }
    return (await store.get(callId)) ?? null;
  }

  /**
   * @param {string} callId
   * @returns {Promise<boolean>}
   */
  async function has(callId) {
    return (await get(callId)) !== null;
  }

  /**
   * @returns {Promise<number>} how many calls are tracked
   */
  async function size() {
    return (await store.keys()).length;
  }

  /**
   * @returns {Promise<Array<object>>} the tracked calls, in reservation order
   */
  async function entries() {
    const keys = await store.keys();
    const found = [];
    for (const key of keys) {
      const entry = await store.get(key);
      if (entry !== null && entry !== undefined) {
        found.push(entry);
      }
    }
    return found;
  }

  return Object.freeze({
    ledgerKind: LEDGER_KIND,
    storeKind: store.kind ?? 'injected',
    maxEntries,
    reserve,
    release,
    complete,
    get,
    has,
    size,
    entries,
  });
}

module.exports = {
  DISPATCH_RESERVATION_KEYS,
  DISPATCH_COMPLETION_KEYS,
  DISPATCH_CALL_STATES,
  DEFAULT_MAX_ENTRIES,
  createMapDispatchStore,
  createDispatchLedger,
  projectReservation,
  projectCompletion,
  isTransportText,
};
'use strict';

/**
 * W9 — REAL MongoDB store seams for the accepted W6 relay layer.
 *
 * WHY THIS FILE EXISTS. `dispatchLedger.js` and `resultSink.js` each own an async store seam and each
 * says, in its own header, that the default in-process store is NOT durable and that a deployment
 * injects a durable one. W9's job is the whole loop, so the ledger's final state has to be REAL
 * state: the correlation record must be readable by a process that did not write it, and the
 * complete-exactly-once property has to survive a process boundary. This module supplies those two
 * seams over the same real MongoDB replica set the pairing ceremony uses.
 *
 * WHAT IT IS NOT. It is not a reimplementation of the ledger or the sink: every law (one call id per
 * call, complete-exactly-once, the outcome vocabulary, the memory bound) still lives in the accepted
 * modules, and this file implements only the four methods the ledger's seam declares plus the two the
 * sink's seam declares. It contains no policy, no outcome mapping and no default.
 *
 * CONDITIONAL COMPLETION. `dispatchLedger.js` states that a durable store must additionally make the
 * completion write CONDITIONAL (transition only from `state: 'dispatched'`), because the record it
 * holds in memory cannot close a window that spans processes. That obligation is discharged here by
 * `compareAndSet`, and it is exercised by `verify-state.cjs`, which is a SEPARATE process from the one
 * that filled the ledger.
 */

const WRITE_CONCERN = Object.freeze({ w: 'majority', j: true });

/** Raised when a conditional write is asked to transition from a state the row is not in. */
class StoreConflictError extends Error {
  constructor(message, detail = {}) {
    super(message);
    this.name = 'StoreConflictError';
    this.code = 'STORE_CONDITIONAL_WRITE_CONFLICT';
    this.detail = detail;
  }
}

/**
 * A collection-backed key/value store in the exact shape `createMapDispatchStore()` declares.
 *
 * `keys()` is ordered by insertion sequence rather than by Mongo's natural order, so the ledger's
 * "forget the OLDEST completed call first" eviction is deterministic instead of incidental.
 *
 * @param {object} params
 * @param {import('mongodb').Collection} params.collection
 * @param {import('mongodb').Collection} params.meta another collection holding the sequence counter
 * @param {string} params.scope a `runId`-style discriminator written on every row
 * @returns {Readonly<object>}
 */
function createMongoDispatchStore({ collection, meta, scope }) {
  async function nextSeq() {
    const updated = await meta.findOneAndUpdate(
      { _id: 'dispatch-seq' },
      { $inc: { value: 1 } },
      { upsert: true, returnDocument: 'after', writeConcern: WRITE_CONCERN },
    );
    const value = updated === null || updated === undefined ? null : updated.value;
    return Number.isInteger(value) ? value : 1;
  }

  return Object.freeze({
    kind: 'mongo-dispatch-store',
    collectionName: collection.collectionName,
    async get(key) {
      const row = await collection.findOne({ _id: key }, { projection: { _seq: 0 } });
      return row ?? null;
    },
    async set(key, value) {
      const seq = await nextSeq();
      const { _id, _seq, ...rest } = value;
      await collection.replaceOne(
        { _id: key },
        { _id: key, _seq: seq, scope, ...rest },
        { upsert: true, writeConcern: WRITE_CONCERN },
      );
    },
    /**
     * CONDITIONAL completion: writes `next` only when the stored row is still exactly `expected`.
     * Returns `true` when this caller won the transition, `false` when it lost — never throws for a
     * lost race, because "already completed" is a normal outcome the ledger classifies.
     */
    async compareAndSet(key, expected, next) {
      const seq = await nextSeq();
      const { _id, _seq, ...rest } = next;
      const result = await collection.replaceOne(
        { _id: key, ...expected },
        { _id: key, _seq: seq, scope, ...rest },
        { upsert: false, writeConcern: WRITE_CONCERN },
      );
      return result.matchedCount === 1;
    },
    async delete(key) {
      await collection.deleteOne({ _id: key }, { writeConcern: WRITE_CONCERN });
    },
    async keys() {
      const rows = await collection
        .find({}, { projection: { _id: 1 } })
        .sort({ _seq: 1 })
        .toArray();
      return rows.map((row) => row._id);
    },
    async size() {
      return collection.countDocuments({});
    },
  });
}

/**
 * A collection-backed store in the exact shape `createMapResultStore()` declares.
 * @param {object} params
 * @param {import('mongodb').Collection} params.collection
 * @param {string} params.scope
 * @returns {Readonly<object>}
 */
function createMongoResultStore({ collection, scope }) {
  return Object.freeze({
    kind: 'mongo-result-store',
    collectionName: collection.collectionName,
    async get(key) {
      const row = await collection.findOne({ _id: key });
      return row ?? null;
    },
    async set(key, value) {
      const { _id, ...rest } = value;
      await collection.replaceOne(
        { _id: key },
        { _id: key, scope, ...rest },
        { upsert: true, writeConcern: WRITE_CONCERN },
      );
    },
    async size() {
      return collection.countDocuments({});
    },
  });
}

/**
 * Builds a dispatch ledger whose durability is real MongoDB, with the conditional completion the
 * accepted module's header requires of a durable store.
 *
 * The wrapping is deliberately thin and fully disclosed: `createDispatchLedger` keeps every decision,
 * and this function only swaps `store.set` for a compare-and-set when the row it is asked to write is
 * a COMPLETION (it carries `completedAt` and a non-`dispatched` state). A reservation keeps the plain
 * `set`, exactly as the in-process store does.
 *
 * @param {object} params
 * @param {Function} params.createDispatchLedger the accepted factory
 * @param {object} params.store the Mongo store above
 * @param {() => number} params.now
 * @returns {{ledger: object, durableCompletionWrites: number, plainWrites: number}}
 */
function createDurableDispatchLedger({ createDispatchLedger, store, now }) {
  const counters = { durableCompletionWrites: 0, plainWrites: 0, completionConflicts: 0 };
  const conditionalStore = Object.freeze({
    ...store,
    async set(key, value) {
      const isCompletion =
        value !== null &&
        typeof value === 'object' &&
        value.state === 'completed' &&
        value.completedAt !== null &&
        value.completedAt !== undefined;
      if (!isCompletion) {
        counters.plainWrites += 1;
        return store.set(key, value);
      }
      // CONDITIONAL: transition ONLY from a live `dispatched` row. `reservedAt` pins the row this
      // completion was derived from, so a completion computed against a superseded row cannot land.
      //
      // A lost race FAILS CLOSED by throwing: `dispatchLedger.complete()` classifies a store failure
      // as a failed completion, so the call is NOT reported as completed and the sink stores nothing.
      // Silently returning would make the ledger believe a completion it did not durably commit,
      // and the sink would then store the outcome of a call whose durable row says `dispatched`.
      const previous = await store.get(key);
      if (previous === null || previous.state !== 'dispatched') {
        counters.completionConflicts += 1;
        throw new StoreConflictError(
          'the durable completion was asked to transition a row that is not live-dispatched',
          { key, observedState: previous === null ? null : previous.state },
        );
      }
      const won = await store.compareAndSet(
        key,
        { state: 'dispatched', reservedAt: previous.reservedAt },
        value,
      );
      if (won) {
        counters.durableCompletionWrites += 1;
      } else {
        counters.completionConflicts += 1;
        throw new StoreConflictError('the conditional completion lost its race', {
          key,
          reservedAt: previous.reservedAt,
        });
      }
      return undefined;
    },
  });

  const ledger = createDispatchLedger({ now, store: conditionalStore });
  return { ledger, counters, store: conditionalStore };
}

module.exports = {
  WRITE_CONCERN,
  StoreConflictError,
  createMongoDispatchStore,
  createMongoResultStore,
  createDurableDispatchLedger,
};
'use strict';

/**
 * W3-B R2 T2-F4 genuine-model call counter (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * The product bytes receive the genuine `createModels(mongoose)` registry directly (no facade).
 * This module temporarily wraps chosen statics ON THE GENUINE MODEL CONSTRUCTORS to count
 * invocations, then restores every one of them. A constructor is never replaced, no proxy and no
 * plain-object model facade is introduced, and the exact original implementation always runs.
 *
 * Truthfulness rules encoded here:
 *   - an invocation is counted when the genuine static is entered, never inferred;
 *   - write statics (`updateOne`, `create`, …) are counted through the promise the product awaits;
 *   - query statics (`findOne`, …) keep the REAL `Query` object so `.lean()` chaining still works:
 *     the thenable is never assimilated here, so no query is executed twice;
 *   - `restoreAll()` is idempotent and the harness calls it before read-back and in `finally`.
 */

const WRITE_METHODS = Object.freeze([
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'findOneAndUpdate',
  'findOneAndDelete',
  'findOneAndReplace',
  'replaceOne',
  'create',
  'insertMany',
  'bulkWrite',
]);

const QUERY_METHODS = Object.freeze(['findOne', 'find', 'countDocuments', 'distinct', 'aggregate']);

/**
 * Statics actually instrumented for the frozen "zero model calls" law. `find`/`aggregate`/
 * `insertMany` are deliberately NOT instrumented: the product bytes never call them directly, and
 * wrapping `insertMany` could observe Mongoose's own internal `create` -> `insertMany` hop and
 * double-count one product write.
 */
const PRODUCT_MODEL_METHODS = Object.freeze([
  'findOne',
  'findOneAndUpdate',
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'create',
]);

function describeError(err) {
  if (err === null || typeof err !== 'object') {
    return { name: null, code: null, message: String(err) };
  }
  return { name: err.name ?? null, code: err.code ?? null, message: err.message ?? null };
}

class ModelCallCounter {
  constructor() {
    this.calls = [];
    this._restores = [];
  }

  /** Temporarily wraps one genuine static method; the original implementation always runs. */
  patch(model, method, label) {
    if (model === null || typeof model !== 'function') {
      throw new TypeError(`counter target for ${method} must be a genuine model constructor`);
    }
    const hadOwn = Object.prototype.hasOwnProperty.call(model, method);
    const original = model[method];
    if (typeof original !== 'function') {
      throw new TypeError(
        `counter target ${model.modelName ?? '(unnamed)'}.${method} is not a function`,
      );
    }
    const calls = this.calls;
    const modelName = model.modelName ?? '(unnamed)';
    const collection = model.collection ? model.collection.name : null;
    const isQuery = QUERY_METHODS.includes(method);

    function counted(...args) {
      const record = {
        label: label ?? null,
        model: modelName,
        collection,
        method,
        kind: isQuery ? 'query' : 'write',
        seq: calls.length,
        argCount: args.length,
        phase: 'issued',
        ok: null,
        error: null,
        leanResolvedWithDocument: null,
      };
      calls.push(record);
      let outcome;
      try {
        outcome = original.apply(this, args);
      } catch (err) {
        record.phase = 'threw';
        record.ok = false;
        record.error = describeError(err);
        throw err;
      }
      if (isQuery) {
        if (outcome !== null && typeof outcome === 'object' && typeof outcome.lean === 'function') {
          const originalLean = outcome.lean.bind(outcome);
          outcome.lean = (...leanArgs) =>
            Promise.resolve(originalLean(...leanArgs)).then(
              (doc) => {
                record.phase = 'lean-settled';
                record.ok = true;
                record.leanResolvedWithDocument = doc !== null && doc !== undefined;
                return doc;
              },
              (err) => {
                record.phase = 'lean-rejected';
                record.ok = false;
                record.error = describeError(err);
                throw err;
              },
            );
        }
        return outcome;
      }
      return Promise.resolve(outcome).then(
        (result) => {
          record.phase = 'settled';
          record.ok = true;
          record.matchedCount =
            result !== null && typeof result === 'object' && typeof result.matchedCount === 'number'
              ? result.matchedCount
              : null;
          record.acknowledged =
            result !== null && typeof result === 'object' && typeof result.acknowledged === 'boolean'
              ? result.acknowledged
              : null;
          return result;
        },
        (err) => {
          record.phase = 'rejected';
          record.ok = false;
          record.error = describeError(err);
          throw err;
        },
      );
    }

    Object.defineProperty(counted, 'name', { value: method, configurable: true });
    model[method] = counted;
    this._restores.push(() => {
      if (hadOwn) {
        model[method] = original;
      } else {
        delete model[method];
      }
    });
    return counted;
  }

  /** Patches every named product model method that exists on the genuine constructor. */
  patchModels(models, modelNames, methods = PRODUCT_MODEL_METHODS) {
    const patched = [];
    for (const name of modelNames) {
      const model = models[name];
      if (model === undefined || model === null) {
        continue;
      }
      for (const method of methods) {
        if (typeof model[method] !== 'function') {
          continue;
        }
        this.patch(model, method, `${name}.${method}`);
        patched.push(`${name}.${method}`);
      }
    }
    return patched;
  }

  mark() {
    return this.calls.length;
  }

  since(mark) {
    return this.calls.slice(mark);
  }

  /** Invocation counts for one model, optionally restricted to a method set. */
  countsFor(records, modelName, methods = null) {
    const selected = records.filter(
      (record) =>
        record.model === modelName && (methods === null || methods.includes(record.method)),
    );
    const byMethod = {};
    for (const record of selected) {
      byMethod[record.method] = (byMethod[record.method] ?? 0) + 1;
    }
    return { total: selected.length, byMethod, records: selected };
  }

  /** Invocation counts across several models, plus the grand total. */
  countsAcross(records, modelNames, methods = null) {
    const byModel = {};
    let total = 0;
    for (const name of modelNames) {
      const counts = this.countsFor(records, name, methods);
      byModel[name] = { total: counts.total, byMethod: counts.byMethod };
      total += counts.total;
    }
    return { total, byModel };
  }

  restoreAll() {
    while (this._restores.length > 0) {
      const restore = this._restores.pop();
      try {
        restore();
      } catch {
        /* restoration must never mask the row outcome */
      }
    }
    return this._restores.length === 0;
  }

  allRestored() {
    return this._restores.length === 0;
  }
}

module.exports = {
  WRITE_METHODS,
  QUERY_METHODS,
  PRODUCT_MODEL_METHODS,
  ModelCallCounter,
  describeError,
};
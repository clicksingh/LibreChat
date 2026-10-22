'use strict';

/**
 * W3-B R2 S4T genuine-constructor argument capture (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * The product bytes are given the genuine `createModels(mongoose)` registry directly, so the exact
 * argument list of every authority-critical write reaches the genuine Mongoose static method. This
 * module temporarily wraps those statics on the GENUINE constructors to record the real arguments,
 * then restores each one. A constructor is never replaced and no facade is introduced.
 *
 * Truthfulness rules encoded here:
 *   - a call is "pinned" only when the captured options object carries
 *     `writeConcern.w === 'majority'` AND `writeConcern.j === true`;
 *   - an absent options object is recorded as `hasOptionsArgument:false`, never inferred;
 *   - every capture is restored by `restoreAll()`, which the harness calls in a `finally` block.
 */

const OPTIONS_INDEX = Object.freeze({
  create: 1,
  insertMany: 1,
  deleteOne: 1,
  deleteMany: 1,
  findOneAndDelete: 1,
  updateOne: 2,
  updateMany: 2,
  replaceOne: 2,
  findOneAndUpdate: 2,
  findOneAndReplace: 2,
});

const DOCUMENT_METHODS = Object.freeze(['create', 'insertMany']);

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function describeError(err) {
  if (err === null || typeof err !== 'object') {
    return { name: null, code: null, message: String(err) };
  }
  return {
    name: err.name ?? null,
    code: err.code ?? null,
    message: err.message ?? null,
  };
}

/** Bounded, JSON-safe projection of a captured value. Never includes functions or buffers. */
function safeJson(value, depth = 0) {
  if (depth > 6) {
    return '[depth-limit]';
  }
  if (value === undefined || value === null) {
    return null;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (Buffer.isBuffer(value)) {
    return `[buffer:${value.length}]`;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => safeJson(entry, depth + 1));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) {
      const entry = value[key];
      if (typeof entry === 'function') {
        continue;
      }
      out[key] = safeJson(entry, depth + 1);
    }
    return out;
  }
  return value;
}

function payloadKindOf(method, args) {
  if (DOCUMENT_METHODS.includes(method)) {
    return 'document';
  }
  return Array.isArray(args[1]) ? 'pipeline' : 'update';
}

function optionsOf(method, args) {
  const index = OPTIONS_INDEX[method];
  if (index === undefined || args.length <= index) {
    return null;
  }
  return args[index] ?? null;
}

function hasOptionsArgument(method, args) {
  const index = OPTIONS_INDEX[method];
  return index !== undefined && args.length > index;
}

function filterOf(method, args) {
  return DOCUMENT_METHODS.includes(method) ? null : (args[0] ?? null);
}

function payloadKeysOf(method, args) {
  if (DOCUMENT_METHODS.includes(method)) {
    const payload = args[0];
    if (Array.isArray(payload)) {
      const keys = new Set();
      for (const entry of payload) {
        if (entry !== null && typeof entry === 'object') {
          for (const key of Object.keys(entry)) {
            keys.add(key);
          }
        }
      }
      return Array.from(keys).sort();
    }
    return payload !== null && typeof payload === 'object' ? Object.keys(payload).sort() : [];
  }
  const update = args[1];
  return update !== null && typeof update === 'object' ? Object.keys(update).sort() : [];
}

function resultSummary(result) {
  if (result === null || result === undefined) {
    return null;
  }
  if (Array.isArray(result)) {
    return {
      kind: 'array',
      length: result.length,
      ids: result.slice(0, 4).map((entry) => (entry && entry._id !== undefined ? String(entry._id) : null)),
    };
  }
  if (typeof result === 'object') {
    if (typeof result.matchedCount === 'number' || typeof result.acknowledged === 'boolean') {
      return {
        kind: 'write-result',
        acknowledged: result.acknowledged ?? null,
        matchedCount: result.matchedCount ?? null,
        modifiedCount: result.modifiedCount ?? null,
        upsertedCount: result.upsertedCount ?? null,
      };
    }
    if (result._id !== undefined) {
      return { kind: 'document', _id: String(result._id) };
    }
    if (typeof result.toObject === 'function') {
      const plain = result.toObject();
      return { kind: 'document', _id: plain && plain._id !== undefined ? String(plain._id) : null };
    }
  }
  return { kind: typeof result };
}

class ModelCapture {
  constructor() {
    this.records = [];
    this.restorations = [];
  }

  /**
   * Temporarily wraps one genuine static method. Records the real argument list; the original
   * implementation always runs. The wrapper is restored by `restoreAll()`.
   */
  patch(model, method, label) {
    if (model === null || typeof model !== 'function') {
      throw new TypeError(`capture target for ${method} must be a genuine model constructor`);
    }
    const hadOwn = Object.prototype.hasOwnProperty.call(model, method);
    const original = model[method];
    if (typeof original !== 'function') {
      throw new TypeError(
        `capture target ${model.modelName ?? '(unnamed)'}.${method} is not a function`,
      );
    }
    const records = this.records;
    const modelName = model.modelName ?? '(unnamed)';
    const collection = model.collection ? model.collection.name : null;

    function captured(...args) {
      const isDocumentMethod = DOCUMENT_METHODS.includes(method);
      const record = {
        label,
        model: modelName,
        collection,
        method,
        seq: records.length,
        argCount: args.length,
        hasOptionsArgument: hasOptionsArgument(method, args),
        documentsAreArray: isDocumentMethod ? Array.isArray(args[0]) : null,
        options: safeJson(optionsOf(method, args)),
        payloadKind: payloadKindOf(method, args),
        payloadKeys: payloadKeysOf(method, args),
        filter: safeJson(filterOf(method, args)),
        ok: null,
        error: null,
        result: null,
      };
      records.push(record);
      let outcome;
      try {
        outcome = original.apply(this, args);
      } catch (err) {
        record.ok = false;
        record.error = describeError(err);
        throw err;
      }
      return Promise.resolve(outcome).then(
        (result) => {
          record.ok = true;
          record.result = resultSummary(result);
          return result;
        },
        (err) => {
          record.ok = false;
          record.error = describeError(err);
          throw err;
        },
      );
    }

    Object.defineProperty(captured, 'name', { value: method, configurable: true });
    model[method] = captured;
    this.restorations.push(() => {
      if (hadOwn) {
        model[method] = original;
      } else {
        delete model[method];
      }
    });
    return captured;
  }

  recordsFor(modelName, method) {
    return this.records.filter(
      (record) => record.model === modelName && (method === undefined || record.method === method),
    );
  }

  recordsForLabel(label) {
    return this.records.filter((record) => record.label === label);
  }

  /** Restores every patched static. Idempotent; never throws. */
  restoreAll() {
    while (this.restorations.length > 0) {
      const restore = this.restorations.pop();
      try {
        restore();
      } catch {
        /* restoration must never mask the row outcome */
      }
    }
    return this.restorations.length === 0;
  }

  /** True when every originally patched method is back to its original implementation. */
  allRestored() {
    return this.restorations.length === 0;
  }
}

function writeConcernOfRecord(record) {
  const options = record.options;
  if (options === null || typeof options !== 'object') {
    return null;
  }
  return options.writeConcern ?? null;
}

function isMajorityJournal(writeConcern) {
  return (
    writeConcern !== null &&
    typeof writeConcern === 'object' &&
    writeConcern.w === 'majority' &&
    writeConcern.j === true
  );
}

/**
 * Mongoose 8 `Model.create(doc, options)` does NOT treat the second argument as options when the
 * first is not an array: `lib/model.js:2681-2701` sets `args = [...arguments]`, so the options
 * object becomes a SECOND document. The only unambiguous options overload is therefore the array
 * form `Model.create([doc], options)`, which R1 freeze F8 requires ("array form where needed").
 */
function isUnambiguousDocumentOptionsOverload(record) {
  if (record.hasOptionsArgument !== true) {
    return false;
  }
  if (!DOCUMENT_METHODS.includes(record.method)) {
    return true;
  }
  return record.documentsAreArray === true;
}

/**
 * F8 verdict for a captured write set: the exact repair predicate is satisfied only when EVERY
 * captured call carried an explicit options object whose writeConcern is majority+journal, passed
 * through an unambiguous overload.
 */
function writeConcernVerdict(records) {
  const calls = records.map((record) => {
    const writeConcern = writeConcernOfRecord(record);
    const unambiguous = isUnambiguousDocumentOptionsOverload(record);
    return {
      label: record.label,
      model: record.model,
      method: record.method,
      argCount: record.argCount,
      hasOptionsArgument: record.hasOptionsArgument,
      documentsAreArray: record.documentsAreArray ?? null,
      unambiguousOptionsOverload: unambiguous,
      writeConcern,
      explicitMajorityJournal: unambiguous && isMajorityJournal(writeConcern),
      ok: record.ok,
    };
  });
  const pinned = calls.filter((call) => call.explicitMajorityJournal);
  return {
    callCount: calls.length,
    pinnedCount: pinned.length,
    allPinned: calls.length > 0 && pinned.length === calls.length,
    anyPinned: pinned.length > 0,
    missingExplicitOptionsCount: calls.filter((call) => call.hasOptionsArgument === false).length,
    ambiguousOptionsOverloadCount: calls.filter(
      (call) => call.hasOptionsArgument === true && call.unambiguousOptionsOverload === false,
    ).length,
    calls,
  };
}

module.exports = {
  OPTIONS_INDEX,
  ModelCapture,
  safeJson,
  describeError,
  isMajorityJournal,
  isUnambiguousDocumentOptionsOverload,
  writeConcernOfRecord,
  writeConcernVerdict,
  isNonEmptyString,
};

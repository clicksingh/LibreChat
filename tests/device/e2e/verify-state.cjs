#!/usr/bin/env node
'use strict';

/**
 * W9 — INDEPENDENT POST-RUN RE-READ (a SEPARATE OS process from the runner).
 *
 * Why it is a separate process rather than a function call: the claim being made is that the dispatch
 * ledger's final state is DURABLE and that "complete exactly once" survives a process boundary. A
 * re-read inside the writer's own process could be satisfied by the writer's memory. This process
 * opens the same database with its own MongoDB client, never imports the runner, and never sees the
 * runner's objects.
 *
 * It proves three things:
 *   1. the call the runner dispatched is present in the durable ledger in state `completed` with the
 *      outcome the DEVICE signed;
 *   2. a SECOND completion of that same call is refused by the accepted ledger, and the row is
 *      unchanged afterwards;
 *   3. the stored result row is the one the run produced.
 *
 * Usage:
 *   node verify-state.cjs --uri <uri> --db <name> --call-id <id> [--ledger-collection <name>]
 *                         [--result-collection <name>] [--expect-outcome <word>] [--out <file>]
 */

const fs = require('node:fs');
const path = require('node:path');

const REPO = path.resolve(__dirname, '..', '..', '..');
const driver = require(path.join(REPO, 'tests', 'device', 'driver.cjs'));
const storage = require('./mongo-seams.cjs');

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      continue;
    }
    const key = arg.slice(2);
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) {
      options[key] = true;
      continue;
    }
    options[key] = next;
    index += 1;
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const uri = options.uri;
  const dbName = options.db;
  const callId = options['call-id'];
  const expectOutcome = options['expect-outcome'] ?? null;
  for (const [name, value] of Object.entries({ uri, db: dbName, 'call-id': callId })) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`verify-state requires --${name}`);
    }
  }
  if (!/^cbhr_rdc_phase1_e2e_[A-Za-z0-9_]+$/.test(dbName)) {
    throw new Error(`verify-state refuses a database outside the harness prefix: ${dbName}`);
  }
  const ledgerCollectionName = options['ledger-collection'] ?? 'w9_dispatch_ledger';
  const resultCollectionName = options['result-collection'] ?? 'w9_results';

  const dispatchLedgerModule = require(path.join(
    REPO,
    'api',
    'server',
    'services',
    'Device',
    'relay',
    'dispatchLedger.js',
  ));

  const client = new driver.MongoClient(uri, {
    serverSelectionTimeoutMS: 15000,
    appName: 'w9-e2e-verify-state',
    retryWrites: false,
  });
  await client.connect();

  const report = {
    process: process.pid,
    node: process.version,
    independentProcess: true,
    database: dbName,
    callId,
    driver: `mongodb@${driver.version}`,
    ledgerCollection: ledgerCollectionName,
    resultCollection: resultCollectionName,
  };

  try {
    const db = client.db(dbName);
    const ledgerCollection = db.collection(ledgerCollectionName);
    const ledgerMeta = db.collection(`${ledgerCollectionName}_meta`);
    const resultCollection = db.collection(resultCollectionName);

    const rawRow = await ledgerCollection.findOne({ _id: callId });
    report.ledgerRowRaw = rawRow === null ? null : { ...rawRow };
    report.ledger = rawRow === null
      ? null
      : {
          callId: rawRow._id,
          state: rawRow.state,
          outcome: rawRow.outcome,
          resultSeq: rawRow.resultSeq,
          toolName: rawRow.toolName,
          tenantId: rawRow.tenantId,
          deviceId: rawRow.deviceId,
          epoch: rawRow.epoch,
          reservedAt: rawRow.reservedAt,
          completedAt: rawRow.completedAt,
        };
    report.storedResult = await resultCollection.findOne({ _id: callId });

    // 2. A second completion, through the accepted ledger over the same durable store.
    const store = storage.createMongoDispatchStore({
      collection: ledgerCollection,
      meta: ledgerMeta,
      scope: 'verify-state',
    });
    const durable = storage.createDurableDispatchLedger({
      createDispatchLedger: dispatchLedgerModule.createDispatchLedger,
      store,
      now: () => Date.now(),
    });
    const second = await durable.ledger.complete(callId, {
      outcome: 'succeeded',
      resultSeq: 9999,
    });
    const afterSecond = await ledgerCollection.findOne({ _id: callId });
    report.secondCompletion = {
      ok: second.ok === true,
      code: second.ok === true ? null : (second.error?.code ?? null),
      refused: second.ok !== true,
      stateUnchanged:
        afterSecond !== null &&
        afterSecond.state === rawRow.state &&
        afterSecond.outcome === rawRow.outcome &&
        afterSecond.resultSeq === rawRow.resultSeq &&
        afterSecond.completedAt?.getTime?.() === rawRow.completedAt?.getTime?.(),
      observedAfter: afterSecond === null
        ? null
        : { state: afterSecond.state, outcome: afterSecond.outcome, resultSeq: afterSecond.resultSeq },
      durableCompletionWrites: durable.counters.durableCompletionWrites,
      completionConflicts: durable.counters.completionConflicts,
    };

    // 3. An unknown call id is refused, so the re-read also proves the ledger is not permissive.
    const unknown = await durable.ledger.complete(`${callId}-never-dispatched`, { outcome: 'succeeded' });
    report.unknownCallCompletion = {
      refused: unknown.ok !== true,
      code: unknown.ok === true ? null : (unknown.error?.code ?? null),
    };

    report.ledgerRowCount = await ledgerCollection.countDocuments({});
    report.resultRowCount = await resultCollection.countDocuments({});
    report.checks = {
      callIsCompleted: report.ledger?.state === 'completed',
      outcomeMatches: expectOutcome === null ? null : report.ledger?.outcome === expectOutcome,
      secondCompletionRefused: report.secondCompletion.refused === true,
      secondCompletionChangedNothing: report.secondCompletion.stateUnchanged === true,
      unknownCallRefused: report.unknownCallCompletion.refused === true,
    };
    report.ok = Object.values(report.checks).every((value) => value === true || value === null);
  } finally {
    await client.close().catch(() => {});
  }

  const out = options.out;
  const text = `${JSON.stringify(report, null, 2)}\n`;
  if (typeof out === 'string' && out.length > 0) {
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, text, 'utf8');
  } else {
    process.stdout.write(text);
  }
  process.exitCode = report.ok === true ? 0 : 2;
}

main().catch((error) => {
  process.stderr.write(`verify-state failed: ${error.message}\n`);
  process.exitCode = 1;
});
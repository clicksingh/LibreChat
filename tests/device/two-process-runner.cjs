'use strict';

/**
 * I9 dual-mode two-OS-process burst harness (lane I9, PHASE1-LOCAL-AUTHORITY-001 / W2-B).
 *
 *   parent: node tests/device/two-process-runner.cjs --fixture=T7 --n=50 --strategy=naive --db=cbhr_rdc_phase1_w2b_...
 *   child : node tests/device/two-process-runner.cjs --role=child --fixture=T7 --n=50 --strategy=naive --shard=A \
 *                   --db=... --prepared=<file> --barrier-dir=<dir> --out=<file>
 *
 * Design constraints honoured:
 *   - exactly two real OS processes per burst (recorded PIDs, parent asserts two distinct PIDs)
 *   - children are spawned with stdio 'inherit' (piped stdio is EPERM in this sandbox)
 *   - child results travel through files, never through a pipe or stdout
 *   - the parent drops ONLY its own cbhr_rdc_phase1_w2b_* database, never a non-w2b database
 *
 * Strategies:
 *   naive    -> naive-baseline/naive-strategy.cjs   (negative control, runnable)
 *   contract -> e1/contract-strategy.cjs            (product service; BLOCKED_PENDING_I6_I5)
 */

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const harness = require('./e1/harness.cjs');

const STRATEGIES = {
  naive: path.join(__dirname, 'naive-baseline', 'naive-strategy.cjs'),
  contract: path.join(__dirname, 'e1', 'contract-strategy.cjs'),
};

function resolveStrategy(name) {
  const absolute = STRATEGIES[name];
  if (!absolute) {
    throw new Error(`unknown strategy ${name}; expected one of ${Object.keys(STRATEGIES).join('|')}`);
  }
  // eslint-disable-next-line global-require, import/no-dynamic-require
  return require(absolute);
}

async function runChild(argv) {
  const options = harness.parseArgs(argv);
  const strategy = resolveStrategy(options.strategy);
  const dbName = options.db;
  const shard = options.shard;
  const attempts = Number(options.attempts ?? Math.floor(Number(options.n) / 2));
  let client = null;
  let result;
  try {
    const connected = await harness.connect({ uri: options.uri, dbName, appName: `cbhr-phase1-w2b-child-${shard}` });
    client = connected.client;
    const prepared = harness.readJsonFile(options.prepared);
    result = await strategy.childRun({
      db: connected.db,
      client,
      shard,
      attempts,
      prepared,
      barrierDir: options['barrier-dir'],
      resultPath: options.out,
    });
  } catch (err) {
    result = { shard, pid: process.pid, status: 'HARNESS_FAIL', error: `${err.name}: ${err.message}` };
  } finally {
    if (client !== null) {
      await client.close().catch(() => {});
    }
  }
  if (options.out) {
    harness.writeJsonFile(options.out, result);
  }
  process.exitCode = result.status === 'OK' || result.status === 'BLOCKED_PENDING_I6_I5' ? 0 : 4;
  return result;
}

async function runTwoProcess(options = {}) {
  const fixture = options.fixture ?? 'T7';
  const n = Number(options.n ?? 50);
  const strategyName = options.strategy ?? 'contract';
  const uri = options.uri ?? harness.DEFAULT_URI;
  const dbName = options.db ?? harness.makeDbName(`twoproc_${fixture}_${strategyName}`);
  const mode = options.mode ?? 'default';
  const emit = options.emit !== false;

  if (!Number.isFinite(n) || n < harness.N_MIN) {
    const blocked = {
      check: 'two-process-runner',
      fixture,
      strategy: strategyName,
      db: dbName,
      status: 'BLOCKED',
      exitCode: 2,
      reason: 'n_below_50',
      n,
      productClaim: false,
    };
    if (options['result-out']) {
      harness.writeJsonFile(options['result-out'], blocked);
    }
    if (emit) {
      harness.emit(blocked);
    }
    return blocked;
  }

  const strategy = resolveStrategy(strategyName);
  const shardA = Math.ceil(n / 2);
  const shardB = n - shardA;
  if (shardA + shardB !== n) {
    throw new Error('shard sum mismatch');
  }

  const workDir = harness.tmpRoot(`twoproc-${fixture}-${strategyName}`);
  const preparedFile = path.join(workDir, 'prepared.json');
  const outA = path.join(workDir, 'child-A.json');
  const outB = path.join(workDir, 'child-B.json');
  const barrierDir = path.join(workDir, 'barrier');
  fs.rmSync(barrierDir, { recursive: true, force: true });
  fs.mkdirSync(barrierDir, { recursive: true });
  for (const stale of [outA, outB]) {
    fs.rmSync(stale, { force: true });
  }

  let client = null;
  let cleanup = 'not_attempted';
  const base = {
    check: 'two-process-runner',
    fixture,
    strategy: strategyName,
    strategyId: strategy.id,
    requiresServices: strategy.requiresServices === true,
    productClaim: false,
    uri,
    db: dbName,
    n,
    shards: { A: shardA, B: shardB },
    mode,
    startedAt: new Date().toISOString(),
  };

  try {
    const connected = await harness.connect({ uri, dbName, appName: 'cbhr-phase1-w2b-twoproc' });
    client = connected.client;
    base.topology = connected.topology;
    base.isolation = connected.isolation;
    if (connected.isolation.foreign.length > 0) {
      cleanup = 'skipped_before_write';
      const blocked = {
        ...base,
        status: 'BLOCKED',
        exitCode: 2,
        stage: 'isolation',
        reason: `foreign non-cbhr_rdc_phase1_ databases present: ${connected.isolation.foreign.join(', ')}`,
      };
      if (options['result-out']) {
        harness.writeJsonFile(options['result-out'], blocked);
      }
      if (emit) {
        harness.emit(blocked);
      }
      return blocked;
    }

    const seed = options.seed ?? null;
    const prepared = await strategy.prepare({ db: connected.db, fixture: { id: fixture }, options: { mode }, seed });
    harness.writeJsonFile(preparedFile, prepared);
    base.prepared = {
      mode: prepared.mode,
      indexesCreated: prepared.indexesCreated,
      tenantId: prepared.tenantId,
      ownerId: prepared.ownerId,
      shards: prepared.shards,
    };

    const spawnChild = (shard, attempts, out) =>
      new Promise((resolve) => {
        const child = spawn(
          process.execPath,
          [
            __filename,
            '--role=child',
            `--fixture=${fixture}`,
            `--strategy=${strategyName}`,
            `--shard=${shard}`,
            `--attempts=${attempts}`,
            `--n=${n}`,
            `--uri=${uri}`,
            `--db=${dbName}`,
            `--prepared=${preparedFile}`,
            `--barrier-dir=${barrierDir}`,
            `--out=${out}`,
          ],
          { stdio: 'inherit' },
        );
        child.on('exit', (code, signal) => resolve({ status: code, signal, error: null }));
        child.on('error', (error) => resolve({ status: null, signal: null, error }));
      });

    const [spawnA, spawnB] = await Promise.all([spawnChild('A', shardA, outA), spawnChild('B', shardB, outB)]);
    base.childSpawn = {
      A: { exitStatus: spawnA.status, signal: spawnA.signal, error: spawnA.error ? String(spawnA.error.message) : null },
      B: { exitStatus: spawnB.status, signal: spawnB.signal, error: spawnB.error ? String(spawnB.error.message) : null },
      transport: 'concurrent async spawn stdio:inherit + file results (no pipe)',
    };

    const childResults = [outA, outB].filter((file) => fs.existsSync(file)).map((file) => harness.readJsonFile(file));
    base.childResults = childResults;

    if (strategy.requiresServices === true) {
      const childBlocked = childResults.find((entry) => entry.status === 'BLOCKED_PENDING_I6_I5');
      if (childBlocked !== undefined || childResults.length < 2) {
        const blocked = {
          ...base,
          status: 'BLOCKED_PENDING_I6_I5',
          exitCode: 2,
          stage: 'product-service',
          reason:
            'I6 authority service and/or I5 pairing service not implemented; no product CAS was executed and no PASS is claimed',
          childPids: childResults.map((entry) => entry.pid),
          distinctPids: new Set(childResults.map((entry) => entry.pid)).size,
        };
        cleanup = await harness.dropOwnDatabase(connected.db, dbName);
        blocked.cleanup = cleanup;
        if (options['result-out']) {
          harness.writeJsonFile(options['result-out'], blocked);
        }
        if (emit) {
          harness.emit(blocked);
        }
        return blocked;
      }
    }

    const assessment = await strategy.assertAfterBurst({ db: connected.db, prepared, childResults, options: { mode } });
    const report = { ...base, ...assessment, cleanup: 'pending' };
    cleanup = await harness.dropOwnDatabase(connected.db, dbName);
    report.cleanup = cleanup;
    report.finishedAt = new Date().toISOString();
    if (options['result-out']) {
      harness.writeJsonFile(options['result-out'], report);
    }
    if (emit) {
      harness.emit(report);
    }
    return report;
  } catch (err) {
    const failed = {
      ...base,
      status: 'HARNESS_FAIL',
      exitCode: 4,
      reason: `${err.name}: ${err.message}`,
      cleanup,
    };
    if (options['result-out']) {
      harness.writeJsonFile(options['result-out'], failed);
    }
    if (emit) {
      harness.emit(failed);
    }
    return failed;
  } finally {
    if (client !== null) {
      await client.close().catch(() => {});
    }
  }
}

if (require.main === module) {
  const options = harness.parseArgs(process.argv.slice(2));
  if (options.role === 'child') {
    runChild(process.argv.slice(2)).then(
      () => {},
      (err) => {
        process.stderr.write(`${err.stack ?? err.message}\n`);
        process.exitCode = 4;
      },
    );
  } else {
    runTwoProcess(options).then(
      (report) => {
        process.exitCode = report.exitCode ?? 0;
      },
      (err) => {
        process.stdout.write(`${JSON.stringify({ check: 'two-process-runner', status: 'HARNESS_FAIL', error: err.message })}\n`);
        process.exitCode = 4;
      },
    );
  }
}

module.exports = { STRATEGIES, resolveStrategy, runChild, runTwoProcess };

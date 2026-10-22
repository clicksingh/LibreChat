'use strict';

/**
 * W3-A / I11 child-process wiring (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Two-process fixtures coordinate purely through files in the run directory and use
 * `stdio: 'ignore'` (piped stdio is EPERM in this sandbox). This module is required by every
 * child process: it re-loads the same real product bytes, connects to the fixture-owned
 * cbhr_rdc_phase1_w3_* database and drives real product calls.
 */

const fs = require('node:fs');
const path = require('node:path');

const support = require('./support.cjs');

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      continue;
    }
    const [flag, inlineValue] = arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, null];
    const value = inlineValue !== null ? inlineValue : argv[index + 1];
    options[flag.slice(2)] = value === undefined ? true : value;
    if (inlineValue === null) {
      index += 1;
    }
  }
  return options;
}

function writeJsonFile(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function readJsonFile(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForFile(file, { timeoutMs = 120000, intervalMs = 5 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (!fs.existsSync(file)) {
    if (Date.now() > deadline) {
      throw new Error(`BARRIER_TIMEOUT waiting for ${file}`);
    }
    await sleep(intervalMs);
  }
  return readJsonFile(file);
}

/** Deterministic device keys are derived from a tag, so children and parents agree. */
async function buildChildContext({ dbName, clockMs, tag }) {
  const ctx = await support.makeContext({
    tag: `child-${tag ?? 'x'}`,
    dbName,
    syncIndexes: false,
    // The parent owns the fixture database: a child must never drop it.
    dropOnTeardown: false,
  });
  ctx.clock.set(Number(clockMs));
  return ctx;
}

module.exports = {
  parseArgs,
  writeJsonFile,
  readJsonFile,
  sleep,
  waitForFile,
  buildChildContext,
  support,
};
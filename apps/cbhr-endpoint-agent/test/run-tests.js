#!/usr/bin/env node
'use strict';

/**
 * CBHR ENDPOINT AGENT — test entry point (workstream W7).
 *
 * One command runs every spec, with no test framework and no new dependency:
 *
 *   node apps/cbhr-endpoint-agent/test/run-tests.js
 *   pnpm --dir apps/cbhr-endpoint-agent test          (same thing)
 *
 * It uses the Node built-in test runner (`node:test`), which the repository's Node 22 already
 * provides, so the agent's acceptance evidence does not depend on jest being configured for a
 * directory outside `roots`. Each spec file is a real spec: `describe`/`it` and `node:assert/strict`,
 * with no mocks that would let a check pass without exercising the code.
 *
 * Exit code is the runner's: 0 only when every spec passed.
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const TEST_DIR = __dirname;
const AGENT_DIR = path.resolve(TEST_DIR, '..');

const SPECS = fs
  .readdirSync(TEST_DIR)
  .filter((name) => name.endsWith('.test.js'))
  .sort();

if (SPECS.length === 0) {
  process.stderr.write('no spec files found\n');
  process.exit(1);
}

process.stdout.write(`running ${SPECS.length} spec files from ${TEST_DIR}\n`);
const result = spawnSync(
  process.execPath,
  ['--test', ...SPECS.map((name) => path.join(TEST_DIR, name))],
  { stdio: 'inherit', cwd: AGENT_DIR },
);

if (result.error) {
  process.stderr.write(`could not start the test runner: ${result.error.code ?? 'unknown'}\n`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
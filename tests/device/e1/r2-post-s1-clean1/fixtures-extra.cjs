'use strict';

/**
 * R2 extra required items:
 *   - R2-F10-REJOIN-ZERO-ATTEMPTS: MAX_CODE_ATTEMPTS = 5 with same-owner authenticated rejoin
 *     consuming ZERO code-guess attempts (final freeze F10).
 *   - R2-G16-CONTROL (post-S1 clean clone): verify 48 original preimages plus three Governor-approved
 *     S1 replacement hashes and the final-freeze hash before and after this diagnostic run.
 */

const fs = require('node:fs');
const path = require('node:path');

const { runFixture, compositionBlocked, env, results } = require('./ctx.cjs');
const { STATUS } = results;
const preflight = require('./preflight.cjs');
const ctxState = require('./ctx.cjs').state;

const PAIRING = 'pairingSessionService.js';

function rejoinSource() {
  const product = env.readProduct(PAIRING);
  if (!product.source) return null;
  const lines = product.source.split('\n');
  const start = lines.findIndex((line) => line.includes('async function rejoinPendingPairingImpl'));
  if (start < 0) return null;
  return lines
    .slice(start, start + 60)
    .map((line, index) => `${start + 1 + index}: ${line.trim()}`)
    .join('\n');
}

function listNewLaneFiles() {
  const root = env.WORKTREE;
  const dirs = ['tests/device/e1/r2', 'tests/device/_phase1_evidence/w3b-r2/t0'];
  const out = [];
  for (const dir of dirs) {
    const absolute = path.join(root, ...dir.split('/'));
    if (!fs.existsSync(absolute)) continue;
    const walk = (current) => {
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        const full = path.join(current, entry.name);
        if (entry.isDirectory()) walk(full);
        else out.push(path.relative(root, full).replace(/\\/g, '/'));
      }
    };
    walk(absolute);
  }
  return out.sort();
}

function fixtures() {
  return [
    {
      id: 'R2-F10-REJOIN-ZERO-ATTEMPTS',
      hostileRows: ['H-36'],
      tier: 'E1',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff MAX_CODE_ATTEMPTS === 5 and a successful authenticated same-owner rejoin consumes ZERO code-guess attempts, so five rejoins followed by a valid redemption succeed',
      build: async (ctx) => {
        const source = env.readProduct(PAIRING).source ?? '';
        const constantNamePresent = source.includes('MAX_CODE_ATTEMPTS');
        const legacyConstant = /const MAX_ATTEMPTS = 5;/.test(source);
        const rejoinBody = rejoinSource();
        const rejoinIncrementsAttempts = rejoinBody !== null && /\$inc:\s*\{\s*attemptsUsed:\s*1\s*\}/.test(rejoinBody);
        const redemptionGate = /attemptsUsed:\s*\{\s*\$lt:\s*MAX_ATTEMPTS\s*\}/.test(source);
        const blocked = compositionBlocked(ctx, {
          pendingOracle: 'five same-owner authenticated rejoins then a valid redemption: rejoins consume 0 guess attempts and the redemption succeeds',
          extraActual: {
            scenario: 'MAX_CODE_ATTEMPTS=5 with same-owner authenticated rejoin consuming zero guess attempts',
            maxCodeAttemptsConstantPresent: constantNamePresent,
            legacyMaxAttemptsConstantPresent: legacyConstant,
            rejoinBody,
            rejoinIncrementsAttempts,
            redemptionGateUsesLegacyConstant: redemptionGate,
            pendingAfterFirstFix: true,
          },
        });
        blocked.components = [
          {
            name: 'frozen_constant_name_and_value',
            oracle: 'MAX_CODE_ATTEMPTS is frozen at 5',
            actual: constantNamePresent
              ? 'MAX_CODE_ATTEMPTS present'
              : `MAX_CODE_ATTEMPTS absent; the shipped constant is named MAX_ATTEMPTS (value 5: ${legacyConstant})`,
            met: constantNamePresent && legacyConstant,
            tier: 'E0',
          },
          {
            name: 'rejoin_consumes_zero_guess_attempts',
            oracle: 'a successful authenticated same-owner rejoin does not increment the code-guess attempt budget',
            actual: rejoinIncrementsAttempts
              ? 'rejoinPendingPairingImpl performs `$inc: { attemptsUsed: 1 }`, so rejoin consumes the guess budget (F10 violation)'
              : 'no attemptsUsed increment found in rejoinPendingPairingImpl',
            met: !rejoinIncrementsAttempts,
            tier: 'E0',
          },
          {
            name: 'five_rejoins_then_redeem_executes',
            oracle: 'five rejoins followed by a valid redemption succeed (E1)',
            actual: 'not reachable: pairing service construction fails at the factory guard',
            met: false,
            tier: 'E1',
          },
          ...blocked.components,
        ];
        return blocked;
      },
    },
    {
      id: 'R2-G16-CONTROL',
      hostileRows: ['H-38'],
      tier: 'E0',
      group: 'R2-COMPOSITION-ERRORS',
      expectedOracle: 'PASS iff 48 unchanged G16 preimages plus 3 Governor-approved S1 replacement hashes and final-freeze SHA-256 reproduce before and after the post-S1 diagnostic',
      build: async () => {
        const after = preflight.verifyLedger();
        const before = ctxState.g16Before ?? null;
        const newFiles = listNewLaneFiles();
        const ledgerPaths = new Set((ctxState.g16LedgerPaths ?? []).map((entry) => entry.key));
        const collisions = newFiles.filter((file) => ledgerPaths.has(`worktree:${file}`));
        const fingerprintStable =
          before !== null && before.ok === true && after.ok === true && preflight.preimageFingerprint(before) === preflight.preimageFingerprint(after);
        const freezeStable = before !== null && after.freeze.ok === true && before.freeze.actual === after.freeze.actual;
        const outsideLedger = collisions.length === 0;
        const met = fingerprintStable && freezeStable && outsideLedger;
        return {
          status: met ? STATUS.PASS_CURRENT : STATUS.UNEXPECTED_RED,
          executedTier: 'E0',
          attempts: after.itemCount,
          actual: {
            scenario: 'recompute 48 unchanged G16 entries plus 3 approved S1 replacement hashes and the final-freeze hash before and after post-S1 diagnostic',
            ledgerPath: after.ledgerPath,
            itemCount: after.itemCount,
            verified: after.verified,
            mismatches: after.mismatches.length,
            missing: after.missing.length,
            freezeSha: after.freeze.actual,
            freezeExpected: after.freeze.expected,
            beforeFingerprint: before === null ? null : preflight.preimageFingerprint(before),
            afterFingerprint: preflight.preimageFingerprint(after),
            fingerprintStable,
            freezeStable,
            newlyAuthorizedPaths: newFiles,
            newlyAuthorizedPathCount: newFiles.length,
            ledgerCollisions: collisions,
            outsideLedger,
          },
          components: [
            { name: 'preimages_unchanged', oracle: 'all unchanged preimages plus approved S1 replacements reproduce identically', actual: `${after.verified}/${after.itemCount} verified, ${after.mismatches.length} mismatches, ${after.missing.length} missing`, met: after.verified === after.itemCount && after.mismatches.length === 0 && after.missing.length === 0, tier: 'E0' },
            { name: 'freeze_hash_unchanged', oracle: 'final freeze SHA-256 unchanged before and after', actual: `${after.freeze.actual} (expected ${after.freeze.expected})`, met: freezeStable, tier: 'E0' },
            { name: 'new_files_outside_ledger', oracle: 'newly authorized r2/t0 files are outside the old ledger path set', actual: `${newFiles.length} new lane file(s); ledger collisions: ${collisions.length}`, met: outsideLedger, tier: 'E0' },
          ],
          sourceAnchors: ['evidence/w3b-r1/G16-PREIMAGE-LEDGER-20261015.json', 'docs/GOVERNOR-W3B-R2-S1-DISPOSITION-20261015.md'],
          productClaim: false,
          notes: 'Control for the required pre-write gate; the same computation is also the E0 half of H-38.',
        };
      },
    },
  ];
}

module.exports = { id: 'R2-EXTRA', fixtures, STATUS };

async function main(record) {
  for (const def of fixtures()) {
    // eslint-disable-next-line no-await-in-loop
    record(await runFixture(def));
  }
}
module.exports.main = main;
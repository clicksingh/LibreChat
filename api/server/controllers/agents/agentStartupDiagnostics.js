'use strict';

const { createHash } = require('node:crypto');

// These labels describe server-owned phases, never request or model content.
const stages = new Set([
  'initialization',
  'prewarm',
  'run_config',
  'skill_prime',
  'session_seed',
  'execution_conversation',
  'execution_session',
  'file_grants',
  'history_format',
  'skill_injection',
  'token_hydration',
  'memory_history_format',
  'run_create_or_checkpoint',
  'run_create',
  'checkpoint_prune',
  'stream_start',
  'stream_processing',
  'completion_finalize',
]);
const boundedIdentifier = (value, maxLength = 128) =>
  typeof value === 'string' && value.length <= maxLength &&
  /^[A-Za-z0-9_.:/-]+$/.test(value) ? value : null;

function getSafeErrorShape(message) {
  if (typeof message !== 'string') return 'unknown';
  const read = message.match(/^Cannot read propert(?:y|ies) of (?:null|undefined) \(reading ['"]([A-Za-z_$][\w$]{0,63})['"]\)$/);
  if (read) return `null_property_read:${read[1]}`;
  const setting = message.match(/^Cannot set propert(?:y|ies) of (?:null|undefined) \(setting ['"]([A-Za-z_$][\w$]{0,63})['"]\)$/);
  if (setting) return `null_property_write:${setting[1]}`;
  if (/^Maximum call stack size exceeded$/.test(message)) return 'stack_overflow';
  if (/^Cannot convert undefined or null to object$/.test(message)) return 'null_object';
  return 'other';
}

function getSafeStackSite(stack) {
  if (typeof stack !== 'string') return null;
  for (const line of stack.split('\n').slice(1, 16)) {
    const normalized = line.replaceAll('\\', '/');
    const match = normalized.match(/(?:^|\/)((?:api|packages|node_modules)\/[A-Za-z0-9_@./-]+:\d{1,7}:\d{1,6})(?:\)|\s|$)/);
    if (match && match[1].length <= 180 && !match[1].includes('..')) return match[1];
  }
  return null;
}

/**
 * Never emit the exception's raw message, stack, URL, tool inputs, file names,
 * output, credentials, or conversation content. Fingerprints are for grouping
 * incidents, not for reconstructing a confidential exception.
 */
function getAgentStartupFailureDiagnostic(error, { stage, conversationId, runId, streamEntered } = {}) {
  const errorName = boundedIdentifier(error?.name, 64) ?? 'unknown';
  const errorCode = boundedIdentifier(error?.code, 64);
  const rawMessage = typeof error?.message === 'string' ? error.message : '';
  const errorShape = getSafeErrorShape(rawMessage);
  const stackSite = getSafeStackSite(error?.stack);
  const fingerprint = createHash('sha256')
    .update(JSON.stringify([errorName, errorCode, rawMessage, stackSite]))
    .digest('hex')
    .slice(0, 20);

  return {
    conversationId: boundedIdentifier(conversationId),
    runId: boundedIdentifier(runId),
    failureStage: stages.has(stage) ? stage : 'unknown',
    errorName,
    errorCode,
    errorShape,
    stackSite,
    failureFingerprint: fingerprint,
    streamEntered: streamEntered === true,
  };
}

module.exports = { getAgentStartupFailureDiagnostic };

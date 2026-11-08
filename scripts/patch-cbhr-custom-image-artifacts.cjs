'use strict';

/**
 * Scoped compatibility patch for @librechat/agents 3.4.5.
 * The CBHR AI custom endpoint uses the OpenAI Chat transport, but the agent
 * graph excludes it from MCP image-artifact projection. Even with that branch
 * enabled, the default mixed-media character limiter drops a normal 1920x1080
 * screenshot. Allow a bounded 2 MiB projection for this specific endpoint,
 * leaving all other providers and their limits unchanged.
 */
const fs = require('node:fs');
const path = require('node:path');

const EXPECTED_VERSION = '3.4.5';
const ENDPOINT = 'CBHR AI';
const VISION_ARTIFACT_MAX_CHARS = 2 * 1024 * 1024;

const patches = [
  {
    file: 'dist/cjs/graphs/Graph.cjs',
    before:
      'else if (require_llm.isOpenAILike(agentContext.provider) && agentContext.provider !== "deepseek" || require_llm.isGoogleLike(agentContext.provider)) artifactCandidate',
    after:
      'else if (require_llm.isOpenAILike(agentContext.provider) && agentContext.provider !== "deepseek" || require_llm.isGoogleLike(agentContext.provider) || agentContext.provider === "CBHR AI") artifactCandidate',
  },
  {
    file: 'dist/esm/graphs/Graph.mjs',
    before:
      'else if (isOpenAILike(agentContext.provider) && agentContext.provider !== "deepseek" || isGoogleLike(agentContext.provider)) artifactCandidate',
    after:
      'else if (isOpenAILike(agentContext.provider) && agentContext.provider !== "deepseek" || isGoogleLike(agentContext.provider) || agentContext.provider === "CBHR AI") artifactCandidate',
  },
  {
    file: 'dist/cjs/graphs/Graph.cjs',
    before: 'require_core.projectArtifactPayload(finalMessages, maxProviderToolResultChars)',
    after:
      'require_core.projectArtifactPayload(finalMessages, agentContext.provider === "CBHR AI" ? Math.max(maxProviderToolResultChars, 2 * 1024 * 1024) : maxProviderToolResultChars)',
  },
  {
    file: 'dist/esm/graphs/Graph.mjs',
    before: 'projectArtifactPayload(finalMessages, maxProviderToolResultChars)',
    after:
      'projectArtifactPayload(finalMessages, agentContext.provider === "CBHR AI" ? Math.max(maxProviderToolResultChars, 2 * 1024 * 1024) : maxProviderToolResultChars)',
  },
];

function transform(source, patch, verifyOnly = false) {
  const countBefore = source.split(patch.before).length - 1;
  const countAfter = source.split(patch.after).length - 1;
  if (verifyOnly) {
    if (countAfter !== 1 || countBefore !== 0) {
      throw new Error('CBHR image artifact patch absent or ambiguous in ' + patch.file);
    }
    return source;
  }
  if (countAfter === 1 && countBefore === 0) return source;
  if (countBefore !== 1 || countAfter !== 0) {
    throw new Error('Unexpected upstream agent graph projection in ' + patch.file);
  }
  return source.replace(patch.before, patch.after);
}

function run({ verifyOnly = false, root = process.cwd() } = {}) {
  const agentRoot = path.join(root, 'node_modules', '@librechat', 'agents');
  const descriptor = JSON.parse(fs.readFileSync(path.join(agentRoot, 'package.json'), 'utf8'));
  if (descriptor.name !== '@librechat/agents' || descriptor.version !== EXPECTED_VERSION) {
    throw new Error('Unsupported @librechat/agents version: ' + descriptor.version);
  }
  for (const patch of patches) {
    const filePath = path.join(agentRoot, patch.file);
    const before = fs.readFileSync(filePath, 'utf8');
    const after = transform(before, patch, verifyOnly);
    if (after !== before) fs.writeFileSync(filePath, after);
    console.log((verifyOnly ? 'VERIFIED' : 'PATCHED') + ' CBHR custom MCP vision ' + patch.file);
  }
  console.log('CBHR_CUSTOM_IMAGE_ARTIFACT_' + (verifyOnly ? 'VERIFY' : 'PATCH') + '_PASS');
}

if (require.main === module) {
  run({ verifyOnly: process.argv.includes('--verify') });
}

module.exports = {
  EXPECTED_VERSION,
  ENDPOINT,
  VISION_ARTIFACT_MAX_CHARS,
  patches,
  transform,
  run,
};

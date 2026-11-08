'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const patch = require('../../../../../scripts/patch-cbhr-custom-image-artifacts.cjs');

const root = path.resolve(__dirname, '../../../../..');
const agentsRoot = path.join(root, 'node_modules', '@librechat', 'agents');

test('agent vision patch is exact-version-guarded and applies once to CJS and ESM', () => {
  const version = JSON.parse(
    fs.readFileSync(path.join(agentsRoot, 'package.json'), 'utf8'),
  ).version;
  assert.equal(version, patch.EXPECTED_VERSION);

  for (const change of patch.patches) {
    const before = fs.readFileSync(path.join(agentsRoot, change.file), 'utf8');
    const after = patch.transform(before, change);
    assert.ok(after.includes(change.after), change.file);
    assert.ok(!after.includes(change.before), change.file);
    assert.equal(patch.transform(after, change), after, 'idempotent');
    assert.equal(patch.transform(after, change, true), after, 'verify mode');
    assert.throws(
      () => patch.transform('unexpected upstream graph', change),
      /Unexpected upstream/,
    );
  }
});

test('compiled graph admits only CBHR AI along with existing eligible providers', () => {
  const source = fs.readFileSync(path.join(agentsRoot, patch.patches[0].file), 'utf8');
  const updated = patch.patches
    .filter((change) => change.file === patch.patches[0].file)
    .reduce((text, change) => patch.transform(text, change), source);
  const relevantLine = updated
    .split(/\r?\n/)
    .find((line) => line.includes('require_core.projectArtifactPayload(finalMessages,'));
  assert.ok(relevantLine);
  const condition = relevantLine.match(/else if \((.*?)\) artifactCandidate =/);
  assert.ok(condition, 'find compiled graph predicate');
  const eligible = new Function('agentContext', 'require_llm', 'return (' + condition[1] + ')');
  const compat = {
    isOpenAILike: (provider) =>
      ['openai', 'azureOpenAI', 'openrouter', 'xai', 'deepseek'].includes(provider),
    isGoogleLike: (provider) => ['google', 'vertexAI'].includes(provider),
  };
  assert.equal(eligible({ provider: 'CBHR AI' }, compat), true);
  assert.equal(eligible({ provider: 'openai' }, compat), true);
  assert.equal(eligible({ provider: 'google' }, compat), true);
  assert.equal(eligible({ provider: 'deepseek' }, compat), false);
  assert.equal(eligible({ provider: 'untrusted-other-custom' }, compat), false);
});

test('image artifact is preserved as full-resolution model-visible Human content', () => {
  const { AIMessage, ToolMessage, HumanMessage } = require('@librechat/agents/langchain/messages');
  const { projectArtifactPayload } = require(path.join(agentsRoot, 'dist/cjs/messages/core.cjs'));
  const callId = 'capture-screen-proof-001';
  const payload = 'A'.repeat(210000);
  const dataUrl = 'data:image/png;base64,' + payload;

  const messages = [
    new AIMessage({
      content: '',
      tool_calls: [{ id: callId, name: 'capture_screen_mcp_cbhr-pc', args: {}, type: 'tool_call' }],
    }),
    new ToolMessage({
      content: '{"width":1920,"height":1080}',
      tool_call_id: callId,
      artifact: { content: [{ type: 'image_url', image_url: { url: dataUrl } }] },
    }),
  ];
  const bounded = projectArtifactPayload(messages, 10000);
  assert.equal(
    bounded[2].content.filter((part) => part.type === 'image_url').length,
    0,
    'old text-sized cap reproduces omission',
  );
  const projected = projectArtifactPayload(messages, patch.VISION_ARTIFACT_MAX_CHARS);
  assert.equal(projected.length, 3, 'tool image yields trailing Human message');
  assert.ok(projected[2] instanceof HumanMessage);
  assert.ok(Array.isArray(projected[2].content));
  const images = projected[2].content.filter((part) => part.type === 'image_url');
  assert.equal(images.length, 1);
  assert.equal(images[0].image_url.url, dataUrl, 'the full image survives compaction');
  assert.equal(messages[1].artifact.content[0].image_url.url, dataUrl, 'source remains intact');
});

test('Dockerfile patches before bundle and verifies after npm prune', () => {
  const dockerPath = path.join(root, 'Dockerfile');
  if (!fs.existsSync(dockerPath)) {
    // The Docker build intentionally excludes Dockerfile from /app. Runtime
    // acceptance instead verifies both compiled graph formats in place.
    patch.run({ verifyOnly: true, root });
    return;
  }
  const docker = fs.readFileSync(dockerPath, 'utf8');
  const buildIndex = docker.indexOf('npm run frontend');
  const patchIndex = docker.indexOf('node scripts/patch-cbhr-custom-image-artifacts.cjs;');
  const pruneIndex = docker.indexOf('npm prune --production');
  const verifyIndex = docker.indexOf(
    'node scripts/patch-cbhr-custom-image-artifacts.cjs --verify;',
  );
  assert.ok(patchIndex > 0 && patchIndex < buildIndex);
  assert.ok(pruneIndex > buildIndex && verifyIndex > pruneIndex);
});

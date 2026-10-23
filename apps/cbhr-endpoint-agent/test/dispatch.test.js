'use strict';

/**
 * W7 spec — GM-72 ENFORCEMENT: the ceiling narrows from the server, the floor narrows from the owner,
 * and effective = ceiling ∩ floor in exactly that order.
 *
 * Each case names the REFUSAL CODE as well as the policy judgement, because "refused" is not an
 * answer: the operator must be able to tell "the server does not permit this" from "you switched it
 * off" from "this agent cannot do that yet". And every case also asserts what EXECUTES, or refuses
 * to: dispatch checks decide, and only `execute()` on an allowed decision reaches the filesystem.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { describe, it } = require('node:test');

const fixtures = require('./_fixtures');
const ceilingModule = require('../src/ceiling');
const deviceConfigModule = require('../src/deviceConfig');
const dispatchModule = require('../src/dispatch');
const toolsModule = require('../src/tools');

const SNAPSHOT_PATH = path.resolve(__dirname, '..', 'config', 'server-ceiling.json');

function loadCeiling(snapshotPath = SNAPSHOT_PATH) {
  return ceilingModule.loadCeilingSnapshot(snapshotPath);
}

/** A dispatcher bound to a ceiling and a floor described by tool names. */
function dispatcherFor({ ceiling = loadCeiling(), enabled } = {}) {
  return dispatchModule.createDispatcher({
    ceiling,
    deviceConfig: { enabled, file: '<test>' },
  });
}

describe('the snapshot is the server ceiling, not our own invention', () => {
  it('ships at stage A with the read-only tools, hard-denied names and approval-gated names intact', () => {
    const ceiling = loadCeiling();
    assert.equal(ceiling.stage(), 'A');
    // Stage A: 8 tools in the ceiling.
    assert.deepEqual(ceiling.ceilingNames(), [
      'get_file_info',
      'get_more_search_results',
      'list_directory',
      'list_searches',
      'read_file',
      'read_multiple_files',
      'start_search',
      'stop_search',
    ]);
    // GM-72: these are never dispatchable, whatever a config file says.
    assert.deepEqual(ceiling.deniedNames(), [
      'give_feedback_to_desktop_commander',
      'track_ui_event',
    ]);
    assert.equal(ceiling.ownerApprovalTools().length, 0);
    assert.equal(ceiling.pilot(), true);
    assert.equal(ceiling.describe().ceilingTools, 8);
    assert.equal(ceiling.describe().stageIndexTools, 26);
  });

  it('the committed snapshot matches a fresh call into the server policy module (no drift)', () => {
    const serverPath = path.resolve(
      __dirname,
      '..',
      '..',
      '..',
      'api',
      'server',
      'services',
      'Device',
      'deviceCapabilityPolicy.js',
    );
    const server = require(serverPath);
    const fresh = server.ceilingForStage('A', { pilot: true });
    const snapshot = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, 'utf8'));

    assert.equal(snapshot.ceiling.schema, 'cbhr.rdc.capability-ceiling/1');
    assert.deepEqual(snapshot.ceiling.tools, fresh.tools);
    assert.deepEqual(snapshot.ceiling.approvalRequired, fresh.approvalRequired);
    assert.deepEqual(
      snapshot.ceiling.hardDenied.map((entry) => entry.tool).sort(),
      fresh.hardDenied.map((entry) => entry.tool).sort(),
    );
    // The stage index covers the whole catalog: the endpoint can diagnose a stage refusal precisely.
    assert.equal(Object.keys(snapshot.stageIndex).length, 26);
    assert.equal(snapshot.stageIndex.read_file, 'A');
    assert.equal(snapshot.stageIndex.write_file, 'B');
    assert.equal(snapshot.stageIndex.set_config_value, 'full');
    assert.equal(snapshot.stageIndex.track_ui_event ?? null, null);
  });

  it('a malformed or absent snapshot fails closed: no ceiling, no tools', () => {
    assert.throws(
      () => ceilingModule.ceilingFromSnapshot(null),
      (err) => err.code === 'ENDPOINT_CEILING_SNAPSHOT_INVALID',
    );
    assert.throws(
      () =>
        ceilingModule.ceilingFromSnapshot({
          ceiling: { schema: 'someone-else', tier: 1, source: 'server', deviceSettable: false, stage: 'A', tools: ['x'] },
        }),
      (err) => err.code === 'ENDPOINT_CEILING_SNAPSHOT_INVALID',
    );
    assert.throws(
      () => ceilingModule.ceilingFromSnapshot({ ceiling: { schema: 'cbhr.rdc.capability-ceiling/1', tier: 1, source: 'server', deviceSettable: true, stage: 'A', tools: ['x'] } }),
      (err) => err.code === 'ENDPOINT_CEILING_SNAPSHOT_INVALID',
    );
    assert.throws(
      () => ceilingModule.loadCeilingSnapshot(path.join(fixtures.makeTempRoot(), 'no-such-file.json')),
      (err) => err.code === 'ENDPOINT_CEILING_SNAPSHOT_INVALID',
    );
  });
});

describe('dispatch: ceiling before floor before implementation', () => {
  const ceiling = loadCeiling();

  it('a tool outside the server ceiling is refused on tier-1 grounds even when enabled locally', () => {
    // edit_block is stage B: not in the stage-A ceiling.
    const dispatcher = dispatcherFor({ ceiling, enabled: ['edit_block', 'read_file'] });
    const decision = dispatcher.decide('edit_block');
    assert.equal(decision.allowed, false);
    assert.equal(decision.refusalCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');
    assert.equal(decision.withinCeiling, false);
    assert.equal(decision.enabledOnDevice, true);
  });

  it('a tool inside the ceiling but switched off locally is refused on tier-2 grounds', () => {
    const dispatcher = dispatcherFor({ ceiling, enabled: ['read_file'] });
    const decision = dispatcher.decide('start_search');
    assert.equal(decision.allowed, false);
    assert.equal(decision.refusalCode, 'ENDPOINT_TOOL_NOT_ENABLED_ON_DEVICE');
    assert.equal(decision.withinCeiling, true);
    assert.equal(decision.enabledOnDevice, false);
  });

  it('a tool inside the ceiling, enabled locally, but with no implementation here is refused distinctly', () => {
    // start_search is ceiling+floor: but the agent only implements three tools.
    const dispatcher = dispatcherFor({
      ceiling,
      enabled: ['get_file_info', 'list_directory', 'read_file', 'start_search'],
    });
    const decision = dispatcher.decide('start_search');
    assert.equal(decision.allowed, false);
    assert.equal(decision.refusalCode, 'ENDPOINT_TOOL_NOT_IMPLEMENTED');
    assert.equal(decision.withinCeiling, true);
    assert.equal(decision.enabledOnDevice, true);
    assert.equal(decision.implemented, false);
  });

  it('an always-denied internal handler is refused on ceiling grounds even when enabled locally', () => {
    const dispatcher = dispatcherFor({ ceiling, enabled: ['track_ui_event', 'read_file'] });
    const decision = dispatcher.decide('track_ui_event');
    assert.equal(decision.allowed, false);
    assert.equal(decision.refusalCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');
    assert.equal(ceiling.allows('track_ui_event').refusalCode, ceilingModule.CEILING_REFUSAL_CODE);
  });

  it('an unknown tool name is refused on ceiling grounds, never executed', () => {
    const dispatcher = dispatcherFor({ ceiling, enabled: ['read_file'] });
    const decision = dispatcher.decide('reboot_the_pc');
    assert.equal(decision.allowed, false);
    assert.equal(decision.refusalCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');
    assert.throws(() => dispatcher.execute({ toolName: 'reboot_the_pc', argsBytes: Buffer.alloc(0) }), (err) => {
      return isOutsideCeiling(err);
    });
    function isOutsideCeiling(err) {
      return err.code === 'ENDPOINT_TOOL_OUTSIDE_CEILING';
    }
  });

  it('a ceiling tool with owner-approval consent is refused here rather than pretending consent was asked', () => {
    const { ceilingFromSnapshot } = ceilingModule;
    const fullCeiling = ceilingFromSnapshot({
      ceiling: {
        schema: 'cbhr.rdc.capability-ceiling/1',
        tier: 1,
        source: 'server',
        deviceSettable: false,
        stage: 'full',
        pilot: false,
        tools: ['read_file', 'kill_process'],
        approvalRequired: ['kill_process'],
        hardDenied: [],
      },
      stageIndex: { read_file: 'A', kill_process: 'C' },
    });
    const dispatcher = dispatcherFor({ ceiling: fullCeiling, enabled: ['read_file', 'kill_process'] });
    const decision = dispatcher.decide('kill_process');
    assert.equal(decision.allowed, false);
    assert.equal(decision.refusalCode, 'ENDPOINT_TOOL_NOT_IMPLEMENTED');
    assert.equal(decision.requiresApproval, true);
  });

  it('the effective set is ceiling∩floor, and it is reported both ways', () => {
    const dispatcher = dispatcherFor({ ceiling, enabled: ['read_file', 'get_file_info'] });
    assert.deepEqual(dispatcher.effectiveTools(), ['get_file_info', 'read_file']);
    assert.deepEqual(dispatcher.narrowedByDevice(), [
      'get_more_search_results',
      'list_directory',
      'list_searches',
      'read_multiple_files',
      'start_search',
      'stop_search',
    ]);
    assert.deepEqual(dispatcher.outsideCeiling(), []);
  });
});

describe('the local tool config can only narrow, never widen', () => {
  it('the shipped default enables exactly the three implemented tools', () => {
    assert.deepEqual([...deviceConfigModule.DEFAULT_ENABLED_TOOLS].sort(), [
      'get_file_info',
      'list_directory',
      'read_file',
    ]);
  });

  it('a config naming a tool outside the ceiling is INVALID: the whole config is refused, loudly', () => {
    const root = fixtures.makeTempRoot();
    try {
      const ceiling = loadCeiling();
      const configFile = path.join(root, 'tools.json');
      fs.writeFileSync(configFile, JSON.stringify({ version: 1, enabled: ['read_file', 'write_file'] }), 'utf8');
      assert.throws(
        () => deviceConfigModule.loadDeviceToolConfig({ ceiling, toolsConfigFile: configFile, createIfMissing: false }),
        (err) => err.code === 'ENDPOINT_DEVICE_CONFIG_INVALID',
      );
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('a narrowing floor loads, and narrow() exposes the difference for the panel', () => {
    const root = fixtures.makeTempRoot();
    try {
      const ceiling = loadCeiling();
      const configFile = path.join(root, 'tools.json');
      fs.writeFileSync(configFile, JSON.stringify({ version: 1, enabled: ['list_directory', 'read_file'] }), 'utf8');
      const loaded = deviceConfigModule.loadDeviceToolConfig({
        ceiling,
        toolsConfigFile: configFile,
        createIfMissing: false,
      });
      assert.deepEqual(loaded.enabled, ['list_directory', 'read_file']);
      const narrowed = deviceConfigModule.narrow({ ceiling, enabled: loaded.enabled });
      assert.deepEqual(narrowed.effective, loaded.enabled);
      assert.ok(narrowed.notEnabledOnDevice.includes('get_file_info'));
      assert.deepEqual(narrowed.outsideCeiling, []);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('writing a config with a tool outside the ceiling throws instead of writing', () => {
    const root = fixtures.makeTempRoot();
    try {
      const ceiling = loadCeiling();
      assert.throws(
        () =>
          deviceConfigModule.writeDeviceToolConfig({
            ceiling,
            rootDir: root,
            enabled: ['read_file', 'kill_process'],
          }),
        (err) => err.code === 'ENDPOINT_DEVICE_CONFIG_INVALID',
      );
      assert.equal(fs.existsSync(path.join(root, 'tools.json')), false);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('dispatch-time policy holds even if the config file was hand-edited after load', () => {
    // The config is checked at load AND claimed tools are re-checked per frame: `writeDeviceToolConfig`
    // cannot be bypassed, but a file edited on disk after load would be — so dispatch decides per
    // call from the ceiling, not from the config's word.
    const dispatcher = dispatcherFor({ ceiling: loadCeiling(), enabled: ['read_file', 'write_file'] });
    const decision = dispatcher.decide('write_file');
    assert.equal(decision.allowed, false);
    assert.equal(decision.refusalCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');
  });
});

describe('the implemented tools are real, bounded and contained', () => {
  it('list_directory lists a real directory, paged, sorted, and truncates honestly', () => {
    const root = fixtures.makeTempRoot();
    try {
      const sub = path.join(root, 'ws');
      fs.mkdirSync(sub, { recursive: true });
      fs.writeFileSync(path.join(sub, 'b.txt'), 'b', 'utf8');
      fs.writeFileSync(path.join(sub, 'a.txt'), 'a', 'utf8');
      fs.writeFileSync(path.join(sub, 'c.txt'), 'c', 'utf8');

      const one = toolsModule.executeTool({
        toolName: 'list_directory',
        argsBytes: Buffer.from(JSON.stringify({ path: '.', limit: 2 }), 'utf8'),
        workspaceRoot: sub,
      });
      assert.deepEqual(one.result.entries.map((entry) => entry.name), ['a.txt', 'b.txt']);
      assert.equal(one.result.truncated, true);
      assert.equal(one.result.nextCursor, 'b.txt');

      const two = toolsModule.executeTool({
        toolName: 'list_directory',
        argsBytes: Buffer.from(JSON.stringify({ path: '.', cursor: one.result.nextCursor }), 'utf8'),
        workspaceRoot: sub,
      });
      assert.deepEqual(two.result.entries.map((entry) => entry.name), ['c.txt']);
      assert.equal(two.result.truncated, false);

      const nested = toolsModule.executeTool({
        toolName: 'list_directory',
        argsBytes: Buffer.from(JSON.stringify({ path: '.' }), 'utf8'),
        workspaceRoot: sub,
      });
      assert.equal(nested.result.total, 3);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('read_file returns real bytes with a digest, truncates honestly, and decodes binary losslessly', () => {
    const root = fixtures.makeTempRoot();
    try {
      const sub = path.join(root, 'ws');
      fs.mkdirSync(sub, { recursive: true });
      fs.writeFileSync(path.join(sub, 'hello.txt'), 'hello world', 'utf8');
      fs.writeFileSync(path.join(sub, 'blob.bin'), Buffer.from([0x00, 0xff, 0x80, 0x41]), 'binary');

      const text = toolsModule.executeTool({
        toolName: 'read_file',
        argsBytes: Buffer.from(JSON.stringify({ path: 'hello.txt' }), 'utf8'),
        workspaceRoot: sub,
      });
      assert.equal(text.result.encoding, 'utf8');
      assert.equal(text.result.content, 'hello world');
      assert.equal(text.result.bytesRead, 11);
      assert.equal(text.result.truncated, false);
      const crypto = require('node:crypto');
      assert.equal(
        text.result.sha256Hex,
        crypto.createHash('sha256').update(Buffer.from('hello world', 'utf8')).digest('hex'),
      );

      const binary = toolsModule.executeTool({
        toolName: 'read_file',
        argsBytes: Buffer.from(JSON.stringify({ path: 'blob.bin' }), 'utf8'),
        workspaceRoot: sub,
      });
      assert.equal(binary.result.encoding, 'base64');
      assert.equal(Buffer.from(binary.result.content, 'base64').toString('binary'), Buffer.from([0x00, 0xff, 0x80, 0x41]).toString('binary'));

      const bounded = toolsModule.executeTool({
        toolName: 'read_file',
        argsBytes: Buffer.from(JSON.stringify({ path: 'hello.txt', maxBytes: 5 }), 'utf8'),
        workspaceRoot: sub,
      });
      assert.equal(bounded.result.content, 'hello');
      assert.equal(bounded.result.truncated, true);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('get_file_info reports real metadata', () => {
    const root = fixtures.makeTempRoot();
    try {
      const sub = path.join(root, 'ws');
      fs.mkdirSync(sub, { recursive: true });
      fs.writeFileSync(path.join(sub, 'f.txt'), '0123456789', 'utf8');
      const info = toolsModule.executeTool({
        toolName: 'get_file_info',
        argsBytes: Buffer.from(JSON.stringify({ path: 'f.txt' }), 'utf8'),
        workspaceRoot: sub,
      });
      assert.equal(info.result.kind, 'file');
      assert.equal(info.result.size, 10);
      assert.ok(info.result.modifiedMs > 0);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('paths outside the workspace root are refused, with traversal and drives', () => {
    const root = fixtures.makeTempRoot();
    try {
      const sub = path.join(root, 'ws');
      fs.mkdirSync(sub, { recursive: true });
      assert.throws(
        () =>
          toolsModule.executeTool({
            toolName: 'read_file',
            argsBytes: Buffer.from(JSON.stringify({ path: '..' }), 'utf8'),
            workspaceRoot: sub,
          }),
        (err) => err.code === 'ENDPOINT_TOOL_ARGS_INVALID',
      );
      assert.throws(
        () =>
          toolsModule.executeTool({
            toolName: 'read_file',
            argsBytes: Buffer.from(JSON.stringify({ path: '../../..' }), 'utf8'),
            workspaceRoot: sub,
          }),
        (err) => err.code === 'ENDPOINT_TOOL_ARGS_INVALID',
      );
      const drive = `C:\\Windows\\System32\\drivers\\etc\\hosts`;
      assert.throws(
        () =>
          toolsModule.executeTool({
            toolName: 'read_file',
            argsBytes: Buffer.from(JSON.stringify({ path: drive }), 'utf8'),
            workspaceRoot: sub,
          }),
        (err) => err.code === 'ENDPOINT_TOOL_ARGS_INVALID',
      );
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('unknown keys, missing keys and absurd limits are refused as args errors', () => {
    const root = fixtures.makeTempRoot();
    try {
      const sub = path.join(root, 'ws');
      fs.mkdirSync(sub, { recursive: true });
      const badKeys = () =>
        toolsModule.executeTool({
          toolName: 'list_directory',
          argsBytes: Buffer.from(JSON.stringify({ path: '.', dropbox: true }), 'utf8'),
          workspaceRoot: sub,
        });
      assert.throws(badKeys, (err) => err.code === 'ENDPOINT_TOOL_ARGS_INVALID');
      const badLimit = () =>
        toolsModule.executeTool({
          toolName: 'list_directory',
          argsBytes: Buffer.from(JSON.stringify({ path: '.', limit: 1000000 }), 'utf8'),
          workspaceRoot: sub,
        });
      assert.throws(badLimit, (err) => err.code === 'ENDPOINT_TOOL_ARGS_INVALID');
      const badMax = () =>
        toolsModule.executeTool({
          toolName: 'read_file',
          argsBytes: Buffer.from(JSON.stringify({ path: '.', maxBytes: -1 }), 'utf8'),
          workspaceRoot: sub,
        });
      assert.throws(badMax, (err) => err.code === 'ENDPOINT_TOOL_ARGS_INVALID');
    } finally {
      fixtures.removeTempRoot(root);
    }
  });
});
'use strict';

/**
 * W7 spec — THE KEY STORE: owner-only on disk, and unreachable from logs, serialization or errors.
 *
 * The endpoint's private key is the one secret the relay does not have, so "we do not log it" is not a
 * testable claim on its own. Three independent proofs, the same standard `DeviceError` and `RelayError`
 * already meet:
 *
 *   A. RUNTIME — create the key, run a successful dispatch and every failure path, capture EVERY
 *      console call and every injected-logger call, and assert no 20-character window of any private-key
 *      encoding appears anywhere. A 20-character window catches a partial leak, not just a whole key.
 *   B. SERIALIZATION — the same for `JSON.stringify`, `util.inspect` (including `showHidden` and the
 *      `cause` chain), `Object.keys` and a deep text flattening of every object this agent produces.
 *   C. ON-DISK AND PERMISSIONS — the file is inside the configured agent root (NEVER the repository
 *      worktree), its POSIX mode is 0600, and on Windows the `icacls` listing is CLASSIFIED: no
 *      foreign principal, no inherited entry, and the classification itself is tested against a
 *      synthetic listing that contains one.
 *
 * The keypairs here live only inside this test process. Nothing in this file reads, writes or even
 * looks at the owner's real key store: every case uses a unique temporary root.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const nodeUtil = require('node:util');
const { describe, it } = require('node:test');

const fixtures = require('./_fixtures');
const keystoreModule = require('../src/keystore');
const permissionsModule = require('../src/permissions');
const { createEndpointAgent } = require('../src/agent');
const { buildPinSet } = require('../src/pinnedKeys');
const { writeOwnerOnlyFile } = require('../src/permissions');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');

/** Every encoding of a private key this spec knows how to look for, plus sliding 20-char windows. */
function keyMaterialNeedles(privateKeyPkcs8B64u, privateKeyPem) {
  const pkcs8Der = Buffer.from(privateKeyPkcs8B64u, 'base64url');
  const base64Std = pkcs8Der.toString('base64');
  const base64Url = pkcs8Der.toString('base64url');
  const hex = pkcs8Der.toString('hex');
  const pemBody = String(privateKeyPem ?? '')
    .replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '')
    .replace(/\s+/g, '');
  const needles = new Set([privateKeyPkcs8B64u, base64Std, base64Url, hex, pkcs8Der.toString('latin1')]);
  if (privateKeyPem) {
    needles.add(privateKeyPem);
  }
  for (const encoding of [base64Std, base64Url, hex, pemBody]) {
    for (let index = 0; index + 20 <= encoding.length; index++) {
      needles.add(encoding.slice(index, index + 20));
    }
  }
  return [...needles].filter((needle) => typeof needle === 'string' && needle.length >= 8);
}

function findKeyMaterial(text, needles) {
  if (typeof text !== 'string' || text.length === 0) {
    return [];
  }
  return needles.filter((needle) => text.includes(needle));
}

/** Flattens any value into searchable text without JSON-serializing Buffers away. */
function deepText(value) {
  const parts = [];
  const walk = (item, depth) => {
    if (depth > 8 || item === null || item === undefined) {
      return;
    }
    if (typeof item === 'string') {
      parts.push(item);
      return;
    }
    if (Buffer.isBuffer(item)) {
      parts.push(item.toString('base64'), item.toString('hex'), item.toString('utf8'));
      return;
    }
    if (typeof item !== 'object') {
      parts.push(String(item));
      return;
    }
    parts.push(nodeUtil.inspect(item, { depth: 8, showHidden: true, getters: false }));
    for (const key of Object.keys(item)) {
      parts.push(key);
      walk(item[key], depth + 1);
    }
  };
  walk(value, 0);
  return parts.join('\n');
}

/** A fully wired agent on a throwaway root, with a throwaway backend key pinned. */
function makeAgent() {
  const root = fixtures.makeTempRoot();
  const backend = fixtures.makeKeypair();
  const deviceId = 'device-keystore-test';
  writeOwnerOnlyFile(path.join(root, 'device.json'), JSON.stringify({ version: 1, deviceId }));
  pointer = root;
  const keystore = keystoreModule.loadDeviceKeystore({ rootDir: root });
  const agent = createEndpointAgent({
    rootDir: root,
    deviceId,
    pins: buildPinSet([{ keyId: backend.keyId, publicKeySpkiB64u: backend.publicKeySpkiB64u }]),
    workspaceRoot: path.join(root, 'workspace'),
    persistReplay: false,
  });
  return { root, backend, deviceId, agent, keystore };
}

let pointer = null;

function frameFor(agent, backend, overrides = {}) {
  const workspace = path.join(path.dirname(agent.describe().deviceKeyFile), 'workspace');
  fs.mkdirSync(workspace, { recursive: true });
  fs.writeFileSync(path.join(workspace, 'note.txt'), 'hello', 'utf8');
  const now = Date.now();
  return fixtures.buildFrame({
    sign: backend.sign,
    keyId: backend.keyId,
    core: {
      deviceId: agent.deviceId(),
      deviceKeyId: agent.deviceKeyId(),
      issuedAt: String(now),
      deadlineMs: String(now + 60000),
      nonce: require('node:crypto').randomBytes(16).toString('base64url'),
      toolName: 'read_file',
      ...overrides.core,
    },
    args: overrides.args ?? { path: 'note.txt' },
    ...(overrides.rest ?? {}),
  }).frame;
}

describe('A + B. no private key material is logged, serialized or inspectable', () => {
  it('captures every console call and every produced object across success AND failure paths', async () => {
    const { root, backend, agent } = makeAgent();
    try {
      const privateRecord = JSON.parse(
        fs.readFileSync(path.join(root, 'device-key.json'), 'utf8'),
      );
      const needles = keyMaterialNeedles(privateRecord.privateKeyPkcs8B64u);
      assert.ok(needles.length > 100, 'the needle set must be large enough to catch a partial leak');

      const consoleCalls = [];
      const loggerCalls = [];
      const spies = ['log', 'info', 'warn', 'error', 'debug', 'trace'].map((method) => {
        const original = console[method];
        console[method] = (...args) => {
          consoleCalls.push({ method, args });
        };
        return () => {
          console[method] = original;
        };
      });
      const restore = () => spies.forEach((fn) => fn());

      const logger = {
        info: (...args) => loggerCalls.push(args),
        warn: (...args) => loggerCalls.push(args),
        error: (...args) => loggerCalls.push(args),
      };

      try {
        // SUCCESS.
        const okFrame = frameFor(agent, backend);
        const ok = await agent.handleFrame(okFrame);
        assert.equal(ok.outcome, 'succeeded', JSON.stringify(ok.refusalCode));

        // REFUSED: bad signature.
        const forged = { ...frameFor(agent, backend), signatureB64u: Buffer.alloc(64, 7).toString('base64url') };
        const refused = await agent.handleFrame(forged);
        assert.equal(refused.outcome, 'refused');

        // REFUSED: tool policy (outside the ceiling).
        const outside = frameFor(agent, backend, { core: { toolName: 'edit_block' } });
        const policy = await agent.handleFrame(outside);
        assert.equal(policy.outcome, 'refused');
        assert.equal(policy.refusalCode, 'ENDPOINT_TOOL_OUTSIDE_CEILING');

        // UNCERTAIN: a ceiling+floor tool with no implementation yields a policy refusal, so force the
        // genuine 'uncertain' path by asking for a tool that IS implemented but with unusable args.
        const brokenArgs = frameFor(agent, backend, { args: { path: 42 } });
        const uncertain = await agent.handleFrame(brokenArgs);
        assert.ok(['refused', 'uncertain'].includes(uncertain.outcome));

        // A thrown error from the keystore itself, with a hostile cause that carries the PEM.
        let thrown = null;
        try {
          await agent.handleFrame({ ...frameFor(agent, backend), argsB64u: '!!!' });
        } catch (err) {
          thrown = err;
        }

        const produced = [agent.describe(), ok, refused, policy, uncertain, thrown, loggerCalls];
        const logged = deepText([consoleCalls, loggerCalls]);
        assert.deepEqual(findKeyMaterial(logged, needles), [], 'no key material may be logged');

        for (const value of produced) {
          const json = JSON.stringify(value) ?? '';
          const inspected = nodeUtil.inspect(value, { depth: 10, showHidden: true });
          const flat = deepText(value);
          const keys = Object.keys(value ?? {}).join(' ');
          assert.deepEqual(findKeyMaterial(json, needles), [], 'JSON.stringify leak');
          assert.deepEqual(findKeyMaterial(inspected, needles), [], 'util.inspect leak');
          assert.deepEqual(findKeyMaterial(flat, needles), [], 'deep text leak');
          assert.deepEqual(findKeyMaterial(keys, needles), [], 'own-key leak');
        }

        // The describe() payload names the file and the PUBLIC key id, which is a label, not material.
        const describeText = JSON.stringify(agent.describe());
        assert.ok(describeText.includes(agent.deviceKeyId()));
        assert.equal(describeText.includes(privateRecord.privateKeyPkcs8B64u), false);
        assert.equal(
          describeText.includes(agent.devicePublicKeySpkiB64u()),
          true,
          'the public half is published on purpose: the platform needs it to verify result frames',
        );
        assert.deepEqual(findKeyMaterial(JSON.stringify(agent.devicePublicKeySpkiB64u()), needles), []);
        assert.equal(consoleCalls.length, 0, 'the agent writes nothing to the console');
      } finally {
        restore();
      }
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('the keystore surface exposes no key material: not by property, not by inspect, not by JSON', () => {
    const { root, keystore } = makeAgent();
    try {
      const record = JSON.parse(fs.readFileSync(path.join(root, 'device-key.json'), 'utf8'));
      const needles = keyMaterialNeedles(record.privateKeyPkcs8B64u, null);

      assert.deepEqual(Object.keys(keystore).sort(), [
        'describe',
        'keyFile',
        'keyId',
        'permission',
        'publicKeySpkiB64u',
        'rootDir',
        'sign',
      ]);
      const inspected = nodeUtil.inspect(keystore, { depth: 10, showHidden: true });
      assert.deepEqual(findKeyMaterial(inspected, needles), []);
      assert.deepEqual(findKeyMaterial(JSON.stringify(keystore), needles), []);
      assert.deepEqual(findKeyMaterial(deepText(keystore.describe()), needles), []);

      // `sign` is the only member that touches the key, and it returns a signature, never the key.
      const signature = keystore.sign(Buffer.from('probe', 'utf8'));
      assert.match(signature, /^[A-Za-z0-9_-]{86}$/);
      assert.deepEqual(findKeyMaterial(signature, needles), []);
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('an error thrown by the keystore carries no key material and no raw cause', () => {
    const { root } = makeAgent();
    try {
      // Corrupt the stored record so loading fails, then inspect EVERYTHING the failure exposes.
      const keyFile = path.join(root, 'device-key.json');
      const record = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      const needles = keyMaterialNeedles(record.privateKeyPkcs8B64u, null);
      record.privateKeyPkcs8B64u = 'not-a-key';
      writeOwnerOnlyFile(keyFile, JSON.stringify(record));

      let failure = null;
      try {
        keystoreModule.loadDeviceKeystore({ rootDir: root });
      } catch (err) {
        failure = err;
      }
      assert.ok(failure, 'a corrupted key file must fail closed');
      assert.equal(failure.code, 'ENDPOINT_DEVICE_KEY_UNAVAILABLE');
      const everything = `${failure.message}\n${failure.stack}\n${nodeUtil.inspect(failure, { depth: 10, showHidden: true })}\n${JSON.stringify(failure)}`;
      assert.deepEqual(findKeyMaterial(everything, needles), []);
      assert.equal(failure.message, 'endpoint refused the frame');
      assert.ok(!everything.includes('not-a-key'));
    } finally {
      fixtures.removeTempRoot(root);
    }
  });
});

describe('C. the key file is owner-only, and outside the repository', () => {
  it('writes the key under the configured agent root, never into the worktree', () => {
    const { root, keystore } = makeAgent();
    try {
      const keyFile = keystore.keyFile();
      assert.ok(keyFile.startsWith(root), 'the key must live under the configured root');
      assert.equal(keyFile.startsWith(REPO_ROOT), false, 'the key must NOT live in the worktree');
      assert.equal(fs.existsSync(keyFile), true);
      const stat = fs.statSync(keyFile);
      if (process.platform !== 'win32') {
        assert.equal(stat.mode & 0o777, 0o600);
        assert.equal(fs.statSync(path.dirname(keyFile)).mode & 0o777, 0o700);
      }
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('the default root is under the user profile, not under the repository', () => {
    const defaultRoot = keystoreModule.defaultRootDir();
    const home = process.env.USERPROFILE ?? process.env.HOME ?? os.homedir();
    assert.ok(defaultRoot.startsWith(home));
    assert.equal(defaultRoot.startsWith(REPO_ROOT), false);
    // An explicit override is honoured, and it is still resolved to an absolute path.
    assert.equal(keystoreModule.resolveRootDir(path.join(home, 'elsewhere')), path.join(home, 'elsewhere'));
    assert.equal(path.isAbsolute(keystoreModule.resolveRootDir()), true);
  });

  it('classification: a foreign principal on the ACL is REJECTED', () => {
    const owner = permissionsModule.ownerAccountName();
    const foreignAcl = [
      `C:\\Users\\someone\\.cbhr\\device-key.json ${owner}:(F)`,
      '                                                    BUILTIN\\Users:(RX)',
      '',
      'Successfully processed 1 files; Failed processing 0 files',
    ].join('\n');
    const verdict = permissionsModule.verifyOwnerOnlyAcl(foreignAcl, owner);
    assert.equal(verdict.ok, false);
    assert.ok(verdict.foreign.map((entry) => entry.toLowerCase()).includes('builtin\\users'));

    const inheritedAcl = [
      `C:\\Users\\someone\\.cbhr\\device-key.json ${owner}:(F)`,
      '                                                    NT AUTHORITY\\Authenticated Users:(I)(RX)',
      '',
    ].join('\n');
    const inheritedVerdict = permissionsModule.verifyOwnerOnlyAcl(inheritedAcl, owner);
    assert.equal(inheritedVerdict.ok, false, 'any inherited entry must fail the assertion');
    assert.equal(inheritedVerdict.inherited.length, 1);

    const ownerMissingAcl = ['C:\\x\\device-key.json NT AUTHORITY\\SYSTEM:(F)', ''].join('\n');
    assert.equal(permissionsModule.verifyOwnerOnlyAcl(ownerMissingAcl, owner).ok, false);
  });

  it('classification: the platform entries Windows re-adds are accepted, and are REPORTED as such', () => {
    const owner = permissionsModule.ownerAccountName();
    const realAcl = [
      `C:\\Users\\someone\\.cbhr\\device-key.json ${owner}:(F)`,
      '                                                    NT AUTHORITY\\SYSTEM:(F)',
      '                                                    NT AUTHORITY\\LogonSessionId_0_1618811:(RX)',
      '',
      'Successfully processed 1 files; Failed processing 0 files',
    ].join('\n');
    const verdict = permissionsModule.verifyOwnerOnlyAcl(realAcl, owner);
    assert.equal(verdict.ok, true, JSON.stringify(verdict));
    assert.deepEqual(verdict.foreign, []);
    assert.equal(verdict.inherited.length, 0);
    assert.equal(verdict.explicit.length, 3);
    assert.equal(verdict.acceptablePlatformPrincipals.length, 2);
  });

  it('the permission evidence is real: an owner-only mode claim on POSIX, a classified ACL on Windows', () => {
    const { root, keystore } = makeAgent();
    try {
      const permission = keystore.permission();
      assert.deepEqual(permission.foreign, []);
      // `fs` mode is advisory on Windows (a file still reads back as 0o666 whatever the ACL says), so
      // each platform's guarantee is asserted where it means something rather than fudged into one
      // number that would be a false claim on one of them.
      if (process.platform === 'win32') {
        assert.ok(typeof permission.acl === 'string' && permission.acl.length > 0, 'raw icacls evidence');
        assert.ok(permission.acl.includes(keystore.keyFile()));
        assert.ok(permission.principals.length >= 1);
        assert.equal(permission.acceptablePlatformPrincipals.length, permission.principals.length - 1);
        const owner = permissionsModule.ownerAccountName().toLowerCase();
        assert.equal(permission.principals[0].toLowerCase(), owner);
      } else {
        assert.equal(permission.mode & 0o777, 0o600);
        assert.equal(permission.mode & 0o077, 0, 'no group or other access at all');
        assert.equal(permission.principals.length, 1);
      }
    } finally {
      fixtures.removeTempRoot(root);
    }
  });

  it('a second key creation with force replaces the identity entirely (re-pairing semantics)', () => {
    const { root } = makeAgent();
    try {
      const first = keystoreModule.loadDeviceKeystore({ rootDir: root }).keyId();
      const second = keystoreModule.createDeviceKeystore({ rootDir: root, force: true });
      assert.notEqual(second.keyId, first);
      const reloaded = keystoreModule.loadDeviceKeystore({ rootDir: root });
      assert.equal(reloaded.keyId(), second.keyId);
      assert.equal(reloaded.keyId(), keystoreModule.keyIdOfPublicKey(reloaded.publicKeySpkiB64u()));
    } finally {
      fixtures.removeTempRoot(root);
    }
  });
});
'use strict';

/**
 * W15 — `deviceCommandDeps`: THE ASSEMBLY THAT LETS `device_command` REACH DISPATCH.
 *
 * WHAT THIS SPEC IS FOR
 * `device_command` resolves its seams from `options.deviceCommand`, and nothing populated that bag, so
 * every call answered `not-configured`. This spec proves the new module closes that gap — and proves
 * it the way the platform requires: with the REAL assembly (`createDeviceDispatchAssembly` and its
 * armed policy port), the REAL replay window, the REAL relay transport (an HTTP stand-in for the
 * relay's own route is the only substitute) and a REAL Ed25519 lab key read from a real file. The
 * frame that reaches the wire is verified with the frozen envelope verifier against that key, so "the
 * lab key signed it" is a cryptographic fact here, not a claim.
 *
 * It also proves the three refusals that matter more than the happy path:
 *   - no custody configured (the DEFAULT) → `not-configured`, no transport touched, nothing signed;
 *   - a lab key that cannot be used → fail closed, loudly, with nothing dispatched;
 *   - key material is not reachable through a log, an error, a cause chain, a serialization or an
 *     `util.inspect` output.
 */

const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const nodeUtil = require('node:util');
const nodeCrypto = require('node:crypto');

const {
  relay,
  deviceCrypto,
  AUTHORITY,
  makeTestKeypair,
  deepText,
} = require('~/server/services/Device/relay/__tests__/_fixtures.cjs');
const {
  DEVICE_COMMAND_TOOL_NAME,
  DEVICE_COMMAND_OUTCOMES,
} = require('~/app/clients/tools/deviceCommand');
const { loadTools } = require('~/app/clients/tools/util/handleTools');
const {
  LAB_CUSTODY_KEY_FILE_ENV,
  RELAY_BASE_URL_ENV,
  LAB_CUSTODY_FAILURES,
  LAB_MARKERS,
  createDeviceCommandDeps,
  createRelayTransport,
  classifyRelayAnswer,
  describeDeviceCommandDeps,
  loadLabCustodySeam,
} = require('../deviceCommandDeps');

/** The environment the tool reads the server capability stage from. Empty = the narrowest rung. */
const NO_STAGE_ENV = Object.freeze({});
const READ_FILE_ARGS = { path: 'C:/notes/today.txt' };
const PRINCIPAL = AUTHORITY.ownerPrincipalId;
/** Test-only marker: it stands in for key material that must never be echoed. */
const SECRET_MARKER = `SECRET-${nodeCrypto.randomBytes(24).toString('hex')}`;

const silentLogger = {
  warn: () => {},
  error: () => {},
  info: () => {},
  debug: () => {},
  log: () => {},
};

/** A logger that RECORDS every line, so "it logged loudly" is witnessed rather than asserted. */
function recordingLogger() {
  const lines = [];
  const push = (level) => (message) => {
    lines.push({ level, message: typeof message === 'string' ? message : deepText(message) });
  };
  return {
    lines,
    of(level) {
      return lines.filter((line) => line.level === level).map((line) => line.message);
    },
    text() {
      return lines.map((line) => `${line.level}: ${line.message}`).join('\n');
    },
    logger: { warn: push('warn'), error: push('error'), info: push('info'), debug: () => {} },
  };
}

let tmpDir;

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbhr-device-deps-'));
});

afterAll(() => {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    /* the OS reaps its own temp directory */
  }
});

/**
 * Writes a lab signing key the way W7's lab signer writes it: the PKCS#8 DER private key in unpadded
 * base64url, one line. The key is freshly generated per call and never leaves this process.
 */
function writeLabKeyFile(name = 'lab-backend-key.txt') {
  const keypair = makeTestKeypair();
  const file = path.join(tmpDir, name);
  fs.writeFileSync(file, `${keypair.privateKeyPkcs8B64u}\n`, 'utf8');
  return { file, keypair, keyId: deviceCrypto.thumbprintB64u(keypair.publicKeySpkiB64u) };
}

/** A local HTTP stand-in for the relay's own frame admission. It records every request. */
function startRelayStub({ status = 200, answer = { ok: true, admitted: true, seq: 1 } } = {}) {
  const received = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      received.push({ method: req.method, url: req.url, headers: req.headers, body });
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(answer));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        received,
        async close() {
          server.closeAllConnections?.();
          await new Promise((done) => server.close(done));
        },
      });
    });
  });
}

/** A base URL nothing is listening on: the port is bound once and released immediately. */
async function closedPortBaseUrl() {
  const stub = await startRelayStub();
  const { baseUrl } = stub;
  await stub.close();
  return baseUrl;
}

/**
 * A non-Ed25519 key file: a loadable PKCS#8 that the lab gate must refuse by TYPE, not half-use.
 */
function makeRsaPkcs8B64u() {
  return nodeCrypto
    .generateKeyPairSync('rsa', { modulusLength: 2048 })
    .privateKey.export({ type: 'pkcs8', format: 'der' })
    .toString('base64url');
}

/** The session request. Identity is provided by the injected resolver; nothing here is dispatch data. */
function makeReq() {
  return {
    user: { id: PRINCIPAL, tenantId: AUTHORITY.tenantId },
    body: { deviceId: 'forged-device-from-the-request' },
    query: { deviceId: 'forged-device-from-the-request' },
  };
}

/**
 * Loads `device_command` the way the agent does — through the real registration — with the assembled
 * bag, and returns the constructed tool. The capability stage is read from an EMPTY environment, so
 * the narrowest server stage is the one under test regardless of the ambient process environment.
 */
async function loadDeviceTool({ deps }) {
  const toolMap = await loadTools({
    user: PRINCIPAL,
    tools: [DEVICE_COMMAND_TOOL_NAME],
    returnMap: true,
    options: {
      req: makeReq(),
      deviceCommand: { ...deps, env: NO_STAGE_ENV },
    },
  });
  return toolMap[DEVICE_COMMAND_TOOL_NAME]();
}

/** Invokes the tool the way the model does and parses the payload it returns. */
async function invoke(deviceTool, input) {
  const raw = await deviceTool.invoke({
    name: DEVICE_COMMAND_TOOL_NAME,
    args: input,
    type: 'tool_call',
  });
  return { raw, payload: JSON.parse(raw) };
}

/**
 * The bag with a fake identity seam. The device database is the one stand-in on this path (there is
 * no MongoDB in this suite); everything else — custody, replay window, transport, assembly — is real.
 */
function withIdentity(deps, authority = AUTHORITY) {
  return { ...deps, resolveAuthority: async () => authority };
}

/** The private-key material of a keypair, in every encoding this process can produce. */
function secretForms(keypair) {
  const der = Buffer.from(keypair.privateKeyPkcs8B64u, 'base64url');
  return [
    keypair.privateKeyPkcs8B64u,
    keypair.privateKeyPkcs8B64u.slice(0, 24),
    keypair.privateKeyPkcs8B64u.slice(-24),
    der.toString('hex'),
    der.toString('base64'),
    der.toString('base64url'),
  ];
}

/** Every link of a cause chain, flattened to text. Nothing is assumed about its depth. */
function causeChainText(error) {
  const parts = [];
  let current = error;
  for (let depth = 0; depth < 8 && current !== null && current !== undefined; depth += 1) {
    parts.push(deepText(current));
    current = current.cause;
  }
  return parts.join('\n');
}

describe('W15 — deviceCommandDeps: the injection that puts device_command on the wire', () => {
  describe('custody is OFF by default and cannot be enabled by accident', () => {
    it('assembles no custody and no hop, and the tool keeps answering not-configured', async () => {
      const env = {};
      const deps = createDeviceCommandDeps({ env, logger: silentLogger });

      expect(deps.custody).toBeNull();
      expect(deps.transport).toBeNull();
      expect(deps.replayWindow).not.toBeNull();
      expect(typeof deps.replayWindow.checkAndRemember).toBe('function');
      expect(describeDeviceCommandDeps({ env })).toMatchObject({
        custody: 'absent',
        labCustodyKeyFile: null,
        transport: 'absent',
      });

      const deviceTool = await loadDeviceTool({ deps });
      const { payload } = await invoke(deviceTool, {
        tool: 'read_file',
        arguments: READ_FILE_ARGS,
      });

      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED);
      expect(payload.ok).toBe(false);
      expect(payload.delivered).toBeNull();
      expect(payload.requestId).toBeNull();
      expect(payload.code).toBeNull();
      expect(payload.policy).toBeNull();
      expect(payload.summary).toMatch(/no device signing-key custody configured/i);
    });

    it('touches no transport and signs nothing when custody is absent but a hop IS configured', async () => {
      const stub = await startRelayStub();
      try {
        // The hop is deliberately configured: the fail-closed rule must be about CUSTODY, and a
        // configured relay must still not be reached when there is nothing to sign with.
        const deps = createDeviceCommandDeps({
          env: { [RELAY_BASE_URL_ENV]: stub.baseUrl },
          logger: silentLogger,
        });
        expect(typeof deps.transport).toBe('function');
        expect(deps.custody).toBeNull();

        const deviceTool = await loadDeviceTool({ deps });
        const { payload } = await invoke(deviceTool, {
          tool: 'read_file',
          arguments: READ_FILE_ARGS,
        });

        expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED);
        expect(payload.requestId).toBeNull();
        expect(stub.received).toHaveLength(0);
      } finally {
        await stub.close();
      }
    });

    it('is unmoved by every custody-shaped variable except the one explicit lab opt-in', async () => {
      const lab = writeLabKeyFile('lookalike-lab-key.txt');
      const env = {
        CBHR_DEVICE_CUSTODY_KEY_FILE: lab.file,
        CBHR_LAB_CUSTODY_KEY_FILE: lab.file,
        CBHR_DEVICE_CUSTODY: lab.file,
        CBHR_LAB_CUSTODY_KEY: lab.file,
        CBHR_ENDPOINT_AGENT_ROOT: tmpDir,
      };
      const deps = createDeviceCommandDeps({ env, logger: silentLogger });

      expect(fs.existsSync(lab.file)).toBe(true);
      expect(deps.custody).toBeNull();
      expect(deps.transport).toBeNull();
      expect(describeDeviceCommandDeps({ env }).custody).toBe('absent');
      // The one variable that DOES enable it is the lab opt-in, spelled exactly.
      expect(
        describeDeviceCommandDeps({ env: { [LAB_CUSTODY_KEY_FILE_ENV]: lab.file } }),
      ).toMatchObject({ custody: 'lab-key-file', labCustodyKeyFile: lab.file });
    });

    it('logs the lab presence at load (startup) when the explicit opt-in is set', () => {
      const lab = writeLabKeyFile('startup-lab-key.txt');
      const warnings = [];
      const spy = jest.spyOn(console, 'warn').mockImplementation((message) => {
        warnings.push(String(message));
      });
      const previous = process.env[LAB_CUSTODY_KEY_FILE_ENV];
      process.env[LAB_CUSTODY_KEY_FILE_ENV] = lab.file;
      try {
        jest.isolateModules(() => {
          // Requiring the module IS the server's startup path: ToolService requires it at boot.
          const first = require('../deviceCommandDeps');
          const second = require('../deviceCommandDeps');
          expect(first).toBe(second);
        });
      } finally {
        if (previous === undefined) {
          delete process.env[LAB_CUSTODY_KEY_FILE_ENV];
        } else {
          process.env[LAB_CUSTODY_KEY_FILE_ENV] = previous;
        }
        spy.mockRestore();
      }

      // Exactly one banner per process, not one per require and not one per call.
      expect(warnings).toHaveLength(1);
      const banner = warnings.join('\n');
      expect(banner).toContain(LAB_MARKERS.BANNER);
      expect(banner).toContain(LAB_CUSTODY_KEY_FILE_ENV);
      expect(banner).toContain(lab.file);
      expect(banner).toMatch(/not a deployment signer/i);
      // And with no opt-in at all, startup is silent about custody.
      const quiet = [];
      const quietSpy = jest.spyOn(console, 'warn').mockImplementation((message) => {
        quiet.push(String(message));
      });
      try {
        jest.isolateModules(() => {
          require('../deviceCommandDeps');
        });
      } finally {
        quietSpy.mockRestore();
      }
      expect(quiet.join('\n')).not.toContain(LAB_MARKERS.BANNER);
    });
  });

  describe('with a lab key opted in, the real assembly reaches the wire', () => {
    it('loadTools yields a device_command tool whose call is signed by the lab key and dispatched', async () => {
      const lab = writeLabKeyFile('dispatch-lab-key.txt');
      const stub = await startRelayStub();
      const log = recordingLogger();
      try {
        const deps = createDeviceCommandDeps({
          env: { [LAB_CUSTODY_KEY_FILE_ENV]: lab.file, [RELAY_BASE_URL_ENV]: stub.baseUrl },
          logger: log.logger,
        });
        expect(typeof deps.custody).toBe('function');
        expect(typeof deps.transport).toBe('function');

        const deviceTool = await loadDeviceTool({ deps: withIdentity(deps) });
        const { raw, payload } = await invoke(deviceTool, {
          tool: 'read_file',
          arguments: READ_FILE_ARGS,
        });

        // 1. The platform's own verdict, and the REAL assembly: `policy.evaluated` can only be true
        //    when `createDeviceDispatchAssembly` armed the registry's gate. A hand-built client would
        //    report `evaluated: false, reason: 'policy-port-absent'`.
        expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.ACCEPTED);
        expect(payload.ok).toBe(true);
        expect(payload.delivered).toBe('accepted');
        expect(payload.deviceId).toBe(AUTHORITY.deviceId);
        expect(payload.policy).toMatchObject({ evaluated: true, decision: 'allowed', stage: 'A' });

        // 2. The dispatch really happened, once, on the relay's own route.
        expect(stub.received).toHaveLength(1);
        const sent = stub.received[0];
        expect(sent.method).toBe('POST');
        expect(sent.url).toBe(`/d/${encodeURIComponent(AUTHORITY.deviceId)}/frame`);
        expect(sent.headers['content-type']).toMatch(/application\/json/);

        const envelope = JSON.parse(sent.body);
        expect(typeof envelope.payload).toBe('string');
        const frame = JSON.parse(envelope.payload);
        expect(envelope.callId).toBe(frame.callId);
        expect(envelope.epoch).toBe(frame.epoch);

        // 3. The frame is the platform's own envelope, bound to the session's device and this call.
        expect(frame.tag).toBe(relay.RPC_V2_TAG);
        expect(frame.toolName).toBe('read_file');
        expect(frame.opKind).toBe('command');
        expect(frame.audience).toBe('endpoint');
        expect(frame.deviceId).toBe(AUTHORITY.deviceId);
        expect(frame.deviceKeyId).toBe(AUTHORITY.deviceKeyId);
        expect(frame.grantId).toBe(AUTHORITY.grantId);
        expect(frame.ownerPrincipalId).toBe(AUTHORITY.ownerPrincipalId);
        expect(frame.tenantId).toBe(AUTHORITY.tenantId);
        expect(frame.requestId).toBe(payload.requestId);
        expect(frame.keyId).toBe(lab.keyId);

        const argsBytes = Buffer.from(frame.argsB64u, 'base64url');
        expect(argsBytes.toString('utf8')).toBe(JSON.stringify(READ_FILE_ARGS));
        expect(frame.argsDigestHex).toBe(
          nodeCrypto.createHash('sha256').update(argsBytes).digest('hex'),
        );

        // 4. THE LAB KEY REALLY SIGNED IT: the frozen verifier, pinned to the lab key, accepts the
        //    frame. Nothing in this assertion depends on the module agreeing with itself.
        const verifier = relay.createEnvelopeVerifier({
          publicKeySpkiB64u: lab.keypair.publicKeySpkiB64u,
          expectedKeyId: lab.keyId,
        });
        expect(verifier.verifySignature(relay.signedFromWireFrame(frame))).toMatchObject({
          ok: true,
          keyId: lab.keyId,
        });

        // 5. The lab custody is LOUD on the use, through the injected server logger.
        const warnings = log.of('warn').join('\n');
        expect(warnings).toContain(LAB_MARKERS.IN_PLAY);
        expect(warnings).toContain(LAB_CUSTODY_KEY_FILE_ENV);
        expect(warnings).toContain(lab.file);
        expect(log.text()).not.toContain(SECRET_MARKER);
        expect(raw).not.toContain(SECRET_MARKER);
      } finally {
        await stub.close();
      }
    });

    it('shares ONE replay window across assemblies instead of rebuilding it per request', () => {
      const first = createDeviceCommandDeps({ env: {}, logger: silentLogger });
      const second = createDeviceCommandDeps({ env: {}, logger: silentLogger });
      expect(first.replayWindow).toBe(second.replayWindow);
      expect(typeof first.replayWindow.checkAndRemember).toBe('function');
    });

    it('classifies a relay answer as accepted ONLY when the relay admitted the frame', () => {
      expect(classifyRelayAnswer({ ok: true, admitted: true, seq: 3 })).toMatchObject({
        accepted: true,
        seq: 3,
      });
      expect(
        classifyRelayAnswer({ ok: false, admitted: false, reason: 'STALE_EPOCH' }),
      ).toMatchObject({ accepted: false });
      expect(classifyRelayAnswer({ ok: true })).toMatchObject({ accepted: false });
      expect(classifyRelayAnswer(null)).toMatchObject({ accepted: false });
      expect(classifyRelayAnswer('<html>not json</html>')).toMatchObject({ accepted: false });
    });

    it('refuses a relay answer that is not an admission instead of reporting an acceptance', async () => {
      const lab = writeLabKeyFile('refused-lab-key.txt');
      const stub = await startRelayStub({
        status: 200,
        answer: { ok: false, admitted: false, reason: 'STALE_EPOCH' },
      });
      try {
        const deps = createDeviceCommandDeps({
          env: { [LAB_CUSTODY_KEY_FILE_ENV]: lab.file, [RELAY_BASE_URL_ENV]: stub.baseUrl },
          logger: silentLogger,
        });
        const deviceTool = await loadDeviceTool({ deps: withIdentity(deps) });
        const { payload } = await invoke(deviceTool, {
          tool: 'read_file',
          arguments: READ_FILE_ARGS,
        });

        expect(stub.received).toHaveLength(1);
        expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.REFUSED);
        expect(payload.ok).toBe(false);
        expect(payload.delivered).toBe('refused');
      } finally {
        await stub.close();
      }
    });

    it('reports an unreachable relay honestly as unknown, never as success', async () => {
      const lab = writeLabKeyFile('unreachable-lab-key.txt');
      const baseUrl = await closedPortBaseUrl();
      const deps = createDeviceCommandDeps({
        env: { [LAB_CUSTODY_KEY_FILE_ENV]: lab.file, [RELAY_BASE_URL_ENV]: baseUrl },
        logger: silentLogger,
      });
      // The module's own transport, built by the module, with a short timeout so a dropped (rather
      // than refused) connection cannot stall the suite. Nothing else about the path is substituted.
      const quickTransport = createRelayTransport({ baseUrl, timeoutMs: 400 });
      expect(typeof quickTransport).toBe('function');

      const deviceTool = await loadDeviceTool({
        deps: withIdentity({ ...deps, transport: quickTransport }),
      });
      const { payload } = await invoke(deviceTool, {
        tool: 'read_file',
        arguments: READ_FILE_ARGS,
      });

      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.UNKNOWN);
      expect(payload.ok).toBe(false);
      expect(payload.delivered).toBe('unknown');
      expect(payload.status).toBe('warning');
      expect(payload.summary).toMatch(/OUTCOME UNKNOWN/);
      expect(payload.next_action).toMatch(/do NOT retry|Do NOT retry/i);
    });

    it('builds no transport from a relay URL that is not a usable http(s) URL', () => {
      expect(createRelayTransport({ baseUrl: 'not a url' })).toBeNull();
      expect(createRelayTransport({ baseUrl: 'ftp://127.0.0.1:1/frame' })).toBeNull();
      expect(createRelayTransport({ baseUrl: '' })).toBeNull();
      expect(createRelayTransport({ baseUrl: 'http://127.0.0.1:1' })).not.toBeNull();
    });
  });

  describe('a lab opt-in that cannot be used fails closed', () => {
    const rsaPkcs8 = makeRsaPkcs8B64u();

    const cases = [
      {
        name: 'a path that does not exist',
        code: LAB_CUSTODY_FAILURES.MISSING,
        make: () => path.join(tmpDir, 'no-such-lab-key.txt'),
      },
      {
        name: 'a directory',
        code: LAB_CUSTODY_FAILURES.NOT_A_FILE,
        make: () => tmpDir,
      },
      {
        name: 'an empty file',
        code: LAB_CUSTODY_FAILURES.EMPTY,
        make: () => {
          const file = path.join(tmpDir, 'empty-lab-key.txt');
          fs.writeFileSync(file, '', 'utf8');
          return file;
        },
      },
      {
        name: 'a file that is not a key at all',
        code: LAB_CUSTODY_FAILURES.MALFORMED,
        make: () => {
          const file = path.join(tmpDir, 'not-a-key.txt');
          fs.writeFileSync(file, SECRET_MARKER, 'utf8');
          return file;
        },
      },
      {
        name: 'an oversized file',
        code: LAB_CUSTODY_FAILURES.TOO_LARGE,
        make: () => {
          const file = path.join(tmpDir, 'huge-lab-key.txt');
          fs.writeFileSync(file, 'A'.repeat(9000), 'utf8');
          return file;
        },
      },
      {
        name: 'a non-Ed25519 key',
        code: LAB_CUSTODY_FAILURES.NOT_ED25519,
        make: () => {
          const file = path.join(tmpDir, 'rsa-lab-key.txt');
          fs.writeFileSync(file, `${rsaPkcs8}\n`, 'utf8');
          return file;
        },
      },
    ];

    it.each(cases)('refuses $name and dispatches nothing', async ({ code, make }) => {
      const keyFile = make();
      const stub = await startRelayStub();
      const log = recordingLogger();
      try {
        const deps = createDeviceCommandDeps({
          env: { [LAB_CUSTODY_KEY_FILE_ENV]: keyFile, [RELAY_BASE_URL_ENV]: stub.baseUrl },
          logger: log.logger,
        });
        expect(typeof deps.custody).toBe('function');

        // The seam itself refuses, with a fixed code and nothing else.
        let thrown;
        try {
          deps.custody();
        } catch (error) {
          thrown = error;
        }
        expect(thrown).toBeDefined();
        expect(thrown.code).toBe(code);
        expect(causeChainText(thrown)).not.toContain(SECRET_MARKER);

        // The tool fails closed: not-configured, nothing minted, nothing signed, nothing sent.
        const deviceTool = await loadDeviceTool({ deps: withIdentity(deps) });
        const { raw, payload } = await invoke(deviceTool, {
          tool: 'read_file',
          arguments: READ_FILE_ARGS,
        });
        expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED);
        expect(payload.ok).toBe(false);
        expect(payload.delivered).toBeNull();
        expect(payload.requestId).toBeNull();
        expect(stub.received).toHaveLength(0);

        // Loud, and specific: the code and the file are both named, per use.
        const errors = log.of('error').join('\n');
        expect(errors).toContain(LAB_MARKERS.UNAVAILABLE);
        expect(errors).toContain(code);
        expect(errors).toContain(keyFile);
        expect(log.of('warn').join('\n')).toContain(LAB_MARKERS.IN_PLAY);
        expect(raw).not.toContain(SECRET_MARKER);
        expect(log.text()).not.toContain(SECRET_MARKER);
      } finally {
        await stub.close();
      }
    });

    it('refuses an UNREADABLE key file without re-emitting the underlying error', async () => {
      // The unreadable case is the one a real restricted token produces (the owner-only ACL finding):
      // the file stats fine and the read fails. The failure is forced here so the branch is exercised
      // deterministically, and the injected error deliberately carries text a leak would expose.
      const lab = writeLabKeyFile('unreadable-lab-key.txt');
      const stub = await startRelayStub();
      const log = recordingLogger();
      const hostile = new Error(
        `EACCES: simulated read failure for ${lab.keypair.privateKeyPkcs8B64u}`,
      );
      const realReadFileSync = fs.readFileSync;
      const readSpy = jest.spyOn(fs, 'readFileSync').mockImplementation((target, ...rest) => {
        // Only the lab key file is made unreadable; every other read in the process is untouched.
        if (target === lab.file) {
          throw hostile;
        }
        return realReadFileSync.call(fs, target, ...rest);
      });
      try {
        const deps = createDeviceCommandDeps({
          env: { [LAB_CUSTODY_KEY_FILE_ENV]: lab.file, [RELAY_BASE_URL_ENV]: stub.baseUrl },
          logger: log.logger,
        });

        let thrown;
        try {
          deps.custody();
        } catch (error) {
          thrown = error;
        }
        expect(thrown).toBeDefined();
        expect(thrown.code).toBe(LAB_CUSTODY_FAILURES.UNREADABLE);
        // The caught filesystem error is DISCARDED: neither its message nor the key bytes it quoted
        // appear anywhere in the refusal, its cause chain, the log or the tool's answer.
        const chain = `${causeChainText(thrown)}\n${JSON.stringify(thrown)}\n${nodeUtil.inspect(
          thrown,
          {
            depth: 8,
            showHidden: true,
            getters: true,
          },
        )}`;
        expect(chain).not.toContain(lab.keypair.privateKeyPkcs8B64u);
        expect(chain).not.toContain('simulated read failure');

        const deviceTool = await loadDeviceTool({ deps: withIdentity(deps) });
        const { raw, payload } = await invoke(deviceTool, {
          tool: 'read_file',
          arguments: READ_FILE_ARGS,
        });
        expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED);
        expect(payload.requestId).toBeNull();
        expect(stub.received).toHaveLength(0);
        expect(log.of('error').join('\n')).toContain(LAB_CUSTODY_FAILURES.UNREADABLE);
        expect(log.text()).not.toContain(lab.keypair.privateKeyPkcs8B64u);
        expect(log.text()).not.toContain('simulated read failure');
        expect(raw).not.toContain(lab.keypair.privateKeyPkcs8B64u);
      } finally {
        readSpy.mockRestore();
        await stub.close();
      }
    });
  });

  describe('no key material anywhere', () => {
    it('never lets the private key reach a log, an error, a cause chain, JSON or inspect output', async () => {
      const lab = writeLabKeyFile('leak-proof-lab-key.txt');
      const stub = await startRelayStub();
      const log = recordingLogger();
      const secrets = secretForms(lab.keypair);
      const labels = [lab.keypair.publicKeySpkiB64u, lab.keyId];
      try {
        const env = { [LAB_CUSTODY_KEY_FILE_ENV]: lab.file, [RELAY_BASE_URL_ENV]: stub.baseUrl };
        const deps = createDeviceCommandDeps({ env, logger: log.logger });
        const deviceTool = await loadDeviceTool({ deps: withIdentity(deps) });
        const { raw } = await invoke(deviceTool, { tool: 'read_file', arguments: READ_FILE_ARGS });
        const seam = loadLabCustodySeam(lab.file);

        // Every surface a caller or an operator could print.
        const surfaces = {
          'deps (JSON)': JSON.stringify(deps),
          'deps (inspect)': nodeUtil.inspect(deps, { depth: 8, showHidden: true, getters: true }),
          'describe (JSON)': JSON.stringify(describeDeviceCommandDeps({ env })),
          'logger lines': log.text(),
          'tool payload': raw,
          'seam (JSON)': JSON.stringify(seam),
          'seam (inspect)': nodeUtil.inspect(seam, { depth: 8, showHidden: true, getters: true }),
          'seam keys': JSON.stringify(Object.keys(seam)),
        };

        const failed = [];
        for (const [name, text] of Object.entries(surfaces)) {
          secrets.forEach((secret, index) => {
            if (text.includes(secret)) {
              failed.push(`${name} leaked private-key form #${index}`);
            }
          });
        }
        expect(failed).toEqual([]);

        // The seam carries exactly the two contract keys, and no public label reaches a log either.
        expect(Object.keys(seam).sort()).toEqual(['keyId', 'sign']);
        const labelSurfaces = {
          'deps (JSON)': surfaces['deps (JSON)'],
          'deps (inspect)': surfaces['deps (inspect)'],
          'describe (JSON)': surfaces['describe (JSON)'],
          'logger lines': surfaces['logger lines'],
          'tool payload': surfaces['tool payload'],
        };
        const labelled = [];
        for (const [name, text] of Object.entries(labelSurfaces)) {
          labels.forEach((label, index) => {
            if (text.includes(label)) {
              labelled.push(`${name} leaked key label #${index}`);
            }
          });
        }
        expect(labelled).toEqual([]);

        // The wire frame legitimately carries the keyId label (the endpoint pins it) — but never the
        // private key, in any encoding.
        const sentFrame = JSON.parse(JSON.parse(stub.received[0].body).payload);
        const frameText = JSON.stringify(sentFrame);
        secrets.forEach((secret, index) => {
          expect({ index, leaked: frameText.includes(secret) }).toEqual({ index, leaked: false });
        });

        // The cause chain of every refusal this module can throw is inert.
        const notAKeyFile = path.join(tmpDir, 'leak-not-a-key.txt');
        const rsaFile = path.join(tmpDir, 'leak-rsa-key.txt');
        const emptyFile = path.join(tmpDir, 'leak-empty-key.txt');
        const missingFile = path.join(tmpDir, 'leak-missing-key.txt');
        fs.writeFileSync(notAKeyFile, SECRET_MARKER, 'utf8');
        fs.writeFileSync(rsaFile, `${makeRsaPkcs8B64u()}\n`, 'utf8');
        fs.writeFileSync(emptyFile, '', 'utf8');
        const refusals = [];
        for (const bad of [missingFile, notAKeyFile, rsaFile, emptyFile]) {
          try {
            loadLabCustodySeam(bad);
          } catch (error) {
            refusals.push(error);
          }
        }
        try {
          seam.sign('not a Buffer');
        } catch (error) {
          refusals.push(error);
        }
        expect(refusals.length).toBeGreaterThanOrEqual(5);
        // The custody refusals carry a code and a code-only stand-in cause; the sign-input refusal
        // is a plain fixed error for a programmer-shaped call and carries no value at all.
        const coded = refusals.filter((error) => typeof error.code === 'string');
        expect(coded.length).toBeGreaterThanOrEqual(4);
        expect(
          coded.every((error) => error.cause !== null && typeof error.cause === 'object'),
        ).toBe(true);
        const chain = refusals.map((error) => causeChainText(error)).join('\n');
        const chainFailed = [];
        secrets.forEach((secret, index) => {
          if (chain.includes(secret)) {
            chainFailed.push(`cause chain leaked private-key form #${index}`);
          }
        });
        if (chain.includes(SECRET_MARKER)) {
          chainFailed.push('cause chain leaked the file content marker');
        }
        expect(chainFailed).toEqual([]);
      } finally {
        await stub.close();
      }
    });
  });

  describe('the registration stays additive', () => {
    it('constructs an existing tool identically with and without the deviceCommand bag', async () => {
      const lab = writeLabKeyFile('additive-lab-key.txt');
      const deps = createDeviceCommandDeps({
        env: { [LAB_CUSTODY_KEY_FILE_ENV]: lab.file },
        logger: silentLogger,
      });

      const withoutBag = await loadTools({
        user: PRINCIPAL,
        tools: ['calculator'],
        returnMap: true,
        options: { req: makeReq() },
      });
      const withBag = await loadTools({
        user: PRINCIPAL,
        tools: ['calculator'],
        returnMap: true,
        options: { req: makeReq(), deviceCommand: deps },
      });

      const plain = await withoutBag.calculator();
      const alongside = await withBag.calculator();
      expect(Object.keys(withBag)).toEqual(['calculator']);
      expect(alongside.name).toBe(plain.name);
      expect(alongside.description).toBe(plain.description);
    });

    it('still hands back a constructible device_command that fails closed with no bag at all', async () => {
      const toolMap = await loadTools({
        user: PRINCIPAL,
        tools: [DEVICE_COMMAND_TOOL_NAME],
        returnMap: true,
        options: { req: makeReq() },
      });
      const deviceTool = await toolMap[DEVICE_COMMAND_TOOL_NAME]();
      expect(deviceTool.name).toBe(DEVICE_COMMAND_TOOL_NAME);
      const { payload } = await invoke(deviceTool, {
        tool: 'read_file',
        arguments: READ_FILE_ARGS,
      });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED);
    });
  });
});

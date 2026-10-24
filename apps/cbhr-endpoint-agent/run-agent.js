#!/usr/bin/env node
'use strict';

/**
 * CBHR ENDPOINT AGENT — runnable entry point (workstream W7, GM-73).
 *
 *   node apps/cbhr-endpoint-agent/run-agent.js <command> [options]
 *
 * Commands
 *   init          create this endpoint's device key (owner-only file, outside the repo), record its
 *                 server-issued device id, and write the default (narrowest) tool configuration
 *   describe      print the agent's PUBLIC state: device id, key id, pinned backend keys, ceiling,
 *                 effective tool set, the verification order and every refusal code. No secrets.
 *   pin-backend   pin a backend PUBLIC key from a file (`--spki-file <path to base64url SPKI>`)
 *   tools         print the effective tool set and the reason each other tool is refused
 *   handle        read frames (JSON, one per line, or a single JSON document) from stdin or `--in`,
 *                 verify + dispatch each, and write one result frame per input line to stdout
 *   verify-only   same, but never executes: prints the verification verdict only (a safe dry run)
 *   serve         connect to the relay as a DEVICE and stay: receive command frames over the socket,
 *                 feed each through the EXISTING agent path (verify -> dispatch -> execute -> sign),
 *                 send the result back as `{t:'result', callId, payload}`, and ack each frame once the
 *                 relay has judged the result. Reconnects with backoff; stops cleanly on
 *                 SIGINT/SIGTERM. This is the resident participant (W13); every other command is a
 *                 one-shot.
 *
 * LAB ARTIFACT (GM-73). This is the owner's own machine and the logic the Tauri shell will host; it is
 * NOT the employee deliverable (D008 still forbids requiring Node for end users), and it claims no
 * graphical control.
 *
 * NOTHING HERE EVER PRINTS KEY MATERIAL. `describe` prints public labels and file PATHS; `handle`
 * prints result frames, which carry public metadata plus the tool's output. A refusal prints its code
 * and its fixed message, never the non-enumerable `detail` that names the failing field.
 */

const fs = require('node:fs');
const path = require('node:path');

const { createEndpointAgent } = require('./src/agent');
const {
  createAgentRuntime,
  installShutdownHandlers,
  buildDeviceSocketUrl,
  DEVICE_SOCKET_TAG,
} = require('./src/runtime');
const { createDeviceKeystore, resolveRootDir, inspectKeyFilePermissions } = require('./src/keystore');
const { pinBackendKey, defaultPinFile } = require('./src/pinnedKeys');
const { loadCeilingSnapshot, defaultSnapshotPath } = require('./src/ceiling');
const { loadDeviceToolConfig, writeDeviceToolConfig, DEFAULT_ENABLED_TOOLS } = require('./src/deviceConfig');
const { describeVerificationOrder } = require('./src/verify');
const { isEndpointRefusal } = require('./src/errors');
const { writeOwnerOnlyFile } = require('./src/permissions');

const USAGE = `CBHR endpoint agent (lab artifact, GM-73)

usage: node run-agent.js <command> [options]

commands:
  init          --device-id <id> [--force]     create the device key + record the device id
  describe                                     print public agent state and the verification order
  tools                                        print the effective tool set and refusal reasons
  pin-backend   --spki-file <path> [--label L] [--replace]
  handle        [--in <file>] [--device-id <id>] [--out <file>]
  verify-only   [--in <file>] [--device-id <id>]
  serve         --relay <url>                   connect as a device and stay

serve options:
  --relay <url>           relay base URL, e.g. http://127.0.0.1:8787
                          (a path-less URL gets /d/<deviceId>/ws?tag=device appended;
                          a URL with a path is used as the device route, and the tag is forced
                          to 'device' either way — the runtime never claims the platform role)
  --no-replay-on-connect  pass replay=0 to the relay: do not redeliver unacked frames on connect
                          (default: replay ON, which is the relay's production path)
  --backoff-initial-ms N  first reconnect delay in ms (default 500)
  --backoff-max-ms N      reconnect delay cap in ms (default 30000)
  --max-reconnects N      give up (exit 1) after N consecutive failed reconnects
                          (default: retry forever — the agent is a resident)
  --verdict-timeout-ms N  how long to wait for the relay's verdict on one result (default 15000)
  --drain-ms N            how long a shutdown waits for in-flight frames (default 5000)
  --shutdown-on-stdin-eof also shut down cleanly when stdin reaches EOF (opt-in control channel for
                          hosts that cannot deliver signals; useful in tests and service managers)
  --print-url             print the device socket URL being connected to, then continue serving

common options:
  --root <dir>          agent root (default ~/.cbhr/endpoint-agent; NEVER inside the repo)
  --workspace <dir>     tool containment root (default <root>/workspace)
  --snapshot <file>     server ceiling snapshot (default config/server-ceiling.json)
  --tools-config <f>    local tool configuration file (default <root>/tools.json)
  --pin-file <file>     pinned backend keys file (default <root>/backend-keys.json)
  --replay-file <file>  durable replay window file (default <root>/replay-window.json)
  --no-pins             describe/tools without a pinned backend key (every frame would be refused)
  --help
`;

function parseArgs(argv) {
  const options = { _: [] };
  const booleanFlags = new Set([
    'force',
    'replace',
    'no-pins',
    'help',
    'no-replay-on-connect',
    'shutdown-on-stdin-eof',
    'print-url',
  ]);
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '-h') {
      options.help = true;
      continue;
    }
    if (!arg.startsWith('--')) {
      options._.push(arg);
      continue;
    }
    const key = arg.slice(2);
    if (booleanFlags.has(key)) {
      options[key] = true;
      continue;
    }
    index += 1;
    if (argv[index] === undefined) {
      throw new Error(`${arg} requires a value`);
    }
    options[key] = argv[index];
  }
  return options;
}

/** Writes JSON to stdout as one line (the frame-per-line protocol). */
function emit(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function agentOptionsFrom(options, extra = {}) {
  const base = {
    rootDir: options.root,
    deviceId: options['device-id'],
    snapshotPath: options.snapshot,
    toolsConfigFile: options['tools-config'],
    pinFile: options['pin-file'],
    replayFile: options['replay-file'],
    workspaceRoot: options.workspace,
  };
  if (options['no-pins'] === true) {
    // An EXPLICITLY empty pin set: every frame is refused with ENDPOINT_KEY_UNPINNED because
    // `pinned()` finds nothing. Never a wildcard, never "skip the check".
    base.pins = Object.freeze({
      keyIds: () => Object.freeze([]),
      size: () => 0,
      pinned: () => null,
      verify: () => false,
    });
  }
  return { ...base, ...extra };
}

function commandInit(options) {
  const rootDir = resolveRootDir(options.root);
  const deviceId = options['device-id'];
  if (typeof deviceId !== 'string' || deviceId.length === 0) {
    process.stderr.write('init requires --device-id <the server-issued device id>\n');
    return 2;
  }
  const created = createDeviceKeystore({ rootDir, force: options.force === true });
  writeOwnerOnlyFile(
    path.join(rootDir, 'device.json'),
    `${JSON.stringify({ version: 1, deviceId, createdAt: new Date().toISOString() }, null, 2)}\n`,
  );
  const ceiling = loadCeilingSnapshot(options.snapshot ?? defaultSnapshotPath());
  const config = writeDeviceToolConfig({
    ceiling,
    rootDir,
    toolsConfigFile: options['tools-config'],
    enabled: DEFAULT_ENABLED_TOOLS,
  });
  const permission = inspectKeyFilePermissions(created.file);
  emit({
    command: 'init',
    rootDir,
    deviceId,
    deviceKeyId: created.keyId,
    deviceKeyFile: created.file,
    keyCreated: created.created,
    permission,
    toolsConfigFile: config.file,
    enabledTools: config.enabled,
    pinnedBackendKeysFile: defaultPinFile(rootDir),
    nextSteps: [
      'pin the backend public key:  node run-agent.js pin-backend --spki-file <file>',
      'then handle frames:          node run-agent.js handle --in <frames.jsonl>',
    ],
  });
  return 0;
}

function commandDescribe(options) {
  const agent = createEndpointAgent(agentOptionsFrom(options));
  emit({ command: 'describe', agent: agent.describe() });
  return 0;
}

function commandTools(options) {
  const agent = createEndpointAgent(agentOptionsFrom(options));
  const description = agent.describe();
  const snapshot = JSON.parse(fs.readFileSync(options.snapshot ?? defaultSnapshotPath(), 'utf8'));
  // Every tool the snapshot describes, PLUS the hard-denied names that are not catalog tools
  // (`track_ui_event` is an internal dispatch handler, so it is deliberately absent from the stage
  // index). Listing it is what lets the panel say "off at the server, not on your PC" instead of
  // leaving the employee with a capability that silently never appears.
  const known = [
    ...new Set([
      ...Object.keys(snapshot.stageIndex ?? {}),
      ...(Array.isArray(snapshot.rulingAbsoluteDenies) ? snapshot.rulingAbsoluteDenies : []),
    ]),
  ].sort();
  emit({
    command: 'tools',
    effective: agent.effectiveTools(),
    ceiling: description.ceiling,
    deviceEnabled: description.dispatch.deviceEnabled,
    narrowedByDevice: description.dispatch.narrowedByDevice,
    implemented: description.dispatch.implemented,
    decisions: known.map((toolName) => {
      const decision = agent.decideTool(toolName);
      return {
        tool: toolName,
        allowed: decision.allowed,
        withinCeiling: decision.withinCeiling,
        enabledOnDevice: decision.enabledOnDevice,
        implemented: decision.implemented,
        requiresApproval: decision.requiresApproval,
        refusalCode: decision.refusalCode,
      };
    }),
  });
  return 0;
}

function commandPinBackend(options) {
  const spkiFile = options['spki-file'];
  if (typeof spkiFile !== 'string' || spkiFile.length === 0) {
    process.stderr.write('pin-backend requires --spki-file <path containing the base64url SPKI key>\n');
    return 2;
  }
  const publicKeySpkiB64u = fs.readFileSync(spkiFile, 'utf8').trim();
  const result = pinBackendKey({
    publicKeySpkiB64u,
    label: options.label,
    replace: options.replace === true,
    rootDir: options.root,
    pinFile: options['pin-file'],
  });
  emit({ command: 'pin-backend', keyId: result.keyId, pinFile: result.pinFile, keys: result.keys, mode: result.mode, acl: result.acl });
  return 0;
}

function readInput(options) {
  if (typeof options.in === 'string' && options.in.length > 0) {
    return fs.readFileSync(options.in, 'utf8');
  }
  return fs.readFileSync(0, 'utf8');
}

/**
 * Splits input into frames. Three shapes are accepted, and the ambiguity between them is resolved by
 * STRUCTURE rather than by guessing:
 *
 *   - a JSON array                     `[ {...}, {...} ]`
 *   - one pretty-printed JSON document `{ ... }` (a `tools/lab-backend.cjs sign` output file)
 *   - JSON lines                       one flat frame per line (the relay's own shape)
 *
 * A hand-written pretty-printed object and a hand-written run of one-line objects both begin with `{`,
 * so the single-document parse is attempted FIRST and the line-by-line parse is the fallback. A
 * malformed line is then reported as a line number, which is what makes a JSON-lines feed debuggable.
 *
 * @param {string} text
 * @returns {object[]}
 */
function parseFrames(text) {
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    return [];
  }
  if (trimmed.startsWith('[')) {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) {
      throw new Error('the input JSON array did not parse as an array');
    }
    return parsed;
  }
  if (!trimmed.startsWith('{')) {
    throw new Error('the input is neither a JSON document nor JSON lines');
  }
  try {
    const single = JSON.parse(trimmed);
    if (single !== null && typeof single === 'object' && !Array.isArray(single)) {
      return [single];
    }
  } catch {
    // Not a single document: fall through to the line-by-line reading below.
  }
  const lines = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (err) {
      throw new Error(`input line ${index + 1} is not valid JSON: ${err.message}`);
    }
  });
}

async function commandHandle(options, { execute }) {
  const agent = createEndpointAgent(agentOptionsFrom(options));
  const frames = parseFrames(readInput(options));
  const out = [];
  for (const frame of frames) {
    if (execute) {
      const handled = await agent.handleFrame(frame);
      out.push(handled.resultFrame);
    } else {
      // verify-only: run the same chain but NEVER dispatch. The nonce is still consumed, because a
      // dry run that silently frees a nonce would be a replay hole.
      const { verifyCommandFrame } = require('./src/verify');
      const internal = agent._internal;
      const verdict = await verifyCommandFrame({
        frame,
        pins: internal.pins,
        deviceId: agent.deviceId(),
        deviceKeyId: agent.deviceKeyId(),
        now: internal.now,
        replayWindow: internal.replayWindow,
      });
      out.push(
        verdict.ok === true
          ? {
              verdict: 'verified',
              toolName: verdict.core.toolName,
              callId: frame.callId ?? null,
              effective: agent.effectiveTools().includes(verdict.core.toolName),
            }
          : { verdict: 'refused', code: verdict.error.code, message: verdict.error.message },
      );
    }
  }
  const body = out.map((entry) => `${JSON.stringify(entry)}\n`).join('');
  if (typeof options.out === 'string' && options.out.length > 0) {
    fs.writeFileSync(options.out, body, 'utf8');
  } else {
    process.stdout.write(body);
  }
  return 0;
}

/**
 * Reads an optional integer flag, refusing a non-numeric value loudly rather than silently ignoring
 * it. A mistyped `--backoff-max-ms` that quietly became the default would leave an operator believing
 * a policy is in force that is not — the same failure the device-config loader refuses to commit.
 *
 * @param {object} options parsed argv
 * @param {string} name
 * @returns {number|undefined}
 */
function optionalInteger(options, name) {
  const raw = options[name];
  if (raw === undefined || raw === null) {
    return undefined;
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`--${name} must be a non-negative integer`);
  }
  return value;
}

/**
 * `serve` — the resident participant (W13).
 *
 * Everything about the LOOP is the existing agent's: this command only builds the agent once (so the
 * ceiling, the device floor and the pin set cannot change under a running process), connects the
 * device socket, and routes signals to one shutdown path. It never prints key material, and it never
 * writes a result the agent core did not produce.
 *
 * @param {object} options
 * @returns {Promise<number>} the process exit code
 */
async function commandServe(options) {
  const relay = options.relay;
  if (typeof relay !== 'string' || relay.length === 0) {
    process.stderr.write(
      'serve requires --relay <url> (for example http://127.0.0.1:8787).\n' +
        'It never guesses a relay: a resident agent that connects somewhere unasked is worse than one that does not start.\n',
    );
    return 2;
  }
  const agent = createEndpointAgent(agentOptionsFrom(options));
  let runtime;
  try {
    runtime = createAgentRuntime({
      agent,
      relay,
      deviceId: agent.deviceId(),
      replayOnConnect: options['no-replay-on-connect'] !== true,
      backoff: {
        initialMs: optionalInteger(options, 'backoff-initial-ms'),
        maxMs: optionalInteger(options, 'backoff-max-ms'),
      },
      maxReconnects: optionalInteger(options, 'max-reconnects') ?? null,
      verdictTimeoutMs: optionalInteger(options, 'verdict-timeout-ms'),
      drainMs: optionalInteger(options, 'drain-ms'),
      // The default sink: info on stdout, warn/error on stderr. An operator sees a disconnect, a
      // refusal and a reconnect without asking, which is the whole point of the command.
    });
  } catch (err) {
    if (isEndpointRefusal(err)) {
      throw err;
    }
    // A malformed flag is a usage error, not a crash: say which one and exit 2.
    process.stderr.write(`serve: ${err.message}\n`);
    return 2;
  }

  if (options['print-url'] === true) {
    process.stdout.write(`${buildDeviceSocketUrl({ relay, deviceId: agent.deviceId() })}\n`);
  }

  let signalCount = 0;
  const uninstall = installShutdownHandlers({
    emitter: process,
    onSignal: (signal) => {
      signalCount += 1;
      if (signalCount > 1) {
        // A second Ctrl+C is the operator saying "now", so stop insisting on a graceful drain.
        process.stderr.write(`\nsecond ${signal}: exiting now\n`);
        process.exit(0);
      }
      runtime
        .stop(`signal:${signal}`)
        .then(() => {
          uninstall();
        })
        .catch(() => {
          process.exit(1);
        });
    },
  });

  process.on('uncaughtException', (err) => {
    // LOUD, never silent: an agent that dies without saying why is the failure mode this command
    // exists to remove. The exit code is non-zero so a supervisor restarts it.
    process.stderr.write(
      `${new Date().toISOString()} ERROR runtime.uncaught ${JSON.stringify({
        name: err?.name ?? 'Error',
        code: isEndpointRefusal(err) ? err.code : null,
      })}\n`,
    );
    runtime.stop('uncaught-exception').finally(() => process.exit(1));
  });

  if (options['shutdown-on-stdin-eof'] === true) {
    process.stdin.on('end', () => {
      runtime.stop('stdin-eof').catch(() => process.exit(1));
    });
    process.stdin.on('close', () => {
      runtime.stop('stdin-eof').catch(() => process.exit(1));
    });
    // Reading is the only way Node emits 'end'; the runtime does nothing with the bytes.
    process.stdin.resume();
  }

  process.stdout.write(
    `${new Date().toISOString()} INFO  serve.identity ${JSON.stringify({
      deviceId: agent.deviceId(),
      deviceKeyId: agent.deviceKeyId(),
      rootDir: agent._internal.rootDir,
      relay,
      tag: DEVICE_SOCKET_TAG,
      tools: agent.effectiveTools(),
    })}\n`,
  );

  // `start()` throws a typed refusal when this machine has no WebSocket client at all; `main()`'s
  // catch reports it as a code and exits 1 rather than pretending to listen.
  runtime.start();

  const outcome = await runtime.whenStopped();
  uninstall();
  if (options['shutdown-on-stdin-eof'] === true) {
    // Stop holding the process open on a stdin that is no longer the control channel.
    process.stdin.pause();
  }
  // Exit code: 0 for every clean shutdown (signal, stdin EOF, request), 1 when the runtime gave up
  // because the relay never came back — a supervisor should see that difference.
  const code = outcome.gaveUp === true ? 1 : 0;
  const forced = setTimeout(() => process.exit(code), 250);
  if (typeof forced.unref === 'function') {
    // Does not keep the loop alive: an idle loop exits on its own, flushing these last lines first.
    forced.unref();
  }
  return code;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help === true || options._.length === 0) {
    process.stdout.write(USAGE);
    return options._.length === 0 && options.help !== true ? 1 : 0;
  }
  const command = options._[0];
  switch (command) {
    case 'init':
      return commandInit(options);
    case 'describe':
      return commandDescribe(options);
    case 'tools':
      return commandTools(options);
    case 'pin-backend':
      return commandPinBackend(options);
    case 'handle':
      return commandHandle(options, { execute: true });
    case 'verify-only':
      return commandHandle(options, { execute: false });
    case 'serve':
      return commandServe(options);
    default:
      process.stderr.write(`unknown command: ${command}\n\n${USAGE}`);
      return 2;
  }
}

if (require.main === module) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      // One fixed line. A typed refusal reports its own code; anything else is an operational failure
      // whose message may name a path, so only its CLASS travels — never a stack, never a value.
      if (isEndpointRefusal(err)) {
        process.stderr.write(`endpoint agent failed: ${err.code}: ${err.message}\n`);
      } else {
        process.stderr.write(`endpoint agent failed: ENDPOINT_UNEXPECTED_FAILURE: ${err.name}\n`);
      }
      process.exitCode = 1;
    });
}

module.exports = { parseArgs, parseFrames, main, USAGE };
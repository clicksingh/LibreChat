#!/usr/bin/env node
'use strict';

/**
 * CBHR ENDPOINT AGENT — LAB BACKEND (workstream W7 test harness).
 *
 * Not part of the agent: this is the STAND-IN for the platform's signing half, so an operator can run
 * a real end-to-end try on their own machine without a running backend. It signs a `CBHR-RPC-V2`
 * frame over the frozen 15-field string using a private key the operator supplies, and prints the flat
 * wire frame the relay would forward.
 *
 *   node tools/lab-backend.cjs keygen   --out <dir>                  create a lab signing key
 *   node tools/lab-backend.cjs pubkey   --key <pkcs8 file>           print the base64url SPKI to pin
 *   node tools/lab-backend.cjs sign     --key <pkcs8> --device-id <id> --device-key-id <id>
 *                                       --tool <name> [--args '<json>'] [--call-id <id>]
 *                                       [--grant-id <b64u>] [--epoch <n>] [--owner <id>]
 *                                       [--tenant <id>] [--now <ms>] [--nonce <b64u>]
 *                                       [--request-id <uuid>] [--key-id <label>] [--out <file>]
 *   node tools/lab-backend.cjs tamper   --in <frame.json> [--swap-args] [--break-signature]
 *                                       [--out <file>]
 *   node tools/lab-backend.cjs selftest                              check the published golden vector
 *
 * It is deliberately INDEPENDENT of `src/layout.js`: the canonical join here is written out from the
 * contract by hand, so if the two ever disagree the agent REFUSES the frame instead of both sides
 * quietly agreeing on something wrong. `selftest` asserts that against the published worked example.
 *
 * The key this tool writes is a LAB key for the owner's own machine. It is not the deployment custody
 * choice, and it lives wherever `--out` points — never inside the repository.
 */

const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');

/** The frozen field order, written out from F-V24C-4 rather than imported. */
const FIELD_ORDER = [
  'tag',
  'requestId',
  'nonce',
  'issuedAt',
  'deadlineMs',
  'epoch',
  'grantId',
  'ownerPrincipalId',
  'tenantId',
  'deviceId',
  'deviceKeyId',
  'toolName',
  'opKind',
  'audience',
  'argsDigestHex',
];

const SEPARATOR = '\u001f';

/** The contract's published worked example, used by `selftest` only. */
const WORKED_EXAMPLE = {
  tag: 'CBHR-RPC-V2',
  requestId: '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
  nonce: 'AAECAwQFBgcICQoLDA0ODw',
  issuedAt: '1761200000000',
  deadlineMs: '1761200060000',
  epoch: '7',
  grantId: 'EBESExQVFhcYGRobHB0eHw',
  ownerPrincipalId: '64f0a1b2c3d4e5f60718293a',
  tenantId: 'tenant-kelowna',
  deviceId: '65a1b2c3d4e5f60718293b4c',
  deviceKeyId: 'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw',
  toolName: 'read_file',
  opKind: 'command',
  audience: 'endpoint',
  argsDigestHex: '3795b53e4665398f141a5fafb3b006777f9f15f56423821f3e88795a8b972d14',
};
const WORKED_EXAMPLE_CANONICAL =
  'CBHR-RPC-V2\u001f' +
  '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93\u001f' +
  'AAECAwQFBgcICQoLDA0ODw\u001f' +
  '1761200000000\u001f' +
  '1761200060000\u001f' +
  '7\u001f' +
  'EBESExQVFhcYGRobHB0eHw\u001f' +
  '64f0a1b2c3d4e5f60718293a\u001f' +
  'tenant-kelowna\u001f' +
  '65a1b2c3d4e5f60718293b4c\u001f' +
  'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw\u001f' +
  'read_file\u001f' +
  'command\u001f' +
  'endpoint\u001f' +
  '3795b53e4665398f141a5fafb3b006777f9f15f56423821f3e88795a8b972d14';
const GOLDEN_PUBLIC_KEY_SPKI_B64U = 'MCowBQYDK2VwAyEAebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ';
const GOLDEN_SIGNATURE_B64U =
  'Zq8MZuROHEygKRQQmiXTWU80omRN4zPfaMYGt2NIBQot3pApk4_v92ljRvsblHar0nyGhoD2dsKrks20hsonAw';

const USAGE = `CBHR lab backend (W7 test harness; NOT the deployment signer)

usage: node tools/lab-backend.cjs <command> [options]

commands:
  keygen    --out <dir>                  create an Ed25519 lab signing key (PKCS#8 DER, base64url)
  pubkey    --key <file>                 print the base64url SPKI to pin at the endpoint
  sign      --key <file> --device-id <id> --device-key-id <id> --tool <name>
            [--args '<json>'] [--call-id <id>] [--grant-id <b64u>] [--epoch <n>]
            [--owner <id>] [--tenant <id>] [--now <epochMs>] [--nonce <b64u>]
            [--request-id <uuid4>] [--key-id <label>] [--out <file>]
  tamper    --in <frame.json> [--swap-args] [--break-signature] [--out <file>]
  selftest                               verify the published golden vector locally

Flag names may be written dashed (--call-id) or camelCase (--callId); both reach the same option.
`;

/**
 * Flags that take NO value. Every other `--name` consumes the next argv entry.
 *
 * This list is load-bearing. Until it existed, `--swap-args --out <file>` consumed `--out` as the
 * VALUE of `swap-args`, so the output path silently became a positional argument and the file was
 * never written — the tool printed to stdout and the operator's next command read a missing file.
 * A parser that cannot tell a flag from an option makes every downstream harness result suspect, so
 * the distinction is explicit here rather than inferred.
 */
const BOOLEAN_FLAGS = new Set(['swap-args', 'break-signature', 'help', 'h']);

/**
 * Parses the command line into a NORMALIZED option record.
 *
 * A dashed flag is stored under BOTH its literal name and its camelCase form, so a call site can read
 * either spelling and neither can be silently unset. Both properties are deliberate: the dashed name
 * is what a shell user typed, and the camelCase alias means a JavaScript property read cannot miss it.
 *
 * @param {string[]} argv
 * @returns {Record<string, string|boolean|string[]>}
 */
function parseArgs(argv) {
  const options = { _: [] };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      options._.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (name.length === 0) {
      throw new Error('an empty -- flag is not a valid option');
    }
    const camel = name.replace(/-([a-z0-9])/g, (_match, char) => char.toUpperCase());
    let value = true;
    if (!BOOLEAN_FLAGS.has(name) && !BOOLEAN_FLAGS.has(camel)) {
      index += 1;
      if (argv[index] === undefined) {
        throw new Error(`${arg} requires a value`);
      }
      value = argv[index];
    }
    options[name] = value;
    if (camel !== name && options[camel] === undefined) {
      options[camel] = value;
    }
  }
  return options;
}

/**
 * Reads an option by its dashed spelling, falling back to the camelCase alias.
 * @param {Record<string, unknown>} options
 * @param {string} dashed e.g. `call-id`
 * @returns {unknown}
 */
function optionOf(options, dashed) {
  const camel = dashed.replace(/-([a-z0-9])/g, (_match, char) => char.toUpperCase());
  return options[dashed] ?? options[camel];
}

/**
 * The independent canonical join: literal 0x1F, literal field order, no shared code with the agent.
 * @param {Record<string, string>} core
 * @returns {Buffer}
 */
function canonicalFor(core) {
  const parts = FIELD_ORDER.map((property) => {
    const value = core[property];
    if (typeof value !== 'string' || value.includes(SEPARATOR)) {
      throw new Error(`core field ${property} must be a string without the 0x1F separator`);
    }
    return value;
  });
  return Buffer.from(parts.join(SEPARATOR), 'utf8');
}

/** The `keyId` label for a public key: its base64url SHA-256 SPKI thumbprint. */
function thumbprint(spkiB64u) {
  return nodeCrypto.createHash('sha256').update(Buffer.from(spkiB64u, 'base64url')).digest('base64url');
}

function loadPrivateKey(file) {
  const text = fs.readFileSync(file, 'utf8').trim();
  return nodeCrypto.createPrivateKey({
    key: Buffer.from(text, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  });
}

function spkiOf(privateKey) {
  return nodeCrypto
    .createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
}

/** A non-empty string option, or null. */
function textOf(options, name) {
  const value = optionOf(options, name);
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Prints a value to stdout as pretty JSON, or writes it to `outFile` when one is supplied.
 * Parameter ORDER matters: value first, destination second.
 * @param {unknown} value
 * @param {unknown} outFile
 */
function writeOrPrint(value, outFile) {
  const text = `${JSON.stringify(value, null, 2)}\n`;
  if (typeof outFile === 'string' && outFile.length > 0) {
    fs.writeFileSync(outFile, text, 'utf8');
    process.stdout.write(`wrote ${outFile}\n`);
    return;
  }
  process.stdout.write(text);
}

/**
 * `keygen` — creates a lab signing key and prints the public value to pin.
 * @param {Record<string, unknown>} options
 * @returns {number} exit code
 */
function commandKeygen(options) {
  const outDir = textOf(options, 'out');
  if (outDir === null) {
    process.stderr.write('keygen requires --out <dir>\n');
    return 2;
  }
  fs.mkdirSync(outDir, { recursive: true });
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url');
  const keyFile = path.join(outDir, 'lab-backend-key.txt');
  fs.writeFileSync(keyFile, `${pkcs8}\n`, 'utf8');
  const spkiFile = path.join(outDir, 'lab-backend-spki.txt');
  fs.writeFileSync(spkiFile, `${spki}\n`, 'utf8');
  writeOrPrint(
    {
      privateKeyFile: keyFile,
      publicKeySpkiFile: spkiFile,
      publicKeySpkiB64u: spki,
      keyId: thumbprint(spki),
      nextSteps: [
        `pin it at the endpoint:  node run-agent.js pin-backend --spki-file ${spkiFile}`,
        `sign a frame:            node tools/lab-backend.cjs sign --key ${keyFile} ...`,
      ],
    },
    undefined,
  );
  return 0;
}

/**
 * `pubkey` — prints the SPKI and `keyId` for an existing lab key.
 * @param {Record<string, unknown>} options
 * @returns {number} exit code
 */
function commandPubkey(options) {
  const keyFile = textOf(options, 'key');
  if (keyFile === null) {
    process.stderr.write('pubkey requires --key <pkcs8 file>\n');
    return 2;
  }
  const spki = spkiOf(loadPrivateKey(keyFile));
  writeOrPrint({ publicKeySpkiB64u: spki, keyId: thumbprint(spki) }, undefined);
  return 0;
}

/**
 * `sign` — mints a `CBHR-RPC-V2` command frame over the frozen 15-field string.
 * @param {Record<string, unknown>} options
 * @returns {number} exit code
 */
function commandSign(options) {
  const keyFile = textOf(options, 'key');
  const deviceId = textOf(options, 'device-id');
  const deviceKeyId = textOf(options, 'device-key-id');
  const tool = textOf(options, 'tool');
  for (const [name, value] of [
    ['--key', keyFile],
    ['--device-id', deviceId],
    ['--device-key-id', deviceKeyId],
    ['--tool', tool],
  ]) {
    if (value === null) {
      process.stderr.write(`sign requires ${name}\n`);
      return 2;
    }
  }
  const privateKey = loadPrivateKey(keyFile);
  const spki = spkiOf(privateKey);

  const argsB64uOption = textOf(options, 'args-b64u');
  const argsOption = textOf(options, 'args');
  const argsBytes =
    argsB64uOption !== null
      ? Buffer.from(argsB64uOption, 'base64url')
      : Buffer.from(argsOption === null ? '{}' : argsOption, 'utf8');

  const nowOption = textOf(options, 'now');
  const now = nowOption === null ? Date.now() : Number(nowOption);
  if (!Number.isSafeInteger(now) || now < 0) {
    process.stderr.write('--now must be an epoch-millisecond integer\n');
    return 2;
  }
  const nonce = textOf(options, 'nonce') ?? nodeCrypto.randomBytes(16).toString('base64url');
  const requestId = textOf(options, 'request-id') ?? nodeCrypto.randomUUID();
  const callId = textOf(options, 'call-id') ?? `call-${nonce.slice(0, 8)}`;
  const epochOption = textOf(options, 'epoch');

  const core = {
    tag: 'CBHR-RPC-V2',
    requestId,
    nonce,
    issuedAt: String(now),
    deadlineMs: String(now + 60000),
    epoch: String(epochOption === null ? 1 : epochOption),
    grantId: textOf(options, 'grant-id') ?? Buffer.alloc(16, 0x11).toString('base64url'),
    ownerPrincipalId: textOf(options, 'owner') ?? 'lab-owner-0001',
    tenantId: textOf(options, 'tenant') ?? 'tenant-lab',
    deviceId,
    deviceKeyId,
    toolName: tool,
    opKind: 'command',
    audience: 'endpoint',
    argsDigestHex: nodeCrypto.createHash('sha256').update(argsBytes).digest('hex'),
  };
  const frame = {
    ...core,
    signatureB64u: nodeCrypto.sign(null, canonicalFor(core), privateKey).toString('base64url'),
    keyId: textOf(options, 'key-id') ?? thumbprint(spki),
    argsB64u: argsBytes.toString('base64url'),
    callId,
    idempotencyKey: `idem-${callId}`,
  };
  writeOrPrint(frame, optionOf(options, 'out'));
  return 0;
}

/**
 * `tamper` — produces a frame that must be REFUSED: swapped args under a genuine signature, or a
 * broken signature, or both.
 * @param {Record<string, unknown>} options
 * @returns {number} exit code
 */
function commandTamper(options) {
  const inFile = textOf(options, 'in');
  if (inFile === null) {
    process.stderr.write('tamper requires --in <frame.json>\n');
    return 2;
  }
  const frame = JSON.parse(fs.readFileSync(inFile, 'utf8'));
  const tampered = { ...frame };
  const breakSignature = optionOf(options, 'break-signature') !== undefined;
  const swapArgs = optionOf(options, 'swap-args') !== undefined || !breakSignature;
  if (swapArgs) {
    tampered.argsB64u = Buffer.from(
      '{"path":"C:/Windows/System32/drivers/etc/hosts"}',
      'utf8',
    ).toString('base64url');
  }
  if (breakSignature) {
    tampered.signatureB64u = Buffer.alloc(64, 0x2a).toString('base64url');
  }
  writeOrPrint(tampered, optionOf(options, 'out'));
  return 0;
}

/**
 * `selftest` — reproduces the published golden vector locally, so an operator can confirm this tool's
 * own canonical join and signature before using it to exercise the endpoint.
 * @returns {number} exit code
 */
function commandSelftest() {
  const seed = Buffer.from(Array.from({ length: 32 }, (_unused, index) => index + 1));
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = spkiOf(privateKey);
  const canonical = canonicalFor(WORKED_EXAMPLE);
  const signature = nodeCrypto.sign(null, canonical, privateKey).toString('base64url');
  const checks = {
    spkiMatches: spki === GOLDEN_PUBLIC_KEY_SPKI_B64U,
    canonicalMatches: canonical.toString('utf8') === WORKED_EXAMPLE_CANONICAL,
    signatureMatches: signature === GOLDEN_SIGNATURE_B64U,
  };
  const ok = Object.values(checks).every(Boolean);
  process.stdout.write(`${JSON.stringify({ ok, ...checks }, null, 2)}\n`);
  return ok ? 0 : 1;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const command = options._[0];
  switch (command) {
    case 'keygen':
      return commandKeygen(options);
    case 'pubkey':
      return commandPubkey(options);
    case 'sign':
      return commandSign(options);
    case 'tamper':
      return commandTamper(options);
    case 'selftest':
      return commandSelftest();
    default:
      process.stdout.write(USAGE);
      return command === undefined ? 1 : 2;
  }
}

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (err) {
    process.stderr.write(`lab backend failed: ${err.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { canonicalFor, thumbprint, parseArgs, optionOf, BOOLEAN_FLAGS, FIELD_ORDER };
'use strict';

/**
 * DEVICE COMMAND DEPENDENCY ASSEMBLY — the injection the AI tool was missing (W15).
 *
 * LOCAL LAB ONLY. Production G0 remains BLOCKED; nothing here changes that.
 *
 * WHY THIS FILE EXISTS
 * `createDeviceCommandTool` (`api/app/clients/tools/deviceCommand.js`) takes every seam by injection —
 * `{ custody, transport, replayWindow }` — because custody is an owner decision that is unmade and the
 * relay hop's route is an integration choice. Nothing populated those seams, so `device_command` could
 * only ever answer `not-configured`. This module is the one place that turns DEPLOYMENT CONFIGURATION
 * into those seams, and it is deliberately the only new dispatch-side file: it does not mint, sign,
 * classify or transport anything itself. It reads configuration, builds the seams, and hands them to
 * the tool, which passes them to the single production assembly (`createDeviceDispatchAssembly`).
 * There is no second dispatch path here.
 *
 * THE THREE SEAMS, AND WHAT EACH DOES WHEN IT IS NOT CONFIGURED
 *
 *   custody       a `{ sign, keyId }` provider. CUSTODY IS OFF BY DEFAULT and can only be turned on
 *                 by naming a LOCAL LAB key file in `CBHR_DEVICE_LAB_CUSTODY_KEY_FILE` (below). With
 *                 the variable absent, `custody` is `null`, the tool returns `not-configured` before
 *                 it builds a client, and NOTHING is signed, reserved or sent.
 *   transport     an HTTP POST into the relay's own frame admission (`POST /d/<deviceId>/frame`),
 *                 with the base URL taken from `CBHR_DEVICE_RELAY_BASE_URL`. With the variable
 *                 absent or unusable the hop is `null`, and the tool returns `not-configured`
 *                 (`HOP_ABSENT`) rather than dispatching. No relay URL is invented here: the relay's
 *                 route is a contract this module reads from configuration, never a default.
 *   replayWindow  `relay.createReplayWindow()` — ONE window per process, shared by every tool
 *                 instance. A per-request window would forget a nonce as soon as the request ended,
 *                 which is exactly when a replay would arrive, so the window is created once and
 *                 reused. It is the in-process pre-dispatch guard; the durable window stays on the
 *                 endpoint, as the relay contract requires.
 *
 * THE LAB CUSTODY GATE (requirement: impossible to enable by accident, never the default)
 * A lab signing key is read ONLY when `CBHR_DEVICE_LAB_CUSTODY_KEY_FILE` names it. The gate is
 * structural, not advisory:
 *   - there is NO default path, NO fallback path and NO other custody variable this module reads;
 *   - an unset, empty or whitespace-only value means custody is ABSENT — the current, fail-closed
 *     state — and the tool keeps answering `not-configured` exactly as it does today;
 *   - the named file must be a bounded, non-empty, canonical-base64url PKCS#8 **Ed25519** key
 *     (the shape W7's lab signer writes). Anything else — a directory, an unreadable file, a JSON
 *     config, a PEM, a truncated or non-Ed25519 key — is REFUSED and logged, never half-used;
 *   - the refusal is per use and immediate: deleting or corrupting the file stops lab custody at
 *     once, without a restart.
 *
 * THE LAB KEY IS LOUD, AT STARTUP AND ON EVERY USE
 * Requiring this module is the server's startup path (ToolService requires it at boot), and a lab
 * opt-in present at that moment emits a banner through `console.warn`. Every single use of the lab
 * seam emits the same warning again through the injected server logger, and every failure emits an
 * error-level line naming the refusal code and the key file path. An accidental lab enablement is
 * therefore visible in the first log line of every affected call, not discovered later.
 *
 * NO KEY MATERIAL, ANYWHERE (the same standard the endpoint key store already meets)
 * This module never logs, throws, returns, serializes or inspects key bytes, and it never re-emits a
 * caught error from `node:crypto` or the filesystem: every failure here is a fixed, field-naming,
 * value-free refusal whose `cause` is a code-only stand-in. The signing key lives in one closure and
 * is reachable only through `sign(bytes)`. The returned seams carry exactly `{ sign, keyId }`; the
 * `keyId` is a public SPKI thumbprint label, never secret material, and it is not logged here either.
 *
 * The one non-secret configuration value that IS logged (and returned by `describe()` in
 * `describeDeviceCommandDeps`) is the configured FILE PATH: it is configuration, not key material,
 * and an operator cannot act on a lab-custody warning that does not say which file is in play.
 */

const fs = require('node:fs');
const nodeCrypto = require('node:crypto');

const { thumbprintB64u } = require('./crypto');
const relay = require('./relay');

/** The explicit lab opt-in: the path of a LOCAL LAB signing key. Never defaulted, never inferred. */
const LAB_CUSTODY_KEY_FILE_ENV = 'CBHR_DEVICE_LAB_CUSTODY_KEY_FILE';

/** The relay's base URL. Absent means the hop is unconfigured and no frame may leave the process. */
const RELAY_BASE_URL_ENV = 'CBHR_DEVICE_RELAY_BASE_URL';

/** How long one relay frame POST may take. A timeout is an UNKNOWN outcome, never a success. */
const RELAY_FRAME_TIMEOUT_MS = 10000;

/** The largest file that can still be a lab signing key; W7's lab key file is 65 bytes. */
const LAB_KEY_MAX_BYTES = 8192;

/** Canonical unpadded base64url, the only encoding the lab key file may carry. */
const LAB_KEY_PATTERN = /^[A-Za-z0-9_-]+$/;

/** The loud markers, so a lab line is greppable and unmistakable in a server log. */
const LAB_MARKERS = Object.freeze({
  IN_PLAY: '*** LAB CUSTODY IN PLAY ***',
  UNAVAILABLE: '*** LAB CUSTODY UNAVAILABLE ***',
  BANNER: '*************** LAB CUSTODY IS IN PLAY FOR device_command ***************',
});

/** The refusal vocabulary. Fixed codes, no values: a code names the fault, the log names the file. */
const LAB_CUSTODY_FAILURES = Object.freeze({
  MISSING: 'LAB_CUSTODY_KEY_FILE_MISSING',
  NOT_A_FILE: 'LAB_CUSTODY_KEY_PATH_NOT_A_FILE',
  UNREADABLE: 'LAB_CUSTODY_KEY_FILE_UNREADABLE',
  EMPTY: 'LAB_CUSTODY_KEY_FILE_EMPTY',
  TOO_LARGE: 'LAB_CUSTODY_KEY_FILE_TOO_LARGE',
  MALFORMED: 'LAB_CUSTODY_KEY_FILE_MALFORMED',
  NOT_ED25519: 'LAB_CUSTODY_KEY_NOT_ED25519',
});

/** The schema id of the operator-facing description. */
const DEPS_DESCRIPTION_SCHEMA = 'cbhr.rdc.device-command-deps/1';

/** One banner per process, whichever call site gets there first. */
let bannerEmitted = false;

/** One replay window per process, shared by every assembled tool (see the header). */
let sharedReplayWindow = null;

/** A non-empty, trimmed environment string, or null. An absent value is never a default. */
function envText(env, name) {
  const raw = env === null || env === undefined ? undefined : env[name];
  if (typeof raw !== 'string') {
    return null;
  }
  const trimmed = raw.trim();
  return trimmed.length === 0 ? null : trimmed;
}

/**
 * A fixed, value-free refusal. No filesystem text, no `node:crypto` text and no key bytes travel on:
 * the `cause` is a code-only stand-in so even a printout of the cause chain is inert.
 */
function labCustodyRefusal(code, detail) {
  const error = new Error(`lab device-signing custody is unavailable (${code}): ${detail}`, {
    cause: Object.freeze({ code, field: 'labCustodyKeyFile' }),
  });
  error.code = code;
  error.field = 'labCustodyKeyFile';
  return error;
}

/** A log sink that prefers the injected server logger and never lets a log call change an outcome. */
function makeSink(logger) {
  const call = (level, fallback) => (message) => {
    try {
      if (logger !== null && logger !== undefined && typeof logger[level] === 'function') {
        logger[level](message);
        return;
      }
      fallback(message);
    } catch {
      /* A failing logger never changes custody, the hop or an outcome. */
    }
  };
  return Object.freeze({
    warn: call('warn', (message) => console.warn(message)),
    error: call('error', (message) => console.error(message)),
  });
}

/**
 * Loads the lab signing seam from the named file, or throws a fixed refusal.
 *
 * The file format is W7's lab key file: the PKCS#8 DER private key in unpadded base64url, one line.
 * `keyId` is derived exactly as the endpoint derives it — the base64url SHA-256 thumbprint of the
 * SPKI DER — so the label the frame carries is the thumbprint the endpoint pins.
 *
 * @param {string} keyFile
 * @returns {Readonly<{sign: (bytes: Buffer) => string, keyId: string}>}
 */
function loadLabCustodySeam(keyFile) {
  let stats;
  try {
    stats = fs.statSync(keyFile);
  } catch {
    throw labCustodyRefusal(
      LAB_CUSTODY_FAILURES.MISSING,
      'the configured lab custody key file does not exist or cannot be reached',
    );
  }
  if (!stats.isFile()) {
    throw labCustodyRefusal(
      LAB_CUSTODY_FAILURES.NOT_A_FILE,
      'the configured lab custody key path is not a file',
    );
  }
  if (stats.size === 0) {
    throw labCustodyRefusal(LAB_CUSTODY_FAILURES.EMPTY, 'the lab custody key file is empty');
  }
  if (stats.size > LAB_KEY_MAX_BYTES) {
    throw labCustodyRefusal(
      LAB_CUSTODY_FAILURES.TOO_LARGE,
      `the lab custody key file is larger than ${LAB_KEY_MAX_BYTES} bytes, so it is not a lab key`,
    );
  }

  let text;
  try {
    text = fs.readFileSync(keyFile, 'utf8');
  } catch {
    throw labCustodyRefusal(
      LAB_CUSTODY_FAILURES.UNREADABLE,
      'the lab custody key file could not be read',
    );
  }
  const encoded = text.trim();
  if (encoded.length === 0) {
    throw labCustodyRefusal(LAB_CUSTODY_FAILURES.EMPTY, 'the lab custody key file is empty');
  }
  if (!LAB_KEY_PATTERN.test(encoded)) {
    throw labCustodyRefusal(
      LAB_CUSTODY_FAILURES.MALFORMED,
      'the lab custody key file is not a single canonical unpadded base64url value',
    );
  }

  let privateKey;
  try {
    privateKey = nodeCrypto.createPrivateKey({
      key: Buffer.from(encoded, 'base64url'),
      format: 'der',
      type: 'pkcs8',
    });
  } catch {
    // The caught error is deliberately DISCARDED: nothing from the crypto layer is re-emitted.
    throw labCustodyRefusal(
      LAB_CUSTODY_FAILURES.MALFORMED,
      'the lab custody key file is not a loadable PKCS#8 private key',
    );
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw labCustodyRefusal(
      LAB_CUSTODY_FAILURES.NOT_ED25519,
      'the lab custody key file is not an Ed25519 key, so it cannot sign endpoint-audience frames',
    );
  }

  let keyId;
  try {
    const spki = nodeCrypto
      .createPublicKey(privateKey)
      .export({ type: 'spki', format: 'der' })
      .toString('base64url');
    keyId = thumbprintB64u(spki);
  } catch {
    throw labCustodyRefusal(
      LAB_CUSTODY_FAILURES.MALFORMED,
      'the lab custody key file yields no usable Ed25519 SPKI thumbprint',
    );
  }

  // Everything below closes over `privateKey`; no accessor, property or serialization exposes it.
  return Object.freeze({
    keyId,
    sign: (bytes) => {
      if (!Buffer.isBuffer(bytes)) {
        throw new Error('the lab custody seam signs Buffers only');
      }
      return nodeCrypto.sign(null, bytes, privateKey).toString('base64url');
    },
  });
}

/** The banner an operator cannot miss. Configuration only: no key material, no identity. */
function labCustodyStartupNotice(keyFile) {
  return [
    `[deviceCommandDeps] ${LAB_MARKERS.BANNER}`,
    `[deviceCommandDeps] ${LAB_CUSTODY_KEY_FILE_ENV} is set, so LOCAL LAB signing custody is in play.`,
    `[deviceCommandDeps] Lab key file: ${keyFile}`,
    '[deviceCommandDeps] Every device_command frame this process dispatches will be signed with that',
    '[deviceCommandDeps] LAB key. It is NOT a deployment signer, NOT an owner-approved custody choice',
    '[deviceCommandDeps] and it must never be used outside the local lab. Unset ' +
      `${LAB_CUSTODY_KEY_FILE_ENV}`,
    '[deviceCommandDeps] (and restart) to return to the fail-closed not-configured behaviour.',
    `[deviceCommandDeps] ${LAB_MARKERS.BANNER}`,
  ].join('\n');
}

/**
 * Emits the lab banner once per process, through `sink`, when the opt-in is present.
 * @param {object} env
 * @param {{warn: Function}} sink
 * @returns {boolean} whether a lab opt-in was seen (and the banner is therefore in play)
 */
function logLabCustodyStartupNotice(env, sink = makeSink(null)) {
  const keyFile = envText(env, LAB_CUSTODY_KEY_FILE_ENV);
  if (keyFile === null) {
    return false;
  }
  if (!bannerEmitted) {
    bannerEmitted = true;
    sink.warn(labCustodyStartupNotice(keyFile));
  }
  return true;
}

/**
 * The custody seam provider handed to the tool.
 *
 * It is a FUNCTION, not a surface, so the tool re-resolves it on every call: each call logs that lab
 * custody is in play (the "on every use" requirement), and each call re-reads the key file, so
 * removing or corrupting it stops dispatch immediately. A failed load logs loudly and throws a fixed
 * refusal, which the tool's own `resolveCustodySeam` turns into "custody absent" — the tool then
 * answers `not-configured` and never builds a client, signs anything or touches the transport.
 *
 * @param {object} params
 * @param {string} params.keyFile
 * @param {{warn: Function, error: Function}} params.sink
 * @returns {() => Readonly<{sign: Function, keyId: string}>}
 */
function createLabCustodyProvider({ keyFile, sink }) {
  return function labCustodyProvider() {
    sink.warn(
      `[deviceCommandDeps] ${LAB_MARKERS.IN_PLAY} ${LAB_CUSTODY_KEY_FILE_ENV} names ${keyFile}: ` +
        'the next device_command frame is signed with a LOCAL LAB key, not a deployment signer.',
    );
    try {
      return loadLabCustodySeam(keyFile);
    } catch (error) {
      const code = typeof error?.code === 'string' ? error.code : LAB_CUSTODY_FAILURES.MALFORMED;
      sink.error(
        `[deviceCommandDeps] ${LAB_MARKERS.UNAVAILABLE} (${code}) device_command will answer ` +
          `not-configured and NOTHING will be signed. Lab key file: ${keyFile}`,
      );
      throw error;
    }
  };
}

/**
 * Presents a relay answer to the dispatch client's classification vocabulary.
 *
 * The relay's frame admission answers `{ ok, admitted, seq, ... }`; the dispatch client reads
 * `body.accepted === false` as "the relay refused the frame". A 2xx answer is therefore an ACCEPTANCE
 * only when the relay itself says `admitted: true` (or an explicit `accepted: true`). An unreadable
 * body, a missing verdict or a relay refusal is presented as `accepted: false`, which the client
 * reports as `delivered: 'refused'`. The conversion never runs the other way: nothing here can turn
 * an unknown or refused answer into a success.
 *
 * @param {unknown} body the relay's parsed answer, or null
 * @returns {object} the body plus the classification flag
 */
function classifyRelayAnswer(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { accepted: false, relayVerdictUnreadable: true };
  }
  return { ...body, accepted: body.admitted === true || body.accepted === true };
}

/**
 * Builds the relay HTTP transport, or `null` when the configured base URL is unusable (fail closed).
 *
 * The route is the relay's own: `POST /d/<deviceId>/frame` with `{ epoch, payload, callId }`, where
 * `payload` is the frame SERIALIZED (the relay is a keyless forwarder that never parses it) and
 * `epoch` is the frame's own signed epoch. There is no retry: a retried frame would be a second
 * dispatch of the same call, and the outcome law forbids a blind retry of the same envelope.
 *
 * @param {object} params
 * @param {string} params.baseUrl
 * @param {number} [params.timeoutMs]
 * @param {Function} [params.fetchImpl] injectable fetch (tests); defaults to the platform fetch
 * @returns {Function|null}
 */
function createRelayTransport({ baseUrl, timeoutMs = RELAY_FRAME_TIMEOUT_MS, fetchImpl = null }) {
  let base;
  try {
    base = new URL(baseUrl);
  } catch {
    return null;
  }
  if (base.protocol !== 'http:' && base.protocol !== 'https:') {
    return null;
  }
  const doFetch = typeof fetchImpl === 'function' ? fetchImpl : globalThis.fetch;
  if (typeof doFetch !== 'function') {
    return null;
  }

  return async function relayTransport({ deviceId, frame }) {
    const url = new URL(`/d/${encodeURIComponent(deviceId)}/frame`, base);
    const callId =
      typeof frame?.callId === 'string' && frame.callId.length > 0 ? frame.callId : null;
    const body = JSON.stringify({
      epoch: frame?.epoch ?? null,
      payload: JSON.stringify(frame),
      ...(callId === null ? {} : { callId }),
    });
    // The abort signal is minted PER CALL: `AbortSignal.timeout()` starts counting when it is
    // created, so a signal built at construction time would abort the first dispatch that happens
    // more than `timeoutMs` after startup.
    const signal =
      typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function'
        ? AbortSignal.timeout(timeoutMs)
        : undefined;
    const answer = await doFetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      ...(signal === undefined ? {} : { signal }),
    });
    let parsed = null;
    try {
      parsed = await answer.json();
    } catch {
      parsed = null;
    }
    return { status: answer.status, body: classifyRelayAnswer(parsed) };
  };
}

/** The process-wide replay window, created on first use and reused by every assembly. */
function sharedReplayWindowFor() {
  if (sharedReplayWindow === null) {
    sharedReplayWindow = relay.createReplayWindow();
  }
  return sharedReplayWindow;
}

/**
 * Assembles the seams `createDeviceCommandTool` needs, from configuration alone.
 *
 * @param {object} [options]
 * @param {object} [options.env] environment to read; defaults to the process environment
 * @param {object} [options.logger] server logger used for the lab warnings and the assembly notices
 * @param {Function} [options.fetchImpl] injectable fetch for the relay transport (tests)
 * @returns {Readonly<{custody: (Function|null), transport: (Function|null), replayWindow: object,
 *   logger?: object}>} the `deviceCommand` bag the tool consumes. The environment itself is NOT
 *   returned: a bag that carried `process.env` could dump unrelated secrets through `util.inspect`.
 */
function createDeviceCommandDeps({ env = process.env, logger = null, fetchImpl = null } = {}) {
  const sink = makeSink(logger);
  const labKeyFile = envText(env, LAB_CUSTODY_KEY_FILE_ENV);

  let custody = null;
  if (labKeyFile !== null) {
    // The banner is emitted once per process, here if boot did not already do it (a lazily required
    // module, or an explicitly injected environment), so lab mode can never be quiet.
    logLabCustodyStartupNotice(env, sink);
    custody = createLabCustodyProvider({ keyFile: labKeyFile, sink });
  }

  const relayBaseUrl = envText(env, RELAY_BASE_URL_ENV);
  const transport =
    relayBaseUrl === null ? null : createRelayTransport({ baseUrl: relayBaseUrl, fetchImpl });
  if (relayBaseUrl !== null && transport === null) {
    sink.warn(
      `[deviceCommandDeps] ${RELAY_BASE_URL_ENV} is not a usable http(s) relay URL, so the relay hop ` +
        'stays UNCONFIGURED: device_command answers not-configured rather than dispatching.',
    );
  }

  return Object.freeze({
    custody,
    transport,
    replayWindow: sharedReplayWindowFor(),
    ...(logger === null || logger === undefined ? {} : { logger }),
  });
}

/**
 * The operator-facing description of what this configuration assembles. Configuration only: the
 * custody MODE and the configured paths, never key material, never an identity.
 *
 * @param {object} [options]
 * @param {object} [options.env]
 * @returns {Readonly<object>}
 */
function describeDeviceCommandDeps({ env = process.env } = {}) {
  const labKeyFile = envText(env, LAB_CUSTODY_KEY_FILE_ENV);
  const relayBaseUrl = envText(env, RELAY_BASE_URL_ENV);
  return Object.freeze({
    schema: DEPS_DESCRIPTION_SCHEMA,
    custody: labKeyFile === null ? 'absent' : 'lab-key-file',
    labCustodyKeyFile: labKeyFile,
    labCustodyKeyFileEnv: LAB_CUSTODY_KEY_FILE_ENV,
    transport: relayBaseUrl === null ? 'absent' : 'relay-http',
    relayBaseUrl,
    relayBaseUrlEnv: RELAY_BASE_URL_ENV,
    replayWindow: 'in-process-shared',
    framePathTemplate: '/d/<deviceId>/frame',
    frameTimeoutMs: RELAY_FRAME_TIMEOUT_MS,
  });
}

module.exports = {
  LAB_CUSTODY_KEY_FILE_ENV,
  RELAY_BASE_URL_ENV,
  RELAY_FRAME_TIMEOUT_MS,
  LAB_KEY_MAX_BYTES,
  LAB_MARKERS,
  LAB_CUSTODY_FAILURES,
  DEPS_DESCRIPTION_SCHEMA,
  loadLabCustodySeam,
  createLabCustodyProvider,
  createRelayTransport,
  classifyRelayAnswer,
  sharedReplayWindowFor,
  createDeviceCommandDeps,
  describeDeviceCommandDeps,
  logLabCustodyStartupNotice,
  labCustodyStartupNotice,
};

// STARTUP, NOT LAZINESS: this module is required by `ToolService` while the server boots, so a lab
// opt-in present at boot is announced in the server's first log lines rather than at first dispatch.
logLabCustodyStartupNotice(process.env);

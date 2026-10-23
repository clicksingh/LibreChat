'use strict';

/**
 * CBHR ENDPOINT AGENT — owner-only filesystem permissions (workstream W7).
 *
 * The endpoint holds the ONLY private key the relay does not have, so the file that carries it must be
 * unreachable by any principal that is not the owner. Node has one portable permission value (`fs`
 * mode) and it is advisory on Windows, so this module makes the restriction REAL on both platforms and
 * FAILS CLOSED when it cannot:
 *
 *   - POSIX: the file is created with `0o600` (directory `0o700`) and re-asserted with `fchmod` while
 *     the descriptor is still open. If the mode cannot be applied, the caller gets a refusal: an
 *     unreadable-by-others guarantee that was not applied is not a guarantee.
 *   - Windows: `mode` does not deny a second reader, so `icacls` drops inheritance and grants exactly
 *     one principal (the current owner). See the IMPORTANT NOTE below for the two non-owner entries
 *     Windows itself re-adds, and why they are accepted without pretending the file is single-ACE.
 *
 * IMPORTANT, AND STATED HONESTLY RATHER THAN PAPERED OVER
 * On Windows, after `icacls <file> /inheritance:r /grant:r <owner>:(F)`, listing the file in a typical
 * interactive session shows THREE explicit entries:
 *
 *     <owner>:(F)                                we granted this
 *     NT AUTHORITY\SYSTEM:(F)                    Windows re-adds it to every object
 *     NT AUTHORITY\LogonSessionId_0_<id>:(RX)    Windows re-adds the CURRENT LOGON SESSION
 *
 * The last one is the interesting case. It is not a second human account: it is a SID bound to the
 * logged-on session, so any process running in the owner's own session holds it — including everything
 * the owner starts themselves. Removing it is not durable (the operating system re-applies it), so a
 * module that demanded a literal one-ACE file would never succeed, and an "owner-only" claim that
 * cannot be applied is worse than an accurate one. What this module therefore does is:
 *
 *   - refuse any OTHER principal (a real second account, any group such as Users / Authenticated
 *     Users / Everyone, or any SID it does not recognise as SYSTEM / an administrative local group / a
 *     logon-session SID);
 *   - refuse ANY inherited entry outright, because an inherited entry can name a broad group;
 *   - return the RAW `icacls` text as evidence alongside the classified principal list, so nobody has
 *     to take the classification on trust: `run-agent.js init` prints exactly what Windows says, and
 *     the test suite asserts both the refusal for a foreign principal and the classification of a real
 *     post-restriction listing.
 *
 * The guarantee delivered is therefore: no account other than the owner (plus SYSTEM and the owner's
 * own session) can read the key file, and no inherited ACE survives. That is the strongest guarantee
 * Windows offers for a file, and it is the guarantee this module claims — nothing more.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

/** Written with the tightest portable mode; Windows gets the ACL treatment on top. */
const OWNER_ONLY_FILE_MODE = 0o600;
const OWNER_ONLY_DIR_MODE = 0o700;

/** Principal shapes Windows itself re-adds; everything else must fail closed. */
const ACCEPTABLE_NON_OWNER_PRINCIPAL =
  /^(NT AUTHORITY\\(SYSTEM|SERVICE|LOCAL SERVICE|LogonSessionId_.*)|NT SERVICE\\[^\\]+|BUILTIN\\(Administrators|SYSTEM)|S-1-5-18|S-1-5-32-544)$/i;

/** True on Windows, where `fs` mode is advisory and an explicit ACL is required. */
function isWindows() {
  return process.platform === 'win32';
}

/**
 * The current user's account name (`DOMAIN\user`) or POSIX user name, used as the single explicit
 * grant. Falls back to `os.userInfo().username` when `whoami` is unavailable — still an identity,
 * never an empty grant.
 * @returns {string}
 */
function ownerAccountName() {
  if (isWindows()) {
    try {
      const out = execFileSync('whoami', { encoding: 'utf8', windowsHide: true }).trim();
      if (out.length > 0) {
        return out;
      }
    } catch {
      // fall through to os.userInfo()
    }
  }
  try {
    return os.userInfo().username;
  } catch {
    return '';
  }
}

/** Case-insensitive comparison (`whoami` lower-cases the domain, `icacls` does not). */
function samePrincipal(left, right) {
  return (
    typeof left === 'string' && typeof right === 'string' && left.toLowerCase() === right.toLowerCase()
  );
}

/**
 * True when the principal is one this platform adds to every object or to the owner's own session, and
 * which therefore cannot be removed durably. Everything else is a foreign principal and is refused.
 * @param {string} principal
 * @param {string} owner
 * @returns {boolean}
 */
function isPlatformPrincipal(principal, owner) {
  if (samePrincipal(principal, owner)) {
    return true;
  }
  return ACCEPTABLE_NON_OWNER_PRINCIPAL.test(principal);
}

/**
 * Parses an `icacls` listing into `{ explicit, inherited }` principal/rights pairs.
 *
 * `icacls` prints one ACE per line and, for a file with several ACEs, right-aligns the following lines
 * under the first: line one carries the path, the rest are padding. The parse is therefore deliberately
 * conservative — it looks for `<principal>:<rights>` at the END of a line and strips a leading
 * filesystem path when one is present (the path's own colon would otherwise be mistaken for the
 * principal separator).
 *
 * @param {string} aclText
 * @returns {{explicit: Array<{principal: string, rights: string}>, inherited: Array<{principal: string, rights: string}>}}
 */
function parseAcl(aclText) {
  const explicit = [];
  const inherited = [];
  for (const rawLine of String(aclText).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0) {
      continue;
    }
    const match = /^(.*?):?((?:\([^)]*\))+)$/.exec(line);
    if (match === null) {
      continue;
    }
    let principal = match[1].trim();
    const rights = match[2];
    if (principal.length === 0) {
      continue;
    }
    // Strip a leading path (`C:\...\file` or `\\server\share`): a path is not a principal.
    const drivePath = /^[A-Za-z]:\\.*?\s+(?=\S+$)/.exec(principal);
    if (drivePath !== null) {
      principal = principal.slice(drivePath[0].length).trim();
    } else if (/^\\\\/.test(principal)) {
      const parts = principal.split(/\s+/);
      principal = parts[parts.length - 1];
    }
    if (principal.length === 0) {
      continue;
    }
    if (rights.includes('(I)')) {
      inherited.push({ principal, rights });
    } else {
      explicit.push({ principal, rights });
    }
  }
  return { explicit, inherited };
}

/**
 * The verdict an owner-only assertion needs, plus the raw evidence behind it.
 *
 * @param {string} aclText raw `icacls` output
 * @param {string} [owner] the owner's account name; defaults to the current account
 * @returns {{ok: boolean, owner: string, explicit: Array<{principal: string, rights: string}>,
 *   inherited: Array<{principal: string, rights: string}>, foreign: string[],
 *   acceptablePlatformPrincipals: string[]}}
 */
function verifyOwnerOnlyAcl(aclText, owner = ownerAccountName()) {
  const parsed = parseAcl(aclText);
  const explicitPrincipals = parsed.explicit.map((entry) => entry.principal);
  const foreign = [];
  const acceptablePlatformPrincipals = [];
  for (const principal of explicitPrincipals) {
    if (samePrincipal(principal, owner)) {
      continue;
    }
    if (isPlatformPrincipal(principal, owner)) {
      acceptablePlatformPrincipals.push(principal);
    } else {
      foreign.push(principal);
    }
  }
  const ownerGranted = explicitPrincipals.some((principal) => samePrincipal(principal, owner));
  const ok =
    owner.length > 0 &&
    ownerGranted &&
    foreign.length === 0 &&
    parsed.inherited.length === 0 &&
    parsed.explicit.length > 0;
  return {
    ok,
    owner,
    explicit: parsed.explicit,
    inherited: parsed.inherited,
    foreign,
    acceptablePlatformPrincipals,
  };
}

function aclRefusalMessage(verdict, what) {
  const ownerGranted = verdict.explicit.some((entry) => samePrincipal(entry.principal, verdict.owner));
  return `the owner-only ACL on a ${what} was not applied (${verdict.foreign.length} foreign principal(s), ${verdict.inherited.length} inherited, owner ${ownerGranted ? 'granted' : 'missing'})`;
}

/**
 * Runs `icacls <target> /inheritance:r /grant:r <owner>:(F)` — drop inherited ACEs, then grant exactly
 * one principal — and returns the verdict plus the raw listing.
 * @param {string} target absolute path to a file or directory
 * @param {string} [owner] principal to grant; defaults to the current account
 * @returns {{ok: boolean, owner: string, acl: string, explicit: object[], inherited: object[],
 *   foreign: string[], acceptablePlatformPrincipals: string[]}}
 */
function restrictToOwnerWindows(target, owner = ownerAccountName()) {
  if (owner.length === 0) {
    throw new Error('cannot determine the owning account for an owner-only ACL');
  }
  execFileSync('icacls', [target, '/inheritance:r', '/grant:r', `${owner}:(F)`], {
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const acl = readAclWindows(target);
  return { ...verifyOwnerOnlyAcl(acl, owner), acl };
}

/** Reads back the effective ACL as raw text (evidence, and the input to the classifier). */
function readAclWindows(target) {
  return execFileSync('icacls', [target], {
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/**
 * Creates a directory only the owner can enter, failing closed when the restriction cannot be applied.
 * Idempotent: an existing directory is re-restricted and re-verified.
 * @param {string} dir absolute path
 * @returns {{dir: string, mode: number, acl: string|null}}
 */
function ensureOwnerOnlyDir(dir) {
  if (typeof dir !== 'string' || dir.length === 0) {
    throw new Error('ensureOwnerOnlyDir requires a directory path');
  }
  fs.mkdirSync(dir, { recursive: true, mode: OWNER_ONLY_DIR_MODE });
  let acl = null;
  if (isWindows()) {
    const verdict = restrictToOwnerWindows(dir);
    if (!verdict.ok) {
      throw new Error(aclRefusalMessage(verdict, 'directory'));
    }
    acl = verdict.acl;
  } else {
    fs.chmodSync(dir, OWNER_ONLY_DIR_MODE);
  }
  return { dir, mode: OWNER_ONLY_DIR_MODE, acl };
}

/**
 * Writes a file whose only reader is the owner.
 *
 * The Windows ACL is applied BEFORE the content is written: a file that exists for a moment with
 * inherited access is exactly the leak this function prevents. On POSIX the restrictive mode is passed
 * to `open` itself (no window exists) and re-asserted with `fchmod`.
 *
 * @param {string} file absolute path
 * @param {string|Buffer} content bytes to write
 * @param {object} [options]
 * @param {string} [options.owner] Windows principal for the ACL; defaults to the current account
 * @returns {{file: string, mode: number, bytes: number, acl: string|null, aclVerdict: object|null}}
 */
function writeOwnerOnlyFile(file, content, options = {}) {
  if (typeof file !== 'string' || file.length === 0) {
    throw new Error('writeOwnerOnlyFile requires a file path');
  }
  const dir = path.dirname(file);
  ensureOwnerOnlyDir(dir);
  const payload = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');

  if (isWindows()) {
    const handle = fs.openSync(file, 'w', OWNER_ONLY_FILE_MODE);
    fs.closeSync(handle);
    const verdict = restrictToOwnerWindows(file, options.owner);
    if (!verdict.ok) {
      throw new Error(aclRefusalMessage(verdict, 'file'));
    }
    const fd = fs.openSync(file, 'r+');
    try {
      fs.writeSync(fd, payload, 0, payload.length, 0);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return {
      file,
      mode: OWNER_ONLY_FILE_MODE,
      bytes: payload.length,
      acl: verdict.acl,
      aclVerdict: verdict,
    };
  }

  const fd = fs.openSync(file, 'w', OWNER_ONLY_FILE_MODE);
  try {
    fs.fchmodSync(fd, OWNER_ONLY_FILE_MODE);
    fs.writeSync(fd, payload, 0, payload.length, 0);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  return { file, mode: OWNER_ONLY_FILE_MODE, bytes: payload.length, acl: null, aclVerdict: null };
}

/**
 * Re-asserts and verifies the owner-only restriction on an existing file, returning the evidence a
 * caller can store. Throws when the restriction cannot be proven.
 * @param {string} file
 * @param {object} [options]
 * @param {string} [options.owner]
 * @returns {{file: string, mode: number, acl: string|null, principals: string[], foreign: string[],
 *   acceptablePlatformPrincipals: string[]}}
 */
function assertOwnerOnlyFile(file, options = {}) {
  const stat = fs.statSync(file);
  if (!stat.isFile()) {
    throw new Error('owner-only assertion requires a regular file');
  }
  if (isWindows()) {
    const verdict = restrictToOwnerWindows(file, options.owner);
    if (!verdict.ok) {
      throw new Error(aclRefusalMessage(verdict, 'file'));
    }
    return {
      file,
      mode: stat.mode & 0o777,
      acl: verdict.acl,
      principals: verdict.explicit.map((entry) => entry.principal),
      foreign: verdict.foreign,
      acceptablePlatformPrincipals: verdict.acceptablePlatformPrincipals,
    };
  }
  fs.chmodSync(file, OWNER_ONLY_FILE_MODE);
  const after = fs.statSync(file);
  if ((after.mode & 0o777) !== OWNER_ONLY_FILE_MODE) {
    throw new Error('owner-only mode was not applied');
  }
  return {
    file,
    mode: after.mode & 0o777,
    acl: null,
    principals: [ownerAccountName()],
    foreign: [],
    acceptablePlatformPrincipals: [],
  };
}

/**
 * Atomically replaces a file inside an owner-only directory: write `target.tmp`, fsync, rename over
 * the target, then fsync the directory. A crash therefore leaves either the old file or the new one,
 * never a truncated one — which is what makes the durable replay window trustworthy.
 * @param {string} target absolute path
 * @param {string|Buffer} content
 * @returns {{file: string, bytes: number}}
 */
function atomicReplaceOwnerOnlyFile(target, content) {
  const tmp = `${target}.tmp`;
  writeOwnerOnlyFile(tmp, content);
  fs.renameSync(tmp, target);
  if (!isWindows()) {
    const dirFd = fs.openSync(path.dirname(target), 'r');
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  }
  return { file: target, bytes: Buffer.byteLength(content) };
}

module.exports = {
  OWNER_ONLY_FILE_MODE,
  OWNER_ONLY_DIR_MODE,
  ACCEPTABLE_NON_OWNER_PRINCIPAL,
  isWindows,
  ownerAccountName,
  samePrincipal,
  isPlatformPrincipal,
  parseAcl,
  verifyOwnerOnlyAcl,
  restrictToOwnerWindows,
  readAclWindows,
  ensureOwnerOnlyDir,
  writeOwnerOnlyFile,
  assertOwnerOnlyFile,
  atomicReplaceOwnerOnlyFile,
};
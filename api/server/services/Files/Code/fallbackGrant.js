'use strict';

const crypto = require('node:crypto');

const PURPOSE = 'cbhr-code-output-project-download-v1';
const MAX_TOKEN_LENGTH = 4096;
const MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;
const invalid = () => new Error('CODE_PROJECT_FALLBACK_DENIED');

function signingKey() {
  const secret = process.env.JWT_SECRET;
  if (typeof secret !== 'string' || !secret.trim()) {
    throw new Error('CODE_PROJECT_FALLBACK_SIGNING_UNAVAILABLE');
  }
  // A purpose-separated signing key cannot be exchanged with login JWTs.
  return crypto.createHmac('sha256', secret).update(PURPOSE).digest();
}

function mac(body) {
  return crypto.createHmac('sha256', signingKey()).update(body).digest();
}

function normalizeTenant(value) {
  return value == null ? null : String(value);
}

/** Sign only a server-verified project execution context, never a client scope. */
function signProjectFallback({ req, outputScope, sessionId, fileId, expiresAt }) {
  if (
    outputScope?.kind !== 'project' ||
    typeof outputScope.id !== 'string' ||
    !outputScope.id.trim() ||
    !req?.user?.id ||
    !sessionId ||
    !fileId
  ) {
    throw invalid();
  }
  const now = Date.now();
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt > now + MAX_LIFETIME_MS) {
    throw invalid();
  }
  const payload = {
    v: 1,
    u: String(req.user.id),
    t: normalizeTenant(req.user.tenantId),
    w: outputScope.id,
    s: String(sessionId),
    f: String(fileId),
    iat: now,
    exp: expiresAt,
  };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return body + '.' + mac(body).toString('base64url');
}

/** Verify identity, tenant, requested file and expiry before any CodeAPI fetch. */
function verifyProjectFallback({ token, req, sessionId, fileId }) {
  if (
    typeof token !== 'string' ||
    token.length > MAX_TOKEN_LENGTH ||
    !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(token)
  ) {
    throw invalid();
  }
  const [body, signature] = token.split('.');
  const provided = Buffer.from(signature, 'base64url');
  const expected = mac(body);
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    throw invalid();
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    throw invalid();
  }
  const now = Date.now();
  if (
    !payload ||
    payload.v !== 1 ||
    typeof payload.u !== 'string' ||
    typeof payload.w !== 'string' ||
    !payload.w.trim() ||
    typeof payload.s !== 'string' ||
    typeof payload.f !== 'string' ||
    !Number.isSafeInteger(payload.iat) ||
    !Number.isSafeInteger(payload.exp) ||
    payload.iat > now + 60_000 ||
    payload.exp <= now ||
    payload.exp <= payload.iat ||
    payload.exp > payload.iat + MAX_LIFETIME_MS ||
    payload.u !== String(req?.user?.id ?? '') ||
    payload.t !== normalizeTenant(req?.user?.tenantId) ||
    payload.s !== String(sessionId) ||
    payload.f !== String(fileId)
  ) {
    throw invalid();
  }
  return { kind: 'project', id: payload.w };
}

module.exports = { signProjectFallback, verifyProjectFallback };

const crypto = require('crypto');
const fs = require('fs/promises');

function parseBearer(header) {
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1] : null;
}

function tokenMatches(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  if (expected.length < 32) return false;
  const actualBuffer = Buffer.from(provided);
  const expectedBuffer = Buffer.from(expected);
  return (
    actualBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

function createModelPolicyServiceAuth({ loadExpectedToken }) {
  if (typeof loadExpectedToken !== 'function') throw new TypeError('loadExpectedToken is required');
  return async function modelPolicyServiceAuth(req, res, next) {
    let expected;
    try {
      expected = String((await loadExpectedToken()) ?? '').trim();
    } catch {
      return res.status(503).json({ error: 'Model policy service authentication unavailable' });
    }
    if (expected.length < 32)
      return res.status(503).json({ error: 'Model policy service authentication unavailable' });
    const provided = parseBearer(req.get('Authorization'));
    if (!tokenMatches(provided, expected)) return res.status(401).json({ error: 'Unauthorized' });
    req.modelPolicyService = { authenticated: true };
    return next();
  };
}

function fileTokenLoader(filePath) {
  return async () => fs.readFile(filePath, 'utf8');
}

module.exports = { parseBearer, tokenMatches, createModelPolicyServiceAuth, fileTokenLoader };

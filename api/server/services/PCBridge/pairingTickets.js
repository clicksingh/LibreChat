'use strict';

/**
 * Single-use device pairing tickets. This module never returns user identity to
 * callers; the authenticated/claimed session coordinator consumes the ticket.
 *
 * Mongo is shared between API replicas. An atomic findOneAndUpdate guarantees
 * at-most-once redemption, without an in-memory lock.
 */
const crypto = require('node:crypto');

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_LENGTH = 12;
const TTL_MS = 3 * 60 * 1000;

function normalizeCode(value) {
  if (typeof value !== 'string') return null;
  const clean = value.replace(/[-\s]/g, '').toUpperCase();
  return clean.length === CODE_LENGTH && [...clean].every((char) => ALPHABET.includes(char))
    ? clean
    : null;
}

function generateCode(randomInt = crypto.randomInt) {
  return Array.from({ length: CODE_LENGTH }, () => ALPHABET[randomInt(ALPHABET.length)]).join('');
}

function digest(code) {
  return crypto
    .createHash('sha256')
    .update('cbhr-pc-pair-v1:' + code)
    .digest('hex');
}

function displayCode(code) {
  return code.match(/.{1,4}/g).join('-');
}

function createPairingTickets({
  collection,
  now = () => new Date(),
  randomInt = crypto.randomInt,
} = {}) {
  if (!collection || typeof collection.findOneAndUpdate !== 'function') {
    throw new TypeError('A shared Mongo collection is required');
  }

  async function ensureIndexes() {
    await collection.createIndex({ digest: 1 }, { unique: true, name: 'pc_ticket_digest' });
    await collection.createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 0, name: 'pc_ticket_ttl' },
    );
    await collection.createIndex(
      { userId: 1 },
      {
        unique: true,
        partialFilterExpression: { status: 'pending' },
        name: 'pc_ticket_one_pending_per_user',
      },
    );
  }

  async function issue({ userId }) {
    if (typeof userId !== 'string' || !/^[a-f\d]{24}$/i.test(userId)) {
      throw new TypeError('Authenticated user ID is required');
    }
    // A fresh browser code replaces the previous outstanding code.
    await collection.updateMany({ userId, status: 'pending' }, { $set: { status: 'cancelled' } });
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const code = generateCode(randomInt);
      const createdAt = now();
      const expiresAt = new Date(createdAt.getTime() + TTL_MS);
      try {
        await collection.insertOne({
          digest: digest(code),
          userId,
          status: 'pending',
          createdAt,
          expiresAt,
          claimedAt: null,
        });
        return { code: displayCode(code), expiresAt, expiresInSeconds: TTL_MS / 1000 };
      } catch (error) {
        if (error?.code !== 11000) throw error;
      }
    }
    throw new Error('Unable to allocate a unique pairing ticket');
  }

  async function claim({ code }) {
    const normalized = normalizeCode(code);
    if (!normalized) return null;
    const claimedAt = now();
    const result = await collection.findOneAndUpdate(
      { digest: digest(normalized), status: 'pending', expiresAt: { $gt: claimedAt } },
      { $set: { status: 'claimed', claimedAt } },
      { returnDocument: 'after' },
    );
    if (!result) return null;
    return { ticketId: String(result._id), userId: result.userId, claimedAt: result.claimedAt };
  }

  async function cancel({ userId, code }) {
    const normalized = normalizeCode(code);
    if (!normalized) return false;
    const result = await collection.updateOne(
      { userId, digest: digest(normalized), status: 'pending' },
      { $set: { status: 'cancelled' } },
    );
    return result.modifiedCount === 1;
  }

  return { ensureIndexes, issue, claim, cancel };
}

module.exports = {
  ALPHABET,
  CODE_LENGTH,
  TTL_MS,
  normalizeCode,
  generateCode,
  digest,
  displayCode,
  createPairingTickets,
};

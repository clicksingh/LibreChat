'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPairingTickets, normalizeCode, digest, CODE_LENGTH } = require('../pairingTickets');

const USER_A = '6a31557594ab025c7537576e';
const USER_B = '6a31557594ab025c7537576f';

function makeCollection() {
  const rows = [];
  let nextId = 1;
  const match = (row, query) =>
    Object.entries(query).every(([k, v]) => {
      if (v && typeof v === 'object' && '$gt' in v) return row[k] > v.$gt;
      return row[k] === v;
    });
  return {
    rows,
    async createIndex() {},
    async countDocuments(query) {
      return rows.filter((r) => match(r, query)).length;
    },
    async insertOne(doc) {
      if (rows.some((r) => r.digest === doc.digest)) {
        const error = new Error('duplicate');
        error.code = 11000;
        throw error;
      }
      rows.push({ _id: String(nextId++), ...doc });
    },
    async findOneAndUpdate(query, update) {
      const row = rows.find((r) => match(r, query));
      if (!row) return null;
      Object.assign(row, update.$set);
      return { ...row };
    },
    async updateMany(query, update) {
      const found = rows.filter((r) => match(r, query));
      found.forEach((r) => Object.assign(r, update.$set));
      return { modifiedCount: found.length };
    },
    async updateOne(query, update) {
      const row = rows.find((r) => match(r, query));
      if (!row) return { modifiedCount: 0 };
      Object.assign(row, update.$set);
      return { modifiedCount: 1 };
    },
  };
}

function fixture() {
  const collection = makeCollection();
  let time = new Date('2026-11-03T08:00:00Z');
  let cursor = 0;
  const service = createPairingTickets({
    collection,
    now: () => new Date(time),
    randomInt: (max) => (cursor++ * 7 + 3) % max,
  });
  return {
    service,
    collection,
    advance: (ms) => {
      time = new Date(time.getTime() + ms);
    },
  };
}

test('issues formatted code with a hash only in the database', async () => {
  const { service, collection } = fixture();
  const ticket = await service.issue({ userId: USER_A });
  assert.match(ticket.code, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  assert.equal(normalizeCode(ticket.code).length, CODE_LENGTH);
  assert.equal(ticket.expiresInSeconds, 180);
  assert.equal(collection.rows[0].digest, digest(normalizeCode(ticket.code)));
  assert.ok(!JSON.stringify(collection.rows).includes(ticket.code));
  assert.ok(!JSON.stringify(collection.rows).includes(normalizeCode(ticket.code)));
});

test('claim is single use even under simultaneous redemption', async () => {
  const { service } = fixture();
  const ticket = await service.issue({ userId: USER_A });
  const results = await Promise.all(
    Array.from({ length: 20 }, () => service.claim({ code: ticket.code })),
  );
  assert.equal(results.filter(Boolean).length, 1);
  assert.equal(results.find(Boolean).userId, USER_A);
});

test('expired and malformed codes cannot be redeemed', async () => {
  const { service, advance } = fixture();
  const ticket = await service.issue({ userId: USER_A });
  assert.equal(await service.claim({ code: 'not a code' }), null);
  advance(180001);
  assert.equal(await service.claim({ code: ticket.code }), null);
});

test('a newly generated code revokes the previous one', async () => {
  const { service } = fixture();
  const oldCode = await service.issue({ userId: USER_A });
  const fresh = await service.issue({ userId: USER_A });
  assert.equal(await service.claim({ code: oldCode.code }), null);
  assert.equal(await service.cancel({ userId: USER_B, code: fresh.code }), false);
  assert.equal(await service.cancel({ userId: USER_A, code: fresh.code }), true);
  assert.equal(await service.claim({ code: fresh.code }), null);
  const next = await service.issue({ userId: USER_A });
  assert.ok(next.code);
});

test('user identity must be an authenticated object ID', async () => {
  const { service } = fixture();
  await assert.rejects(service.issue({ userId: 'some-user' }), TypeError);
  await assert.rejects(service.issue({ userId: '' }), TypeError);
});

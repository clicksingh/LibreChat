'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { flattenFileSearchResults } = require('./fileSearchResults');

const files = [
  { file_id: 'first', filename: 'Policy.docx' },
  { file_id: 'second', filename: 'Manual.pdf' },
  { file_id: 'third', filename: 'Supplement.xlsx' },
];
const hit = (source, content, distance, page) =>
  [{ metadata: { source, page }, page_content: content }, distance];

test('first query error never shifts the identity of the successful second file', () => {
  const result = flattenFileSearchResults([
    null,
    { data: [hit('/private/Manual.pdf', 'The relevant policy', 0.1, 2)] },
  ], files);
  assert.equal(result.length, 1);
  assert.equal(result[0].file_id, 'second');
  assert.equal(result[0].filename, 'Manual.pdf');
  assert.equal(result[0].page, 2);
});

test('middle failure preserves source identities and relevance order', () => {
  const result = flattenFileSearchResults([
    { data: [hit('C:\\docs\\Policy.docx', 'Alpha', 0.5, 1)] },
    null,
    { data: [hit('Supplement.xlsx', 'Beta', 0.15, null)] },
  ], files);
  assert.deepEqual(result.map((r) => [r.file_id, r.content]), [
    ['third', 'Beta'],
    ['first', 'Alpha'],
  ]);
});

test('malformed responses never crash result formatting or misattribute citations', () => {
  const result = flattenFileSearchResults([
    { data: [['bad']] },
    { data: [hit('Manual.pdf', 'Good', 0.3, 0), [null, 0.2]] },
    { data: 'incorrect shape' },
  ], files);
  assert.deepEqual(result.map((r) => r.file_id), ['second']);
});

test('caps to top ten and does not expose absolute source paths as filenames', () => {
  const result = flattenFileSearchResults([
    { data: Array.from({ length: 20 }, (_, i) =>
      hit('/internal/secret/path/Policy.docx', String(i), i / 20, i + 1)) },
  ], files);
  assert.equal(result.length, 10);
  assert.equal(result[0].filename, 'Policy.docx');
  assert.equal(result[0].content, '0');
});

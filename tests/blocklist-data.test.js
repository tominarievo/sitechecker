'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('node:crypto');
const { parse, verify } = require('../blocklist-data.js');

const domains = Array.from({ length: 1000 }, (_, i) => `d${String(i).padStart(3, '0')}.example`);
const valid = {
  schemaVersion: 1,
  source: 'hagezi-fake',
  generatedAt: '2026-11-07T00:00:00.000Z',
  count: domains.length,
  sha256: crypto.createHash('sha256').update(domains.join('\n') + '\n').digest('hex'),
  domains,
};

test('dynamic feed accepts a sorted and correctly shaped domain list', () => {
  assert.equal(parse(valid), valid);
});

test('dynamic feed verifies its content hash', async () => {
  assert.equal(await verify(valid), valid);
  await assert.rejects(verify({ ...valid, sha256: 'a'.repeat(64) }), /SHA-256/);
});

test('dynamic feed rejects bad schema, count, timestamps, hostnames and ordering', () => {
  for (const data of [
    { ...valid, schemaVersion: 2 },
    { ...valid, source: 'untrusted-source' },
    { ...valid, generatedAt: '2026-02-31T00:00:00.000Z' },
    { ...valid, count: 999 },
    { ...valid, domains: ['not a domain', ...valid.domains.slice(1)] },
    { ...valid, domains: [...valid.domains].reverse() },
    { ...valid, domains: [...valid.domains.slice(0, -1), valid.domains[0]] },
  ]) assert.throws(() => parse(data));
});

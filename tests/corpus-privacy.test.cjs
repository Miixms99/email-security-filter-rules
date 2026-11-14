'use strict';
// Fails if any corpus sample contains personal data. The generic check always runs
// (also in CI, where config/private-identifiers.json does not exist); the private
// identifier check runs additionally when that local, gitignored file is present.
const assert = require('node:assert/strict');
const path = require('node:path');
const { readSamples, privacyFindings, validateSample } = require('../scripts/corpus.cjs');
const { loadPrivateIdentifiers } = require('../scripts/redact.cjs');

const samples = readSamples();
assert.ok(samples.length >= 1, 'corpus must contain samples');
const ids = new Set();
for (const { file, sample } of samples) {
  validateSample(sample);
  assert.equal(path.basename(file), sample.id + '.json', 'file name must equal the random sample id');
  assert.ok(!ids.has(sample.id)); ids.add(sample.id);
  assert.deepEqual(privacyFindings(sample, null), [], `${sample.id}: generic personal-data patterns`);
}
const identifiers = loadPrivateIdentifiers();
if (identifiers) for (const { sample } of samples) assert.deepEqual(privacyFindings(sample, identifiers), [], `${sample.id}: private identifiers`);

// The scanner itself must catch typical leaks (synthetic values only).
const base = samples[0].sample;
const leak = patch => privacyFindings({ ...base, ...patch }, { names: ['Alice Example'], emails: ['alice@example.org'] }).map(f => f.kind);
assert.ok(leak({ notes: 'contact bob@example.net' }).includes('email_address'));
assert.ok(leak({ notes: 'link https://evil.example/x?u=abc' }).includes('query_string'));
assert.ok(leak({ notes: 'call +31 6 12345678' }).includes('phone_number'));
assert.ok(leak({ notes: 'ref 12345678' }).includes('long_digit_run'));
assert.ok(leak({ notes: 'host 192.0.2.10' }).includes('ip_address'));
assert.ok(leak({ notes: 'Hi alice example' }).includes('private_identifier'));
assert.deepEqual(leak({ notes: 'marker 111.957097 and sq=111-957097 path' }).filter(k => k === 'long_digit_run'), [], 'campaign marker is allowed');
console.log(`Corpus privacy passed for ${samples.length} samples (generic check${identifiers ? ' + private identifiers' : '; private identifier file not present'}).`);

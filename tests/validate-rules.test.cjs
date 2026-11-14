'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { validateDocument, validateFiles } = require('../scripts/validate-rules.cjs');

const schema = JSON.parse(fs.readFileSync('rules/filter-rules.schema.json', 'utf8'));
const result = validateFiles();
assert.ok(result.rules >= 1);
assert.equal(result.schemaVersion, '1.0.0');

const document = JSON.parse(fs.readFileSync('rules/filter-rules.json', 'utf8'));
const clone = () => structuredClone(document);

assert.throws(() => validateDocument({ ...clone(), privacy: { ...document.privacy, privateDataAllowed: true } }, schema));
assert.throws(() => validateDocument({ ...clone(), activationPolicy: { ...document.activationPolicy, automaticMailboxActions: true } }, schema));
assert.throws(() => {
  const next = clone();
  next.rules = [...next.rules, { ...next.rules[0] }];
  validateDocument(next, schema);
});
assert.throws(() => {
  const next = clone();
  delete next.rules[0].indicators;
  validateDocument(next, schema);
});
assert.throws(() => {
  const next = clone();
  next.rules[0].verdictEffect = 'Contact victim@example.com for details.';
  validateDocument(next, schema);
});

const extended = clone();
extended.rules.push({
  id: 'synthetic.forward-compatible.v1',
  status: 'signal_only',
  category: 'authentication_failure',
  indicators: { authResults: ['dmarc=fail'], lookalikes: true },
  requiredCombination: 'Synthetic extension fields must remain schema-compatible.',
  verdictEffect: 'Review signal only.',
  privateDataExcluded: true,
  extraDocumentation: 'allowed'
});
assert.equal(validateDocument(extended, schema).rules, document.rules.length + 1);
console.log('Rule schema validator: current document, policy rejections, and forward-compatible extension passed.');

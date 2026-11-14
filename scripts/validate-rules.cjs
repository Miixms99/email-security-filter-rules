'use strict';
// Validates the public rule document only. Never reads mail or private local state.
const fs = require('node:fs');
const path = require('node:path');

function fail(message) { throw new Error(message); }

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function resolveRef(schema, root) {
  if (!schema || typeof schema !== 'object' || typeof schema.$ref !== 'string') return schema;
  const ref = schema.$ref;
  if (!ref.startsWith('#/$defs/')) fail('Unsupported schema reference: ' + ref);
  const def = root.$defs?.[ref.slice('#/$defs/'.length)];
  if (!def) fail('Missing schema definition: ' + ref);
  return def;
}

function validateAgainstSchema(value, schema, root, pointer) {
  schema = resolveRef(schema, root);
  if (schema.type && typeOf(value) !== schema.type) fail(`${pointer} must be ${schema.type}`);
  if (Object.hasOwn(schema, 'const') && value !== schema.const) fail(`${pointer} must be ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) fail(`${pointer} must be one of ${schema.enum.join(', ')}`);
  if (schema.type === 'string') {
    if (schema.minLength && value.length < schema.minLength) fail(`${pointer} is shorter than ${schema.minLength}`);
    if (schema.maxLength && value.length > schema.maxLength) fail(`${pointer} is longer than ${schema.maxLength}`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) fail(`${pointer} does not match ${schema.pattern}`);
  }
  if (schema.type === 'array') {
    if (schema.minItems && value.length < schema.minItems) fail(`${pointer} must contain at least ${schema.minItems} item(s)`);
    if (schema.items) value.forEach((item, index) => validateAgainstSchema(item, schema.items, root, `${pointer}/${index}`));
  }
  if (schema.type === 'object') {
    if (schema.minProperties && Object.keys(value).length < schema.minProperties) fail(`${pointer} must have at least ${schema.minProperties} propert${schema.minProperties === 1 ? 'y' : 'ies'}`);
    for (const key of schema.required || []) {
      if (!Object.hasOwn(value, key)) fail(`${pointer} missing required property ${key}`);
    }
    const properties = schema.properties || {};
    for (const [key, child] of Object.entries(value)) {
      if (properties[key]) validateAgainstSchema(child, properties[key], root, `${pointer}/${key}`);
      else if (schema.additionalProperties === false) fail(`${pointer} has unexpected property ${key}`);
    }
  }
}

function walkStrings(value, pointer, visit) {
  if (typeof value === 'string') visit(value, pointer);
  else if (Array.isArray(value)) value.forEach((item, index) => walkStrings(item, `${pointer}/${index}`, visit));
  else if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) walkStrings(child, `${pointer}/${key}`, visit);
  }
}

function assertNoPrivateData(document) {
  const email = /(?:^|[\s<("'])[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+(?:$|[\s>("'])/;
  const messageId = /<[^<>\s@]+@[^<>\s@]+>/;
  const secret = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xox[abprs]-|Bearer\s+[A-Za-z0-9._-]{16,})\b/;
  walkStrings(document, '#', (value, pointer) => {
    if (email.test(value) || messageId.test(value) || secret.test(value)) fail(`${pointer} appears to contain private data`);
  });
}

// Every enabled rule must load into the analyzer exactly as fetch-rules delivers it,
// so a rule shape the analyzer cannot accept fails CI instead of crashing at runtime.
function assertRuntimeLoadable(document) {
  const { runtimeRuleSet } = require('./rule-learning.cjs');
  const { normalizeCampaignRules } = require('./Controle-Email.cjs');
  const { normalizeSenderRules, normalizeSignalRules } = require('./signals.cjs');
  const set = runtimeRuleSet(document);
  normalizeCampaignRules(set.campaignRules);
  normalizeSenderRules(set.senderRules);
  normalizeSignalRules(set.signalRules);
  const scale = document.severityScale;
  for (const [index, rule] of document.rules.entries()) {
    if (scale && rule.severity && Number.isFinite(rule.weight) && scale[rule.severity]?.weight !== rule.weight) fail(`#/rules/${index} weight ${rule.weight} does not match severity ${rule.severity}`);
  }
  return set;
}

function validateDocument(document, schema) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) fail('Rule document must be an object');
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) fail('Schema must be an object');
  validateAgainstSchema(document, schema, schema, '#');
  const ids = new Set();
  for (const [index, rule] of document.rules.entries()) {
    if (ids.has(rule.id)) fail(`#/rules/${index}/id duplicates ${rule.id}`);
    ids.add(rule.id);
  }
  assertNoPrivateData(document);
  assertRuntimeLoadable(document);
  return { rules: document.rules.length, schemaVersion: document.schemaVersion, filterRevision: document.filterRevision };
}

function validateFiles(root = path.resolve(__dirname, '..')) {
  const document = JSON.parse(fs.readFileSync(path.join(root, 'rules/filter-rules.json'), 'utf8'));
  const schema = JSON.parse(fs.readFileSync(path.join(root, 'rules/filter-rules.schema.json'), 'utf8'));
  return validateDocument(document, schema);
}

if (require.main === module) {
  const result = validateFiles();
  console.log(`Validated ${result.rules} rules against filter-rules.schema.json (revision ${result.filterRevision}).`);
}

module.exports = { validateDocument, validateFiles, assertRuntimeLoadable, validateAgainstSchema };

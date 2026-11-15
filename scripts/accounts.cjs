'use strict';
// Local mailbox account list. Optional, gitignored when real. Never stores
// secrets, addresses or tokens. Used to remember which Gmail and Outlook
// mailboxes you manage with this package (one or several per provider).
const fs = require('node:fs');
const path = require('node:path');
const { validateAgainstSchema } = require('./validate-rules.cjs');

const ROOT = path.resolve(__dirname, '..');
const SECRET_KEY = /password|passwd|secret|token|apikey|api_key|authorization|cookie|credential|refresh|client_secret|private_key/i;
const EMAIL_LIKE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

function defaultRoot() {
  return process.env.ESF_ROOT ? path.resolve(process.env.ESF_ROOT) : ROOT;
}

function paths(root = defaultRoot()) {
  return {
    root,
    file: path.join(root, 'config/accounts.json'),
    example: path.join(root, 'config/accounts.example.json'),
    schema: path.join(root, 'config/accounts.schema.json')
  };
}

function fail(message) { throw new Error(message); }

function loadSchema(p = paths()) {
  return JSON.parse(fs.readFileSync(p.schema, 'utf8'));
}

function assertNoSecretsOrAddresses(value, pointer = '#') {
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertNoSecretsOrAddresses(item, `${pointer}/${i}`));
    return;
  }
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string' && EMAIL_LIKE.test(value)) {
      fail(`${pointer} looks like an email address; use a short label, never an address`);
    }
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) fail(`${pointer}/${key} is not allowed (no secrets or credentials in this file)`);
    assertNoSecretsOrAddresses(child, `${pointer}/${key}`);
  }
}

function validateAccounts(document, schema) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) fail('Accounts document must be an object');
  const sch = schema || loadSchema();
  validateAgainstSchema(document, sch, sch, '#');
  assertNoSecretsOrAddresses(document);
  const ids = new Set();
  for (const [i, account] of document.accounts.entries()) {
    if (ids.has(account.id)) fail(`#/accounts/${i}/id is not unique (${account.id})`);
    ids.add(account.id);
  }
  return document;
}

function loadAccountsFile(file, schema) {
  const document = JSON.parse(fs.readFileSync(file, 'utf8'));
  return validateAccounts(document, schema);
}

function loadAccounts(options = {}) {
  const p = paths(options.root || defaultRoot());
  const schema = loadSchema(p);
  const file = options.file ? path.resolve(options.file) : p.file;
  if (fs.existsSync(file)) {
    return { source: 'file', path: file, document: loadAccountsFile(file, schema) };
  }
  if (options.requireFile) fail(`No accounts file at ${file}. Copy config/accounts.example.json to config/accounts.json and edit the labels.`);
  return { source: 'missing', path: file, document: null };
}

function loadExample(options = {}) {
  const p = paths(options.root || defaultRoot());
  return { source: 'example', path: p.example, document: loadAccountsFile(p.example, loadSchema(p)) };
}

function isEnabled(account) {
  return account.enabled !== false;
}

function enabledAccounts(document) {
  return (document?.accounts || []).filter(isEnabled);
}

function accountsByProvider(document, provider) {
  return enabledAccounts(document).filter((account) => account.provider === provider);
}

function usage() {
  return `Usage:
  node scripts/accounts.cjs --check
  node scripts/accounts.cjs --list

--check validates config/accounts.json when present, and always validates
config/accounts.example.json. Missing accounts.json is fine (the file is
optional and gitignored).

--list prints enabled accounts from config/accounts.json, or explains how
to create it. Never put passwords, tokens or email addresses in this file.`;
}

function formatList(document, source) {
  const rows = enabledAccounts(document);
  if (!rows.length) return 'No enabled accounts.';
  const lines = [`${rows.length} enabled account(s) (${source}):`];
  for (const account of rows) {
    const gambling = account.options?.treatUnsolicitedGamblingAsSpam ? ', treat unsolicited gambling as spam' : '';
    lines.push(`- ${account.id} [${account.provider}] ${account.label}${gambling}`);
  }
  const disabled = (document.accounts || []).filter((account) => !isEnabled(account)).length;
  if (disabled) lines.push(`(${disabled} disabled)`);
  return lines.join('\n');
}

function main(argv = process.argv.slice(2), options = {}) {
  const root = options.root || defaultRoot();
  if (argv.includes('--help') || argv.includes('-h') || argv.length === 0) {
    console.log(usage());
    return 0;
  }
  const check = argv.includes('--check');
  const list = argv.includes('--list');
  if (!check && !list) fail(usage());

  const example = loadExample({ root });
  if (check) console.log(`Example accounts file is valid (${example.document.accounts.length} entries).`);

  const loaded = loadAccounts({ root });
  if (loaded.document) {
    if (check) console.log(`Local accounts file is valid (${loaded.document.accounts.length} entries) at ${path.relative(root, loaded.path) || loaded.path}.`);
    if (list) console.log(formatList(loaded.document, path.relative(root, loaded.path) || loaded.path));
  } else {
    if (check) console.log('No config/accounts.json yet (optional). Copy config/accounts.example.json to config/accounts.json and edit the labels.');
    if (list) {
      console.log('No config/accounts.json yet. Copy the example and edit the labels:');
      console.log('  cp config/accounts.example.json config/accounts.json');
      console.log('Showing the example list until you do:');
      console.log(formatList(example.document, 'config/accounts.example.json'));
    }
  }
  return 0;
}

if (require.main === module) {
  try {
    process.exit(main() ?? 0);
  } catch (error) {
    console.error(error.message || error);
    process.exit(1);
  }
}

module.exports = {
  ROOT, EMAIL_LIKE,
  paths, loadSchema, validateAccounts, loadAccounts, loadExample,
  isEnabled, enabledAccounts, accountsByProvider, formatList, main
};

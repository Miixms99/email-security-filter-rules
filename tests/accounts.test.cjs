'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const {
  paths, loadExample, loadAccounts, validateAccounts, loadSchema,
  enabledAccounts, accountsByProvider, formatList
} = require('../scripts/accounts.cjs');

const repo = paths();
const schema = loadSchema(repo);

// The committed example is valid, has both providers, and contains no addresses or secrets.
const example = loadExample();
assert.equal(example.source, 'example');
assert.equal(example.document.schemaVersion, 1);
const providers = new Set(example.document.accounts.map((a) => a.provider));
assert.ok(providers.has('gmail') && providers.has('outlook'));
assert.ok(example.document.accounts.length >= 2);
assert.ok(enabledAccounts(example.document).length >= 1);
assert.ok(accountsByProvider(example.document, 'gmail').length >= 1);
const exampleText = fs.readFileSync(repo.example, 'utf8');
assert.equal(exampleText.includes('@'), false, 'accounts example must not contain @ (no addresses)');
assert.doesNotMatch(exampleText, /password|token|secret|apikey/i);

// Real accounts.json is optional; if present (local only) it must also validate.
const local = loadAccounts();
if (local.document) {
  assert.equal(local.source, 'file');
  validateAccounts(local.document, schema);
}

// Validation rejects bad providers, duplicate ids, secret keys and email-like labels.
assert.throws(() => validateAccounts({ schemaVersion: 1, accounts: [{ id: 'a', provider: 'yahoo', label: 'Nope' }] }, schema), /enum|provider/i);
assert.throws(() => validateAccounts({
  schemaVersion: 1,
  accounts: [
    { id: 'same', provider: 'gmail', label: 'One' },
    { id: 'same', provider: 'outlook', label: 'Two' }
  ]
}, schema), /not unique/);
assert.throws(() => validateAccounts({
  schemaVersion: 1,
  accounts: [{ id: 'x', provider: 'gmail', label: 'Home', password: 'nope' }]
}, schema), /not allowed|unexpected property/i);
assert.throws(() => validateAccounts({
  schemaVersion: 1,
  accounts: [{ id: 'x', provider: 'gmail', label: 'me@example.com' }]
}, schema), /email address/);

// CLI --check accepts the example when no local file is in a temp root.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'esf-accounts-'));
fs.cpSync(path.join(repo.root, 'config'), path.join(tmp, 'config'), { recursive: true });
fs.rmSync(path.join(tmp, 'config/accounts.json'), { force: true });
const env = { ...process.env, ESF_ROOT: tmp };
const check = spawnSync(process.execPath, [path.join(repo.root, 'scripts/accounts.cjs'), '--check'], {
  cwd: tmp, encoding: 'utf8', env
});
assert.equal(check.status, 0, check.stderr);
assert.match(check.stdout, /Example accounts file is valid/);
assert.match(check.stdout, /No config\/accounts\.json yet/);

const list = spawnSync(process.execPath, [path.join(repo.root, 'scripts/accounts.cjs'), '--list'], {
  cwd: tmp, encoding: 'utf8', env
});
assert.equal(list.status, 0, list.stderr);
assert.match(list.stdout, /Personal Gmail/);

fs.writeFileSync(path.join(tmp, 'config/accounts.json'), JSON.stringify({
  schemaVersion: 1,
  accounts: [
    { id: 'home-gmail', provider: 'gmail', label: 'Home Gmail', enabled: true },
    { id: 'work-outlook', provider: 'outlook', label: 'Work Outlook', enabled: false }
  ]
}, null, 2));
const listed = spawnSync(process.execPath, [path.join(repo.root, 'scripts/accounts.cjs'), '--list'], {
  cwd: tmp, encoding: 'utf8', env
});
assert.equal(listed.status, 0, listed.stderr);
assert.match(listed.stdout, /home-gmail \[gmail] Home Gmail/);
assert.match(listed.stdout, /1 disabled/);
assert.doesNotMatch(listed.stdout, /Work Outlook/);

assert.match(formatList(example.document, 'example'), /enabled account/);

fs.rmSync(tmp, { recursive: true, force: true });
console.log('Accounts config validation and CLI tests passed.');

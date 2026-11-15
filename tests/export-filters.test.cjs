'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const rules = require('../rules/filter-rules.json');
const {
  collectSignals, isSharedInfrastructure, buildGmailXml, buildOutlookText,
  exportFilters, writeExport
} = require('../scripts/export-filters.cjs');

const root = path.resolve(__dirname, '..');
const script = path.join(root, 'scripts/export-filters.cjs');

function assertWellFormedXml(xml) {
  assert.ok(xml.startsWith("<?xml version='1.0' encoding='UTF-8'?>"));
  assert.ok(xml.includes("xmlns='http://www.w3.org/2005/Atom'"));
  assert.ok(xml.includes("xmlns:apps='http://schemas.google.com/apps/2006'"));
  const stack = [];
  const token = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<\/?([A-Za-z0-9:]+)([^>]*)>/g;
  let match;
  while ((match = token.exec(xml))) {
    const raw = match[0];
    if (raw.startsWith('<!--') || raw.startsWith('<?')) continue;
    const name = match[1];
    const attrs = match[2] || '';
    if (raw.startsWith('</')) {
      assert.equal(stack.pop(), name, `mismatched closing tag ${name}`);
    } else if (!attrs.trim().endsWith('/')) {
      stack.push(name);
    }
  }
  assert.deepEqual(stack, [], 'unclosed XML tags: ' + stack.join(', '));
}

function propertyValues(xml, name) {
  const values = [];
  const re = new RegExp(`<apps:property name='${name}' value='([^']*)'/>`, 'g');
  let match;
  while ((match = re.exec(xml))) values.push(match[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>'));
  return values;
}

const live = collectSignals(rules);
assert.equal(live.filterRevision, rules.filterRevision);
assert.ok(live.markers.length >= 2, 'expected campaign markers');
assert.ok(live.domains.length >= 4, 'expected listed sender domains');
assert.ok(live.markers.some((item) => item.value === '111.957097'));
assert.ok(live.markers.some((item) => item.value === '111-957097'));
assert.ok(live.domains.some((item) => item.value === 'cloudtivo2.biz'));
assert.ok(live.domains.some((item) => item.value === 'ravenstone.pro'));
assert.ok(live.domains.every((item) => item.ruleId === 'campaign.repeated-malicious-sender-domain.v1'));

// Shared infrastructure, including the campaign supporting host, must never be exported.
assert.equal(isSharedInfrastructure('storage.googleapis.com'), true);
assert.equal(isSharedInfrastructure('googleapis.com'), true);
assert.equal(isSharedInfrastructure('outlook.com'), true);
assert.equal(isSharedInfrastructure('cloudtivo2.biz'), false);
assert.ok(live.skippedHosts.some((item) => item.value === 'storage.googleapis.com'));
assert.ok(!live.domains.some((item) => item.value.includes('googleapis')));
assert.ok(!live.domains.some((item) => isSharedInfrastructure(item.value)));

const { xml, entryCount } = buildGmailXml(live);
assertWellFormedXml(xml);
assert.equal(entryCount, live.markers.length + live.domains.length);
const xmlEmails = xml.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || [];
assert.deepEqual([...new Set(xmlEmails)], ['filters@example.com'], 'Gmail XML may only contain the example.com author placeholder');
assert.ok(xml.includes('filters@example.com'));
assert.ok(xml.includes('shouldTrash'));
const phrases = propertyValues(xml, 'hasTheWord');
assert.ok(phrases.includes('"111.957097"'));
assert.ok(phrases.includes('"111-957097"'));
const froms = propertyValues(xml, 'from');
assert.deepEqual([...froms].sort(), live.domains.map((item) => item.value).sort());
assert.ok(!froms.includes('storage.googleapis.com'));

const outlook = buildOutlookText(live);
assert.match(outlook, /## Blocked domains/);
assert.match(outlook, /111-957097/);
assert.match(outlook, /cloudtivo2\.biz/);
assert.ok(!outlook.includes('storage.googleapis.com'));
assert.doesNotMatch(outlook, /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
assert.match(outlook, /permanently delete/i);

// Disabled rules and supporting-only hosts are ignored; regex/brand signals stay out of the import lists.
const synthetic = collectSignals({
  filterRevision: '2026-01-01.0',
  generatedAt: '2026-01-01T00:00:00Z',
  rules: [
    { id: 'campaign.repeated-malicious-sender-domain.v1', status: 'signal_only', indicators: { senderDomains: ['evil-example.test', 'storage.googleapis.com'] } },
    { id: 'campaign.marker-and-path.v1', status: 'signal_only', indicators: { markers: ['111.957097'], hosts: ['storage.googleapis.com'] } },
    { id: 'disabled.domain', status: 'disabled', indicators: { senderDomains: ['should-not-export.test'] } },
    { id: 'candidate.domain', status: 'candidate', indicators: { senderDomains: ['also-not-export.test'] } }
  ]
});
assert.deepEqual(synthetic.domains.map((item) => item.value), ['evil-example.test']);
assert.ok(!synthetic.domains.some((item) => item.value === 'should-not-export.test'));
assert.ok(synthetic.skippedHosts.some((item) => item.value === 'storage.googleapis.com'));

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'esf-export-'));
const outDir = path.join(tmp, 'export');
const files = exportFilters({ root });
assert.deepEqual(files.providers, ['gmail', 'outlook']);
const written = writeExport(files, outDir);
assert.equal(written.length, 4);
assert.equal(fs.readFileSync(path.join(outDir, 'mailFilters.xml'), 'utf8'), files.gmailXml);
assert.ok(fs.readFileSync(path.join(outDir, 'EXPORT-REVIEW.txt'), 'utf8').includes('Review every entry'));
const manifest = JSON.parse(fs.readFileSync(path.join(outDir, 'export-manifest.json'), 'utf8'));
assert.equal(manifest.optional, true);
assert.equal(manifest.reviewRequired, true);
assert.equal(manifest.automaticMailboxActions, false);
assert.equal(manifest.includesSharedInfrastructure, false);
assert.equal(manifest.filterRevision, rules.filterRevision);

const cli = spawnSync(process.execPath, [script, '--out-dir', outDir], { cwd: root, encoding: 'utf8' });
assert.equal(cli.status, 0, cli.stderr);
assert.match(cli.stdout, /Review EXPORT-REVIEW\.txt/);
assert.match(cli.stdout, /Nothing was applied to a mailbox/);

const stdoutCli = spawnSync(process.execPath, [script, '--stdout', '--provider', 'gmail'], { cwd: root, encoding: 'utf8' });
assert.equal(stdoutCli.status, 0, stdoutCli.stderr);
assertWellFormedXml(stdoutCli.stdout);
assert.ok(stdoutCli.stdout.includes('111-957097'));

// --accounts with only Outlook enabled skips the Gmail XML.
const accRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'esf-export-acc-'));
fs.cpSync(path.join(root, 'rules'), path.join(accRoot, 'rules'), { recursive: true });
fs.mkdirSync(path.join(accRoot, 'config'), { recursive: true });
fs.copyFileSync(path.join(root, 'config/accounts.example.json'), path.join(accRoot, 'config/accounts.example.json'));
fs.copyFileSync(path.join(root, 'config/accounts.schema.json'), path.join(accRoot, 'config/accounts.schema.json'));
fs.writeFileSync(path.join(accRoot, 'config/accounts.json'), JSON.stringify({
  schemaVersion: 1,
  accounts: [{ id: 'only-outlook', provider: 'outlook', label: 'Home Outlook', enabled: true }]
}));
const limited = exportFilters({ root: accRoot, useAccounts: true });
assert.deepEqual(limited.providers, ['outlook']);
assert.equal(limited.gmailXml, undefined);
assert.ok(limited.outlookText.includes('Blocked domains'));

const noEnabledRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'esf-export-none-'));
fs.cpSync(path.join(accRoot, 'rules'), path.join(noEnabledRoot, 'rules'), { recursive: true });
fs.cpSync(path.join(accRoot, 'config'), path.join(noEnabledRoot, 'config'), { recursive: true });
fs.writeFileSync(path.join(noEnabledRoot, 'config/accounts.json'), JSON.stringify({
  schemaVersion: 1,
  accounts: [{ id: 'paused', provider: 'gmail', label: 'Paused', enabled: false }]
}));
const none = spawnSync(process.execPath, [script, '--accounts', '--out-dir', path.join(noEnabledRoot, 'export')], {
  cwd: noEnabledRoot, encoding: 'utf8', env: { ...process.env, ESF_ROOT: noEnabledRoot }
});
assert.notEqual(none.status, 0);
assert.match(none.stderr, /No enabled Gmail or Outlook accounts/);

fs.rmSync(tmp, { recursive: true, force: true });
fs.rmSync(accRoot, { recursive: true, force: true });
fs.rmSync(noEnabledRoot, { recursive: true, force: true });
console.log('Filter export (Gmail XML, Outlook list, shared-host exclusion) tests passed.');

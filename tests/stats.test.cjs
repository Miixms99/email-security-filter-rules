'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { validateAgainstSchema } = require('../scripts/validate-rules.cjs');
const {
  paths, loadStats, saveStats, validateStats, record, render, renderBlock,
  deriveFromRepo, nowAmsterdamIso, START, END, reset, initLocal, isPublicStatsFile, emptyDocument
} = require('../scripts/stats.cjs');
const { loadPrivateIdentifiers } = require('../scripts/redact.cjs');

const repo = paths();
const schema = JSON.parse(fs.readFileSync(repo.schema, 'utf8'));
const live = loadStats(repo);

// Live document matches the schema and derived repository values.
const derived = deriveFromRepo(repo, live.derived);
assert.equal(live.derived.activeRuleCount, derived.activeRuleCount);
assert.equal(live.derived.filterRevision, derived.filterRevision);
assert.deepEqual(live.derived.corpusSamples, derived.corpusSamples);
assert.ok(live.derived.mergedRulePrCount >= 1);
assert.equal(live.totals.mailsChecked, live.providers.gmail.mailsChecked + live.providers.outlook.mailsChecked);

// Schema rejects negatives and unknown keys.
const badNegative = structuredClone(live);
badNegative.totals.phishing = -1;
assert.throws(() => validateAgainstSchema(badNegative, schema, schema, '#'), /below 0|integer/i);
assert.throws(() => validateStats(badNegative, schema));

const badUnknown = structuredClone(live);
badUnknown.extra = 1;
assert.throws(() => validateAgainstSchema(badUnknown, schema, schema, '#'), /unexpected property/i);

const badProviderKey = structuredClone(live);
badProviderKey.providers.gmail.senderEmails = ['a@b.c'];
assert.throws(() => validateAgainstSchema(badProviderKey, schema, schema, '#'), /unexpected property/i);

const badMailsChecked = structuredClone(live);
badMailsChecked.totals.mailsChecked = 0;
assert.throws(() => validateStats(badMailsChecked, schema), /categorised sum/);

// Record arithmetic on an isolated copy of the repository stats and schema.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'esf-stats-'));
fs.cpSync(path.join(repo.root, 'stats'), path.join(tmp, 'stats'), { recursive: true });
fs.cpSync(path.join(repo.root, 'rules'), path.join(tmp, 'rules'), { recursive: true });
fs.cpSync(path.join(repo.root, 'corpus'), path.join(tmp, 'corpus'), { recursive: true });
const starter = 'Intro.\n\n' + START + '\nplaceholder\n' + END + '\n\n## Questions, ideas and problems\n';
fs.writeFileSync(path.join(tmp, 'README.md'), starter);
const before = loadStats(paths(tmp));

const run = {
  lastCheck: '2026-11-15T18:00:00+01:00',
  gmail: { mailsChecked: 3, phishing: 1, spam: 2, sendersBlocked: 3, reportedToProvider: 1, movedToTrash: 3 },
  outlook: { mailsChecked: 2, spam: 2, sendersBlocked: 1, domainsBlocked: 1, movedToTrash: 2 }
};
const { document: after, checkedProviders } = record(run, { root: tmp });
assert.deepEqual(checkedProviders, ['gmail', 'outlook']);
assert.equal(after.totals.mailsChecked, before.totals.mailsChecked + 5);
assert.equal(after.totals.phishing, before.totals.phishing + 1);
assert.equal(after.totals.spam, before.totals.spam + 4);
assert.equal(after.totals.sendersBlocked, before.totals.sendersBlocked + 4);
assert.equal(after.totals.domainsBlocked, before.totals.domainsBlocked + 1);
assert.equal(after.totals.reportedToProvider, before.totals.reportedToProvider + 1);
assert.equal(after.totals.movedToTrash, before.totals.movedToTrash + 5);
assert.equal(after.totals.spamChecksRun, before.totals.spamChecksRun + 1);
assert.equal(after.providers.gmail.phishing, before.providers.gmail.phishing + 1);
assert.equal(after.providers.outlook.spam, before.providers.outlook.spam + 2);
assert.equal(after.providers.gmail.spamChecksRun, before.providers.gmail.spamChecksRun + 1);
assert.equal(after.providers.outlook.spamChecksRun, before.providers.outlook.spamChecksRun + 1);
assert.equal(after.lastCheck, '2026-11-15T18:00:00+01:00');

assert.throws(() => record({ gmail: { phishing: -2 } }, { root: tmp }), /non-negative integer/);
assert.throws(() => record({ yahoo: { spam: 1 } }, { root: tmp }), /Unknown record property/);
assert.throws(() => record({ gmail: { subject: 'hello' } }, { root: tmp }), /Unknown record property/);
assert.throws(() => record({ gmail: { spam: 5, mailsChecked: 1 } }, { root: tmp }), /categorised sum/);

// Render is idempotent, and --check accepts a block it just wrote.
const first = render({ root: tmp });
const second = render({ root: tmp });
assert.equal(second.changed, false);
assert.equal(first.block, second.block);
const written = fs.readFileSync(path.join(tmp, 'README.md'), 'utf8');
assert.equal(written, written.replace(first.block, first.block));
assert.ok(written.includes(START) && written.includes(END));
assert.ok(written.includes('## Project status'));
assert.equal(written, replaceOnce(starter, first.block));
assert.equal(render({ root: tmp, check: true }).changed, false);
fs.writeFileSync(path.join(tmp, 'README.md'), written.replace('Mails checked', 'Mails processed'));
assert.throws(() => render({ root: tmp, check: true }), /out of sync/);
const unsynced = spawnSync(process.execPath, [path.join(repo.root, 'scripts/stats.cjs'), '--render', '--check'], {
  cwd: repo.root, encoding: 'utf8', env: { ...process.env, ESF_STATS_ROOT: tmp }
});
assert.notEqual(unsynced.status, 0);
assert.match(unsynced.stderr, /out of sync/);

function replaceOnce(readme, block) {
  const start = readme.indexOf(START);
  const end = readme.indexOf(END);
  return readme.slice(0, start) + START + '\n' + block + END + '\n' + readme.slice(end + END.length).replace(/^\r?\n/, '');
}

// Rendered block must not contain email addresses or owner identifiers.
const block = renderBlock(live);
assert.equal(block.includes('@'), false, 'rendered status block must not contain @ (no email addresses)');
assert.match(block, /since 14 November 2026/);
assert.match(block, /Updated automatically by Grok Bot after every daily spam check/);
assert.match(block, /img\.shields\.io\/badge\//);
assert.doesNotMatch(block, /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
const identifiers = loadPrivateIdentifiers();
if (identifiers) {
  const lower = block.toLowerCase();
  for (const name of identifiers.names || []) {
    assert.equal(lower.includes(String(name).toLowerCase()), false, 'rendered block contains a private name');
  }
  for (const email of identifiers.emails || []) {
    assert.equal(lower.includes(String(email).toLowerCase()), false, 'rendered block contains a private address');
  }
}

// Timestamp helper produces an explicit numeric offset (not Z).
assert.match(nowAmsterdamIso(new Date('2026-11-15T12:00:00Z')), /^2026-11-15T13:00:00\+01:00$/);

// --init-local writes a gitignored-style local file and never overwrites public stats.
const localPath = path.join(tmp, 'stats/local-stats.json');
const initialized = initLocal(localPath, { root: tmp, now: new Date('2026-11-15T12:00:00Z') });
assert.equal(initialized.path, localPath);
assert.equal(initialized.document.totals.mailsChecked, 0);
assert.equal(initialized.document.providers.gmail.phishing, 0);
assert.equal(initialized.document.trackingSince, '2026-11-15');
assert.equal(initialized.document.notes.includes('@'), false);
const publicBefore = loadStats(paths(tmp));
assert.ok(publicBefore.totals.mailsChecked > 0);
assert.throws(() => initLocal(path.join(tmp, 'stats/stats.json'), { root: tmp }), /Refusing to initialize the public/);

// Recording to a local file does not rewrite the README status block.
const localRecord = spawnSync(process.execPath, [
  path.join(repo.root, 'scripts/stats.cjs'), '--file', localPath, '--record',
  JSON.stringify({ gmail: { mailsChecked: 2, spam: 2, sendersBlocked: 2, movedToTrash: 2 } })
], { cwd: tmp, encoding: 'utf8', env: { ...process.env, ESF_STATS_ROOT: tmp, ESF_STATS_FILE: '' } });
assert.equal(localRecord.status, 0, localRecord.stderr);
assert.match(localRecord.stdout, /Skipped README render because this is a local stats file/);
const localAfter = JSON.parse(fs.readFileSync(localPath, 'utf8'));
assert.equal(localAfter.totals.mailsChecked, 2);
assert.equal(loadStats(paths(tmp)).totals.mailsChecked, publicBefore.totals.mailsChecked);
assert.throws(() => render({ root: tmp, statsFile: localPath }), /Refusing to render the repository README from a local stats file/);

// --reset --yes zeros the selected file only.
const resetLocal = reset({ root: tmp, statsFile: localPath, now: new Date('2026-11-16T09:00:00Z') });
assert.equal(resetLocal.totals.mailsChecked, 0);
assert.equal(resetLocal.providers.outlook.spam, 0);
assert.equal(resetLocal.trackingSince, '2026-11-16');
assert.equal(loadStats(paths(tmp)).totals.mailsChecked, publicBefore.totals.mailsChecked);

const resetCli = spawnSync(process.execPath, [path.join(repo.root, 'scripts/stats.cjs'), '--reset'], {
  cwd: tmp, encoding: 'utf8', env: { ...process.env, ESF_STATS_ROOT: tmp }
});
assert.notEqual(resetCli.status, 0);
assert.match(resetCli.stderr, /without --yes/);

const resetYes = spawnSync(process.execPath, [path.join(repo.root, 'scripts/stats.cjs'), '--file', localPath, '--reset', '--yes'], {
  cwd: tmp, encoding: 'utf8', env: { ...process.env, ESF_STATS_ROOT: tmp }
});
assert.equal(resetYes.status, 0, resetYes.stderr);
assert.match(resetYes.stdout, /Reset stats/);
assert.equal(isPublicStatsFile(paths(tmp)), true);
assert.equal(isPublicStatsFile(paths(tmp, { statsFile: localPath })), false);
assert.ok(emptyDocument(paths(tmp)).derived.filterRevision);

fs.rmSync(tmp, { recursive: true, force: true });
console.log('Stats record, schema, render, reset and privacy tests passed.');

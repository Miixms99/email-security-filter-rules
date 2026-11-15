'use strict';
// Public aggregate handling stats: record one check run, and render the README
// status block. Totals only — never stores addresses, subjects or message IDs.
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { validateAgainstSchema } = require('./validate-rules.cjs');

const ROOT = path.resolve(__dirname, '..');
const START = '<!-- STATS:START -->';
const END = '<!-- STATS:END -->';
const PROVIDERS = ['gmail', 'outlook'];
const COUNT_KEYS = [
  'mailsChecked', 'phishing', 'spam', 'uncertain', 'legitimate',
  'sendersBlocked', 'domainsBlocked', 'reportedToProvider', 'movedToTrash', 'spamChecksRun'
];
const RECORD_KEYS = COUNT_KEYS.filter((k) => k !== 'spamChecksRun');

function defaultRoot() {
  return process.env.ESF_STATS_ROOT ? path.resolve(process.env.ESF_STATS_ROOT) : ROOT;
}

function paths(root = defaultRoot(), options = {}) {
  const base = root || defaultRoot();
  const resolved = {
    root: base,
    stats: path.join(base, 'stats/stats.json'),
    schema: path.join(base, 'stats/stats.schema.json'),
    readme: path.join(base, 'README.md'),
    rules: path.join(base, 'rules/filter-rules.json'),
    corpus: path.join(base, 'corpus')
  };
  const statsFile = options.statsFile || process.env.ESF_STATS_FILE;
  if (statsFile) resolved.stats = path.resolve(statsFile);
  return resolved;
}

function isPublicStatsFile(p) {
  return path.resolve(p.stats) === path.resolve(path.join(p.root, 'stats/stats.json'));
}

function emptyDocument(p, now = new Date()) {
  const lastCheck = nowAmsterdamIso(now);
  return {
    schemaVersion: 1,
    trackingSince: lastCheck.slice(0, 10),
    lastCheck,
    totals: emptyCounts(),
    providers: { gmail: emptyCounts(), outlook: emptyCounts() },
    derived: deriveFromRepo(p),
    countsAreLowerBounds: false,
    notes: 'Local stats initialized empty. Totals are aggregate counts only (no addresses, subjects or personal data).'
  };
}

function reset(options = {}) {
  const p = paths(options.root || ROOT, options);
  const document = emptyDocument(p, options.now);
  saveStats(document, p);
  return document;
}

function initLocal(dest, options = {}) {
  const root = options.root || ROOT;
  const destPath = path.resolve(dest || path.join(root, 'stats/local-stats.json'));
  const publicStats = path.resolve(root, 'stats/stats.json');
  if (path.resolve(destPath) === publicStats) {
    fail('Refusing to initialize the public stats/stats.json via --init-local. Use --reset --yes to zero that file in a private clone, or pass a different --file path.');
  }
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  const p = paths(root, { statsFile: destPath });
  const document = emptyDocument(p, options.now);
  saveStats(document, p);
  return { path: destPath, document };
}

function emptyCounts(overrides = {}) {
  const counts = {};
  for (const key of COUNT_KEYS) counts[key] = 0;
  return { ...counts, ...overrides };
}

function fail(message) { throw new Error(message); }

function loadSchema(p) {
  return JSON.parse(fs.readFileSync(p.schema, 'utf8'));
}

function assertConsistentCounts(counts, pointer) {
  const categorised = counts.phishing + counts.spam + counts.uncertain + counts.legitimate;
  if (counts.mailsChecked < categorised) {
    fail(`${pointer}/mailsChecked (${counts.mailsChecked}) is below the categorised sum (${categorised})`);
  }
}

function validateStats(document, schema) {
  validateAgainstSchema(document, schema, schema, '#');
  assertConsistentCounts(document.totals, '#/totals');
  for (const name of PROVIDERS) assertConsistentCounts(document.providers[name], `#/providers/${name}`);
  const corpus = document.derived.corpusSamples;
  if (corpus.total !== corpus.phishing + corpus.spam + corpus.ad) {
    fail('#/derived/corpusSamples/total must equal phishing + spam + ad');
  }
  // Totals must equal the sum of the per-provider breakdown, except spamChecksRun:
  // one check may cover both mailboxes, so the total is at least each provider count
  // and at least the larger of the two, not necessarily their sum.
  for (const key of COUNT_KEYS) {
    if (key === 'spamChecksRun') {
      for (const name of PROVIDERS) {
        if (document.totals[key] < document.providers[name][key]) {
          fail(`#/totals/${key} is below providers.${name}.${key}`);
        }
      }
      continue;
    }
    const sum = PROVIDERS.reduce((n, name) => n + document.providers[name][key], 0);
    if (document.totals[key] !== sum) fail(`#/totals/${key} must equal gmail + outlook (${sum})`);
  }
  return document;
}

function loadStats(p) {
  const document = JSON.parse(fs.readFileSync(p.stats, 'utf8'));
  return validateStats(document, loadSchema(p));
}

function saveStats(document, p) {
  validateStats(document, loadSchema(p));
  fs.mkdirSync(path.dirname(p.stats), { recursive: true });
  fs.writeFileSync(p.stats, JSON.stringify(document, null, 2) + '\n');
}

function nowAmsterdamIso(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Amsterdam',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hourCycle: 'h23'
  }).formatToParts(date);
  const get = (type) => parts.find((part) => part.type === type).value;
  const asUtc = Date.UTC(+get('year'), +get('month') - 1, +get('day'), +get('hour'), +get('minute'), +get('second'));
  const offsetMin = Math.round((asUtc - date.getTime()) / 60000);
  const sign = offsetMin >= 0 ? '+' : '-';
  const abs = Math.abs(offsetMin);
  const hour = String(Math.floor(abs / 60)).padStart(2, '0');
  const minute = String(abs % 60).padStart(2, '0');
  return `${get('year')}-${get('month')}-${get('day')}T${get('hour')}:${get('minute')}:${get('second')}${sign}${hour}:${minute}`;
}

function formatAmsterdamDay(isoDate) {
  const [year, month, day] = isoDate.split('-').map(Number);
  const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  return `${day} ${months[month - 1]} ${year}`;
}

function formatAmsterdamStamp(iso) {
  const match = iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})([+-]\d{2}:\d{2})$/);
  if (!match) return iso;
  return `${formatAmsterdamDay(`${match[1]}-${match[2]}-${match[3]}`)}, ${match[4]}:${match[5]} Europe/Amsterdam`;
}

function countCorpusSamples(corpusDir) {
  const counts = { phishing: 0, spam: 0, ad: 0, total: 0 };
  if (!fs.existsSync(corpusDir)) return counts;
  for (const name of fs.readdirSync(corpusDir)) {
    if (!name.endsWith('.json') || name === 'sample.schema.json') continue;
    const sample = JSON.parse(fs.readFileSync(path.join(corpusDir, name), 'utf8'));
    if (!Object.hasOwn(counts, sample.category)) fail(`Unknown corpus category in ${name}: ${sample.category}`);
    counts[sample.category] += 1;
    counts.total += 1;
  }
  return counts;
}

function countActiveRules(rulesPath) {
  const document = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
  const active = document.rules.filter((rule) => rule.status === 'signal_only' || rule.status === 'active').length;
  return { activeRuleCount: active, filterRevision: document.filterRevision };
}

function countMergedRulePrs(root) {
  try {
    const log = execFileSync('git', ['log', '--first-parent', '--format=%H %s'], {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
    if (!log) return null;
    let count = 0;
    for (const line of log.split('\n')) {
      const match = line.match(/^([0-9a-f]{7,40})\s+(.*)$/i);
      if (!match) continue;
      const [, hash, subject] = match;
      if (!/(?:Merge(?:\s+pull\s+request)?\s+#\d+|\(#\d+\))/.test(subject)) continue;
      const files = execFileSync('git', ['diff', '--name-only', `${hash}^1`, hash], {
        cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']
      });
      if (files.split(/\r?\n/).includes('rules/filter-rules.json')) count += 1;
    }
    return count;
  } catch {
    return null;
  }
}

function deriveFromRepo(p, previous = null) {
  const rules = countActiveRules(p.rules);
  const corpusSamples = countCorpusSamples(p.corpus);
  const merged = countMergedRulePrs(p.root);
  return {
    activeRuleCount: rules.activeRuleCount,
    filterRevision: rules.filterRevision,
    corpusSamples,
    mergedRulePrCount: merged === null ? (previous?.mergedRulePrCount ?? 0) : merged
  };
}

function parseRecordInput(raw) {
  const trimmed = String(raw).trim();
  if (!trimmed) fail('Record input is empty');
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return JSON.parse(trimmed);
  const text = fs.readFileSync(trimmed, 'utf8');
  return JSON.parse(text);
}

function assertNonNegativeInt(value, pointer) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    fail(`${pointer} must be a non-negative integer`);
  }
}

function incrementFromRun(run, p) {
  if (!run || typeof run !== 'object' || Array.isArray(run)) fail('Record payload must be an object');
  const allowed = new Set(['lastCheck', 'notes', ...PROVIDERS]);
  for (const key of Object.keys(run)) {
    if (!allowed.has(key)) fail(`Unknown record property ${key}`);
  }
  if (run.lastCheck !== undefined) {
    if (typeof run.lastCheck !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/.test(run.lastCheck)) {
      fail('lastCheck must be an ISO-8601 timestamp with a numeric offset (Europe/Amsterdam)');
    }
  }

  const document = loadStats(p);
  const checkedProviders = [];
  for (const name of PROVIDERS) {
    if (run[name] === undefined) continue;
    const increment = run[name];
    if (!increment || typeof increment !== 'object' || Array.isArray(increment)) fail(`${name} must be an object`);
    for (const key of Object.keys(increment)) {
      if (!RECORD_KEYS.includes(key)) fail(`Unknown record property ${name}.${key}`);
      assertNonNegativeInt(increment[key], `${name}.${key}`);
    }
    for (const key of RECORD_KEYS) {
      document.providers[name][key] += increment[key] || 0;
    }
    document.providers[name].spamChecksRun += 1;
    checkedProviders.push(name);
  }
  // A check with no per-provider increments still counts as a run on the totals.
  document.totals.spamChecksRun += 1;
  for (const key of RECORD_KEYS) {
    document.totals[key] = PROVIDERS.reduce((n, name) => n + document.providers[name][key], 0);
  }
  document.lastCheck = run.lastCheck || nowAmsterdamIso();
  if (run.notes !== undefined) {
    if (typeof run.notes !== 'string') fail('notes must be a string');
    document.notes = run.notes;
  }
  document.derived = deriveFromRepo(p, document.derived);
  return { document, checkedProviders };
}

function record(raw, options = {}) {
  const p = paths(options.root || ROOT, options);
  const run = typeof raw === 'string' ? parseRecordInput(raw) : raw;
  const { document, checkedProviders } = incrementFromRun(run, p);
  saveStats(document, p);
  return { document, checkedProviders };
}

function badge(label, value, color) {
  const encode = (text) => encodeURIComponent(String(text)).replace(/-/g, '--');
  return `![${label}](https://img.shields.io/badge/${encode(label)}-${encode(value)}-${color})`;
}

function renderBlock(document) {
  const t = document.totals;
  const d = document.derived;
  const g = document.providers.gmail;
  const o = document.providers.outlook;
  const since = formatAmsterdamDay(document.trackingSince);
  const last = formatAmsterdamStamp(document.lastCheck);
  const bound = document.countsAreLowerBounds
    ? ' Mail-handling figures are lower bounds: only verified, classified mail is included.'
    : '';
  const badges = [
    badge('Mails checked', t.mailsChecked, '0a66c2'),
    badge('Phishing caught', t.phishing, 'c41e3a'),
    badge('Spam removed', t.spam, 'd97706'),
    badge('Senders blocked', t.sendersBlocked, '4b5563'),
    badge('Domains blocked', t.domainsBlocked, '4b5563'),
    badge('Detection rules', d.activeRuleCount, '0f766e')
  ].join(' ');

  return [
    '## Project status',
    '',
    'Updated automatically by Grok Bot after every daily spam check. Totals below are aggregate counts only (no addresses, subjects or personal data), since ' + since + '.' + bound,
    '',
    badges,
    '',
    '| | Count |',
    '| --- | ---: |',
    `| Mails checked | ${t.mailsChecked} |`,
    `| Phishing caught | ${t.phishing} |`,
    `| Spam removed | ${t.spam} |`,
    `| Senders blocked | ${t.sendersBlocked} |`,
    `| Domains blocked | ${t.domainsBlocked} |`,
    `| Detection rules | ${d.activeRuleCount} |`,
    `| Corpus samples | ${d.corpusSamples.total} |`,
    `| Rules revision | ${d.filterRevision} |`,
    `| Last check | ${last} |`,
    '',
    '| Provider | Checked | Phishing | Spam | Senders blocked |',
    '| --- | ---: | ---: | ---: | ---: |',
    `| Gmail | ${g.mailsChecked} | ${g.phishing} | ${g.spam} | ${g.sendersBlocked} |`,
    `| Outlook | ${o.mailsChecked} | ${o.phishing} | ${o.spam} | ${o.sendersBlocked} |`,
    ''
  ].join('\n');
}

function replaceReadmeSection(readme, block) {
  const start = readme.indexOf(START);
  const end = readme.indexOf(END);
  if (start === -1 || end === -1 || end < start) fail('README.md is missing the <!-- STATS:START --> / <!-- STATS:END --> markers');
  const after = end + END.length;
  // Keep a single trailing newline after the end marker; preserve the rest of the file.
  const prefix = readme.slice(0, start);
  const suffix = readme.slice(after).replace(/^\r?\n/, '');
  return `${prefix}${START}\n${block}${END}\n${suffix}`;
}

function render(options = {}) {
  const p = paths(options.root || ROOT, options);
  if (!isPublicStatsFile(p) && !options.forceRender) {
    fail('Refusing to render the repository README from a local stats file (that would replace the public project status). Use --no-render, or pass --force-render only if this clone is for your own status block.');
  }
  const document = loadStats(p);
  document.derived = deriveFromRepo(p, document.derived);
  validateStats(document, loadSchema(p));
  const block = renderBlock(document);
  const current = fs.readFileSync(p.readme, 'utf8');
  const next = replaceReadmeSection(current, block);
  if (options.check) {
    if (current !== next) fail('README.md project status block is out of sync with stats/stats.json (run: node scripts/stats.cjs --render)');
    if (options.writeDerived) saveStats(document, p);
    return { document, block, changed: false };
  }
  if (current !== next) fs.writeFileSync(p.readme, next);
  saveStats(document, p);
  return { document, block, changed: current !== next };
}

function usage() {
  return `Usage:
  node scripts/stats.cjs --record <json-file-or-inline-JSON>
  node scripts/stats.cjs --render
  node scripts/stats.cjs --render --check
  node scripts/stats.cjs --init-local [path]
  node scripts/stats.cjs --reset --yes

--record adds one check run's counts (non-negative integers under "gmail"
and/or "outlook"), increments spamChecksRun, and sets lastCheck to now
in Europe/Amsterdam unless lastCheck is provided. Then re-renders the
README status block unless --no-render is also passed.

--render rewrites the README section between <!-- STATS:START --> and
<!-- STATS:END --> from stats/stats.json plus values derived from the
repository (active rule count, filter revision, corpus samples, merged
rule pull requests). --check leaves the files unchanged and exits
non-zero if the section is out of sync.

--init-local writes a fresh empty stats file (default: stats/local-stats.json,
gitignored) so your mailbox counts stay separate from the public project
status. It never overwrites stats/stats.json.

--reset --yes zeros the current stats file (public stats/stats.json, or
--file / ESF_STATS_FILE). Use this only in a private clone. Do not commit a
reset of the public project status back upstream.

--file PATH    Read and write this stats file instead of stats/stats.json.
               Recording to a local file skips README rendering unless
               --force-render is also passed.
ESF_STATS_FILE and ESF_STATS_ROOT environment variables select a file or
a separate repository-shaped root, respectively.`;
}

function parseFileOption(argv, options) {
  const idx = argv.indexOf('--file');
  if (idx === -1) return options.statsFile;
  const value = argv[idx + 1];
  if (!value || value.startsWith('--')) fail('Usage: --file <path>');
  return value;
}

function main(argv = process.argv.slice(2), options = {}) {
  const root = options.root || defaultRoot();

  if (argv.includes('--help') || argv.includes('-h') || argv.length === 0) {
    console.log(usage());
    return 0;
  }
  const renderFlag = argv.includes('--render');
  const checkFlag = argv.includes('--check');
  const noRender = argv.includes('--no-render');
  const forceRender = argv.includes('--force-render');
  const statsFile = parseFileOption(argv, options);
  const pathOptions = { root, statsFile };

  if (argv.includes('--init-local')) {
    const idx = argv.indexOf('--init-local');
    const next = argv[idx + 1];
    const dest = next && !next.startsWith('--') ? next : path.join(root, 'stats/local-stats.json');
    const result = initLocal(dest, pathOptions);
    console.log(`Wrote empty local stats to ${result.path}. Record runs with:`);
    console.log(`  node scripts/stats.cjs --file ${result.path} --record run.json --no-render`);
    return 0;
  }
  if (argv.includes('--reset')) {
    if (!argv.includes('--yes')) fail('Refusing to reset stats without --yes. This zeros the selected stats file.');
    const document = reset(pathOptions);
    const p = paths(root, pathOptions);
    console.log(`Reset stats in ${p.stats} (tracking since ${document.trackingSince}).`);
    if (renderFlag && !noRender) {
      const result = render({ ...pathOptions, forceRender });
      console.log(result.changed ? 'Updated the README project status block.' : 'README project status block already up to date.');
    }
    return 0;
  }
  const recordIdx = argv.indexOf('--record');
  if (recordIdx !== -1) {
    const raw = argv[recordIdx + 1];
    if (!raw || raw.startsWith('--')) fail('Usage: node scripts/stats.cjs --record <json-file-or-inline-JSON>');
    const { document, checkedProviders } = record(raw, pathOptions);
    const names = checkedProviders.length ? checkedProviders.join(', ') : 'totals only';
    console.log(`Recorded check run #${document.totals.spamChecksRun} (${names}). Last check ${document.lastCheck}.`);
    const p = paths(root, pathOptions);
    const skipRender = noRender || (!isPublicStatsFile(p) && !forceRender);
    if (!skipRender) {
      const result = render({ ...pathOptions, forceRender });
      console.log(result.changed ? 'Updated the README project status block.' : 'README project status block already up to date.');
    } else if (!isPublicStatsFile(p) && !noRender && !forceRender) {
      console.log('Skipped README render because this is a local stats file. Pass --force-render only if you want your own clone README updated.');
    }
    return 0;
  }
  if (renderFlag) {
    const result = render({ ...pathOptions, check: checkFlag, forceRender });
    if (checkFlag) console.log('README project status block is in sync with stats/stats.json.');
    else console.log(result.changed ? 'Updated the README project status block.' : 'README project status block already up to date.');
    return 0;
  }
  fail(usage());
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
  COUNT_KEYS, RECORD_KEYS, START, END, ROOT,
  paths, emptyCounts, emptyDocument, isPublicStatsFile, loadStats, saveStats, validateStats,
  nowAmsterdamIso, formatAmsterdamDay, formatAmsterdamStamp,
  deriveFromRepo, countMergedRulePrs, record, render, renderBlock,
  replaceReadmeSection, parseRecordInput, reset, initLocal, main
};

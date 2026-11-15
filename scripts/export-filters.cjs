'use strict';
// Export optional, reviewable Gmail filter XML and an Outlook blocked-senders
// / rules list from the current signal-only rules. Never includes shared
// infrastructure hosts, secrets, or personal data. Importing or applying the
// output is a manual, user-reviewed step — this script does not touch a mailbox.
const fs = require('node:fs');
const path = require('node:path');
const { loadAccounts, accountsByProvider } = require('./accounts.cjs');

const ROOT = path.resolve(__dirname, '..');
const SHARED_INFRA_SUFFIXES = [
  'googleapis.com', 'google.com', 'googleusercontent.com', 'gstatic.com',
  'gmail.com', 'googlemail.com',
  'microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com',
  'outlook.com', 'live.com', 'hotmail.com', 'msn.com', 'azure.com', 'windows.net',
  'amazonaws.com', 'cloudfront.net', 'akamaiedge.net', 'akamai.net',
  'cloudflare.net', 'cloudflare.com', 'fastly.net',
  'sendgrid.net', 'mailchimp.com', 'mailgun.org'
];

function defaultRoot() {
  return process.env.ESF_ROOT ? path.resolve(process.env.ESF_ROOT) : ROOT;
}

function fail(message) { throw new Error(message); }

function loadRules(root = defaultRoot()) {
  const file = path.join(root, 'rules/filter-rules.json');
  const document = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!document || !Array.isArray(document.rules)) fail('rules/filter-rules.json is missing a rules array');
  return document;
}

function isSharedInfrastructure(domain) {
  const host = String(domain || '').toLowerCase().replace(/^\.+/, '');
  if (!host || host === 'localhost') return true;
  return SHARED_INFRA_SUFFIXES.some((suffix) => host === suffix || host.endsWith('.' + suffix));
}

function isEnabledRule(rule) {
  return rule && (rule.status === 'signal_only' || rule.status === 'active');
}

function collectSignals(document) {
  const domains = new Map();
  const markers = new Map();
  const skippedHosts = [];

  for (const rule of document.rules) {
    if (!isEnabledRule(rule)) continue;
    const indicators = rule.indicators || {};

    for (const domain of indicators.senderDomains || []) {
      const value = String(domain).trim().toLowerCase();
      if (!value) continue;
      if (isSharedInfrastructure(value)) {
        skippedHosts.push({ value, ruleId: rule.id, reason: 'shared_infrastructure' });
        continue;
      }
      if (!domains.has(value)) domains.set(value, { value, ruleId: rule.id, kind: 'sender_domain' });
    }

    // Supporting hosts (for example a shared cloud storage host) are never exportable.
    for (const host of indicators.hosts || []) {
      skippedHosts.push({ value: String(host).trim().toLowerCase(), ruleId: rule.id, reason: 'supporting_host_not_exported' });
    }

    for (const marker of indicators.markers || []) {
      const value = String(marker).trim();
      if (!value) continue;
      if (!markers.has(value)) markers.set(value, { value, ruleId: rule.id, kind: 'campaign_marker' });
    }
  }

  return {
    filterRevision: document.filterRevision,
    generatedAt: document.generatedAt || null,
    domains: [...domains.values()].sort((a, b) => a.value.localeCompare(b.value)),
    markers: [...markers.values()].sort((a, b) => a.value.localeCompare(b.value)),
    skippedHosts
  };
}

function xmlEscape(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function atomTimestamp(iso) {
  if (typeof iso === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(iso)) {
    const asUtc = new Date(iso);
    if (!Number.isNaN(asUtc.getTime())) return asUtc.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }
  return '2026-01-01T00:00:00Z';
}

function entryId(revision, kind, value) {
  const slug = String(value).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  return `tag:mail.google.com,2008:filter:esf:${revision}:${kind}:${slug}`;
}

function gmailProperty(name, value) {
  return `    <apps:property name='${xmlEscape(name)}' value='${xmlEscape(value)}'/>`;
}

function gmailEntry({ id, updated, properties }) {
  return [
    '  <entry>',
    "    <category term='filter'></category>",
    '    <title>Mail Filter</title>',
    `    <id>${xmlEscape(id)}</id>`,
    `    <updated>${xmlEscape(updated)}</updated>`,
    '    <content></content>',
    ...properties.map(([name, value]) => gmailProperty(name, value)),
    '  </entry>'
  ].join('\n');
}

function commonGmailAction() {
  return [
    ['shouldTrash', 'true'],
    ['sizeOperator', 's_sl'],
    ['sizeUnit', 's_smb']
  ];
}

function buildGmailXml(signals, options = {}) {
  const updated = atomTimestamp(signals.generatedAt);
  const revision = signals.filterRevision || 'unknown';
  const entries = [];

  for (const marker of signals.markers) {
    entries.push(gmailEntry({
      id: entryId(revision, 'marker', marker.value),
      updated,
      properties: [
        ['hasTheWord', `"${marker.value}"`],
        ...commonGmailAction()
      ]
    }));
  }
  for (const domain of signals.domains) {
    entries.push(gmailEntry({
      id: entryId(revision, 'domain', domain.value),
      updated,
      properties: [
        ['from', domain.value],
        ...commonGmailAction()
      ]
    }));
  }

  const xml = [
    "<?xml version='1.0' encoding='UTF-8'?>",
    "<!-- Optional, reviewable Gmail filters generated from Email Security Filter Rules",
    `     revision ${revision}. Review every filter before importing. These signals are`,
    '     not proof of malice and do not authorize unreviewed mailbox actions.',
    '     Shared infrastructure hosts are never included. This file contains no',
    '     personal addresses or account data. -->',
    "<feed xmlns='http://www.w3.org/2005/Atom' xmlns:apps='http://schemas.google.com/apps/2006'>",
    '  <title>Mail Filters</title>',
    `  <id>tag:mail.google.com,2008:filters:esf:${xmlEscape(revision)}</id>`,
    `  <updated>${xmlEscape(updated)}</updated>`,
    '  <author>',
    '    <name>Email Security Filter Rules</name>',
    '    <email>filters@example.com</email>',
    '  </author>',
    ...entries,
    '</feed>',
    ''
  ].join('\n');

  return { xml, entryCount: entries.length, updated };
}

function buildOutlookText(signals) {
  const revision = signals.filterRevision || 'unknown';
  const lines = [
    '# Email Security Filter Rules — optional Outlook blocked-senders and rule suggestions',
    `# Rules revision: ${revision}`,
    '# REVIEW every entry before adding it. These are signals, not automatic proof.',
    '# This file contains no personal addresses. Shared infrastructure is not listed.',
    '# Applying this list is a manual step; the script never signs in to Outlook.',
    '#',
    '# How to add blocked domains (Outlook on the web):',
    '#   Settings > Mail > Junk email > Blocked senders and domains > add each domain.',
    '# How to add blocked domains (classic Outlook desktop):',
    '#   Home > Junk > Junk Email Options > Blocked Senders. Some versions can import a',
    '#   plain text list (one domain per line). You can copy the domain-only section below.',
    '# How to add a rule (Outlook on the web):',
    '#   Settings > Mail > Rules > Add new rule. Use the suggested conditions.',
    '# Warning: in the Junk folder, Delete can permanently delete a message. Prefer',
    '#   Block or Move to Deleted Items.',
    '',
    '## Blocked domains',
    '# One domain per line. Do not add an @ prefix. Review before adding.',
    ''
  ];
  if (!signals.domains.length) lines.push('# (none in the current rules)');
  for (const domain of signals.domains) {
    lines.push(`# from rule ${domain.ruleId}`);
    lines.push(domain.value);
  }
  lines.push('');
  lines.push('## Suggested Inbox rules (create manually; not auto-imported)');
  lines.push('# Move matching messages to Deleted Items, not a permanent-delete action.');
  if (!signals.markers.length) lines.push('# (no campaign-marker rules in the current revision)');
  for (const [i, marker] of signals.markers.entries()) {
    lines.push(`# Rule ${i + 1} (from ${marker.ruleId}):`);
    lines.push(`#   If the subject or body contains ${marker.value}`);
    lines.push('#   then move the message to Deleted Items.');
  }
  lines.push('');
  return lines.join('\n');
}

function buildManifest(signals, extras = {}) {
  return {
    filterRevision: signals.filterRevision,
    generatedAt: signals.generatedAt,
    optional: true,
    reviewRequired: true,
    automaticMailboxActions: false,
    includesSharedInfrastructure: false,
    domains: signals.domains,
    markers: signals.markers,
    skippedHosts: signals.skippedHosts,
    ...extras
  };
}

function buildReviewNotes(signals) {
  const revision = signals.filterRevision || 'unknown';
  const lines = [
    `Email Security Filter Rules ${revision} — filter export review notes`,
    '',
    'This export is optional. Review every entry before you import or add it.',
    'The analyzer and this script never sign in to a mailbox and never apply',
    'filters for you. A listed domain or marker is a repeated signal, not proof.',
    '',
    `Campaign markers (${signals.markers.length}), exported as Gmail "Has the words"`,
    'phrase filters and as suggested Outlook rules:',
    ...signals.markers.map((item) => `- "${item.value}"  (${item.ruleId})`),
    '',
    `Sender domains (${signals.domains.length}), exported as Gmail From filters and`,
    'as an Outlook blocked-domain list. These come from',
    'campaign.repeated-malicious-sender-domain.v1 (repeated observations, not',
    'shared infrastructure):',
    ...signals.domains.map((item) => `- ${item.value}  (${item.ruleId})`),
    '',
    'Not exported (by design):',
    '- Supporting hosts such as shared cloud storage (never block these).',
    '- Regex sender shapes, brand local-parts, and phrase lures that need',
    '  human review and would be too broad as an automatic trash rule.',
    '- Genuine brand domains (for example a real retailer or government domain).',
    '',
    'Gmail: Settings > See all settings > Filters and Blocked Addresses > Import',
    'filters. Review the list, then confirm. "Delete it" means Trash, not',
    'permanent deletion. Gmail may ask you to verify your identity.',
    '',
    'Outlook: add domains under Junk email > Blocked senders and domains, and',
    'create the suggested rules under Mail > Rules. In Junk, prefer Block or',
    'Move to Deleted Items; Delete can erase the message permanently.',
    ''
  ];
  return lines.join('\n');
}

function shouldExportProvider(provider, options) {
  const only = options.providers;
  if (Array.isArray(only) && only.length) return only.includes(provider);
  return true;
}

function resolveProviders(options = {}) {
  if (Array.isArray(options.providers) && options.providers.length) {
    return options.providers;
  }
  if (options.useAccounts) {
    const loaded = loadAccounts({ root: options.root, file: options.accountsFile });
    if (!loaded.document) return ['gmail', 'outlook'];
    const providers = [];
    if (accountsByProvider(loaded.document, 'gmail').length) providers.push('gmail');
    if (accountsByProvider(loaded.document, 'outlook').length) providers.push('outlook');
    return providers.length ? providers : [];
  }
  return ['gmail', 'outlook'];
}

function exportFilters(options = {}) {
  const root = options.root || defaultRoot();
  const document = options.document || loadRules(root);
  const signals = collectSignals(document);
  const providers = resolveProviders({ ...options, root });
  const files = {};

  if (shouldExportProvider('gmail', { providers })) {
    const { xml, entryCount } = buildGmailXml(signals);
    files.gmailXml = xml;
    files.gmailEntryCount = entryCount;
  }
  if (shouldExportProvider('outlook', { providers })) {
    files.outlookText = buildOutlookText(signals);
  }
  files.reviewNotes = buildReviewNotes(signals);
  files.manifest = buildManifest(signals, { providers });
  files.signals = signals;
  files.providers = providers;
  return files;
}

function writeExport(files, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const written = [];
  if (files.gmailXml !== undefined) {
    const dest = path.join(outDir, 'mailFilters.xml');
    fs.writeFileSync(dest, files.gmailXml);
    written.push(dest);
  }
  if (files.outlookText !== undefined) {
    const dest = path.join(outDir, 'outlook-blocked-senders.txt');
    fs.writeFileSync(dest, files.outlookText);
    written.push(dest);
  }
  if (files.reviewNotes !== undefined) {
    const dest = path.join(outDir, 'EXPORT-REVIEW.txt');
    fs.writeFileSync(dest, files.reviewNotes);
    written.push(dest);
  }
  if (files.manifest !== undefined) {
    const dest = path.join(outDir, 'export-manifest.json');
    fs.writeFileSync(dest, JSON.stringify(files.manifest, null, 2) + '\n');
    written.push(dest);
  }
  return written;
}

function usage() {
  return `Usage:
  node scripts/export-filters.cjs [--out-dir DIR] [--accounts] [--provider gmail|outlook]

Writes optional, reviewable mailbox filter lists from the current rules:

  mailFilters.xml              Gmail import format (Settings > Filters and
                               Blocked Addresses > Import filters)
  outlook-blocked-senders.txt  Outlook blocked-domain list and suggested rules
  EXPORT-REVIEW.txt            What was exported and what to review
  export-manifest.json         Machine-readable list of domains and markers

Nothing is applied automatically. Review every entry before importing.
Shared infrastructure hosts are never included. No personal data is written.

--out-dir DIR   Destination directory (default: export/)
--accounts      Limit providers to those enabled in config/accounts.json
--provider X    Export only gmail or only outlook (may be repeated)
--stdout        Print the Gmail XML or Outlook text to stdout (with one
                provider) instead of writing files`;
}

function parseArgs(argv) {
  const options = { providers: [], outDir: null, useAccounts: false, stdout: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return { help: true };
    if (arg === '--accounts') { options.useAccounts = true; continue; }
    if (arg === '--stdout') { options.stdout = true; continue; }
    if (arg === '--out-dir' || arg === '--out') {
      const value = argv[++i];
      if (!value || value.startsWith('--')) fail('Usage: --out-dir <directory>');
      options.outDir = value;
      continue;
    }
    if (arg === '--provider') {
      const value = argv[++i];
      if (value !== 'gmail' && value !== 'outlook') fail('Usage: --provider gmail|outlook');
      options.providers.push(value);
      continue;
    }
    fail(usage());
  }
  return options;
}

function main(argv = process.argv.slice(2), options = {}) {
  const parsed = parseArgs(argv);
  if (parsed.help) {
    console.log(usage());
    return 0;
  }
  const root = options.root || defaultRoot();
  const files = exportFilters({
    root,
    useAccounts: parsed.useAccounts,
    accountsFile: options.accountsFile,
    providers: parsed.providers
  });
  if (!files.providers.length) {
    fail('No enabled Gmail or Outlook accounts in config/accounts.json; add one or omit --accounts');
  }
  if (parsed.stdout) {
    if (files.providers.length !== 1) fail('--stdout requires exactly one --provider');
    if (files.providers[0] === 'gmail') process.stdout.write(files.gmailXml);
    else process.stdout.write(files.outlookText);
    return 0;
  }
  const outDir = path.resolve(root, parsed.outDir || 'export');
  const written = writeExport(files, outDir);
  const signals = files.signals;
  console.log(`Exported optional filters for rules ${signals.filterRevision} (${signals.markers.length} markers, ${signals.domains.length} domains) to ${outDir}`);
  console.log('Review EXPORT-REVIEW.txt before importing anything. Nothing was applied to a mailbox.');
  for (const file of written) console.log(`  ${path.relative(root, file) || file}`);
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
  ROOT, SHARED_INFRA_SUFFIXES,
  loadRules, isSharedInfrastructure, collectSignals,
  buildGmailXml, buildOutlookText, buildManifest, buildReviewNotes,
  exportFilters, writeExport, resolveProviders, main
};

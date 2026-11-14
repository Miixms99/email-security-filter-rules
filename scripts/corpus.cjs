'use strict';
// Redacted phishing/spam corpus: builds, privacy-checks and evaluates samples.
// Samples are short redacted lure excerpts plus public indicators only; never
// full bodies, recipient headers or message IDs. Never reads mail or fetches URLs.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { redact, redactUrl, loadPrivateIdentifiers, KEEP_MARKERS } = require('./redact.cjs');

const ROOT = path.resolve(__dirname, '..');
const DIR = path.join(ROOT, 'corpus');
const SCHEMA = path.join(DIR, 'sample.schema.json');
const MAX_SNIPPET_CHARS = 600;
const OFFLINE = { cache: { schemaVersion: 1, sources: {} }, status: 'unavailable' };

function newId() { return 'cs-' + crypto.randomBytes(6).toString('hex').replace(/\d/g, d => 'ghijklmnop'[d]); }
function readSamples(dir = DIR) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(f => f.endsWith('.json') && f !== 'sample.schema.json').sort()
    .map(f => ({ file: path.join(dir, f), sample: JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')) }));
}

// Analyzer evaluation of one sample against the repository rules, offline.
function evaluateSample(sample) {
  const { analyze } = require('./Controle-Email.cjs');
  const text = [sample.subject, ...sample.lureSnippets].join('\n');
  const result = analyze({ useBundledRules: true, messages: [{ mailbox: sample.provider === 'gmail' ? 'Gmail' : 'Outlook', messageId: sample.id,
    fromAddress: sample.senderAddress, displayName: sample.senderDisplayName || undefined, text, urls: sample.linkHostsAndPaths,
    attachments: sample.attachmentTypes.map(type => ({ filename: 'attachment.' + type, mime: '' })) }] }, OFFLINE).messages[0];
  const ids = [...result.configuredCampaignMatches, ...result.configuredSenderMatches, ...result.configuredSignalMatches].map(m => m.ruleId);
  return { matchedRuleIds: [...new Set(ids)].sort(), reviewStatus: result.review.status };
}

// raw: {category, provider, receivedDate, senderAddress, senderDisplayName, subject, lureSnippets[], links[], attachmentTypes[], notes}
function buildSample(raw, options = {}) {
  const identifiers = options.identifiers === undefined ? loadPrivateIdentifiers() : options.identifiers;
  if (!identifiers) throw Error('config/private-identifiers.json is required to add samples (see config/private-identifiers.example.json)');
  const senderAddress = String(raw.senderAddress || '').trim().toLowerCase();
  if ((identifiers.emails || []).includes(senderAddress)) throw Error('Sender is one of your own addresses; not allowed in the corpus');
  const applied = {};
  const r = value => { const out = redact(value, { identifiers, senderAddress }); for (const [k, v] of Object.entries(out.applied)) applied[k] = (applied[k] || 0) + v; return out.text; };
  let budget = MAX_SNIPPET_CHARS;
  const lureSnippets = [];
  for (const snippet of raw.lureSnippets || []) {
    const text = r(snippet);
    if (!text || /^(?:\[[A-Z_]+\][\s,.:;]*)+$/.test(text) || budget <= 0 || lureSnippets.length >= 10) continue;
    const cut = text.length > budget ? text.slice(0, budget - 1).replace(/\s+\S*$/, '') + '…' : text;
    lureSnippets.push(cut); budget -= cut.length;
  }
  const sample = {
    id: options.id || newId(),
    category: raw.category, provider: raw.provider,
    receivedDate: String(raw.receivedDate).slice(0, 10),
    senderAddress, senderDisplayName: r(raw.senderDisplayName || ''), subject: r(raw.subject || ''),
    lureSnippets,
    linkHostsAndPaths: [...new Set((raw.links || []).map(redactUrl))].filter(u => u !== '[URL]').sort().slice(0, 25),
    attachmentTypes: [...new Set((raw.attachmentTypes || []).map(x => String(x).toLowerCase()))].sort(),
    matchedRuleIds: [], notes: r(raw.notes || '')
  };
  sample.matchedRuleIds = evaluateSample(sample).matchedRuleIds;
  const redactionApplied = Object.keys(applied).sort();
  if (redactionApplied.length) sample.redactionApplied = redactionApplied;
  return { sample, applied };
}

// Privacy scan: generic personal-data patterns always; private identifiers when present.
function privacyFindings(sample, identifiers = loadPrivateIdentifiers()) {
  const findings = [];
  const sender = String(sample.senderAddress || '').toLowerCase();
  const walk = (value, pointer) => {
    if (typeof value === 'string') check(value, pointer);
    else if (Array.isArray(value)) value.forEach((v, i) => walk(v, `${pointer}/${i}`));
    else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) if (!(pointer === '#' && ['id', 'senderAddress'].includes(k))) walk(v, `${pointer}/${k}`);
  };
  const check = (value, pointer) => {
    let v = value;
    for (const marker of KEEP_MARKERS) v = v.split(marker).join(' ');
    const lowerValue = value.toLowerCase();
    const emails = value.match(/[A-Za-z0-9._%+-]+(?:@|%40|%2540)[A-Za-z0-9.-]+\.[A-Za-z]{2,}/gi) || [];
    for (const e of emails) if (e.toLowerCase() !== sender) findings.push({ pointer, kind: 'email_address' });
    if (/\d{6,}/.test(v)) findings.push({ pointer, kind: 'long_digit_run' });
    if (/(?:\+|\b00)\d{1,3}[\s().-]*(?:\d[\s().-]*){6,13}\d|\(?\b\d{2,4}\)?[\s.-]\d{3}[\s.-]\d{3,4}\b/.test(v)) findings.push({ pointer, kind: 'phone_number' });
    if (/https?:\/\/[^\s]*[?#]|[?&][A-Za-z0-9_.-]+=[^\s&]*/.test(value)) findings.push({ pointer, kind: 'query_string' });
    if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(v)) findings.push({ pointer, kind: 'ip_address' });
    if (/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}\b/.test(value)) findings.push({ pointer, kind: 'iban_like' });
    if (/<[^<>\s@]+@[^<>\s@]+>/.test(value)) findings.push({ pointer, kind: 'message_id' });
    if (identifiers) for (const id of [...(identifiers.names || []), ...(identifiers.emails || [])]) {
      if (lowerValue.includes(id.toLowerCase())) findings.push({ pointer, kind: 'private_identifier' });
    }
  };
  walk(sample, '#');
  if (identifiers && [...(identifiers.names || []), ...(identifiers.emails || [])].some(id => sender.includes(id.toLowerCase()))) findings.push({ pointer: '#/senderAddress', kind: 'private_identifier' });
  if (sample.lureSnippets && sample.lureSnippets.join('').length > MAX_SNIPPET_CHARS + 20) findings.push({ pointer: '#/lureSnippets', kind: 'too_long' });
  return findings;
}

function validateSample(sample) {
  const { validateAgainstSchema } = require('./validate-rules.cjs');
  const schema = JSON.parse(fs.readFileSync(SCHEMA, 'utf8'));
  validateAgainstSchema(sample, schema, schema, '#');
  if (sample.lureSnippets.length > 10 || sample.linkHostsAndPaths.length > 25) throw Error(`${sample.id}: too many items`);
}

module.exports = { buildSample, evaluateSample, privacyFindings, validateSample, readSamples, MAX_SNIPPET_CHARS, DIR };

if (require.main === module) {
  const [command] = process.argv.slice(2);
  const finish = value => console.log(JSON.stringify(value, null, 2));
  if (command === '--add') {
    let raw = ''; process.stdin.setEncoding('utf8');
    process.stdin.on('data', d => { raw += d; if (raw.length > 2e6) throw Error('Input too large'); });
    process.stdin.on('end', () => {
      const inputs = [].concat(JSON.parse(raw));
      const out = inputs.map(input => {
        const { sample, applied } = buildSample(input);
        validateSample(sample);
        const findings = privacyFindings(sample);
        if (findings.length) throw Error(`Refusing to write sample with privacy findings: ${JSON.stringify(findings)}`);
        fs.writeFileSync(path.join(DIR, sample.id + '.json'), JSON.stringify(sample, null, 2) + '\n');
        return { id: sample.id, category: sample.category, matchedRuleIds: sample.matchedRuleIds, redactions: applied };
      });
      finish(out);
    });
  } else if (command === '--check') {
    const results = readSamples().map(({ file, sample }) => { validateSample(sample); return { file: path.basename(file), findings: privacyFindings(sample) }; });
    const bad = results.filter(r => r.findings.length);
    finish({ samples: results.length, privateIdentifiersChecked: Boolean(loadPrivateIdentifiers()), failures: bad });
    if (bad.length) process.exitCode = 1;
  } else if (command === '--evaluate') {
    const rows = readSamples().map(({ sample }) => ({ id: sample.id, category: sample.category, expected: sample.matchedRuleIds, ...evaluateSample(sample) }));
    const detected = rows.filter(r => r.matchedRuleIds.length).length;
    finish({ samples: rows.length, detected, byCategory: rows.reduce((a, r) => { a[r.category] = a[r.category] || { total: 0, detected: 0 }; a[r.category].total++; if (r.matchedRuleIds.length) a[r.category].detected++; return a; }, {}), rows });
  } else {
    console.error('Usage: node scripts/corpus.cjs --add < raw-sample.json | --check | --evaluate');
    process.exitCode = 2;
  }
}

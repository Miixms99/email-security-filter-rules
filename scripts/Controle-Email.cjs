'use strict';
// Observe-only helper. Public downloads only; never visits mail URLs or changes mail.
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { domainToASCII } = require('node:url');
const { isIP } = require('node:net');
const assert = require('node:assert/strict');
const os = require('node:os');
const signalsLib = require('./signals.cjs');
// Public-source cache location. ESF_CACHE_DIR (or legacy EMAILCONTROL_CACHE_DIR)
// overrides; otherwise Windows keeps the script folder (must be on D:) and other
// platforms use $XDG_CACHE_HOME/email-security or ~/.cache/email-security.
function defaultCacheDir(platform = process.platform, env = process.env, home = os.homedir()) {
  if (platform === 'win32') return __dirname;
  const xdg = env.XDG_CACHE_HOME && path.isAbsolute(env.XDG_CACHE_HOME) ? env.XDG_CACHE_HOME : path.join(home, '.cache');
  return path.join(xdg, 'email-security');
}
const CACHE_OVERRIDE = process.env.ESF_CACHE_DIR || process.env.EMAILCONTROL_CACHE_DIR || '';
const ROOT = CACHE_OVERRIDE || defaultCacheDir();
const DATA_ROOT = process.env.EMAILCONTROL_DATA_DIR;
const CACHE = path.join(ROOT, 'publieke-bronnen.json');
const MAX_CACHE = 8 * 1024 * 1024;
const MAX_INPUT = 2 * 1024 * 1024;
const SOURCES = Object.freeze({
  psl: { url: 'https://publicsuffix.org/list/public_suffix_list.dat', interval: 86400000, max: 2 * 1024 * 1024 },
  openphish: { url: 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt', interval: 43200000, max: 4 * 1024 * 1024 }
});
const RULES = Object.freeze({
  url_userinfo: ['url.userinfo.v1', true],
  public_feed_exact_match: ['feed.openphish.exact.v1', true],
  link_domain_mismatch: ['link.visible_domain_mismatch.v1', true],
  link_boundary_unknown: ['link.domain_boundary_unknown.v1', false],
  reply_to_domain_difference: ['identity.reply_to_domain_difference.v1', false],
  reply_to_boundary_unknown: ['identity.reply_to_boundary_unknown.v1', false],
  display_identity_difference: ['identity.display_explicit_domain.v1', true],
  display_boundary_unknown: ['identity.display_boundary_unknown.v1', false],
  display_mailbox_difference: ['identity.display_mailbox_difference.v1', true],
  display_mailbox_case_difference: ['identity.display_mailbox_case_difference.v1', false],
  campaign_in_confirmed_report: ['context.confirmed_security_report.v1', false]
});
const hash = text => createHash('sha256').update(text, 'utf8').digest('hex');
function fail(message) { throw new Error(message); }
function escapeRegExp(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function normalizeCampaignRules(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 100) fail('campaignRules must be an array of at most 100 rules');
  return value.map((rule, index) => {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) fail(`Invalid campaignRules[${index}]`);
    const id = bounded(rule.id, 120, `campaignRules[${index}].id`);
    if (!/^[a-z0-9][a-z0-9._-]*$/i.test(id)) fail(`Invalid campaign rule id: ${id}`);
    const strings = (name, limit, predicate = () => true) => {
      const list = rule[name] ?? [];
      if (!Array.isArray(list) || list.length > limit || list.some(x => typeof x !== 'string' || !x || x.length > 500 || !predicate(x))) fail(`Invalid campaignRules[${index}].${name}`);
      return [...new Set(list)];
    };
    const markers = strings('markers', 20);
    const exactPaths = strings('exactPaths', 50, x => x.startsWith('/'));
    const urlParameters = rule.urlParameters ?? [];
    if (!Array.isArray(urlParameters) || urlParameters.length > 20 || urlParameters.some(x => !x || typeof x !== 'object' || Array.isArray(x) || typeof x.name !== 'string' || !/^[A-Za-z0-9._~-]{1,80}$/.test(x.name) || typeof x.value !== 'string' || !x.value || x.value.length > 500)) fail(`Invalid campaignRules[${index}].urlParameters`);
    if ((!markers.length && !urlParameters.length) || !exactPaths.length) fail(`Campaign rule ${id} requires an indicator and an exact path`);
    const hosts = strings('hosts', 50, x => /^[a-z0-9.-]{1,253}$/.test(x));
    return { id, markers, exactPaths: new Set(exactPaths), urlParameters: urlParameters.map(x => ({ name: x.name, value: x.value })), hosts: new Set(hosts) };
  });
}
function campaignMatches(message, urlFindings, rules) {
  const fields = [['text', message.text], ['fromAddress', message.fromAddress], ['replyTo', message.replyTo], ...message.urls.map((value, i) => [`urls[${i}]`, value])];
  return rules.map(rule => {
    const markers = rule.markers.flatMap(marker => {
      const pattern = new RegExp(`(^|[^\\p{L}\\p{N}_])${escapeRegExp(marker)}($|[^\\p{L}\\p{N}_])`, 'u');
      const sourceFields = fields.filter(([, value]) => pattern.test(value)).map(([field]) => field);
      return sourceFields.length ? [{ marker, sourceFields }] : [];
    });
    const parameters = [], paths = [], hosts = [];
    for (const finding of urlFindings) if (finding.status === 'parsed') {
      const url = new URL(finding.originalUrl);
      if (rule.exactPaths.has(finding.pathname)) paths.push({ originalUrl: finding.originalUrl, pathname: finding.pathname });
      if (rule.hosts.has(finding.hostname)) hosts.push(finding.hostname);
      for (const expected of rule.urlParameters) {
        const parts = [url.search.slice(1), url.hash.slice(1)];
        const rawParameter = new RegExp(`(?:^|[?&])${escapeRegExp(expected.name)}=${escapeRegExp(expected.value)}(?:&|$)`);
        if (parts.some(part => rawParameter.test(part))) parameters.push({ originalUrl: finding.originalUrl, ...expected });
      }
    }
    // Configured hosts are supporting infrastructure context only, never required or sufficient.
    return { ruleId: rule.id, matched: Boolean(paths.length && (markers.length || parameters.length)), markers, parameters, paths, supportingHosts: [...new Set(hosts)] };
  }).filter(x => x.matched);
}
function bounded(value, limit, label, optional = false) {
  if (optional && value === undefined) return '';
  if (typeof value !== 'string' || value.length > limit) fail(`Invalid ${label}`);
  return value;
}
function validTime(value) {
  return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value));
}
function hostname(value) {
  const plain = value.replace(/\.$/, '').toLowerCase();
  const ip = plain.startsWith('[') && plain.endsWith(']') ? plain.slice(1, -1) : plain;
  if (isIP(ip)) return { value: ip, kind: 'ip' };
  const ascii = domainToASCII(plain);
  if (!ascii || ascii.length > 253 || !ascii.split('.').every(x => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))) return null;
  return { value: ascii, kind: 'domain' };
}
function parseUrl(original) {
  if (typeof original !== 'string' || !original || original.length > 16384 || /[\s\x00-\x1f\x7f]/u.test(original)) return { status: 'invalid' };
  let value;
  try { value = new URL(original); } catch { return { status: 'invalid' }; }
  if (!['http:', 'https:'].includes(value.protocol)) return { status: 'unsupported_scheme' };
  // Require an explicit authority; WHATWG also accepts ambiguous https:example.org.
  if (!/^https?:\/\/[^/]/i.test(original) || original.includes('\\')) return { status: 'ambiguous' };
  let host = hostname(value.hostname);
  // Some web platforms publish HTTP hosts containing underscores. Preserve these
  // parser-accepted URLs for exact feed matching/scanners, without claiming that
  // they are valid DNS names or deriving an ownership boundary through the PSL.
  if (!host) {
    const candidate = value.hostname.replace(/\.$/, '').toLowerCase();
    if (candidate.length <= 253 && candidate.includes('_') && candidate.split('.').every(x => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(x))) host = { value: candidate, kind: 'non_dns_hostname' };
  }
  if (!host) return { status: 'invalid' };
  return { status: 'parsed', hostname: host.value, hostKind: host.kind, pathname: value.pathname,
    hasUserInfo: Boolean(value.username || value.password), idn: host.value.split('.').some(x => x.startsWith('xn--')) };
}
function parsePsl(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > SOURCES.psl.max) fail('Invalid PSL format');
  const exact = new Set(), wildcard = new Set(), exceptions = new Set();
  const markers = ['// ===BEGIN ICANN DOMAINS===', '// ===END ICANN DOMAINS===', '// ===BEGIN PRIVATE DOMAINS===', '// ===END PRIVATE DOMAINS==='];
  let section = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (markers.includes(line)) { if (line !== markers[section]) fail('Invalid PSL section order'); section++; continue; }
    if (!line || line.startsWith('//')) continue;
    if (![1, 3].includes(section)) fail('PSL rule outside section');
    const type = line.startsWith('!') ? exceptions : line.startsWith('*.') ? wildcard : exact;
    const base = line.startsWith('!') ? line.slice(1) : line.startsWith('*.') ? line.slice(2) : line;
    const host = hostname(base);
    if (!host || host.kind !== 'domain' || /[!*\s]/.test(base)) fail('Invalid PSL rule');
    type.add(host.value);
  }
  if (section !== 4 || !exact.size) fail('Incomplete or empty PSL');
  return { exact, wildcard, exceptions, count: exact.size + wildcard.size + exceptions.size };
}
function registeredDomain(host, psl) {
  const parsed = hostname(host);
  if (!parsed) return { status: 'invalid', value: null };
  if (parsed.kind === 'ip') return { status: 'not_applicable', value: null };
  if (!psl) return { status: 'unavailable', value: null };
  const labels = parsed.value.split('.');
  let length = 0, exception = 0;
  for (let i = 0; i < labels.length; i++) {
    const suffix = labels.slice(i).join('.');
    if (psl.exceptions.has(suffix)) exception = Math.max(exception, labels.length - i - 1);
    if (psl.exact.has(suffix)) length = Math.max(length, labels.length - i);
    if (i > 0 && psl.wildcard.has(suffix)) length = Math.max(length, labels.length - i + 1);
  }
  if (exception) length = exception;
  // Do not invent the default '*' rule for unknown suffixes.
  if (!length) return { status: 'unknown_suffix', value: null };
  if (labels.length <= length) return { status: 'public_suffix_only', value: null };
  return { status: 'known', value: labels.slice(-(length + 1)).join('.') };
}
function parseOpenPhish(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > SOURCES.openphish.max) fail('Invalid OpenPhish size');
  const entries = new Set();
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    if (parseUrl(line).status !== 'parsed') fail('Invalid OpenPhish URL format');
    entries.add(line);
    if (entries.size > 50000) fail('OpenPhish entry limit exceeded');
  }
  if (!entries.size) fail('Empty OpenPhish feed');
  return { entries, count: entries.size };
}
function parseSource(name, text) { return name === 'psl' ? parsePsl(text) : parseOpenPhish(text); }
function validateRecord(name, record, now = Date.now()) {
  if (!record || typeof record !== 'object' || Array.isArray(record) || record.sourceUrl !== SOURCES[name].url || typeof record.text !== 'string' || record.sha256 !== hash(record.text)) fail(`Invalid ${name} cache integrity`);
  if (!validTime(record.retrievedAt) || !validTime(record.validatedAt) || Date.parse(record.retrievedAt) > Date.parse(record.validatedAt) || Date.parse(record.validatedAt) > now + 300000 || record.publishedAt !== null) fail(`Invalid ${name} cache time`);
  for (const field of ['etag', 'lastModified']) if (record[field] !== null && (typeof record[field] !== 'string' || record[field].length > 1024 || /[\r\n]/.test(record[field]))) fail(`Invalid ${name} HTTP metadata`);
  const parsed = parseSource(name, record.text);
  if (parsed.count !== record.count) fail(`Invalid ${name} cache count`);
  return parsed;
}
function validateCache(value, now = Date.now(), indexes) {
  if (!value || value.schemaVersion !== 1 || !value.sources || typeof value.sources !== 'object' || Array.isArray(value.sources)) fail('Invalid public cache schema');
  if (Object.keys(value.sources).some(x => !Object.hasOwn(SOURCES, x))) fail('Unknown public cache source');
  for (const [name, record] of Object.entries(value.sources)) {
    const parsed = validateRecord(name, record, now);
    if (indexes) indexes[name] = parsed;
  }
  return value;
}
function assertStorage(target, root = ROOT, { platform = process.platform, explicit = Boolean(CACHE_OVERRIDE) } = {}) {
  const pathApi = platform === 'win32' ? path.win32 : path;
  if (!pathApi.isAbsolute(root)) fail('Cache directory must be an absolute path');
  const full = pathApi.resolve(target), base = pathApi.resolve(root);
  if (platform === 'win32' && !explicit && !/^D:\\/i.test(base)) fail('Storage must remain in the fixed D: script folder (or set ESF_CACHE_DIR)');
  const rel = pathApi.relative(base, full);
  if (rel.startsWith('..') || pathApi.isAbsolute(rel)) fail('Storage must remain inside the cache directory');
  if (platform !== process.platform) return true;
  // Refuse symbolic links or junctions between the cache root and the target.
  let cursor = full;
  while (true) {
    try { if (fs.lstatSync(cursor).isSymbolicLink()) fail('Symbolic link or junction refused'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (cursor === base) break;
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  // Realpath containment: the nearest existing ancestor must resolve inside the root.
  if (fs.existsSync(base)) {
    let existing = full;
    while (!fs.existsSync(existing)) existing = path.dirname(existing);
    const realBase = fs.realpathSync(base), realExisting = fs.realpathSync(existing), realRel = path.relative(realBase, realExisting);
    if (realRel.startsWith('..') || path.isAbsolute(realRel)) fail('Resolved storage path escapes the cache directory');
  }
  return true;
}
function readCache() {
  try {
    assertStorage(CACHE);
    const stat = fs.statSync(CACHE);
    if (!stat.isFile() || stat.size > MAX_CACHE) fail('Invalid public cache file');
    const indexes = {};
    return { cache: validateCache(JSON.parse(fs.readFileSync(CACHE, 'utf8')), Date.now(), indexes), indexes, status: 'loaded' };
  } catch (error) { return { cache: { schemaVersion: 1, sources: {} }, status: error.code === 'ENOENT' ? 'unavailable' : 'failed' }; }
}
function sourceStatus(name, record, now = Date.now()) {
  if (!record) return { status: 'unavailable', sourceUrl: SOURCES[name].url };
  return { status: now - Date.parse(record.validatedAt) < SOURCES[name].interval ? 'current' : 'stale', sourceUrl: record.sourceUrl,
    retrievedAt: record.retrievedAt, validatedAt: record.validatedAt, publishedAt: null, count: record.count, sha256: record.sha256 };
}
function statuses(loaded) {
  const result = { cache: loaded.status };
  for (const name of Object.keys(SOURCES)) result[name] = loaded.status === 'failed' ? { status: 'failed', reason: 'public_cache_invalid', sourceUrl: SOURCES[name].url } : sourceStatus(name, loaded.cache.sources[name]);
  return result;
}
async function download(name, old) {
  const config = SOURCES[name];
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    const headers = { 'User-Agent': 'Emailcontrole/1.0 personal-public-feed-client', Accept: 'text/plain' };
    if (old?.etag) headers['If-None-Match'] = old.etag;
    if (old?.lastModified) headers['If-Modified-Since'] = old.lastModified;
    const response = await fetch(config.url, { redirect: 'error', signal: controller.signal, headers });
    const now = new Date().toISOString();
    if (response.status === 304) {
      if (!old) fail('304 without existing data');
      return { record: { ...old, validatedAt: now }, status: 'not_modified' };
    }
    if (!response.ok) { const error = new Error('Feed HTTP error'); error.state = [401, 403].includes(response.status) ? 'access_denied' : response.status === 429 ? 'rate_limited' : 'failed'; error.httpStatus = response.status; throw error; }
    if (!response.body || (Number(response.headers.get('content-length')) || 0) > config.max) fail('Invalid feed length');
    const text = await readUtf8(response.body, config.max, () => controller.abort());
    const parsed = parseSource(name, text);
    if (name === 'psl' && parsed.count < 5000) fail('Implausibly small production PSL; previous data retained');
    const record = { sourceUrl: config.url, text, sha256: hash(text), count: parsed.count,
      retrievedAt: now, validatedAt: now, publishedAt: null,
      etag: response.headers.get('etag'), lastModified: response.headers.get('last-modified') };
    validateRecord(name, record);
    return { record, status: 'updated' };
  } finally { clearTimeout(timeout); }
}
async function refresh() {
  assertStorage(CACHE);
  await fsp.mkdir(ROOT, { recursive: true, mode: 0o700 });
  assertStorage(CACHE);
  const lockPath = CACHE + '.lock', temp = CACHE + '.tmp';
  assertStorage(lockPath); assertStorage(temp);
  const lock = await fsp.open(lockPath, 'wx');
  let staged = false;
  try {
    const loaded = readCache(), results = {}; let changed = false;
    if (loaded.status === 'failed') fail('Public cache invalid; retained for inspection');
    for (const name of Object.keys(SOURCES)) {
      const old = loaded.cache.sources[name];
      if (old && sourceStatus(name, old).status === 'current') { results[name] = { status: 'not_due' }; continue; }
      try {
        const result = await download(name, old);
        loaded.cache.sources[name] = result.record;
        results[name] = { status: result.status, count: result.record.count };
        changed = true;
      } catch (error) { results[name] = { status: error.state || (error.name === 'AbortError' ? 'timeout' : 'failed'), reason: String(error.message || 'Public feed refresh failed').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 240), httpStatus: Number.isInteger(error.httpStatus) ? error.httpStatus : null, previousDataRetained: Boolean(old) }; }
    }
    if (changed) {
      validateCache(loaded.cache);
      const content = JSON.stringify(loaded.cache);
      if (Buffer.byteLength(content) > MAX_CACHE) fail('Public cache size limit exceeded');
      const handle = await fsp.open(temp, 'wx'); staged = true;
      try { await handle.writeFile(content, 'utf8'); await handle.sync(); } finally { await handle.close(); }
      validateCache(JSON.parse(await fsp.readFile(temp, 'utf8')));
      await fsp.rename(temp, CACHE); staged = false;
    }
    return { mode: 'public_feed_refresh', results, sources: statuses(readCache()), complete: Object.values(results).every(x => ['updated', 'not_modified', 'not_due'].includes(x.status)) };
  } finally {
    if (staged) await fsp.unlink(temp).catch(() => {});
    await lock.close(); await fsp.unlink(lockPath);
  }
}
function addressDomain(address, psl) {
  if (!address) return { status: 'not_provided' };
  if (!/^[^\s<>@]+@[^\s<>@]+$/.test(address)) return { status: 'invalid' };
  const host = hostname(address.slice(address.lastIndexOf('@') + 1));
  if (!host || host.kind !== 'domain') return { status: 'invalid' };
  const localPart = address.slice(0, address.lastIndexOf('@'));
  return { status: 'parsed', hostname: host.value, localPart, normalizedAddress: localPart + '@' + host.value, registeredDomain: registeredDomain(host.value, psl) };
}

function compareHosts(left, right, domain, pslCurrent) {
  if (!left || !right) return { status: 'not_comparable', method: 'none' };
  if (left === right) return { status: 'same_hostname', method: 'exact_hostname', left, right };
  const a = domain(left), b = domain(right);
  if (pslCurrent && a.status === 'known' && b.status === 'known') return {
    status: a.value === b.value ? 'same_registered_domain' : 'different_registered_domain',
    method: 'current_psl_including_private', left, right, leftDomain: a.value, rightDomain: b.value
  };
  return { status: 'different_hostname_boundary_unknown', method: 'exact_hostname_only', left, right };
}
function extractCssUrls(cssTexts) {
  const urls = [], skipped = [];
  for (const [sourceIndex, css] of cssTexts.entries()) {
    const clean = css.replace(/\/\*[\s\S]*?\*\//g, '');
    const pattern = /\burl\(\s*(?:"([^"\\\r\n]*)"|'([^'\\\r\n]*)'|([^\s'"()\\]*))\s*\)/gi;
    let matched = 0;
    for (const match of clean.matchAll(pattern)) {
      matched++;
      const value = match[1] ?? match[2] ?? match[3];
      if (/^https?:\/\//i.test(value)) urls.push(bounded(value, 16384, 'CSS URL'));
      else skipped.push({ sourceIndex, reason: 'non_absolute_http_url' });
    }
    let imports = 0;
    for (const m of clean.matchAll(/@import\s+(?:"([^"\\\r\n]+)"|'([^'\\\r\n]+)'|url\([^)]*\))/gi)) {
      imports++;
      const value = m[1] ?? m[2];
      if (value && /^https?:\/\//i.test(value)) urls.push(bounded(value, 16384, 'CSS import URL'));
      else if (value) skipped.push({ sourceIndex, reason:'non_absolute_import' });
    }
    if ((clean.match(/\burl\s*\(/gi) || []).length > matched || /\\/.test(clean) || (clean.match(/@import\b/gi)||[]).length>imports)
      skipped.push({ sourceIndex, reason: 'unsupported_escape_import_or_url_syntax' });
  }
  return { status: cssTexts.length ? 'limited_static_extraction' : 'not_provided', urls: [...new Set(urls)], skipped,
    limitations: 'Literal absolute HTTP(S) url() and quoted @import only; stylesheet contents not fetched; no CSS execution, full grammar, relative resolution or escapes' };
}
function inputMessages(input) {
  const messages = Array.isArray(input?.messages) ? input.messages : [input];
  if (!messages.length || messages.length > 100) fail('Input requires 1 to 100 messages');
  const seen = new Set(); let totalUrls = 0;
  return messages.map(message => {
    if (!message || typeof message !== 'object' || Array.isArray(message)) fail('Invalid message');
    const mailbox = bounded(message.mailbox, 320, 'mailbox'), messageId = bounded(message.messageId, 256, 'messageId');
    if (!mailbox || !messageId) fail('Mailbox and messageId required');
    const key = JSON.stringify([mailbox, messageId]);
    if (seen.has(key)) fail('Duplicate mailbox/messageId in input'); seen.add(key);
    const fromAddress = bounded(message.fromAddress, 320, 'fromAddress', true), replyTo = bounded(message.replyTo, 320, 'replyTo', true);
    const displayName = bounded(message.displayName, 320, 'displayName', true), text = bounded(message.text, 500000, 'text', true);
    const linkPairs = message.linkPairs === undefined ? [] : message.linkPairs;
    if (!Array.isArray(message.urls) || !Array.isArray(linkPairs) || linkPairs.length > 500) fail('Invalid URL or link-pair list');
    const pairs = linkPairs.map(pair => {
      if (!pair || typeof pair !== 'object' || Array.isArray(pair)) fail('Invalid link pair');
      return { visibleUrl: bounded(pair.visibleUrl, 16384, 'visibleUrl'), href: bounded(pair.href, 16384, 'href') };
    });
    const cssTexts = message.cssTexts === undefined ? [] : message.cssTexts;
    if (!Array.isArray(cssTexts) || cssTexts.length > 500) fail('Invalid CSS source list');
    let cssLength = 0;
    for (const css of cssTexts) { bounded(css, 500000, 'CSS source'); cssLength += css.length; }
    if (cssLength > 500000) fail('CSS source size limit exceeded');
    const cssExtraction = extractCssUrls(cssTexts);
    const destinations = [...message.urls, ...pairs.map(pair => pair.href), ...cssExtraction.urls];
    if (destinations.length > 500 || (totalUrls += destinations.length) > 2000) fail('URL count limit exceeded');
    for (const url of destinations) bounded(url, 16384, 'URL');
    const context = message.context;
    if (context !== undefined && (!context || typeof context !== 'object' || Array.isArray(context) || typeof context.securityReport !== 'boolean' || context.source !== 'user_confirmed')) fail('Context requires an explicit user-confirmed source');
    // Transport headers: explicit `headers`, else those preserved by --extract.
    const headers = signalsLib.normalizeHeaders(message.headers ?? message.extraction?.originalHeaders ?? message.extraction?.headers);
    const attachments = message.attachments ?? (Array.isArray(message.extraction?.attachments) ? message.extraction.attachments : []);
    if (!Array.isArray(attachments) || attachments.length > 200 || attachments.some(x => !x || typeof x !== 'object' || (x.filename !== undefined && typeof x.filename !== 'string') || (x.mime !== undefined && typeof x.mime !== 'string'))) fail('Invalid attachment metadata');
    return { mailbox, messageId, fromAddress, replyTo, displayName, text, linkPairs: pairs, cssExtraction,
      confirmedReport: context?.securityReport === true, urls: [...new Set(destinations)], headers,
      attachments: attachments.map(x => ({ filename: String(x.filename || '').slice(0, 260), mime: String(x.mime || '').toLowerCase().slice(0, 200) })) };
  });
}
// Optional output of scripts/enrich.cjs (RDAP, URLhaus, Spamhaus DBL, first contact).
function normalizeEnrichment(value) {
  if (value === undefined) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schemaVersion !== 1) fail('Invalid enrichment');
  for (const key of ['domains', 'hosts', 'senders']) if (value[key] !== undefined && (typeof value[key] !== 'object' || Array.isArray(value[key]) || Object.keys(value[key]).length > 2000)) fail('Invalid enrichment ' + key);
  return value;
}
function bundledRuleSet() {
  const { runtimeRuleSet } = require('./rule-learning.cjs');
  return runtimeRuleSet(JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'rules', 'filter-rules.json'), 'utf8')));
}
function analyze(input, loaded = readCache()) {
  if (input?.useBundledRules !== undefined && typeof input.useBundledRules !== 'boolean') fail('useBundledRules must be boolean');
  const bundled = input?.useBundledRules ? bundledRuleSet() : {};
  const messages = inputMessages(input), sourceInfo = statuses(loaded);
  const campaignRules = normalizeCampaignRules(input.campaignRules ?? bundled.campaignRules);
  const senderRules = signalsLib.normalizeSenderRules(input.senderRules ?? bundled.senderRules);
  const signalRules = signalsLib.normalizeSignalRules(input.signalRules ?? bundled.signalRules);
  const manualOnly = new Set();
  const enrichment = normalizeEnrichment(input.enrichment);
  // Validated indexes and per-batch memoization never enter the public cache.
  const indexes = loaded.indexes || Object.fromEntries(Object.entries(loaded.cache.sources).map(([name, record]) => [name, parseSource(name, record.text)]));
  const psl = indexes.psl, feed = indexes.openphish?.entries;
  const memo = action => {
    const values = new Map();
    return key => { if (!values.has(key)) values.set(key, action(key)); return values.get(key); };
  };
  const domain = memo(host => registeredDomain(host, psl)), address = memo(value => addressDomain(value, psl));
  const parsedUrl = memo(parseUrl);
  const compare = (left, right) => compareHosts(left, right, domain, sourceInfo.psl.status === 'current');
  const finding = memo(originalUrl => {
    const parsed = parsedUrl(originalUrl), exactMatch = feed ? feed.has(originalUrl) : null;
    return { originalUrl, ...parsed, registeredDomain: parsed.status === 'parsed' ? domain(parsed.hostname) : { status: 'not_checked', value: null },
      openphish: { status: !feed ? 'unavailable' : sourceInfo.openphish.status === 'stale' ? 'stale' : exactMatch ? 'listed' : 'not_listed', exactMatch, matchScope: 'exact_original_url' } };
  });
  const references = new Map();
  const analyzed = messages.map(message => {
    const observations = new Set(), signals = [], reviewRuleIds = new Set(), uncertain = new Set();
    if (message.cssExtraction.skipped.length) uncertain.add('css_extraction_incomplete');
    const signal = (name, details) => { const [ruleId, review] = RULES[name]; observations.add(name); signals.push({ ruleId, ...details }); if (review) reviewRuleIds.add(ruleId); };
    const signalCampaign = match => { observations.add('configured_campaign_match'); signals.push({ ruleId: match.ruleId, source: 'chatgpt_supplied_campaign_rule', markers: match.markers, parameters: match.parameters, paths: match.paths }); if (!message.confirmedReport) reviewRuleIds.add(match.ruleId); };
    const urlFindings = message.urls.map(originalUrl => {
      const parsed = finding(originalUrl);
      if (parsed.status === 'parsed') {
        if (parsed.hasUserInfo) signal('url_userinfo', { originalUrl });
        if (parsed.openphish.status === 'listed') signal('public_feed_exact_match', { originalUrl, matchScope: 'exact_original_url' });
        if (!references.has(originalUrl)) references.set(originalUrl, []);
        references.get(originalUrl).push({ mailbox: message.mailbox, messageId: message.messageId });
      } else uncertain.add('destination_not_parsed');
      return parsed;
    });
    const configuredCampaignMatches = campaignMatches(message, urlFindings, campaignRules);
    for (const match of configuredCampaignMatches) signalCampaign(match);
    const linkComparisons = message.linkPairs.map((pair, index) => {
      const visible = parsedUrl(pair.visibleUrl), actual = parsedUrl(pair.href);
      const comparison = compare(visible.status === 'parsed' ? visible.hostname : null, actual.status === 'parsed' ? actual.hostname : null);
      if (comparison.status === 'different_registered_domain') signal('link_domain_mismatch', { pairIndex: index, ...pair, comparison });
      if (comparison.status === 'different_hostname_boundary_unknown') { signal('link_boundary_unknown', { pairIndex: index, comparison }); uncertain.add('link_domain_boundary_unknown'); }
      return { ...pair, comparison, visibleParseStatus: visible.status, hrefParseStatus: actual.status };
    });
    const from = address(message.fromAddress), replyTo = address(message.replyTo);
    const replyComparison = compare(from.status === 'parsed' ? from.hostname : null, replyTo.status === 'parsed' ? replyTo.hostname : null);
    if (replyComparison.status === 'different_registered_domain') signal('reply_to_domain_difference', { comparison: replyComparison, contextRequired: true });
    if (replyComparison.status === 'different_hostname_boundary_unknown') signal('reply_to_boundary_unknown', { comparison: replyComparison, contextRequired: true });
    const displayAddress = address(message.displayName), displayUrl = parsedUrl(message.displayName);
    const displayHost = displayAddress.status === 'parsed' ? displayAddress.hostname : displayUrl.status === 'parsed' ? displayUrl.hostname : null;
    const displayComparison = compare(from.status === 'parsed' ? from.hostname : null, displayHost);

    const displayMailbox = from.status === 'parsed' && displayAddress.status === 'parsed'
      ? { status: from.normalizedAddress === displayAddress.normalizedAddress ? 'same_address'
          : from.hostname === displayAddress.hostname && from.localPart.toLowerCase() === displayAddress.localPart.toLowerCase() ? 'case_only_localpart_difference' : 'different_address',
          method: 'exact_localpart_and_idna_domain', actual: from.normalizedAddress, claimed: displayAddress.normalizedAddress, contextRequired: true }
      : { status: 'not_comparable', method: 'none' };
    if (displayMailbox.status === 'different_address') signal('display_mailbox_difference', { comparison: displayMailbox, contextRequired: true, aliasesNotResolved: true });
    if (displayMailbox.status === 'case_only_localpart_difference') signal('display_mailbox_case_difference', { comparison: displayMailbox, contextRequired: true });
    if (displayComparison.status === 'different_registered_domain') signal('display_identity_difference', { comparison: displayComparison, explicitClaimOnly: true });
    if (displayComparison.status === 'different_hostname_boundary_unknown') { signal('display_boundary_unknown', { comparison: displayComparison }); uncertain.add('display_domain_boundary_unknown'); }
    // Central sender rules (exact domains or anchored address shapes).
    const configuredSenderMatches = signalsLib.senderMatches(from.status === 'parsed' ? from.normalizedAddress : '', senderRules);
    for (const match of configuredSenderMatches) { observations.add('configured_sender_match'); signals.push({ source: 'central_sender_rule', ...match }); if (!message.confirmedReport) reviewRuleIds.add(match.ruleId); }
    // Header-derived authentication and provider signals.
    const auth = signalsLib.parseAuthResults(message.headers), ms = signalsLib.parseMsAntispam(message.headers);
    const orgDomain = host => { const r = domain(host); return sourceInfo.psl.status === 'current' && r.status === 'known' ? r.value : null; };
    const alignment = signalsLib.dmarcAlignment(auth, from.status === 'parsed' ? from.hostname : null, orgDomain);
    const ctx = { auth, ms, alignment, from: from.status === 'parsed' ? from : null, replyComparison, linkComparisons, urlFindings, displayName: message.displayName, text: message.text, orgDomain, attachments: message.attachments, enrichment };
    const configuredSignalMatches = [];
    let signalWeight = 0;
    for (const rule of signalRules) {
      const hit = rule.evaluator ? signalsLib.evaluateSignalRule(rule, ctx) : undefined;
      if (hit === undefined) { manualOnly.add(rule.id); continue; }
      if (!hit) continue;
      configuredSignalMatches.push({ ruleId: rule.id, category: rule.category, severity: rule.severity, weight: rule.weight, details: hit });
      observations.add('configured_signal_match');
      signals.push({ ruleId: rule.id, source: 'central_signal_rule', severity: rule.severity, details: hit });
      signalWeight += rule.weight;
      if (rule.severity === 'high') reviewRuleIds.add(rule.id);
    }
    // Low/medium signals recommend review only in combination (weight >= 4).
    if (signalWeight >= 4) for (const m of configuredSignalMatches) reviewRuleIds.add(m.ruleId);
    if (message.confirmedReport && configuredCampaignMatches.length) signal('campaign_in_confirmed_report', { source: 'user_confirmed', doesNotOverrideOtherSignals: true, configuredRuleIds: configuredCampaignMatches.map(x => x.ruleId) });
    const reviewRules = [...reviewRuleIds];
    for (const name of Object.keys(SOURCES)) if (sourceInfo[name].status !== 'current') uncertain.add(name + '_not_current');
    return { mailbox: message.mailbox, messageId: message.messageId, from, replyTo,
      observations: [...observations], signals, configuredCampaignMatches, configuredSenderMatches, configuredSignalMatches, signalWeight,
      authentication: { ...auth, dmarcAlignment: alignment }, providerVerdict: ms, urlFindings, linkComparisons, cssExtraction: message.cssExtraction,
      identityComparisons: { replyTo: replyComparison, displayName: displayComparison, displayMailbox },
      review: { status: reviewRules.length ? 'review_recommended' : uncertain.size ? 'uncertain' : 'no_additional_signal', ruleIds: reviewRules, uncertainties: [...uncertain], meaning: 'Review routing only; no safety or phishing verdict' }, classification: null,
      coverage: { input: 'provided_structured_fields_only', mime: 'not_checked', authentication: auth.status === 'parsed' ? 'headers_parsed_not_cryptographically_verified' : auth.status === 'not_provided' ? 'not_checked' : auth.status, attachments: 'not_checked', qr: 'not_checked', scannerVerdicts: 'not_checked',
        linkPairs: message.linkPairs.length ? 'provided_pairs_compared' : 'not_provided', senderIdentity: 'provided_explicit_domains_only' } };
  });
  return { mode: 'observe_only', sources: sourceInfo, messages: analyzed,
    centralRules: { campaign: campaignRules.length, sender: senderRules.length, signal: signalRules.length, manualReviewOnly: [...manualOnly].sort() }, scanJobs: [...references].flatMap(([originalUrl, refs]) => ['Malwarebytes', 'Bitdefender'].map(engine => ({ engine, originalUrl, status: 'required_not_executed', references: refs }))), mailboxActions: [],
    limitations: ['No URL was visited or scanned by this helper', 'A feed miss is not evidence of safety', 'No classification or automatic mailbox action', 'Original URL strings are preserved; source publication time is unknown'] };
}
function selfTest() {
  let tests = 0;
  const test = (name, action) => { action(); tests++; };
  const fixture = '// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\nid\nweb.id\n*.ck\n!www.ck\nрф\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\nblogspot.com\n// ===END PRIVATE DOMAINS===\n';
  const psl = parsePsl(fixture), now = new Date().toISOString();
  const record = (name, text) => ({ sourceUrl: SOURCES[name].url, text, sha256: hash(text), count: parseSource(name, text).count, retrievedAt: now, validatedAt: now, publishedAt: null, etag: null, lastModified: null });
  const loaded = { status: 'loaded', cache: { schemaVersion: 1, sources: { psl: record('psl', fixture), openphish: record('openphish', 'https://bad.example/a?q=1#x\n') } } };
  const message = { mailbox: 'Gmail', messageId: 'synthetic-1', text: '', urls: [] };
  // Load the real central campaign rules so the self-test cannot drift from rules/filter-rules.json.
  const campaignRules = bundledRuleSet().campaignRules;
  assert.ok(campaignRules.some(r => r.id === 'campaign.marker-and-path.v1'), 'central campaign rule missing');
  const first = overrides => analyze({ ...message, ...overrides, campaignRules }, loaded).messages[0];
  test('CSS URLs preserve query and fragment and queue both engines',()=>{const u='https://images.example.com/a?q=1&x=2#part';const a=analyze({...message,cssTexts:['background:url("'+u+'")']},loaded);assert.deepEqual(a.messages[0].cssExtraction.urls,[u]);assert.equal(a.scanJobs.length,2);assert.ok(a.scanJobs.every(x=>x.originalUrl===u));});
  test('CSS quoted parentheses and unquoted URLs extracted',()=>assert.deepEqual(first({cssTexts:["a{background:url('https://example.com/a(b).png')} b{background:url(https://example.com/b)}"]}).cssExtraction.urls,['https://example.com/a(b).png','https://example.com/b']));
  test('CSS and existing URLs share scanner jobs',()=>assert.equal(analyze({...message,urls:['https://example.com/a'],cssTexts:['url(https://example.com/a) url(https://example.com/a)']},loaded).scanJobs.length,2));
  test('CSS comment URL does not create scanner job',()=>assert.equal(analyze({...message,cssTexts:['/* url(https://example.com/a) */']},loaded).scanJobs.length,0));
  test('relative and data CSS URLs are not activated',()=>{const a=first({cssTexts:['url(/image.png) url(data:image/png;base64,AAAA)']});assert.equal(a.cssExtraction.urls.length,0);assert.ok(a.review.uncertainties.includes('css_extraction_incomplete'));});
  test('escaped CSS and imports remain explicitly incomplete',()=>{const a=first({cssTexts:['@import "https://example.com/s.css"; a{background:u\\72l(https://example.com/a)}']});assert.ok(a.cssExtraction.skipped.length);assert.ok(a.review.uncertainties.includes('css_extraction_incomplete'));});
  test('CSS input type and size bounded',()=>{assert.throws(()=>first({cssTexts:'url(x)'}));assert.throws(()=>first({cssTexts:['x'.repeat(250001),'x'.repeat(250001)]}));});
  test('CSS cannot bypass destination count limit',()=>assert.throws(()=>first({urls:Array(500).fill('https://example.com/a'),cssTexts:['url(https://example.com/b)']})));
  test('CSS absent remains unexamined rather than clean',()=>assert.equal(first({}).cssExtraction.status,'not_provided'));
  for (const [name, host, expected] of [
    ['compound suffix', 'a.example.co.uk', 'example.co.uk'],
    ['Indonesian suffix', 'x.y.web.id', 'y.web.id'],
    ['wildcard suffix', 'x.a.ck', 'x.a.ck'],
    ['exception suffix', 'x.www.ck', 'www.ck'],
    ['private suffix', 'x.person.blogspot.com', 'person.blogspot.com']
  ]) test(name, () => assert.equal(registeredDomain(host, psl).value, expected));
  test('public suffix only', () => assert.equal(registeredDomain('co.uk', psl).status, 'public_suffix_only'));
  test('unknown suffix', () => assert.equal(registeredDomain('a.invalid', psl).value, null));
  test('IP not domain', () => assert.equal(registeredDomain('127.0.0.1', psl).status, 'not_applicable'));
  test('IDN', () => assert.equal(registeredDomain('пример.рф', psl).value, domainToASCII('пример.рф')));
  test('real hostname', () => assert.equal(parseUrl('https://paypal.com@evil.example/x').hostname, 'evil.example'));
  test('userinfo flag', () => assert.equal(parseUrl('https://good.example@evil.example/').hasUserInfo, true));
  test('IPv6', () => assert.equal(parseUrl('https://[::1]/').hostKind, 'ip'));
  test('underscore web host preserved without DNS claim', () => { const p = parseUrl('http://en-live-ledger-docs_support.typedream.app/'); assert.equal(p.status, 'parsed'); assert.equal(p.hostKind, 'non_dns_hostname'); assert.equal(registeredDomain(p.hostname, psl).value, null); });
  test('ambiguous URL', () => assert.notEqual(parseUrl('https:evil.example').status, 'parsed'));
  for (const [name, url] of [
    ['triple slash rejected', 'https:///evil.example/a'],
    ['quadruple slash rejected', 'https:////evil.example/a'],
    ['backslash rejected', 'https://a.example\\@b.example/']
  ]) test(name, () => assert.equal(parseUrl(url).status, 'ambiguous'));
  test('unsupported scheme', () => assert.equal(parseUrl('javascript:alert(1)').status, 'unsupported_scheme'));
  for (const [name, text] of [['HTML feed rejected', '<html>Unavailable</html>'], ['empty feed rejected', '']]) test(name, () => assert.throws(() => parseOpenPhish(text)));
  test('oversize feed rejected', () => assert.throws(() => parseOpenPhish('x'.repeat(SOURCES.openphish.max + 1))));
  test('missing private section rejected', () => assert.throws(() => parsePsl('com\n')));
  for (const [name, text] of [
    ['truncated PSL rejected', fixture.replace('// ===END PRIVATE DOMAINS===', '')],
    ['PSL section order checked', fixture.replace('// ===BEGIN PRIVATE DOMAINS===', '// ===BEGIN ICANN DOMAINS===')],
    ['PSL out of section rule rejected', fixture + 'net\n']
  ]) test(name, () => assert.throws(() => parsePsl(text)));
  for (const [name, changed] of [
    ['cache hash checked', { text: fixture + 'net\n' }],
    ['cache source URL checked', { sourceUrl: 'https://attacker.example/' }],
    ['future time rejected', { validatedAt: '2099-01-01T00:00:00.000Z' }]
  ]) test(name, () => assert.throws(() => validateRecord('psl', { ...loaded.cache.sources.psl, ...changed })));
  test('input duplicate identity rejected', () => assert.throws(() => inputMessages({ messages: [message, message] })));
  test('invalid input URLs rejected', () => assert.throws(() => inputMessages({ ...message, urls: [5] })));
  test('no campaign marker false hit', () => assert.deepEqual(first({ text: '111.9570975' }).observations, []));
  test('exact marker alone remains supporting context', () => assert.equal(first({ text: 'code: 111.957097 ' }).configuredCampaignMatches.length, 0));
  test('sender marker combines only with configured exact path', () => assert.ok(first({ fromAddress: 'tsgazyu.111.957097@example.com', urls: ['https://a.example/worklinks/proforward.html'] }).signals.some(x => x.ruleId === 'campaign.marker-and-path.v1' && x.source === 'chatgpt_supplied_campaign_rule')));
  test('campaign combination scoped to one message', () => { const a = analyze({ ...message, text: '111.957097', urls: ['https://a.example/worklinks/proforward.html'], campaignRules }, loaded); assert.ok(a.messages[0].observations.includes('configured_campaign_match')); });
  test('separate messages cannot form combination', () => { const a = analyze({ messages: [{ ...message, text: '111.957097' }, { ...message, messageId: 'synthetic-2', urls: ['https://a.example/worklinks/proforward.html'] }], campaignRules }, loaded); assert.ok(a.messages.every(x => !x.observations.includes('configured_campaign_match'))); });
  test('path boundary', () => assert.equal(first({ text: '111.957097', urls: ['https://a.example/worklinks/proforward.html.bak'] }).configuredCampaignMatches.length, 0));
  test('exact feed hit and no classification', () => { const a = analyze({ ...message, urls: ['https://bad.example/a?q=1#x'] }, loaded); assert.equal(a.messages[0].urlFindings[0].openphish.status, 'listed'); assert.equal(a.messages[0].classification, null); });
  test('underscore feed URL exact match and both scanner jobs', () => { const url = 'http://en-live-ledger-docs_support.typedream.app/'; const cache = { ...loaded, cache: { ...loaded.cache, sources: { ...loaded.cache.sources, openphish: record('openphish', url + '\n') } } }; assert.ok(parseOpenPhish(url).entries.has(url)); const a = analyze({ ...message, urls: [url] }, cache); assert.equal(a.messages[0].urlFindings[0].openphish.status, 'listed'); assert.equal(a.messages[0].urlFindings[0].registeredDomain.status, 'invalid'); assert.equal(a.messages[0].urlFindings[0].registeredDomain.value, null); assert.equal(a.scanJobs.length, 2); assert.ok(a.scanJobs.every(x => x.originalUrl === url)); });
  test('underscore sender domain remains invalid', () => assert.equal(addressDomain('sender@docs_support.example', psl).status, 'invalid'));
  test('changed query or fragment not exact hit', () => { for (const url of ['https://bad.example/a?q=2#x', 'https://bad.example/a?q=1#y']) assert.equal(first({ urls: [url] }).urlFindings[0].openphish.exactMatch, false); });
  test('cross-message scanner dedup', () => { const a = analyze({ messages: [{ ...message, urls: ['https://bad.example/a', 'https://bad.example/a'] }, { ...message, messageId: 'synthetic-2', urls: ['https://bad.example/a'] }] }, loaded); assert.equal(a.scanJobs.length, 2); assert.equal(a.scanJobs[0].references.length, 2); assert.deepEqual(a.mailboxActions, []); });
  test('no cross-message campaign join', () => { const a = analyze({ messages: [{ ...message, text: '111.' }, { ...message, messageId: 'synthetic-2', text: '957097' }], campaignRules }, loaded); assert.ok(a.messages.every(x => !x.observations.length)); });
  test('missing feed explicit', () => assert.equal(analyze(message, { status: 'unavailable', cache: { schemaVersion: 1, sources: {} } }).sources.openphish.status, 'unavailable'));
  test('stale feed explicit', () => assert.equal(sourceStatus('openphish', { ...loaded.cache.sources.openphish, validatedAt: '2020-01-01T00:00:00.000Z' }).status, 'stale'));

  test('link domain mismatch is concrete review signal', () => { const a=first({linkPairs:[{visibleUrl:'https://bank.example.com/login',href:'https://account.other.com/login'}]});assert.ok(a.observations.includes('link_domain_mismatch'));assert.equal(a.review.status,'review_recommended');assert.equal(a.classification,null); });
  test('same registered domain link is not mismatch', () => { const a=first({linkPairs:[{visibleUrl:'https://a.example.com/a',href:'https://b.example.com/b'}]});assert.equal(a.linkComparisons[0].comparison.status,'same_registered_domain');assert.ok(!a.observations.includes('link_domain_mismatch')); });
  test('same IDN and ASCII link host is equal', () => { const a=first({linkPairs:[{visibleUrl:'https://пример.рф/a',href:'https://'+domainToASCII('пример.рф')+'/b'}]});assert.equal(a.linkComparisons[0].comparison.status,'same_hostname'); });
  test('different private hosting accounts remain separate', () => assert.ok(first({linkPairs:[{visibleUrl:'https://alice.blogspot.com/',href:'https://bob.blogspot.com/'}]}).observations.includes('link_domain_mismatch')));
  test('unknown suffix is a boundary uncertainty', () => { const a=first({linkPairs:[{visibleUrl:'https://a.invalid/a',href:'https://b.invalid/b'}]});assert.ok(!a.observations.includes('link_domain_mismatch'));assert.equal(a.review.status,'uncertain'); });
  test('link-pair href only is added to scan queue', () => { const a=analyze({...message,linkPairs:[{visibleUrl:'https://visible.example.com/',href:'https://actual.other.com/'}]},loaded);assert.equal(a.scanJobs.length,2);assert.ok(a.scanJobs.every(job=>job.originalUrl==='https://actual.other.com/'));assert.equal(a.messages[0].urlFindings.length,1); });
  test('duplicate href and existing URL are checked once', () => {const url='https://actual.other.com/';const a=analyze({...message,urls:[url],linkPairs:[{visibleUrl:'https://visible.example.com/',href:url}]},loaded);assert.equal(a.scanJobs.length,2);assert.equal(a.scanJobs[0].references.length,1);});
  test('generic visible CTA is not a domain mismatch', () => {const a=first({linkPairs:[{visibleUrl:'Bekijk factuur',href:'https://billing.example.com/'}]});assert.equal(a.linkComparisons[0].comparison.status,'not_comparable');assert.ok(!a.observations.includes('link_domain_mismatch'));});
  test('invalid href is uncertain and never queued', () => {const a=analyze({...message,linkPairs:[{visibleUrl:'https://billing.example.com/',href:'https:///bad.com/'}]},loaded);assert.equal(a.scanJobs.length,0);assert.equal(a.messages[0].review.status,'uncertain');});
  test('reply-to difference alone is supporting context', () => {const a=first({fromAddress:'newsletter@shop.com',replyTo:'responses@mailer.com'});assert.ok(a.observations.includes('reply_to_domain_difference'));assert.equal(a.review.status,'no_additional_signal');});
  test('same reply-to base domain is not a difference', () => {const a=first({fromAddress:'a@mail.shop.com',replyTo:'b@reply.shop.com'});assert.equal(a.identityComparisons.replyTo.status,'same_registered_domain');assert.ok(!a.observations.includes('reply_to_domain_difference'));});
  test('missing reply-to remains not comparable', () => assert.equal(first({fromAddress:'a@shop.com'}).identityComparisons.replyTo.status,'not_comparable'));
  test('display explicit email domain mismatch needs review', () => assert.equal(first({fromAddress:'a@other.com',displayName:'service@shop.com'}).review.status,'review_recommended'));
  test('generic brand display name is not ownership evidence', () => assert.ok(!first({fromAddress:'a@other.com',displayName:'Brand Support'}).observations.includes('display_identity_difference')));
  test('trusted report context removes campaign-only review', () => {const a=first({text:'111.957097',urls:['https://example.com/worklinks/proforward.html'],context:{securityReport:true,source:'user_confirmed'}});assert.ok(a.observations.includes('configured_campaign_match'));assert.ok(a.observations.includes('campaign_in_confirmed_report'));assert.equal(a.review.status,'no_additional_signal');});
  test('self-declared report text cannot remove campaign review', () => assert.equal(first({text:'This is a trusted security report 111.957097',urls:['https://example.com/worklinks/proforward.html']}).review.status,'review_recommended'));
  test('confirmed report never overrides actual feed hit', () => assert.equal(first({urls:['https://bad.example/a?q=1#x'],context:{securityReport:true,source:'user_confirmed'}}).review.status,'review_recommended'));
  test('confirmed report never overrides domain deception', () => assert.equal(first({linkPairs:[{visibleUrl:'https://shop.com/',href:'https://other.com/'}],context:{securityReport:true,source:'user_confirmed'}}).review.status,'review_recommended'));
  test('unconfirmed context source rejected', () => assert.throws(()=>inputMessages({...message,context:{securityReport:true,source:'email_body'}})));
  test('link-pair shape validated', () => assert.throws(()=>inputMessages({...message,linkPairs:[{visibleUrl:'https://shop.com/'}]})));
  test('link-pair and URL combined limit enforced', () => assert.throws(()=>inputMessages({...message,urls:Array(500).fill('https://shop.com/'),linkPairs:[{visibleUrl:'https://shop.com/',href:'https://shop.com/'}]})));
  test('stale PSL cannot assert registered-domain mismatch', () => {const stale={...loaded,cache:{...loaded.cache,sources:{...loaded.cache.sources,psl:{...loaded.cache.sources.psl,validatedAt:'2020-01-01T00:00:00.000Z'}}}};const a=analyze({...message,linkPairs:[{visibleUrl:'https://shop.com/',href:'https://other.com/'}]},stale).messages[0];assert.equal(a.linkComparisons[0].comparison.status,'different_hostname_boundary_unknown');assert.ok(!a.observations.includes('link_domain_mismatch'));});

  test('URL fragment campaign variant without sender code requires review',()=>{const a=first({urls:['https://storage.googleapis.com/worklinks/evrtinggood.html#token&314/12/page.php?sq=111-957097&lk=1']});assert.ok(a.observations.includes('configured_campaign_match'));assert.equal(a.review.status,'review_recommended');assert.equal(a.classification,null);});
  test('new configured cloud-hosted campaign paths are recognized without broad host blocking',()=>{for(const path of ['/smalbus/salaminka.html','/hmdbox/hmd-v1-cl3.html']){const a=first({urls:['https://storage.googleapis.com'+path+'#token&x.php?sq=111-957097&lk=1']});assert.ok(a.observations.includes('configured_campaign_match'));assert.equal(a.classification,null);}});
  test('query campaign variant with known path requires review',()=>assert.equal(first({urls:['https://example.com/worklinks/proforward.html?sq=111-957097']}).review.status,'review_recommended'));
  test('URL parameter alone remains supporting evidence',()=>assert.equal(first({urls:['https://example.com/normal?sq=111-957097']}).review.status,'no_additional_signal'));
  test('longer parameter value is not the campaign',()=>assert.equal(first({urls:['https://example.com/worklinks/proforward.html?sq=111-9570975']}).configuredCampaignMatches.length,0));
  test('different parameter name is not the campaign',()=>assert.equal(first({urls:['https://example.com/worklinks/proforward.html?other_sq=111-957097']}).configuredCampaignMatches.length,0));
  test('parameter and path in different messages cannot combine',()=>{const a=analyze({messages:[{...message,messageId:'parameter',urls:['https://example.com/normal?sq=111-957097']},{...message,messageId:'path',urls:['https://example.com/worklinks/proforward.html']}],campaignRules},loaded);assert.ok(a.messages.every(m=>!m.observations.includes('configured_campaign_match')));});
  test('confirmed report context explains new variant',()=>assert.equal(first({urls:['https://example.com/worklinks/proforward.html?sq=111-957097'],context:{securityReport:true,source:'user_confirmed'}}).review.status,'no_additional_signal'));
  test('synthetic evaluation reports false positives and abstentions',()=>{const e=evaluate();assert.equal(e.dataset.cases,20);assert.ok(e.proposed.counts.falsePositive>=1);assert.equal(e.proposed.counts.abstained,1);assert.equal(e.proposed.counts.unadjudicated,1);assert.equal(e.proposed.counts.uncertainOutputs,2);});

  test('different explicit mailboxes on same provider need context',()=>{const a=first({fromAddress:'sender@gmail.com',displayName:'ceo@gmail.com'});assert.equal(a.identityComparisons.displayMailbox.status,'different_address');assert.ok(a.observations.includes('display_mailbox_difference'));assert.equal(a.review.status,'review_recommended');assert.equal(a.classification,null);});
  test('display email domain case is normalized',()=>{const a=first({fromAddress:'person@example.com',displayName:'person@EXAMPLE.COM'});assert.equal(a.identityComparisons.displayMailbox.status,'same_address');assert.ok(!a.observations.includes('display_mailbox_difference'));});
  test('localpart case difference is supporting only',()=>{const a=first({fromAddress:'Person@example.com',displayName:'person@example.com'});assert.equal(a.identityComparisons.displayMailbox.status,'case_only_localpart_difference');assert.equal(a.review.status,'no_additional_signal');});
  test('possible legitimate alias remains unresolved without spam verdict',()=>{const a=first({fromAddress:'person+orders@example.com',displayName:'person@example.com'});assert.equal(a.identityComparisons.displayMailbox.status,'different_address');assert.ok(a.signals.some(x=>x.ruleId==='identity.display_mailbox_difference.v1'&&x.aliasesNotResolved&&x.contextRequired));assert.equal(a.classification,null);});

  const fullFixture = { id: 'fixture', label_ids: ['SPAM'], payload: { mime_type: 'multipart/alternative', headers: [{name:'From',value:'Service <sender@example.com>'},{name:'Subject',value:'Example'},{name:'Authentication-Results',value:'mx; spf=pass'},{name:'List-Unsubscribe',value:'<https://example.com/leave?q=1&x=2>'}], parts: [{mime_type:'text/plain',body:{content:'Plain version'}},{mime_type:'text/html',body:{content:'<style>a{background:url(https://example.com/bg?q=1#part)}</style><a href=https://other.com/login>https://shop.com/login</a><img src="https://example.com/a?x=1&amp;y=2" style="background:url(&quot;https://example.com/inline&quot;)">'}},{mime_type:'application/pdf',filename:'invoice.pdf',body:{attachment_id:'id'}}] } };
  const prepared = () => extractMail('box', fullFixture);
  test('central extraction preserves headers and versions',()=>{const x=prepared();assert.equal(x.fromAddress,'sender@example.com');assert.equal(x.extraction.authentication[0],'mx; spf=pass');assert.equal(x.sourceHash,prepared().sourceHash);assert.ok(x.text.includes('Plain version'));assert.equal(x.extraction.attachments[0].status,'metadata_only');});
  test('central extraction handles unquoted links and entities once',()=>{const x=prepared();assert.ok(x.urls.includes('https://other.com/login'));assert.ok(x.urls.includes('https://example.com/a?x=1&y=2'));assert.ok(x.urls.includes('https://example.com/leave?q=1&x=2'));assert.equal(x.linkPairs[0].visibleUrl,'https://shop.com/login');assert.equal(decodeEntities('&amp;amp;'),'&amp;');});
  test('central extraction integrates CSS and actual link comparison',()=>{const a=analyze(prepared(),loaded);assert.ok(a.scanJobs.some(j=>j.originalUrl==='https://example.com/inline'));assert.ok(a.scanJobs.some(j=>j.originalUrl==='https://example.com/bg?q=1#part'));assert.ok(a.messages[0].observations.includes('link_domain_mismatch'));});
  test('embedded HTML in nominal plaintext is inspected',()=>{const x=extractMail('box',{id:'x',payload:{mime_type:'text/plain',headers:[],body:{content:'<a href="https://example.com/a">Visit</a>'}}});assert.deepEqual(x.urls,['https://example.com/a']);});
  test('base64 text decoding is explicit and bounded',()=>{const x=extractMail('box',{id:'x',payload:{mime_type:'text/plain',headers:[],body:{base64_url_content:Buffer.from('https://example.com/a').toString('base64url')}}});assert.deepEqual(x.urls,['https://example.com/a']);assert.ok(x.extraction.limitations.some(s=>s.includes('UTF-8')));});
  test('provider tree recursion and malformed headers rejected',()=>{var p={mime_type:'multipart/mixed'};var root=p;for(var i=0;i<32;i++){p.parts=[{mime_type:'multipart/mixed'}];p=p.parts[0];}assert.throws(()=>extractMail('box',{id:'x',payload:root}));assert.throws(()=>extractMail('box',{id:'x',payload:{headers:[{name:1,value:'x'}]}}));});
  const stamp='2026-11-01T12:00:00.000Z', tick=Date.parse(stamp), url='https://example.com/a?q=1#x';
  const job={engine:'Malwarebytes',originalUrl:url,status:'required_not_executed',references:[]};
  const scan={engine:'Malwarebytes',indicatorType:'url',indicator:url,checkedAt:stamp,result:{verdict:'unknown'},error:false};
  test('unknown cache before 24h reused with original time',()=>{const p=planScans([job],[scan],tick+86399999)[0];assert.equal(p.status,'cached_result');assert.equal(p.checkedAt,stamp);});
  test('unknown at 24h expires and safe at 7d expires',()=>{assert.equal(planScans([job],[scan],tick+86400000)[0].status,'required_not_executed');assert.equal(planScans([job],[{...scan,result:{verdict:'safe'}}],tick+604800000)[0].status,'required_not_executed');});
  test('missing engine and changed query cannot reuse cache',()=>{assert.equal(planScans([{...job,engine:'Bitdefender'}],[scan],tick)[0].status,'required_not_executed');assert.equal(planScans([{...job,originalUrl:url+'2'}],[scan],tick)[0].status,'required_not_executed');});
  test('new evidence always forces checks',()=>assert.equal(planScans([job],[scan],tick,[url])[0].reason,'new_evidence_forces_recheck'));
  test('latest failure supersedes older good scan',()=>assert.equal(planScans([job],[scan,{...scan,checkedAt:'2026-11-01T12:00:01.000Z',error:true}],tick+2000)[0].reason,'failed_or_unrecognized_result'));
  test('future missing invalid timestamp and unknown result rejected',()=>{for(const s of [{...scan,checkedAt:null},{...scan,checkedAt:'bad'},{...scan,checkedAt:'2026-11-02T12:00:00.000Z'},{...scan,result:{verdict:'invented'}}])assert.equal(planScans([job],[s],tick)[0].status,'required_not_executed');});
  test('BD inconclusive expires after 24h',()=>assert.equal(planScans([{...job,engine:'Bitdefender'}],[{...scan,engine:'Bitdefender',result:{mappedStatus:'so_far_so_good_2'}}],tick+86400000)[0].status,'required_not_executed'));
  const resumed={mailbox:'box',messageId:'fixture',fromAddress:'sender@example.com',sourceHash:'same',providerLabels:['SPAM']};
  const saved={mailbox:'box',messageId:'fixture',sourceHash:'same',assessment:{classification:'duidelijke phishing'},reports:{gmail:{status:'confirmed',classification:'phishing'}},block:{status:'confirmed',address:'sender@example.com'},action:{status:'confirmed'}};
  test('confirmed steps skipped while Trash remains pending',()=>{const r=resumePlan(resumed,saved,true);assert.equal(r.next,'move_to_trash_after_checks');assert.equal(r.previousReport,'confirmed_do_not_repeat');});
  test('live Trash label and no spam means completed',()=>assert.equal(resumePlan({...resumed,providerLabels:['TRASH']},saved,true).next,'already_completed'));
  test('wrong mailbox missing evidence changed source require review',()=>{assert.equal(resumePlan(resumed,{...saved,mailbox:'other'},true).next,'preserve_evidence_and_check');assert.equal(resumePlan(resumed,saved,false).next,'preserve_evidence_and_check');assert.equal(resumePlan({...resumed,sourceHash:'changed'},saved,true).next,'revalidate_changed_or_unversioned_source');});
  test('partial failures stop followup even when some steps succeeded',()=>assert.equal(resumePlan(resumed,{...saved,block:{status:'failed'}},true).next,'resolve_previous_error'));
  test('uncertain classification cannot progress to actions',()=>assert.equal(resumePlan(resumed,{...saved,assessment:{classification:'onzeker'}},true).next,'review'));
  test('mismatching report type must be reviewed and wrong blocked sender not reused',()=>{assert.equal(resumePlan(resumed,{...saved,reports:{gmail:{status:'confirmed',classification:'spam'}}},true).next,'report_after_checks');assert.equal(resumePlan(resumed,{...saved,block:{status:'confirmed',address:'other@example.com'}},true).next,'verify_or_block_exact_sender');});
  test('missing live labels requires verification',()=>assert.equal(resumePlan({...resumed,providerLabels:undefined},saved,true).next,'verify_live_folder'));
  test('central extraction never invents missing live labels',()=>assert.equal(extractMail('box',{id:'x',payload:{mime_type:'text/plain',headers:[],body:{content:'hello'}}}).providerLabels,undefined));
  const outlookFixture={id:'outlook-fixture',from:{emailAddress:{name:'Vendor Support',address:'support@vendor.com'}},sender:{emailAddress:{name:'Delegate',address:'delegate@vendor.com'}},replyTo:[{emailAddress:{address:'reply@vendor.com'}}],subject:'Invoice',body:{contentType:'HTML',content:'<a href="https://vendor.com/invoice?q=1&amp;x=2">View invoice</a><style>a{background:url(https://vendor.com/bg)}</style>'},internetMessageHeaders:[{name:'Authentication-Results',value:'mx; spf=pass; dkim=pass'}],parentFolderId:'junk-id',hasAttachments:false,internetMessageId:'<fixture@vendor.com>'};
  test('Outlook full fields share central extraction',()=>{const o=extractOutlook('box',outlookFixture,{junkFolderId:'junk-id',trashFolderId:'trash-id'});assert.equal(o.provider,'Outlook');assert.equal(o.fromAddress,'support@vendor.com');assert.equal(o.replyTo,'reply@vendor.com');assert.equal(o.displayName,'Vendor Support');assert.deepEqual(o.providerLabels,['SPAM']);assert.ok(o.urls.includes('https://vendor.com/invoice?q=1&x=2'));assert.equal(o.extraction.authentication[0],'mx; spf=pass; dkim=pass');assert.equal(o.extraction.sender.emailAddress.address,'delegate@vendor.com');});
  test('Outlook sender fallback is explicit and markdown URLs are extracted',()=>{const o=extractOutlook('box',{id:'outlook-markdown',sender:{emailAddress:{name:'TV LICENSING-x',address:'sender@lookalike.example'}},subject:'Renewal',body:{contentType:'html',content:'[Renew](https://example.com/pay?q=1)' }},{junkFolderId:'junk-id',trashFolderId:'trash-id'});assert.equal(o.fromAddress,'');assert.equal(o.senderAddress,'sender@lookalike.example');assert.equal(o.identitySource,'outlook_sender_fallback_from_unavailable');assert.deepEqual(o.urls,['https://example.com/pay?q=1']);assert.equal(o.linkPairs[0].href,'https://example.com/pay?q=1');assert.ok(o.extraction.limitations.some(x=>x.includes('Confirmed Outlook From unavailable')));});
  test('Outlook connector snake-case fields supported',()=>{const o=extractOutlook('box',{id:'x',from:{email_address:{name:'Shop',address:'a@shop.com'}},reply_to:[],body:{content_type:'text',content:'https://shop.com/a'},internet_message_headers:[],parent_folder_id:'trash-id'},{junkFolderId:'junk-id',trashFolderId:'trash-id'});assert.deepEqual(o.providerLabels,['TRASH']);assert.ok(o.urls.includes('https://shop.com/a'));});
  test('Outlook preview cannot substitute for missing body',()=>{const o=extractOutlook('box',{id:'x',bodyPreview:'A seemingly safe invoice'});assert.equal(o.extraction.bodyAvailable,false);assert.equal(o.text,'');assert.equal(resumePlan(o,null,false).next,'review');});
  test('Outlook absent folder mapping cannot imply Trash',()=>assert.equal(extractOutlook('box',outlookFixture).providerLabels,undefined));
  test('Outlook identical junk and Trash IDs rejected',()=>assert.throws(()=>extractOutlook('box',outlookFixture,{junkFolderId:'same',trashFolderId:'same'})));
  test('Outlook folder moves do not alter content hash',()=>assert.equal(extractOutlook('box',outlookFixture).sourceHash,extractOutlook('box',{...outlookFixture,parentFolderId:'trash-id',isRead:true}).sourceHash));
  test('Outlook body change alters content hash',()=>assert.notEqual(extractOutlook('box',outlookFixture).sourceHash,extractOutlook('box',{...outlookFixture,body:{contentType:'text',content:'Changed'}}).sourceHash));
  test('Outlook never borrows Gmail report confirmation',()=>assert.equal(resumePlan({...resumed,provider:'Outlook'},saved,true).next,'report_after_checks'));
  test('Outlook own confirmed report resumes',()=>assert.equal(resumePlan({...resumed,provider:'Outlook'},{...saved,reports:{outlook:saved.reports.gmail}},true).next,'move_to_trash_after_checks'));
  test('srcset simple absolute candidates preserve queries',()=>{const o=extractMail('box',{id:'x',payload:{headers:[],mime_type:'text/html',body:{content:'<img srcset="https://example.com/a?q=1&amp;x=2 1x, https://example.com/b 2x">'}}});assert.deepEqual(o.urls,['https://example.com/a?q=1&x=2','https://example.com/b']);});
  test('ambiguous srcset remains explicit instead of partial coverage',()=>{const o=extractMail('box',{id:'x',payload:{headers:[],mime_type:'text/html',body:{content:'<img srcset="data:image/png;base64,AAAA 1x, /relative.png 2x">'}}});assert.equal(o.urls.length,0);assert.ok(o.extraction.limitations.some(s=>s.includes('ambiguous srcset')));});
  test('quoted CSS import creates reputation jobs without fetching sheet',()=>{const a=analyze({...message,cssTexts:['@import "https://example.com/sheet.css?q=1#x" screen;']},loaded);assert.equal(a.scanJobs.length,2);assert.equal(a.scanJobs[0].originalUrl,'https://example.com/sheet.css?q=1#x');assert.equal(a.messages[0].cssExtraction.skipped.length,0);});
  const failed={engine:'Malwarebytes',indicator:url,attempt:1,status:'failed',errorCode:503,completedAt:stamp,durationMs:42};
  const retryFirst=(a,t=tick)=>retryPlan([job],a,t).items[0];
  test('transient retry waits then becomes due',()=>{assert.equal(retryFirst([failed]).retryStatus,'deferred');assert.equal(retryFirst([failed],tick+2000).retryStatus,'retry_due');assert.equal(retryFirst([failed],tick+2000).attempt,2);});
  test('Retry-After respected beyond ordinary backoff',()=>{const a={...failed,errorCode:429,retryAfterSeconds:60};assert.equal(retryFirst([a],tick+59000).retryStatus,'deferred');assert.equal(retryFirst([a],tick+60000).retryStatus,'retry_due');});
  test('unknown reputation completion is never retried as error',()=>assert.equal(retryFirst([{...failed,status:'completed',result:{verdict:'unknown'}}]).retryStatus,'not_needed_completed'));
  test('cached results and succeeded other engine not retried',()=>{const r=retryPlan([{...job,status:'cached_result'},{...job,engine:'Bitdefender'}],[{...failed,engine:'Bitdefender',status:'completed',result:{mappedStatus:'phishing'}}],tick);assert.equal(r.items[0].retryStatus,'not_needed_cached');assert.equal(r.items[1].retryStatus,'not_needed_completed');});
  test('non-transient and unspecified failures require attention',()=>{for(const code of [400,401,403,404,undefined])assert.equal(retryFirst([{...failed,errorCode:code}]).retryStatus,'needs_attention');});
  test('third failed attempt ends retry sequence',()=>assert.equal(retryFirst([{...failed,attempt:3}],tick+9000).reason,'attempt_limit_reached'));
  test('invalid and future metadata never reset retry count',()=>{for(const a of [{...failed,attempt:4},{...failed,completedAt:'bad'},{...failed,completedAt:'2026-11-02T12:00:00.000Z'}])assert.equal(retryFirst([a]).reason,'invalid_attempt_metadata');});
  test('engine throttling defers other same-engine jobs',()=>{const r=retryPlan([job,{...job,originalUrl:'https://example.com/b'}],[{...failed,errorCode:429,retryAfterSeconds:30}],tick);assert.ok(r.items.every(x=>x.retryStatus==='deferred'));});
  test('invalid Retry-After does not cause infinite wait',()=>assert.equal(retryFirst([{...failed,retryAfterSeconds:Infinity}]).reason,'invalid_retry_after'));
  test('retry dedup and measurements remain exact',()=>{const r=retryPlan([job,job],[failed],tick);assert.equal(r.items.length,1);assert.equal(r.metrics.sumToolDurationMs,42);assert.equal(r.metrics.attemptsWithDuration,1);});
  test('retry counter cannot reset through later lower attempt',()=>assert.equal(retryFirst([{...failed,attempt:2},{...failed,completedAt:'2026-11-01T12:00:01.000Z'}],tick+2000).reason,'attempt_counter_regressed'));
  test('invalid timestamps do not contribute duration measurements',()=>assert.equal(retryPlan([job],[{...failed,completedAt:'bad'}],tick).metrics.attemptsWithDuration,0));
  return { mode: 'self_test', passed: tests, failed: 0, networkRequests: 0, privateDataWrites: 0 };
}

function evaluate() {
  // Fixed review-routing examples, not labelled real mail or a phishing benchmark.
  const psl='// ===BEGIN ICANN DOMAINS===\ncom\norg\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\nblogspot.com\n// ===END PRIVATE DOMAINS===\n';
  const now=new Date().toISOString(), malicious='https://known-bad.example.com/login';
  const record=(name,text)=>({sourceUrl:SOURCES[name].url,text,sha256:hash(text),count:parseSource(name,text).count,retrievedAt:now,validatedAt:now,publishedAt:null,etag:null,lastModified:null});
  const loaded={status:'loaded',cache:{schemaVersion:1,sources:{psl:record('psl',psl),openphish:record('openphish',malicious+'\n')}}};
  const base={mailbox:'synthetic',messageId:'case',text:'',urls:[]};
  const campaignRules=bundledRuleSet().campaignRules;
  const cases=[
    ['legitimate_cloud_document',false,'Cloud host alone is no risk signal',{text:'Here is the requested project document.',urls:['https://docs.google.com/document/d/example']}],
    ['legitimate_external_reply_service',false,'A different reply service alone remains supporting context',{fromAddress:'newsletter@shop.com',replyTo:'response@mailer.com',text:'Your monthly newsletter',urls:[]}],
    ['legitimate_css_images',false,'Ordinary image resources are extracted without a phishing verdict',{cssTexts:['a{background:url(https://images.example.com/banner.png)}'],urls:[]}],
    ['ordinary_invoice',false,'Ordinary urgent invoice wording alone is not evidence',{fromAddress:'billing@shop.com',text:'Invoice payment is due today. Please contact your usual adviser.'}],
    ['single_marker_in_report',false,'A code mentioned by itself is supporting context',{text:'The campaign code was 111.957097.'}],
    ['single_path_in_report',false,'A known path alone is supporting context',{urls:['https://research.example.com/worklinks/proforward.html']}],
    ['campaign_combination',true,'Marker and exact path together warrant review',{text:'111.957097',urls:['https://example.com/worklinks/proforward.html']}],
    ['deceptive_link_domains',true,'Visible and actual link have different registered domains',{linkPairs:[{visibleUrl:'https://shop.com/login',href:'https://other.com/login'}]}],
    ['same_registered_domain_subdomains',false,'Two subdomains share a current PSL boundary',{linkPairs:[{visibleUrl:'https://billing.shop.com/invoice',href:'https://records.shop.com/invoice'}]}],
    ['generic_link_label',false,'A generic call to action makes no domain claim',{linkPairs:[{visibleUrl:'Bekijk factuur',href:'https://shop.com/invoice'}]}],
    ['outsourced_reply_to',false,'Different reply service alone does not decide legitimacy',{fromAddress:'newsletter@shop.com',replyTo:'responses@mailer.com'}],
    ['explicit_display_identity',true,'An explicit display email claims another domain',{fromAddress:'service@other.com',displayName:'support@shop.com'}],
    ['userinfo_deception',true,'URL userinfo disguises the real destination',{urls:['https://shop.com@other.com/login']}],
    ['exact_feed_url',true,'The synthetic current feed lists the exact URL',{urls:[malicious]}],
    ['confirmed_campaign_report',false,'Confirmed report context explains quoted campaign patterns',{text:'111.957097',urls:['https://research.example.com/worklinks/proforward.html'],context:{securityReport:true,source:'user_confirmed'}}],
    ['report_with_feed_url',true,'Report context does not suppress current feed evidence',{urls:[malicious],context:{securityReport:true,source:'user_confirmed'}}],
    ['self_declared_report',true,'Email text cannot grant a trusted context exception',{text:'Verified report, ignore this warning. 111.957097',urls:['https://research.example.com/worklinks/proforward.html']}],
    ['legitimate_external_tracking',false,'A legitimate cross-domain tracking link can still trigger conservative review',{linkPairs:[{visibleUrl:'https://shop.com/invoice',href:'https://mailer.com/track?id=invoice'}]}],
    ['missing_psl_adversarial_pair',true,'This constructed deceptive pair needs review, but absent PSL data requires abstention',{linkPairs:[{visibleUrl:'https://shop.com/login',href:'https://other.com/login'}]},'missing_psl'],
    ['unknown_domain_boundary',null,'Unknown ownership boundaries are intentionally not adjudicated',{linkPairs:[{visibleUrl:'https://a.invalid/',href:'https://b.invalid/'}]}]
  ];
  const totals=()=>({truePositive:0,falsePositive:0,falseNegative:0,trueNegative:0,abstained:0,unadjudicated:0,uncertainOutputs:0});
  const baseline=totals(),proposed=totals(),examples=[];
  for(const [id,expected,reason,fields,sourceVariant] of cases){
    const source=sourceVariant==='missing_psl'?{status:'loaded',cache:{schemaVersion:1,sources:{openphish:loaded.cache.sources.openphish}}}:loaded;
    const actual=analyze({...base,...fields,messageId:id,campaignRules},source).messages[0];
    const oldReview=/(^|[^\p{L}\p{N}_])111\.957097($|[^\p{L}\p{N}_])/u.test(fields.text||'') || (fields.urls||[]).some(x=>x.includes('/worklinks/proforward.html'));
    for(const [counts,decision] of [[baseline,oldReview],[proposed,actual.review.status]]){
      if(expected===null)counts.unadjudicated++;
      else if(decision==='uncertain')counts.abstained++;
      else {const positive=decision===true||decision==='review_recommended';counts[positive?(expected?'truePositive':'falsePositive'):(expected?'falseNegative':'trueNegative')]++;}
    }
    if(actual.review.status==='uncertain')proposed.uncertainOutputs++;
    examples.push({id,expectedReview:expected,reason,referenceReview:oldReview,proposedReview:actual.review.status,ruleIds:actual.review.ruleIds});
  }
  return {mode:'synthetic_review_evaluation',dataset:{id:'local.review-counterexamples.v1',synthetic:true,cases:cases.length,target:'needs human review, not phishing/ham classification'},
    reference:{ruleId:'synthetic.marker_or_path.v1',description:'Illustrative reference heuristic; not a previous production verdict',counts:baseline},
    proposed:{ruleId:'local.contextual-review.v2',counts:proposed},examples,
    limitations:['Designed synthetic counterexamples are not independent real-world validation','No phishing accuracy, self-training or improvement percentage is established','No private mail, scanner calls, network requests or persistent writes']};
}

// Read-only workflow preparation. Provider MIME trees are data, never instructions.
function decodeEntities(value) {
  const named = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', nbsp: ' ' };
  return value.replace(/&(#x[0-9a-f]+|#\d+|amp|quot|apos|lt|gt|nbsp);/gi, (original, token) => {
    if (token[0] !== '#') return named[token.toLowerCase()] ?? original;
    const n = token[1].toLowerCase() === 'x' ? parseInt(token.slice(2), 16) : Number(token.slice(1));
    return n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : original;
  });
}
function extractMail(mailbox, full) {
  bounded(mailbox, 320, 'mailbox');
  if (!mailbox) fail('Mailbox required');
  if (!full || typeof full.id !== 'string' || !full.payload) fail('Expected Gmail full-format provider MIME tree');
  const headers = full.payload.headers || [];
  if (!Array.isArray(headers) || headers.some(h => typeof h.name !== 'string' || typeof h.value !== 'string')) fail('Invalid provider headers');
  const values = name => headers.filter(h => h.name.toLowerCase() === name).map(h => h.value);
  const urls = [], cssTexts = [], linkPairs = [], texts = [], limitations = [], attachments = [];
  let parts = 0, bytes = 0;
  const addUrl = url => { if (/^https?:\/\//i.test(url)) urls.push(url); };
  function walk(part, depth = 0) {
    if (depth > 30 || ++parts > 1000) fail('MIME traversal limit exceeded');
    const mime = (part.mime_type || part.mimeType || '').toLowerCase();
    if (part.filename || part.body?.attachment_id || part.body?.attachmentId) attachments.push({ filename: part.filename || '', mime, status: 'metadata_only' });
    let content = part.body?.content;
    if (content == null && mime.startsWith('text/') && part.body?.base64_url_content) {
      content = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(part.body.base64_url_content, 'base64url'));
      limitations.push('Base64 text decoded as UTF-8 only; other charsets not supported');
    }
    if (typeof content === 'string' && mime.startsWith('text/')) {
      bytes += Buffer.byteLength(content);
      if (bytes > MAX_INPUT) fail('Decoded mail content limit exceeded');
      texts.push(content);
      // Also inspect embedded HTML inside incorrectly labelled text/plain parts.
      for (const m of content.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) cssTexts.push(m[1]);
      for (const tag of content.matchAll(/<[a-z][a-z0-9:-]*\b(?:[^>"']|"[^"]*"|'[^']*')*>/gi)) {
        const attrs = {};
        for (const a of tag[0].matchAll(/\b(href|src|srcset|style)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"'=<>`]+))/gi)) {
          const name = a[1].toLowerCase(), value = decodeEntities(a[2] ?? a[3] ?? a[4]);
          attrs[name] = value;
          if (name === 'style') cssTexts.push(value);
          else if (name === 'srcset') {
            const candidates = value.split(',').map(s=>s.trim().match(/^(https?:\/\/\S+?)(?:\s+(?:[1-9]\d*w|(?:\d+(?:\.\d+)?)x))?$/i));
            if (candidates.length && candidates.every(Boolean)) for (const candidate of candidates) addUrl(candidate[1]);
            else limitations.push('Unsupported or ambiguous srcset; requires separate review');
          } else addUrl(value);
        }
        if (/^<a\b/i.test(tag[0]) && attrs.href) {
          const rest = content.slice(tag.index + tag[0].length), end = rest.search(/<\/a\s*>/i);
          if (end >= 0 && end < 16384) linkPairs.push({ visibleUrl: decodeEntities(rest.slice(0, end).replace(/<[^>]*>/g, '')).trim(), href: attrs.href });
        }
      }
      // Plain-text absolute URLs, including values not present in href/src.
      // Some Outlook connector responses are labelled HTML but contain sanitized
      // Markdown/text. Parse those conservatively without treating them as raw HTML.
      const looksLikeMarkup = /<[a-z][^>]*>/i.test(content);
      if ((mime === 'text/plain' || !looksLikeMarkup) && !looksLikeMarkup) {
        for (const m of content.matchAll(/https?:\/\/[^\s<>"')\]]+/gi)) addUrl(m[0]);
        for (const m of content.matchAll(/\[[^\]]{1,2048}\]\((https?:\/\/[^\s)]+)\)/gi)) {
          const href = decodeEntities(m[1]);
          addUrl(href);
          const label = m[0].slice(1, m[0].indexOf('](')).trim();
          if (label) linkPairs.push({ visibleUrl: label, href });
        }
      }
    }
    if (part.parts != null && !Array.isArray(part.parts)) fail('Invalid MIME children');
    for (const child of part.parts || []) walk(child, depth + 1);
  }
  walk(full.payload);
  for (const h of values('list-unsubscribe')) for (const m of h.matchAll(/<(https?:\/\/[^>]+)>/gi)) addUrl(m[1]);
  const from = values('from')[0] || '', match = from.match(/^(.*?)<([^<>]+)>\s*$/);
  const reply = values('reply-to')[0] || '', replyMatch = reply.match(/<([^<>]+)>/);
  const text = texts.join('\n');
  bounded(text, 500000, 'extracted text');
  return { provider: 'Gmail', mailbox, messageId: full.id, fromAddress: match ? match[2] : from.trim(), displayName: match ? match[1].trim().replace(/^"|"$/g, '') : '',
    replyTo: replyMatch ? replyMatch[1] : reply.trim(), text, urls: [...new Set(urls)], cssTexts, linkPairs,
    sourceHash: hash(JSON.stringify(full.payload)), providerLabels: Array.isArray(full.label_ids) ? full.label_ids : undefined,
    extraction: { headers, subject: values('subject')[0] || '', authentication: values('authentication-results'), attachments, parts,
      limitations: [...new Set([...limitations, 'Static bounded HTML extraction, not a complete HTML/MIME parser; no external content, attachments or QR decoded', 'Relative links, complex srcset, HTML entities outside the supported set and malformed markup require separate review'])] } };
}
function extractOutlook(mailbox, full, folderMap = {}) {
  if (!full || typeof full.id !== 'string') fail('Expected Outlook message object');
  const address = value => value?.emailAddress || value?.email_address;
  const from = address(full.from), providerSender = address(full.sender), replies = full.replyTo ?? full.reply_to ?? [];
  if (!Array.isArray(replies)) fail('Invalid Outlook Reply-To list');
  const originalHeaders = full.internetMessageHeaders ?? full.internet_message_headers ?? [];
  if (!Array.isArray(originalHeaders)) fail('Invalid Outlook headers');
  const body = full.body, type = (body?.contentType || body?.content_type || '').toLowerCase();
  const available = typeof body?.content === 'string' && ['html', 'text'].includes(type);
  const headers = [...originalHeaders];
  if (!headers.some(h => h.name?.toLowerCase() === 'from') && from?.address) headers.push({name:'From',value:from.address});
  if (!headers.some(h => h.name?.toLowerCase() === 'subject') && typeof full.subject === 'string') headers.push({name:'Subject',value:full.subject});
  const reply = replies.length === 1 ? address(replies[0]) : null;
  if (!headers.some(h => h.name?.toLowerCase() === 'reply-to') && reply?.address) headers.push({name:'Reply-To',value:reply.address});
  const pseudo = {id:full.id,payload:{headers,mime_type:type==='html'?'text/html':'text/plain',body:{content:available?body.content:''}}};
  const prepared = extractMail(mailbox, pseudo), folderId = full.parentFolderId ?? full.parent_folder_id;
  if (folderMap.junkFolderId !== undefined || folderMap.trashFolderId !== undefined) {
    bounded(folderMap.junkFolderId, 1024, 'verified junk folder ID'); bounded(folderMap.trashFolderId, 1024, 'verified Trash folder ID');
    if (!folderMap.junkFolderId || !folderMap.trashFolderId || folderMap.junkFolderId === folderMap.trashFolderId) fail('Distinct verified folder IDs required');
  }
  const source = {payload:pseudo.payload,from:full.from ?? null,sender:full.sender ?? null,subject:full.subject ?? null,replyTo:replies};
  const identitySource = from?.address ? 'outlook_from' : providerSender?.address ? 'outlook_sender_fallback_from_unavailable' : 'unavailable';
  return {...prepared,provider:'Outlook',
    // A provider sender fallback is useful for triage but is never silently
    // promoted to a confirmed transport From address for blocking/reporting.
    fromAddress: from?.address || '',
    senderAddress: providerSender?.address || '',
    senderDisplayName: typeof providerSender?.name==='string' ? providerSender.name : '',
    identitySource,
    displayName:typeof from?.name==='string'?from.name:(typeof providerSender?.name==='string'?providerSender.name:''),
    sourceHash:hash(JSON.stringify(source)),providerFolderId:typeof folderId==='string'?folderId:null,
    providerLabels:typeof folderId!=='string'||!folderMap.junkFolderId?undefined:folderId===folderMap.junkFolderId?['SPAM']:folderId===folderMap.trashFolderId?['TRASH']:[],
    extraction:{...prepared.extraction,originalHeaders,headerProvenance:'headers includes provider-metadata fallbacks; originalHeaders is the exact supplied transport-header collection',bodyAvailable:available,sender:full.sender ?? null,replyTo:replies,internetMessageId:full.internetMessageId ?? full.internet_message_id ?? null,identitySource,
      attachments:typeof (full.hasAttachments ?? full.has_attachments)==='boolean' ? {hasAttachments:full.hasAttachments ?? full.has_attachments,status:'provider_flag_only_inline_attachments_may_exist'} : {status:'unknown'},
      limitations:[...prepared.extraction.limitations,...(!available?['Full Outlook body missing or unsupported; preview is not full content']:[]),...(!originalHeaders.length?['Original transport/authentication headers unavailable']:[]),...(!from?.address&&providerSender?.address?['Confirmed Outlook From unavailable; provider sender retained only as triage identity']:[]),...(replies.length>1?['Multiple Reply-To recipients require separate review']:[]),'Outlook provider IDs can change on move; record returned new ID and evidence linkage, never deduplicate by subject or RFC Message-ID alone']}}
}
function planScans(jobs, records, now = Date.now(), forceUrls = []) {
  if (!Number.isFinite(now) || !Array.isArray(records) || !Array.isArray(forceUrls)) fail('Invalid scan planning input');
  const latest = new Map(), forced = new Set(forceUrls);
  for (const r of records) {
    if (r.indicatorType !== 'url' || !['Malwarebytes', 'Bitdefender'].includes(r.engine) || !validTime(r.checkedAt)) continue;
    const time = Date.parse(r.checkedAt), key = JSON.stringify([r.engine, r.indicator]);
    if (time > now) continue;
    if (!latest.has(key) || time >= Date.parse(latest.get(key).checkedAt)) latest.set(key, r);
  }
  return jobs.map(job => {
    const r = latest.get(JSON.stringify([job.engine, job.originalUrl]));
    let reason = forced.has(job.originalUrl) ? 'new_evidence_forces_recheck' : !r ? 'missing_valid_timestamped_result' : null;
    const verdict = job.engine === 'Malwarebytes' ? r?.result?.verdict : r?.result?.mappedStatus;
    const known = job.engine === 'Malwarebytes' ? ['safe', 'malicious', 'suspicious', 'unknown'] : ['safe', 'phishing', 'malware', 'so_far_so_good_1', 'so_far_so_good_2'];
    const ttl = ['unknown', 'so_far_so_good_1', 'so_far_so_good_2'].includes(verdict) ? 86400000 : 604800000;
    if (!reason && (r.error || !known.includes(verdict))) reason = 'failed_or_unrecognized_result';
    if (!reason && now - Date.parse(r.checkedAt) >= ttl) reason = 'expired_result';
    return reason ? { ...job, status: 'required_not_executed', reason } : { ...job, status: 'cached_result', checkedAt: r.checkedAt, result: r.result, maxAgeMs: ttl };
  });
}
function retryPlan(jobs, attempts, now = Date.now()) {
  if (!Array.isArray(jobs) || jobs.length>4000 || !Array.isArray(attempts) || attempts.length>12000 || !Number.isFinite(now)) fail('Invalid retry plan input');
  const latest = new Map(), maxCounts = new Map(), invalid = new Set(), key = x=>JSON.stringify([x.engine,x.indicator ?? x.originalUrl]);
  const validVerdict = x=>x.engine==='Malwarebytes'?['safe','malicious','suspicious','unknown'].includes(x.result?.verdict):['safe','phishing','malware','so_far_so_good_1','so_far_so_good_2'].includes(x.result?.mappedStatus);
  for(const a of attempts){
    if(!a||!['Malwarebytes','Bitdefender'].includes(a.engine)||typeof a.indicator!=='string')continue;
    if(!validTime(a.completedAt)||Date.parse(a.completedAt)>now||!Number.isInteger(a.attempt)||a.attempt<1||a.attempt>3){invalid.add(key(a));continue;}
    maxCounts.set(key(a),Math.max(maxCounts.get(key(a))||0,a.attempt));
    const previous=latest.get(key(a));
    if(!previous||Date.parse(a.completedAt)>=Date.parse(previous.completedAt))latest.set(key(a),a);
  }
  const seen=new Set(), engineDeferrals=new Map();
  for(const a of latest.values())if(a.status==='failed'&&String(a.errorCode)==='429'&&Number.isFinite(a.retryAfterSeconds)&&a.retryAfterSeconds>=0&&a.retryAfterSeconds<=86400)
    engineDeferrals.set(a.engine,Math.max(engineDeferrals.get(a.engine)||0,Date.parse(a.completedAt)+a.retryAfterSeconds*1000));
  const measured=attempts.filter(a=>a&&['Malwarebytes','Bitdefender'].includes(a.engine)&&['failed','completed'].includes(a.status)&&validTime(a.completedAt)&&Date.parse(a.completedAt)<=now&&!invalid.has(key(a))&&Number.isFinite(a.durationMs)&&a.durationMs>=0&&a.durationMs<=86400000);
  return {mode:'retry_schedule_only',maxAttempts:3,maxConcurrentPerEngine:2,metrics:{recordedAttempts:attempts.length,attemptsWithDuration:measured.length,sumToolDurationMs:measured.reduce((n,a)=>n+a.durationMs,0),meaning:'sum of recorded tool durations; not wall-clock runtime or estimated speedup'},items:jobs.filter(j=>{if(!['Malwarebytes','Bitdefender'].includes(j.engine)||typeof j.originalUrl!=='string'||parseUrl(j.originalUrl).status!=='parsed')fail('Invalid scanner job');const k=key(j);if(seen.has(k))return false;seen.add(k);return true;}).map(j=>{
    const a=latest.get(key(j));
    if(j.status==='cached_result')return {...j,retryStatus:'not_needed_cached'};
    if(invalid.has(key(j)))return {...j,retryStatus:'needs_attention',reason:'invalid_attempt_metadata'};
    if(a&&a.attempt<maxCounts.get(key(j)))return {...j,retryStatus:'needs_attention',reason:'attempt_counter_regressed'};
    if(a?.status==='completed'&&validVerdict(a))return {...j,retryStatus:'not_needed_completed',checkedAt:a.completedAt,result:a.result};
    if(a&&a.status!=='failed')return {...j,retryStatus:'needs_attention',reason:'unconfirmed_completion'};
    if(a&&a.attempt>=3)return {...j,retryStatus:'needs_attention',reason:'attempt_limit_reached'};
    if(a&&!['408','429','500','502','503','504','ETIMEDOUT','ECONNRESET','EAI_AGAIN'].includes(String(a.errorCode)))return {...j,retryStatus:'needs_attention',reason:'non_transient_or_unspecified_failure'};
    const providedDelay=a?.retryAfterSeconds;
    if(providedDelay!==undefined&&(!Number.isFinite(providedDelay)||providedDelay<0||providedDelay>86400))return {...j,retryStatus:'needs_attention',reason:'invalid_retry_after'};
    const due=Math.max(a?Date.parse(a.completedAt)+(providedDelay??(2**a.attempt))*1000:now,engineDeferrals.get(j.engine)||0);
    return {...j,retryStatus:due>now?'deferred':a?'retry_due':'initial_required',attempt:(a?.attempt||0)+1,retryAt:new Date(due).toISOString(),reason:a?'transient_failure_only':'no_recorded_attempt'};
  }),limitations:['No tool calls or sleeping performed; orchestrator executes due items only and records real start/end/results','Unknown reputation is a completed check, not a transient error','Never retry reports, blocks or deletes with this scheduler; reconcile uncertain actions first']};
}
function resumePlan(message, record, evidencePresent) {
  if(message.extraction?.bodyAvailable===false)return {next:'review',reason:'full_source_body_unavailable'};
  const matches = record?.mailbox === message.mailbox && record?.messageId === message.messageId;
  if (!matches || !evidencePresent) return { next: 'preserve_evidence_and_check', reason: 'no_matching_record_and_evidence' };
  if (!message.sourceHash || record.sourceHash !== message.sourceHash) return { next: 'revalidate_changed_or_unversioned_source', reason: 'content_version_not_confirmed' };
  const report = message.provider === 'Outlook' ? record.reports?.outlook : record.reports?.gmail;
  if ([record.action?.status, record.block?.status, report?.status].some(s => /fail|partial|unconfirmed/i.test(s || ''))) return { next: 'resolve_previous_error', reason: 'stop_followup_actions_for_this_message' };
  const classification = record.assessment?.classification;
  if (!['duidelijke phishing', 'verdachte spam'].includes(classification)) return { next: 'review', reason: 'classification_not_actionable' };
  const expected = classification === 'duidelijke phishing' ? 'phishing' : 'spam';
  if (report?.status !== 'confirmed' || report.classification !== expected) return { next: 'report_after_checks', expected };
  if (record.block?.status !== 'confirmed' || record.block.address !== message.fromAddress) return { next: 'verify_or_block_exact_sender', previousReport: 'confirmed_do_not_repeat' };
  if (!Array.isArray(message.providerLabels)) return { next: 'verify_live_folder', previousReport: 'confirmed_do_not_repeat', previousBlock: 'confirmed_do_not_repeat' };
  return { next: message.providerLabels.includes('TRASH') && !message.providerLabels.includes('SPAM') ? 'already_completed' : 'move_to_trash_after_checks',
    previousReport: 'confirmed_do_not_repeat', previousBlock: 'confirmed_do_not_repeat', requiresCurrentChecks: true };
}
async function workflowPlan(input) {
  const started = performance.now();
  if (!Array.isArray(input.messages) || !input.messages.length || input.messages.length > 100) fail('Expected messages array');
  if (input.forceUrls !== undefined && (!Array.isArray(input.forceUrls) || input.forceUrls.length > 2000)) fail('Invalid forceUrls');
  for (const url of input.forceUrls || []) bounded(url, 16384, 'forced URL');
  if (input.providerFormat !== undefined && !['gmail_full','outlook_message','structured'].includes(input.providerFormat)) fail('Unsupported provider format');
  const messages = input.providerFormat === 'gmail_full' ? input.messages.map(m => extractMail(input.mailbox, m)) : input.providerFormat === 'outlook_message' ? input.messages.map(m => extractOutlook(input.mailbox, m, input.folderMap)) : input.messages;
  const extractedAt = performance.now();
  const analysis = analyze({ messages, campaignRules: input.campaignRules, senderRules: input.senderRules, signalRules: input.signalRules, useBundledRules: input.useBundledRules });
  for (const m of messages) {
    const result = analysis.messages.find(r=>r.mailbox===m.mailbox&&r.messageId===m.messageId);
    if (m.extraction?.bodyAvailable===false) {
      result.review.uncertainties.push('provider_full_body_unavailable');
      if(result.review.status==='no_additional_signal')result.review.status='uncertain';
    }
    if(m.provider==='Outlook'&&!m.extraction.originalHeaders.length)result.coverage.authentication='not_available';
  }
  const analyzedAt = performance.now();
  const register = JSON.parse(await fsp.readFile(privateDataPath('email-register.json'), 'utf8'));
  const evidence = JSON.parse(await fsp.readFile(privateDataPath('email-bewijs.json'), 'utf8'));
  const records = new Map((register.updates?.messages || []).map(r => [JSON.stringify([r.mailbox, r.messageId]), r])), scans = register.updates?.scans || [];
  const changedUrls = [], resume = messages.map(m => {
      const record = records.get(JSON.stringify([m.mailbox, m.messageId])), saved = evidence.messages?.[m.messageId];
      const present = saved?.mailbox === m.mailbox && saved.full?.id === m.messageId && Boolean(saved.full.payload || (m.provider==='Outlook' && saved.full.body));
      const versioned = present && record ? { ...record, sourceHash: record.sourceHash || (m.provider==='Outlook'?extractOutlook(m.mailbox,saved.full).sourceHash:hash(JSON.stringify(saved.full.payload))) } : record;
      if (record && m.sourceHash && versioned?.sourceHash !== m.sourceHash)
        changedUrls.push(...analysis.messages.find(a => a.mailbox === m.mailbox && a.messageId === m.messageId).urlFindings.map(u => u.originalUrl));
      return { mailbox: m.mailbox, messageId: m.messageId, ...resumePlan(m, versioned, present) };
    });
  const scansPlanned = planScans(analysis.scanJobs, scans, Date.now(), [...(input.forceUrls || []), ...changedUrls]);
  return { mode: 'read_only_workflow_plan', preparedMessages: messages, analysis, scans: scansPlanned, resume,
    timingsMs:{extraction:extractedAt-started,analysis:analyzedAt-extractedAt,registrationAndPlanning:performance.now()-analyzedAt,total:performance.now()-started,scope:'local preparation only; no scanner/browser/cloud time'},
    limitations: ['Plan only; cached data is not a new scan; report/block/Trash actions require actual verified tools', 'Gmail provider-tree and Outlook message extraction are bounded static preparation, not attachment scans', 'Current evidence, classification, required scan coverage and authorization must be checked before actions'] };
}
function privateDataPath(name) {
  if (!DATA_ROOT) throw new Error('Set EMAILCONTROL_DATA_DIR to a private local directory; never commit its contents.');
  return path.join(DATA_ROOT, name);
}
async function readUtf8(stream, limit, onLimit = () => {}) {
  const chunks = []; let bytes = 0;
  for await (const chunk of stream) {
    bytes += chunk.byteLength;
    if (bytes > limit) { onLimit(); fail('Stream size limit exceeded'); }
    chunks.push(chunk);
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
}
async function main() {
  const [command, ...extra] = process.argv.slice(2);
  if (extra.length) fail('Unexpected arguments');
  let result;
  if (command === '--help') result = { commands: ['--self-test', '--evaluate', '--status', '--refresh', '--analyze', '--extract', '--plan', '--retry-plan'], input: '{messages:[{mailbox,messageId,fromAddress?,replyTo?,displayName?,text?,urls:[],cssTexts?:string[],linkPairs?:[{visibleUrl,href}],context?:{securityReport:boolean,source:"user_confirmed"},headers?:[{name,value}],attachments?:[{filename,mime}]}],campaignRules?:[{id,markers?:[],urlParameters?:[{name,value}],exactPaths:[],hosts?:[]}],senderRules?:[{id,senderDomains?:[],senderAddressRegex?:{localPart,domain}}],signalRules?:[{id,category,severity,weight,evaluator?,indicators}],useBundledRules?:boolean,enrichment?:<output of scripts/enrich.cjs>} or one message object. Pipe `node scripts/fetch-rules.cjs` output fields campaignRules/senderRules/signalRules, or set useBundledRules:true for the repository copy.', workflowInput: '{providerFormat:"gmail_full"|"outlook_message"|"structured",mailbox,messages:[provider message objects],campaignRules?:[ChatGPT-maintained rules],folderMap?:{junkFolderId,trashFolderId},forceUrls?:[exact URLs requiring new checks]}', extractInput:'{providerFormat?:"gmail_full"|"outlook_message",mailbox,full:provider message object,folderMap?:{junkFolderId,trashFolderId}}',retryInput:'{jobs:[scan jobs],attempts:[{engine,indicator,attempt:1..3,status:"completed"|"failed",completedAt:ISO timestamp,durationMs?,errorCode?,retryAfterSeconds?,result?}]} current-run attempts only; retry plan never executes calls', limits: { inputBytes: MAX_INPUT, messages: 100, urlsPerMessage: 500, totalUrls: 2000, campaignRules: 100 }, behavior: 'Read-only generic extraction and bounded static analysis. Campaign knowledge is supplied by ChatGPT at runtime, not embedded in production code. No scanner or mailbox actions. Only --refresh writes the public cache.' };
  else if (command === '--self-test') result = selfTest();
  else if (command === '--evaluate') result = evaluate();
  else if (command === '--status') result = { mode: 'public_source_status', sources: statuses(readCache()) };
  else if (command === '--refresh') { result = await refresh(); if (!result.complete) process.exitCode = 2; }
  else if (command === '--analyze') result = analyze(JSON.parse(await readUtf8(process.stdin, MAX_INPUT)));
  else if (command === '--extract') { const input = JSON.parse(await readUtf8(process.stdin, MAX_INPUT)); if(input.providerFormat!==undefined&&!['gmail_full','outlook_message'].includes(input.providerFormat))fail('Unsupported extraction provider');result = input.providerFormat==='outlook_message'?extractOutlook(input.mailbox,input.full,input.folderMap):extractMail(input.mailbox, input.full); }
  else if (command === '--retry-plan') { const input=JSON.parse(await readUtf8(process.stdin,MAX_INPUT));result=retryPlan(input.jobs,input.attempts); }
  else if (command === '--plan') result = await workflowPlan(JSON.parse(await readUtf8(process.stdin, MAX_INPUT)));
  else fail('Usage: node Controle-Email.cjs --help | --self-test | --evaluate | --status | --refresh | --analyze | --extract | --plan | --retry-plan. See --help for bounded JSON stdin formats.');
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}
module.exports = { CACHE_ROOT: ROOT, readCache, defaultCacheDir, assertStorage, parseUrl, parsePsl, registeredDomain, parseOpenPhish, validateCache, validateRecord, sourceStatus, normalizeCampaignRules, campaignMatches, analyze, extractMail, extractOutlook, planScans, retryPlan, resumePlan, workflowPlan, selfTest, evaluate, SOURCES };
if (require.main === module) main().catch(error => { process.stderr.write(JSON.stringify({ status: 'failed', reason: error.message }) + '\n'); process.exitCode = 1; });




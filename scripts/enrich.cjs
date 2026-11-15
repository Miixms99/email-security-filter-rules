'use strict';
// Optional network enrichment for the analyzer. It sends domain or host names
// only (never addresses, URLs, paths or content) to:
//   - RDAP (https://rdap.org), for registration dates; no account needed
//   - URLhaus host lookups, when URLHAUS_AUTH_KEY is set (the maintained
//     daily check supplies a key stored outside the repository)
//   - Spamhaus DBL via DQS, only when SPAMHAUS_DQS_KEY is set (unused by
//     the maintained project; optional for self-hosters)
// It also checks a local first-contact history of salted SHA-256 hashes in
// EMAILCONTROL_DATA_DIR. Results are cached in the public-source cache directory.
// Keys come from environment variables only and are never written anywhere.
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const { CACHE_ROOT, readCache, registeredDomain, parseUrl, assertStorage } = require('./Controle-Email.cjs');

const ENRICH_CACHE = path.join(CACHE_ROOT, 'enrichment-cache.json');
const HISTORY_FILE = 'contact-history.json';
const MAX_DOMAINS = 50, TTL = { registration: 7 * 86400000, urlhaus: 6 * 3600000, dbl: 3600000, error: 1800000 };
const DAY = 86400000;
const UA = 'mailshield/0.5 (+https://github.com/miixms99/mailshield)';
function fail(message) { throw new Error(message); }
const DOMAIN_RE = /^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

// ---- Spamhaus DBL (DQS) ----------------------------------------------------
// 127.0.1.x = listed; 127.255.255.x = query error (never a listing).
function interpretDbl(addresses) {
  if (!addresses.length) return { status: 'not_listed' };
  if (addresses.some(a => a.startsWith('127.255.255.'))) return { status: 'error', reason: 'dbl_query_refused', codes: addresses };
  const listed = addresses.filter(a => /^127\.0\.1\.\d+$/.test(a));
  return listed.length ? { status: 'listed', codes: listed } : { status: 'error', reason: 'unexpected_dbl_answer', codes: addresses };
}
async function queryDbl(domain, key, resolve4 = dns.resolve4) {
  if (!/^[a-z0-9]{10,64}$/i.test(key)) return { status: 'error', reason: 'invalid_dqs_key_format' };
  try { return interpretDbl(await resolve4(`${domain}.${key}.dbl.dq.spamhaus.net`)); }
  catch (error) { return ['ENOTFOUND', 'ENODATA'].includes(error.code) ? { status: 'not_listed' } : { status: 'error', reason: String(error.code || 'dns_error') }; }
}

// ---- RDAP -----------------------------------------------------------------
function interpretRdap(json, now = Date.now(), domain = null) {
  // Some RDAP servers answer with the parent registration; require the exact name.
  if (domain && typeof json?.ldhName === 'string' && json.ldhName.toLowerCase().replace(/\.$/, '') !== domain) return { status: 'unknown', reason: 'rdap_answer_for_other_name' };
  const event = (json?.events || []).find(e => e?.eventAction === 'registration' && typeof e.eventDate === 'string');
  const at = event ? Date.parse(event.eventDate) : NaN;
  if (!Number.isFinite(at)) return { status: 'unknown', reason: 'no_registration_event' };
  return { status: 'known', registeredAt: new Date(at).toISOString().slice(0, 10), ageDays: Math.max(0, Math.floor((now - at) / DAY)) };
}
async function queryRdap(domain, fetchImpl = fetch, now = Date.now()) {
  try {
    const response = await fetchImpl('https://rdap.org/domain/' + encodeURIComponent(domain), { headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': UA }, signal: AbortSignal.timeout(10000) });
    if (response.status === 404) return { status: 'unknown', reason: 'rdap_not_found_or_unsupported_tld' };
    if (!response.ok) return { status: 'error', reason: 'http_' + response.status };
    const text = await response.text();
    if (text.length > 1048576) return { status: 'error', reason: 'response_too_large' };
    return interpretRdap(JSON.parse(text), now, domain);
  } catch (error) { return { status: 'error', reason: error.name === 'TimeoutError' ? 'timeout' : 'request_failed' }; }
}

// ---- URLhaus ----------------------------------------------------------------
function interpretUrlhaus(json) {
  if (json?.query_status === 'ok') return { status: 'listed', urlCount: Number(json.url_count) || null };
  if (json?.query_status === 'no_results') return { status: 'not_listed' };
  return { status: 'error', reason: String(json?.query_status || 'unknown_response').slice(0, 60) };
}
async function queryUrlhaus(host, key, fetchImpl = fetch) {
  try {
    const response = await fetchImpl('https://urlhaus-api.abuse.ch/v1/host/', { method: 'POST', headers: { 'Auth-Key': key, 'User-Agent': UA, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'host=' + encodeURIComponent(host), signal: AbortSignal.timeout(10000) });
    if (!response.ok) return { status: 'error', reason: 'http_' + response.status };
    return interpretUrlhaus(JSON.parse(await response.text()));
  } catch { return { status: 'error', reason: 'request_failed' }; }
}

// ---- First-contact history (salted hashes only) ------------------------------
function historyPath(dataDir = process.env.EMAILCONTROL_DATA_DIR) {
  if (!dataDir || !path.isAbsolute(dataDir)) return null;
  return path.join(dataDir, HISTORY_FILE);
}
function loadHistory(file) {
  if (!file || !fs.existsSync(file)) return { schemaVersion: 1, salt: crypto.randomBytes(32).toString('hex'), hashes: {}, created: true };
  const h = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (h?.schemaVersion !== 1 || !/^[a-f0-9]{64}$/.test(h.salt) || !h.hashes || typeof h.hashes !== 'object') fail('Invalid contact history');
  return h;
}
const contactHash = (history, domain) => crypto.createHmac('sha256', Buffer.from(history.salt, 'hex')).update(domain).digest('hex');
async function saveHistory(file, history) {
  if (!file) fail('Set EMAILCONTROL_DATA_DIR (absolute path) to record contact history');
  await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const { created, ...data } = history;
  const temp = file + '.tmp';
  await fsp.writeFile(temp, JSON.stringify(data), { mode: 0o600 });
  await fsp.rename(temp, file);
}

// ---- Collection ---------------------------------------------------------------
function collect(messages, psl) {
  const org = host => { const r = registeredDomain(host, psl); return r.status === 'known' ? r.value : host; };
  const domains = new Set(), hosts = new Set(), senders = new Set();
  for (const m of messages) {
    const from = typeof m.fromAddress === 'string' && m.fromAddress.includes('@') ? m.fromAddress.slice(m.fromAddress.lastIndexOf('@') + 1).toLowerCase() : null;
    if (from && DOMAIN_RE.test(from)) { domains.add(org(from)); senders.add(org(from)); }
    for (const u of [...(m.urls || []), ...(m.linkPairs || []).map(p => p.href)]) {
      const p = parseUrl(u);
      if (p.status === 'parsed' && p.hostKind === 'domain') { hosts.add(p.hostname); domains.add(org(p.hostname)); }
    }
  }
  return { domains: [...domains].slice(0, MAX_DOMAINS), hosts: [...hosts].slice(0, MAX_DOMAINS), senders: [...senders] };
}

function readEnrichCache() {
  try { assertStorage(ENRICH_CACHE); const c = JSON.parse(fs.readFileSync(ENRICH_CACHE, 'utf8')); return c?.schemaVersion === 1 ? c : { schemaVersion: 1, entries: {} }; }
  catch { return { schemaVersion: 1, entries: {} }; }
}
async function writeEnrichCache(cache) {
  assertStorage(ENRICH_CACHE);
  await fsp.mkdir(CACHE_ROOT, { recursive: true, mode: 0o700 });
  const temp = ENRICH_CACHE + '.tmp';
  await fsp.writeFile(temp, JSON.stringify(cache), { mode: 0o600 });
  await fsp.rename(temp, ENRICH_CACHE);
}

async function enrich(input, { env = process.env, now = Date.now(), fetchImpl = fetch, resolve4 = dns.resolve4, offline = false, cache = null, persist = true } = {}) {
  const messages = Array.isArray(input?.messages) ? input.messages : fail('Expected {messages:[...]}');
  if (messages.length > 100) fail('At most 100 messages');
  const loaded = readCache(), psl = loaded.indexes?.psl;
  const { domains, hosts, senders } = collect(messages, psl);
  const store = cache || readEnrichCache();
  const cached = async (kind, name, action) => {
    const key = kind + ':' + name, hit = store.entries[key];
    if (hit && now - hit.at < (hit.value.status === 'error' ? TTL.error : TTL[kind])) return { ...hit.value, cached: true };
    if (offline) return { status: 'not_checked', reason: 'offline' };
    const value = await action();
    store.entries[key] = { at: now, value };
    return value;
  };
  const dqsKey = env.SPAMHAUS_DQS_KEY || '', urlhausKey = env.URLHAUS_AUTH_KEY || '';
  const result = { schemaVersion: 1, generatedAt: new Date(now).toISOString(), sources: {
    rdap: offline ? 'offline' : 'enabled', urlhaus: urlhausKey ? 'enabled' : 'inactive_no_URLHAUS_AUTH_KEY', spamhausDbl: dqsKey ? 'enabled' : 'inactive_no_SPAMHAUS_DQS_KEY',
    firstContact: historyPath(env.EMAILCONTROL_DATA_DIR) ? 'enabled' : 'inactive_no_EMAILCONTROL_DATA_DIR' }, domains: {}, hosts: {}, senders: {} };
  for (const d of domains) {
    result.domains[d] = { registration: await cached('registration', d, () => queryRdap(d, fetchImpl, now)) };
    if (dqsKey) result.domains[d].dbl = await cached('dbl', d, () => queryDbl(d, dqsKey, resolve4));
  }
  if (urlhausKey) for (const h of hosts) result.hosts[h] = { urlhaus: await cached('urlhaus', h, () => queryUrlhaus(h, urlhausKey, fetchImpl)) };
  const file = historyPath(env.EMAILCONTROL_DATA_DIR);
  if (file) {
    const history = loadHistory(file);
    for (const s of senders) result.senders[s] = { firstContact: !history.hashes[contactHash(history, s)] };
    if (input.recordContacts === true) { for (const s of senders) history.hashes[contactHash(history, s)] ||= new Date(now).toISOString().slice(0, 10); if (persist) await saveHistory(file, history); }
  }
  for (const [k, v] of Object.entries(store.entries)) if (now - v.at > TTL.registration) delete store.entries[k];
  if (persist && !offline) await writeEnrichCache(store);
  return result;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.some(a => !['--offline'].includes(a))) { console.error('Usage: node scripts/enrich.cjs [--offline] < {messages:[...],recordContacts?:boolean}'); process.exit(1); }
  let text = '';
  process.stdin.setEncoding('utf8').on('data', c => { text += c; if (text.length > 2097152) { console.error('Input too large'); process.exit(1); } }).on('end', () => {
    enrich(JSON.parse(text), { offline: args.includes('--offline') }).then(r => process.stdout.write(JSON.stringify(r, null, 2) + '\n')).catch(e => { console.error(JSON.stringify({ status: 'failed', reason: e.message })); process.exitCode = 1; });
  });
}
module.exports = { enrich, interpretDbl, queryDbl, interpretRdap, queryRdap, interpretUrlhaus, queryUrlhaus, loadHistory, contactHash, historyPath, collect };

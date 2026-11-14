'use strict';
// Header, sender and Unicode signal evaluation for the observe-only analyzer.
// Pure functions: no network, no file writes, no mailbox actions. Results are
// review signals only and never a phishing verdict.
const { domainToUnicode } = require('node:url');

function fail(message) { throw new Error(message); }
const MAX_HEADERS = 400, MAX_HEADER_VALUE = 16384;

function normalizeHeaders(value) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_HEADERS) fail('Invalid headers list');
  return value.map(h => {
    if (!h || typeof h.name !== 'string' || typeof h.value !== 'string' || h.name.length > 200 || h.value.length > MAX_HEADER_VALUE) fail('Invalid header');
    return { name: h.name.toLowerCase(), value: h.value };
  });
}
const headerValues = (headers, name) => headers.filter(h => h.name === name).map(h => h.value);

function domainOf(value) {
  if (typeof value !== 'string') return null;
  const v = value.trim().replace(/^<|>$/g, '').replace(/^"|"$/g, '');
  const host = (v.includes('@') ? v.slice(v.lastIndexOf('@') + 1) : v).toLowerCase().replace(/\.$/, '');
  return /^[a-z0-9.-]{1,253}$/.test(host) && host.includes('.') ? host : null;
}
function stripComments(value) {
  // RFC 5322 comments may nest; remove them iteratively, bounded.
  let out = value, guard = 0;
  while (/\([^()]*\)/.test(out) && guard++ < 50) out = out.replace(/\([^()]*\)/g, ' ');
  return out;
}

// Parses one Authentication-Results value (RFC 8601). Microsoft 365 omits the
// authserv-id, so a first segment containing '=' is treated as a method result.
function parseAuthResultsValue(raw) {
  const policyComment = raw.match(/\bdmarc=\w+\s*\(([^)]*)\)/i)?.[1] || '';
  const segments = stripComments(raw).split(';').map(s => s.trim()).filter(Boolean);
  const result = { authservId: null, spf: [], dkim: [], dmarc: [], compauth: [], arc: [] };
  segments.forEach((segment, index) => {
    if (index === 0 && !/^[a-z-]+\s*=/i.test(segment)) { result.authservId = segment.split(/\s+/)[0].toLowerCase().slice(0, 253); return; }
    const m = segment.match(/^([a-z-]+)\s*=\s*([a-z]+)\b(.*)$/i);
    if (!m) return;
    const method = m[1].toLowerCase(), value = m[2].toLowerCase(), props = {};
    for (const p of m[3].matchAll(/([a-z]+(?:\.[a-z-]+)?)\s*=\s*("[^"]*"|[^\s;]+)/gi)) props[p[1].toLowerCase()] = p[2].replace(/^"|"$/g, '');
    if (method === 'spf') result.spf.push({ result: value, domain: domainOf(props['smtp.mailfrom'] || props['smtp.helo'] || '') });
    else if (method === 'dkim') result.dkim.push({ result: value, domain: domainOf(props['header.d'] || props['header.i'] || '') });
    else if (method === 'dmarc') result.dmarc.push({ result: value, headerFrom: domainOf(props['header.from'] || ''), action: props.action?.toLowerCase() || null,
      policy: (policyComment.match(/\bp=(\w+)/i)?.[1] || '').toLowerCase() || null });
    else if (method === 'compauth') result.compauth.push({ result: value, reason: props.reason || null });
    else if (method === 'arc') result.arc.push({ result: value });
  });
  return result;
}
function parseAuthResults(headersInput) {
  const headers = normalizeHeaders(headersInput);
  const ar = headerValues(headers, 'authentication-results');
  const arcAr = headerValues(headers, 'arc-authentication-results');
  const arcSeals = headerValues(headers, 'arc-seal');
  const received = headerValues(headers, 'received');
  // The topmost Authentication-Results is added by the receiving provider; lower
  // ones may be forged by the sender and are reported only as count.
  const top = ar.length ? parseAuthResultsValue(ar[0]) : null;
  const arcInstances = arcAr.map(v => ({ instance: Number(v.match(/\bi\s*=\s*(\d+)/i)?.[1]) || null, ...parseAuthResultsValue(v.replace(/^\s*i\s*=\s*\d+\s*;/i, '')) }))
    .sort((a, b) => (b.instance || 0) - (a.instance || 0));
  const sealCv = arcSeals.map(v => v.match(/\bcv\s*=\s*(\w+)/i)?.[1]?.toLowerCase()).filter(Boolean);
  const returnPath = domainOf(headerValues(headers, 'return-path')[0] || '');
  const fromHeader = headerValues(headers, 'from')[0] || '';
  const fromDomain = domainOf(fromHeader.match(/<([^<>]+)>\s*$/)?.[1] || fromHeader);
  let receivedSpf = null;
  const rs = headerValues(headers, 'received-spf')[0];
  if (rs) receivedSpf = rs.trim().split(/[\s(;]/)[0].toLowerCase() || null;
  const first = (list) => list[0]?.result || null;
  return {
    status: !headers.length ? 'not_provided' : top ? 'parsed' : 'missing_authentication_results',
    headerCount: headers.length, authenticationResultsCount: ar.length, receivedCount: received.length,
    authservId: top?.authservId || null,
    spf: top ? (first(top.spf) || (receivedSpf ? receivedSpf : 'none')) : receivedSpf,
    spfDomain: top?.spf[0]?.domain || null,
    dkim: top ? top.dkim.map(d => ({ result: d.result, domain: d.domain })) : [],
    dmarc: top ? first(top.dmarc) : null,
    dmarcHeaderFrom: top?.dmarc[0]?.headerFrom || null,
    dmarcPolicy: top?.dmarc[0]?.policy || null,
    compauth: top?.compauth[0] || null,
    arc: { present: arcAr.length > 0 || arcSeals.length > 0, topResult: top ? first(top.arc) : null, sealCv, instances: arcInstances.map(a => ({ instance: a.instance, spf: first(a.spf), dkim: first(a.dkim), dmarc: first(a.dmarc) })) },
    returnPathDomain: returnPath, fromDomain
  };
}

// Relaxed DMARC alignment (RFC 7489 3.1): organizational domains must match.
function dmarcAlignment(auth, fromDomain, orgDomain) {
  const from = auth.dmarcHeaderFrom || fromDomain || auth.fromDomain;
  if (auth.status !== 'parsed' || !from) return { status: 'not_available' };
  if (auth.dmarc === 'pass') return { status: 'aligned', method: 'receiver_dmarc_pass', fromDomain: from };
  const fromOrg = orgDomain(from);
  const passing = [...(auth.spf === 'pass' && auth.spfDomain ? [['spf', auth.spfDomain]] : []), ...auth.dkim.filter(d => d.result === 'pass' && d.domain).map(d => ['dkim', d.domain])];
  if (!passing.length) return { status: 'not_aligned', method: 'no_spf_or_dkim_pass', fromDomain: from };
  let unknown = false;
  for (const [method, domain] of passing) {
    if (domain === from) return { status: 'aligned', method: method + '_exact', fromDomain: from };
    const org = orgDomain(domain);
    if (fromOrg && org) { if (fromOrg === org) return { status: 'aligned', method: method + '_relaxed', fromDomain: from }; }
    else if (domain.endsWith('.' + from) || from.endsWith('.' + domain)) return { status: 'aligned', method: method + '_subdomain_relation', fromDomain: from };
    else unknown = true;
  }
  return unknown ? { status: 'boundary_unknown', fromDomain: from, passingDomains: passing.map(p => p[1]) } : { status: 'not_aligned', method: 'pass_domains_unrelated', fromDomain: from, passingDomains: passing.map(p => p[1]) };
}

// Microsoft EOP / Defender headers. Documented at
// https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo
function parseMsAntispam(headersInput) {
  const headers = normalizeHeaders(headersInput);
  const fields = {};
  for (const v of [...headerValues(headers, 'x-forefront-antispam-report'), ...headerValues(headers, 'x-microsoft-antispam')])
    for (const part of v.split(';')) { const m = part.trim().match(/^([A-Z]{2,6}):(.*)$/); if (m && !(m[1] in fields)) fields[m[1]] = m[2].trim(); }
  if (!Object.keys(fields).length) return { status: 'not_provided' };
  const num = v => (v !== undefined && /^-?\d+$/.test(v) ? Number(v) : null);
  return { status: 'parsed', scl: num(fields.SCL), bcl: num(fields.BCL), cat: fields.CAT || null, sfv: fields.SFV || null,
    sfty: fields.SFTY ? fields.SFTY.split(',').map(s => s.trim()).filter(Boolean) : [], dir: fields.DIR || null };
}

// Compact confusables subset (Unicode UTS #39 confusables.txt) for Cyrillic and
// Greek letters that render like Latin letters. Not the full table.
const CONFUSABLES = Object.freeze({
  'а':'a','в':'b','е':'e','ё':'e','к':'k','м':'m','н':'h','о':'o','р':'p','с':'c','т':'t','у':'y','х':'x','і':'i','ї':'i','ј':'j','ѕ':'s','ԁ':'d','ԛ':'q','ԝ':'w','һ':'h','ӏ':'l','ɡ':'g',
  'А':'A','В':'B','Е':'E','К':'K','М':'M','Н':'H','О':'O','Р':'P','С':'C','Т':'T','У':'Y','Х':'X','І':'I','Ј':'J','Ѕ':'S','Ԁ':'D','Ԛ':'Q','Ԝ':'W','Һ':'H','Ӏ':'I',
  'α':'a','β':'b','ε':'e','ι':'i','κ':'k','ν':'v','ο':'o','ρ':'p','τ':'t','υ':'u','χ':'x','γ':'y','ω':'w',
  'Α':'A','Β':'B','Ε':'E','Ζ':'Z','Η':'H','Ι':'I','Κ':'K','Μ':'M','Ν':'N','Ο':'O','Ρ':'P','Τ':'T','Υ':'Y','Χ':'X'
});
const HIDDEN = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\u3164\uFEFF\uFFA0]/gu;
const scriptOf = ch => /\p{Script=Latin}/u.test(ch) ? 'Latin' : /\p{Script=Cyrillic}/u.test(ch) ? 'Cyrillic' : /\p{Script=Greek}/u.test(ch) ? 'Greek' : /\p{L}/u.test(ch) ? 'Other' : null;
function skeleton(text) { return [...text.normalize('NFKC')].map(ch => CONFUSABLES[ch] ?? ch).join('').toLowerCase(); }

function unicodeFindings(value, field, brands = []) {
  if (typeof value !== 'string' || !value) return [];
  const findings = [];
  const hidden = value.match(HIDDEN);
  if (hidden) findings.push({ field, type: 'hidden_or_bidi_characters', count: hidden.length, codePoints: [...new Set(hidden.map(c => 'U+' + c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')))].slice(0, 10) });
  const visible = value.replace(HIDDEN, '');
  const nfkc = visible.normalize('NFKC');
  if (nfkc !== visible && /[\u{1D400}-\u{1D7FF}\uFF21-\uFF5A]/u.test(visible)) findings.push({ field, type: 'compatibility_letter_forms' });
  for (const token of nfkc.split(/[\s.@,;:()<>"'\-_/|]+/).filter(Boolean)) {
    const scripts = new Set([...token].map(scriptOf).filter(Boolean));
    if (scripts.has('Latin') && (scripts.has('Cyrillic') || scripts.has('Greek'))) findings.push({ field, type: 'mixed_script_token', scripts: [...scripts].sort() });
  }
  const sk = skeleton(visible).split(/[^a-z0-9]+/).filter(Boolean);
  const plain = nfkc.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  for (const brand of brands) if (sk.includes(brand) && !plain.includes(brand)) findings.push({ field, type: 'confusable_brand_skeleton', brand });
  return findings;
}
function idnFindings(host, field, brands) {
  if (typeof host !== 'string' || !host.split('.').some(l => l.startsWith('xn--'))) return [];
  const unicode = domainToUnicode(host);
  const out = unicodeFindings(unicode, field, brands);
  return [{ field, type: 'punycode_domain', unicode }, ...out];
}

// ---- configured central rules -------------------------------------------
const SAFE_REGEX = /^[\^$\\a-zA-Z0-9.[\]{}(),?:|+*-]{1,200}$/;
function compilePattern(source, label) {
  if (typeof source !== 'string' || !SAFE_REGEX.test(source) || !source.startsWith('^') || !source.endsWith('$')) fail(`Unsafe or unanchored pattern in ${label}`);
  if (/\([^)]*[+*}]\)[+*{]/.test(source) || /\\\d/.test(source)) fail(`Nested quantifier or backreference refused in ${label}`);
  return new RegExp(source);
}
function normalizeSenderRules(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 100) fail('senderRules must be an array of at most 100 rules');
  return value.map((rule, i) => {
    if (!rule || typeof rule.id !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,119}$/i.test(rule.id)) fail(`Invalid senderRules[${i}]`);
    const domains = rule.senderDomains ?? [];
    if (!Array.isArray(domains) || domains.length > 500 || domains.some(d => typeof d !== 'string' || !/^[a-z0-9.-]{3,253}$/.test(d) || !d.includes('.'))) fail(`Invalid senderRules[${i}].senderDomains`);
    const shape = rule.senderAddressRegex;
    let local = null, domain = null;
    if (shape !== undefined) {
      if (!shape || typeof shape !== 'object') fail(`Invalid senderRules[${i}].senderAddressRegex`);
      local = compilePattern(shape.localPart, rule.id + ' localPart');
      domain = compilePattern(shape.domain, rule.id + ' domain');
    }
    if (!domains.length && !local) fail(`Sender rule ${rule.id} needs senderDomains or senderAddressRegex`);
    return { id: rule.id, severity: rule.severity || 'medium', weight: Number.isFinite(rule.weight) ? rule.weight : 2, senderDomains: [...new Set(domains)], local, domain };
  });
}
function senderMatches(address, rules) {
  if (typeof address !== 'string' || !address.includes('@')) return [];
  const at = address.lastIndexOf('@'), localPart = address.slice(0, at).toLowerCase(), host = address.slice(at + 1).toLowerCase().replace(/\.$/, '');
  const out = [];
  for (const rule of rules) {
    const domain = rule.senderDomains.find(d => host === d || host.endsWith('.' + d));
    if (domain) out.push({ ruleId: rule.id, type: 'sender_domain', domain, severity: rule.severity, weight: rule.weight });
    else if (rule.local && rule.local.test(localPart) && rule.domain.test(host)) out.push({ ruleId: rule.id, type: 'sender_address_shape', severity: rule.severity, weight: rule.weight });
  }
  return out;
}

const EVALUATORS = Object.freeze(['auth_result_tokens', 'auth_missing_or_inconsistent', 'return_path_mismatch', 'reply_to_mismatch', 'link_visible_mismatch',
  'host_html_path', 'dmarc_alignment', 'ms_compauth', 'ms_verdict', 'unicode_confusable']);
const EXTENSION_EVALUATORS = new Map();
function registerEvaluator(name, fn) { EXTENSION_EVALUATORS.set(name, fn); }
function normalizeSignalRules(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 200) fail('signalRules must be an array of at most 200 rules');
  return value.map((rule, i) => {
    if (!rule || typeof rule.id !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,119}$/i.test(rule.id) || !rule.indicators || typeof rule.indicators !== 'object') fail(`Invalid signalRules[${i}]`);
    if (rule.evaluator !== undefined && !EVALUATORS.includes(rule.evaluator) && !EXTENSION_EVALUATORS.has(rule.evaluator)) fail(`Unknown evaluator ${rule.evaluator} in ${rule.id}`);
    return { id: rule.id, category: rule.category || 'uncategorized', severity: rule.severity || 'low', weight: Number.isFinite(rule.weight) ? rule.weight : 1,
      evaluator: rule.evaluator || null, indicators: rule.indicators };
  });
}

// ctx: { auth, ms, alignment, from, replyComparison, linkComparisons, urlFindings, displayName, headersProvided, extra }
function evaluateSignalRule(rule, ctx) {
  const ind = rule.indicators, a = ctx.auth;
  switch (rule.evaluator) {
    case 'auth_result_tokens': {
      if (a.status !== 'parsed') return null;
      const hits = [];
      for (const token of ind.authenticationResults || []) {
        const [method, value] = String(token).toLowerCase().split('=');
        if (method === 'spf' && a.spf === value) hits.push(token);
        if (method === 'dmarc' && a.dmarc === value) hits.push(token);
        if (method === 'dkim' && !a.dkim.some(d => d.result === 'pass') && (a.dkim.some(d => d.result === value) || (value === 'none' && !a.dkim.length))) hits.push(token);
      }
      return hits.length ? { matched: hits } : null;
    }
    case 'auth_missing_or_inconsistent': {
      const reasons = [];
      if (a.status === 'missing_authentication_results' && a.receivedCount > 0) reasons.push('authentication_results_missing');
      if (a.arc.sealCv.includes('fail')) reasons.push('arc_chain_validation_failed');
      if (a.arc.topResult === 'fail') reasons.push('arc_result_fail');
      return reasons.length ? { reasons } : null;
    }
    case 'return_path_mismatch': {
      const rp = a.returnPathDomain, from = ctx.from?.hostname;
      if (!rp || !from || rp === from) return null;
      const x = ctx.orgDomain(rp), y = ctx.orgDomain(from);
      return x && y && x !== y ? { returnPathDomain: rp, fromDomain: from } : null;
    }
    case 'reply_to_mismatch':
      return ctx.replyComparison?.status === 'different_registered_domain' ? { comparison: ctx.replyComparison.status } : null;
    case 'link_visible_mismatch': {
      const idx = (ctx.linkComparisons || []).map((c, i) => c.comparison.status === 'different_registered_domain' ? i : -1).filter(i => i >= 0);
      return idx.length ? { pairIndexes: idx } : null;
    }
    case 'host_html_path': {
      const hosts = new Set((ind.hosts || []).map(h => String(h).toLowerCase())), suffixes = (ind.pathSuffixes || []).map(s => String(s).toLowerCase());
      const urls = (ctx.urlFindings || []).filter(f => f.status === 'parsed' && hosts.has(f.hostname) && suffixes.some(s => f.pathname.toLowerCase().endsWith(s))).map(f => f.originalUrl);
      return urls.length ? { urls: urls.slice(0, 20) } : null;
    }
    case 'dmarc_alignment':
      return ctx.alignment.status === 'not_aligned' ? { alignment: ctx.alignment } : null;
    case 'ms_compauth': {
      const c = a.compauth; const wanted = (ind.compauthResults || ['fail']).map(s => String(s).toLowerCase());
      return c && wanted.includes(c.result) ? { compauth: c.result, reason: c.reason } : null;
    }
    case 'ms_verdict': {
      const m = ctx.ms; if (m.status !== 'parsed') return null;
      const reasons = [];
      if (Number.isFinite(ind.sclMin) && m.scl !== null && m.scl >= ind.sclMin) reasons.push('SCL:' + m.scl);
      if (Number.isFinite(ind.bclMin) && m.bcl !== null && m.bcl >= ind.bclMin) reasons.push('BCL:' + m.bcl);
      if (m.cat && (ind.categories || []).includes(m.cat)) reasons.push('CAT:' + m.cat);
      for (const s of m.sfty) if ((ind.safetyTips || []).includes(s)) reasons.push('SFTY:' + s);
      return reasons.length ? { reasons } : null;
    }
    case 'unicode_confusable': {
      const brands = (ind.brands || []).map(b => String(b).toLowerCase());
      const findings = [...unicodeFindings(ctx.displayName, 'displayName', brands), ...unicodeFindings(ctx.from?.localPart, 'fromLocalPart', brands),
        ...idnFindings(ctx.from?.hostname, 'fromDomain', brands),
        ...(ctx.urlFindings || []).filter(f => f.status === 'parsed' && f.idn).flatMap(f => idnFindings(f.hostname, 'linkHost', brands))];
      const strong = findings.filter(f => f.type !== 'punycode_domain');
      return strong.length ? { findings: findings.slice(0, 20) } : null;
    }
    default: {
      const ext = EXTENSION_EVALUATORS.get(rule.evaluator);
      return ext ? ext(rule, ctx) : undefined; // undefined => not machine-evaluable
    }
  }
}

module.exports = { normalizeHeaders, parseAuthResults, parseAuthResultsValue, dmarcAlignment, parseMsAntispam, unicodeFindings, idnFindings, skeleton, CONFUSABLES,
  normalizeSenderRules, senderMatches, normalizeSignalRules, evaluateSignalRule, registerEvaluator, EVALUATORS, compilePattern };

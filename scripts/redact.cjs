'use strict';
// Redacts text before it may enter the public corpus. Pure string processing:
// never reads mail, never fetches URLs. Private identifiers come from the
// gitignored config/private-identifiers.json and are never committed.
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const PRIVATE_FILE = path.join(ROOT, 'config', 'private-identifiers.json');
// Campaign markers are public indicators and survive redaction.
const KEEP_MARKERS = ['111.957097', '111-957097'];
const INVISIBLE = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\u3164\uFEFF\uFFA0]/g;

function loadPrivateIdentifiers(file = PRIVATE_FILE) {
  if (!fs.existsSync(file)) return null;
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  const list = key => (Array.isArray(value[key]) ? value[key] : []).filter(x => typeof x === 'string' && x.trim().length >= 3).map(x => x.trim());
  return { names: list('names'), emails: list('emails').map(x => x.toLowerCase()) };
}
function escapeRegExp(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function luhn(digits) {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) { let d = +digits[digits.length - 1 - i]; if (i % 2) { d *= 2; if (d > 9) d -= 9; } sum += d; }
  return sum % 10 === 0;
}
function lower(value) { return String(value || '').toLowerCase(); }

// Keeps scheme + host + path only. Opaque path segments (tracking tokens, encoded
// redirect targets, long random strings) collapse to [TOKEN].
function redactUrl(raw) {
  let url;
  try { url = new URL(String(raw).trim()); } catch { return '[URL]'; }
  if (!['http:', 'https:'].includes(url.protocol)) return '[URL]';
  const host = url.hostname.toLowerCase();
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(':') || host.startsWith('[')) return url.protocol + '//[IP]/';
  const segments = url.pathname.split('/').map(seg => {
    if (!seg) return seg;
    let decoded = seg; try { decoded = decodeURIComponent(seg); } catch {}
    const opaque = /[%=@:]/.test(seg) || decoded.length > 32 || /\d{5,}/.test(decoded) ||
      (decoded.length >= 12 && /\d/.test(decoded) && /[A-Za-z]/.test(decoded) && !/^[a-z0-9-]+\.(?:html?|php|aspx?|jpe?g|png|gif|svg)$/i.test(decoded));
    return opaque ? '[TOKEN]' : seg;
  });
  const collapsed = [];
  for (const seg of segments) if (!(seg === '[TOKEN]' && collapsed[collapsed.length - 1] === '[TOKEN]')) collapsed.push(seg);
  return url.protocol + '//' + host + (collapsed.join('/') || '/');
}

// Returns { text, applied: {CATEGORY: count}, invisibleRemoved }.
function redact(input, options = {}) {
  const identifiers = options.identifiers === undefined ? loadPrivateIdentifiers() : options.identifiers;
  const sender = lower(options.senderAddress);
  const senderDomain = sender.includes('@') ? sender.split('@')[1] : '';
  const applied = {};
  const count = (name, n = 1) => { applied[name] = (applied[name] || 0) + n; };
  let text = String(input ?? '');
  const invisible = (text.match(INVISIBLE) || []).length;
  if (invisible) { text = text.replace(INVISIBLE, ''); count('INVISIBLE_CHARS_REMOVED', invisible); }
  text = text.normalize('NFKC').replace(/[\t\u00A0\u2000-\u200A\u202F\u205F\u3000]+/g, ' ').replace(/ {2,}/g, ' ');
  const sub = (pattern, placeholder, name, keep) => {
    text = text.replace(pattern, (...m) => {
      const match = m[0];
      if (keep && keep(match, ...m.slice(1))) return match;
      count(name);
      return typeof placeholder === 'function' ? placeholder(...m) : placeholder;
    });
  };
  // Protect campaign markers from the digit rules.
  for (const marker of KEEP_MARKERS) text = text.split(marker).join(`\u0000M${KEEP_MARKERS.indexOf(marker)}\u0000`);
  // URLs first: scheme + host + path only.
  sub(/\bhttps?:\/\/[^\s<>"')\]]+/gi, m => redactUrl(m.replace(/\u0000M(\d)\u0000/g, (_, i) => KEEP_MARKERS[i])), 'URL_QUERY_AND_TOKENS', m => redactUrl(m.replace(/\u0000M(\d)\u0000/g, (_, i) => KEEP_MARKERS[i])) === m);
  // Email addresses (also percent-encoded), except the spammer's own sender address/domain.
  const restore = v => v.replace(/\u0000M(\d)\u0000/g, (_, i) => KEEP_MARKERS[i]);
  sub(/[A-Za-z0-9._%+\u0000-]+(?:@|%40|%2540)[A-Za-z0-9.\u0000-]+\.[A-Za-z]{2,}/gi, '[EMAIL]', 'EMAIL', m => {
    const v = lower(restore(m)).replace(/%2540|%40/g, '@');
    return v === sender || (senderDomain && v.endsWith('@' + senderDomain) && !(identifiers?.emails || []).includes(v));
  });
  // The user's names and handles (longest first), including trailing digits/handles.
  const names = [...(identifiers?.names || []), ...(identifiers?.emails || []).map(e => e.split('@')[0])].sort((a, b) => b.length - a.length);
  for (const name of [...new Set(names)]) sub(new RegExp(`(?<![\\p{L}\\p{N}])${escapeRegExp(name)}[\\p{L}\\p{N}_]*`, 'giu'), '[NAME]', 'NAME');
  // Greetings with a name.
  sub(/\b(Hi|Hello|Hey|Dear|Hallo|Beste|Geachte|Beste heer|Beste mevrouw)\s+(?!\[NAME\])([\p{L}][\p{L}\p{N}._'-]*(?:\s+[\p{L}][\p{L}\p{N}._'-]*)?)(\s*[,!:])/giu, (m, g, n, p) => `${g} [NAME]${p}`, 'GREETING_NAME');
  // Exact times (receipt timestamps are reduced to dates elsewhere).
  sub(/\b\d{1,2}:\d{2}(?::\d{2})?(?:\s?[+-]\d{4}|\s?(?:UTC|GMT|Z))?\b/g, '[TIME]', 'TIME');
  // IP addresses.
  sub(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]', 'IP');
  sub(/\b(?:[A-F0-9]{1,4}:){4,7}[A-F0-9]{1,4}\b/gi, '[IP]', 'IP');
  // IBANs and card-like numbers.
  sub(/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g, '[IBAN]', 'IBAN', m => !/\d{4}/.test(m.slice(4).replace(/ /g, '')));
  sub(/\b\d(?:[ -]?\d){12,18}\b/g, '[CARD]', 'CARD', m => !luhn(m.replace(/\D/g, '')));
  // Phone numbers: 9+ digits with optional separators, or +country forms.
  sub(/(?:\+|\b00)\d{1,3}[\s().-]*(?:\d[\s().-]*){6,13}\d\b/g, '[PHONE]', 'PHONE');
  sub(/\(?\b\d{2,4}\)?[\s.-]\d{3}[\s.-]\d{3,4}\b/g, '[PHONE]', 'PHONE');
  // Street addresses and postcodes.
  const streetTypes = 'Street|St\\.?|Avenue|Ave\\.?|Road|Rd\\.?|Highway|Hwy|Boulevard|Blvd\\.?|Lane|Ln\\.?|Drive|Dr\\.?|Court|Ct\\.?|Way|Place|Pl\\.?|Suite|straat|weg|laan|plein|gracht|kade|singel|dijk';
  sub(new RegExp(`\\b\\d{1,6}\\s+(?:[NSEW]\\.?\\s+)?(?:[\\p{L}][\\p{L}.'-]*\\s+){0,4}(?:${streetTypes})\\b[^,\\n]{0,40}`, 'giu'), '[ADDRESS]', 'STREET_ADDRESS');
  sub(/\b\d{1,6}\s+(?:Boulevard|Rue|Avenue|Calle|Via|Chemin|Route)\s+[\p{L}' -]{2,40}/giu, '[ADDRESS]', 'STREET_ADDRESS');
  sub(/\b[\p{L}]+(?:straat|weg|laan|plein|gracht|kade|singel|dijk)\s+\d{1,5}[a-z]?\b/giu, '[ADDRESS]', 'STREET_ADDRESS');
  sub(/\b\d{4}\s?[A-Z]{2}\b(?![A-Za-z])/g, '[POSTCODE]', 'POSTCODE');
  sub(/\b[A-Z]{2}\s\d{5}(?:-\d{4})?\b/g, '[POSTCODE]', 'POSTCODE');
  sub(/\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b/g, '[POSTCODE]', 'POSTCODE');
  // Labelled account/order/reference IDs.
  sub(/\b((?:account|member|customer|client|order|subscription|reference|ref|invoice|case|ticket|tracking|transaction|klant|bestel|referentie|factuur)[\s-]*(?:id|no\.?|number|nr\.?|nummer|#)?\s*[:#]\s*)(#?[A-Za-z0-9[\]_.-]{3,})/gi, (m, label) => `${label}[ID]`, 'ID', (m, label, value) => value === '[ID]' || value === '[NAME]');
  // Mixed alphanumeric IDs (e.g. 123456-ABCD) and long digit runs.
  sub(/\b(?=[A-Za-z0-9-]*\d{4})(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+\b/g, '[ID]', 'ID', m => /^(?:[A-Za-z]{1,4}-)?\d{1,2}-\d{1,2}-\d{4}$/.test(m) || /^\d{4}-\d{2}-\d{2}$/.test(m));
  sub(/\d{6,}/g, '[ID]', 'LONG_DIGITS');
  // Long random tokens.
  sub(/\b(?=[A-Za-z0-9_-]{20,}\b)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{20,}\b/g, '[TOKEN]', 'TOKEN');
  text = text.replace(/\u0000M(\d)\u0000/g, (_, i) => KEEP_MARKERS[i]);
  return { text: text.replace(/[ \t]{2,}/g, ' ').trim(), applied, invisibleRemoved: invisible };
}

module.exports = { redact, redactUrl, loadPrivateIdentifiers, KEEP_MARKERS, INVISIBLE, PRIVATE_FILE };

if (require.main === module) {
  let raw = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', d => { raw += d; if (raw.length > 1e6) throw Error('Input too large'); });
  process.stdin.on('end', () => {
    const input = JSON.parse(raw);
    const texts = Array.isArray(input.texts) ? input.texts : [input.text];
    console.log(JSON.stringify(texts.map(t => redact(t, { senderAddress: input.senderAddress })), null, 2));
  });
}

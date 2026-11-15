'use strict';
const assert=require('node:assert/strict');
const S=require('../scripts/signals.cjs');
// Gmail-style results with authserv-id and comments.
const g=S.parseAuthResults([{name:'Authentication-Results',value:'mx.example.net; dkim=pass header.i=@mail.shop.example header.s=s1 header.b=abc; spf=pass (example.net: domain of bounce@em.shop.example designates 192.0.2.5 as permitted sender) smtp.mailfrom=bounce@em.shop.example; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=shop.example'},{name:'From',value:'Shop <news@shop.example>'}]);
assert.equal(g.status,'parsed');assert.equal(g.authservId,'mx.example.net');assert.equal(g.spf,'pass');assert.equal(g.spfDomain,'em.shop.example');
assert.deepEqual(g.dkim,[{result:'pass',domain:'mail.shop.example'}]);assert.equal(g.dmarc,'pass');assert.equal(g.dmarcPolicy,'reject');assert.equal(g.fromDomain,'shop.example');
// Microsoft-style results without authserv-id, plus compauth.
const m=S.parseAuthResults([{name:'Authentication-Results',value:'spf=softfail (sender IP is 192.0.2.9) smtp.mailfrom=other.example; dkim=fail (body hash did not verify) header.d=other.example;dmarc=fail action=oreject header.from=brand.example;compauth=fail reason=000'}]);
assert.equal(m.authservId,null);assert.equal(m.spf,'softfail');assert.equal(m.dmarc,'fail');assert.deepEqual(m.compauth,{result:'fail',reason:'000'});
// Only the topmost header counts; a forged lower header cannot add a pass.
const forged=S.parseAuthResults([{name:'Authentication-Results',value:'mx.example.net; spf=fail smtp.mailfrom=x.example'},{name:'Authentication-Results',value:'evil.example; spf=pass smtp.mailfrom=x.example; dmarc=pass header.from=x.example'}]);
assert.equal(forged.spf,'fail');assert.equal(forged.dmarc,null);assert.equal(forged.authenticationResultsCount,2);
// ARC parsing and missing results.
const arc=S.parseAuthResults([{name:'ARC-Seal',value:'i=1; a=rsa-sha256; cv=fail; d=fwd.example; s=a; b=x'},{name:'ARC-Authentication-Results',value:'i=1; fwd.example; spf=pass smtp.mailfrom=a.example; dkim=pass header.d=a.example; dmarc=pass header.from=a.example'},{name:'Received',value:'from a by b'}]);
assert.equal(arc.status,'missing_authentication_results');assert.deepEqual(arc.arc.sealCv,['fail']);assert.equal(arc.arc.instances[0].dmarc,'pass');
assert.equal(S.parseAuthResults(undefined).status,'not_provided');
assert.throws(()=>S.parseAuthResults([{name:'X',value:'y'.repeat(20000)}]));
// Alignment (relaxed).
const org=h=>h.split('.').slice(-2).join('.');
assert.equal(S.dmarcAlignment({...m,dmarc:'none'},'brand.example',org).status,'not_aligned');
assert.equal(S.dmarcAlignment({...g,dmarc:null},'shop.example',org).status,'aligned');
assert.equal(S.dmarcAlignment({...g,dmarc:null,dmarcHeaderFrom:null},'shop.example',()=>null).method,'spf_subdomain_relation');
assert.equal(S.dmarcAlignment({...g,dmarc:null,dmarcHeaderFrom:null,spfDomain:'esp.example',dkim:[{result:'pass',domain:'esp.example'}]},'shop.example',()=>null).status,'boundary_unknown');
// Microsoft anti-spam headers.
const ms=S.parseMsAntispam([{name:'X-Forefront-Antispam-Report',value:'CIP:192.0.2.1;CTRY:;SCL:1;SFV:NSPM;CAT:NONE;SFTY:9.25;'},{name:'X-Microsoft-Antispam',value:'BCL:8;'}]);
assert.deepEqual([ms.scl,ms.bcl,ms.cat,ms.sfty],[1,8,'NONE',['9.25']]);
assert.equal(S.parseMsAntispam([]).status,'not_provided');
// Unicode.
const types=v=>S.unicodeFindings(v,'displayName',['paypal','binance']).map(f=>f.type);
assert.ok(types('P\u0430yPal Service').includes('mixed_script_token'));
assert.ok(types('P\u0430yPal Service').includes('confusable_brand_skeleton'));
assert.ok(types('Bin\u200bance').includes('hidden_or_bidi_characters'));
assert.ok(types('Support \u202Egnp.exe').includes('hidden_or_bidi_characters'));
assert.ok(types('\u{1D40F}\u{1D41A}\u{1D432}\u{1D40F}\u{1D41A}\u{1D425}').includes('compatibility_letter_forms'));
assert.deepEqual(types('Служба поддержки'),[],'single-script Cyrillic is not flagged');
assert.deepEqual(types('PayPal'),[],'plain brand is not a confusable');
assert.deepEqual(types('José Müller'),[],'Latin diacritics are not flagged');
assert.ok(S.idnFindings('xn--pypal-4ve.example','linkHost',['paypal']).some(f=>f.type==='confusable_brand_skeleton'));
// Sender rules and pattern safety.
const rules=S.normalizeSenderRules([{id:'s.v1',senderDomains:['bad.example']},{id:'r.v1',senderAddressRegex:{localPart:'^[a-z]{3}$',domain:'^x\\.example$'}}]);
assert.equal(S.senderMatches('a@mail.bad.example',rules)[0].ruleId,'s.v1');
assert.equal(S.senderMatches('a@notbad.example',rules).length,0);
assert.equal(S.senderMatches('abc@x.example',rules)[0].ruleId,'r.v1');
for(const p of ['[a-z]+','^(a+)+$','^(a)\\1$','^.*$x'])assert.throws(()=>S.compilePattern(p,'t'));
assert.throws(()=>S.normalizeSignalRules([{id:'x.v1',evaluator:'nope',indicators:{a:1}}]));
// Letter-for-digit amounts and phrase / display-name evaluators.
assert.deepEqual(S.letterForDigitAmountTokens('UP TO €1,25O  +2OO FREE SPINS').sort(),['2OO','€1,25O']);
assert.deepEqual(S.letterForDigitAmountTokens('Invoice €1,250.00 and $20.00 for 200 items'),[]);
assert.ok(S.letterForDigitAmountTokens('Refund of €l00').includes('€l00'));
assert.deepEqual(S.letterForDigitAmountTokens('Traffic update for highway I-95 and route I10'),[]);
const phraseRule={id:'p.v1',evaluator:'text_phrases',indicators:{phrases:['free spins','first deposit bonus'],minMatches:1}};
const nameRule={id:'n.v1',evaluator:'display_name_and_local_part',indicators:{displayNames:['Lucky Boom'],localParts:['outlet']}};
assert.ok(S.evaluateSignalRule(phraseRule,{text:'Join now for 100% First Deposit Bonus'}));
assert.equal(S.evaluateSignalRule(phraseRule,{text:'Your cashback has been credited'}),null);
assert.ok(S.evaluateSignalRule(nameRule,{from:{localPart:'outlet',hostname:'buyharbor.me'},displayName:'Lucky Boom'}));
assert.equal(S.evaluateSignalRule(nameRule,{from:{localPart:'outlet',hostname:'shop.example'},displayName:'Shop Outlet'}),null);
const retailerRule={id:'r.v1',evaluator:'impersonation_local_part_unrelated_domain',indicators:{localParts:['walmart','bestbuy'],genuineDomains:['walmart.com','bestbuy.com']}};
assert.ok(S.evaluateSignalRule(retailerRule,{from:{localPart:'walmart',hostname:'thecuntionter.com'}}));
assert.equal(S.evaluateSignalRule(retailerRule,{from:{localPart:'newsletter',hostname:'walmart.com'}}),null);
assert.equal(S.evaluateSignalRule(retailerRule,{from:{localPart:'walmart',hostname:'mail.walmart.com'}}),null);
const cjibRule={id:'c.v1',evaluator:'impersonation_local_part_unrelated_domain',indicators:{localPartPrefixes:['cjib-nietantwoorden-referentie-'],genuineDomains:['cjib.nl']}};
assert.ok(S.evaluateSignalRule(cjibRule,{from:{localPart:'Cjib-nietantwoorden-referentie-abcdef012345',hostname:'casi-app.com'}}));
assert.equal(S.evaluateSignalRule(cjibRule,{from:{localPart:'cjib-nietantwoorden-referentie-abcdef012345',hostname:'mail.cjib.nl'}}),null);
const hyphenRules=S.normalizeSenderRules([{id:'h.v1',senderAddressRegex:{localPart:'^[a-z0-9.+-]{1,64}$',domain:'^-+[a-z0-9.-]*\\.[a-z]{2,24}$'}},{id:'a.v1',senderAddressRegex:{localPart:'^[a-z0-9]{8}$',domain:'^[a-z0-9]{28,32}\\.com$'}}]);
assert.equal(S.senderMatches('info@-----mail.samplehost.com',hyphenRules)[0].ruleId,'h.v1');
assert.equal(S.senderMatches('ab12cd34@abcdefghijklmnopqrstuvwxyz12.com',hyphenRules)[0].ruleId,'a.v1');
assert.equal(S.senderMatches('info@mail.samplehost.com',hyphenRules).length,0);
// variantSenderAddressRegex is a second evaluated sender shape on the same rule.
const variantRules=S.normalizeSenderRules([{id:'v.v1',senderAddressRegex:{localPart:'^[a-z]{7}\\.111[.-]957097$',domain:'^[a-z]{8}\\.[a-z]{2,24}\\.sample\\.biz$'},variantSenderAddressRegex:{localPart:'^nooreply$',domain:'^[a-z]{9,11}\\.us$'}}]);
assert.equal(S.senderMatches('abcdefg.111.957097@abcdefgh.word.sample.biz',variantRules)[0].ruleId,'v.v1');
assert.equal(S.senderMatches('nooreply@icoutxooeem.us',variantRules)[0].ruleId,'v.v1');
assert.equal(S.senderMatches('noreply@icoutxooeem.us',variantRules).length,0,'correctly spelled no-reply is not the variant');
assert.equal(S.senderMatches('nooreply@short.us',variantRules).length,0,'domain shorter than 9 letters is not the variant');

const brands=[{token:'adobe',genuineDomains:['adobe.com','adobelogin.com']},{token:'google',genuineDomains:['google.com','gmail.com','googleapis.com']},{token:'apple',genuineDomains:['apple.com']},{token:'microsoft',genuineDomains:['microsoft.com','office.com','outlook.com']}];
const brandRule={id:'b.v1',evaluator:'brand_label_in_unrelated_host',indicators:{brands,fields:['sender','links']}};
assert.ok(S.evaluateSignalRule(brandRule,{from:{localPart:'ofubztd',hostname:'iusivkzr.adobe.salilen.me'}}),'adobe label on an unrelated .me domain');
assert.equal(S.evaluateSignalRule(brandRule,{from:{localPart:'mail',hostname:'mail.adobe.com'}}),null,'genuine adobe subdomain is a counterexample');
assert.equal(S.evaluateSignalRule(brandRule,{from:{localPart:'login',hostname:'login.adobelogin.com'}}),null,'related adobe login domain is a counterexample');
assert.equal(S.evaluateSignalRule(brandRule,{from:{localPart:'alerts',hostname:'storage.googleapis.com'},urlFindings:[{status:'parsed',hostname:'storage.googleapis.com'}]}),null,'googleapis is not an exact google label');

const packedRule={id:'p.v1',evaluator:'packed_brand_hostname',indicators:{brands,minBrands:2,fields:['sender','text','headers']}};
assert.ok(S.evaluateSignalRule(packedRule,{text:'relay google-apple.microsoft.biz.cultivo.ro'}),'packed google/apple/microsoft hostname in text');
assert.equal(S.evaluateSignalRule(packedRule,{text:'Google, Apple and Microsoft announced a partnership.'}),null,'prose brand names are not a packed hostname');
assert.equal(S.evaluateSignalRule(packedRule,{from:{localPart:'notify',hostname:'outlook.office.microsoft.com'}}),null,'genuine Microsoft infrastructure is a counterexample');
assert.equal(S.inferredOrgDomain('iusivkzr.adobe.salilen.me'),'salilen.me');
assert.equal(S.inferredOrgDomain('google-apple.microsoft.biz.cultivo.ro'),'cultivo.ro');
assert.equal(S.inferredOrgDomain('abcdefgh.word.sample.biz.id'),'sample.biz.id');

const ossRule={id:'o.v1',evaluator:'display_brand_mismatch_and_phrases',indicators:{rolePhrases:['support team'],phrases:['developer marketing plan','github stars'],minBrandLength:4,stopwords:['support','team']}};
assert.ok(S.evaluateSignalRule(ossRule,{from:{localPart:'market',hostname:'mcpcnserver.com'},displayName:'NiubiStar Support Team',subject:'Developer marketing plan for open-source projects'}));
assert.equal(S.evaluateSignalRule(ossRule,{from:{localPart:'noreply',hostname:'github.com'},displayName:'GitHub Support Team',subject:'Developer marketing plan for open-source projects'}),null,'claimed brand in the sender domain is a counterexample');
assert.equal(S.evaluateSignalRule(ossRule,{from:{localPart:'jane',hostname:'gmail.com'},displayName:'Jane Smith',text:'I maintain open-source projects and github stars.'}),null,'personal mail without a support-team role is a counterexample');

const mediaRule={id:'m.v1',evaluator:'media_endorsement',indicators:{leadins:['as seen on'],mediaBrands:['cbs news','cbs',"men's health"],phrases:['dr. oz on cbs'],genuineDomains:['cbs.com','cbsnews.com','menshealth.com']}};
assert.ok(S.evaluateSignalRule(mediaRule,{from:{localPart:'offers',hostname:'salilen.me'},subject:'As seen on CBS News & Men\'s Health'}));
assert.ok(S.evaluateSignalRule(mediaRule,{from:{localPart:'offers',hostname:'random.example'},text:'Dr. Oz on CBS: a natural compound'}));
assert.equal(S.evaluateSignalRule(mediaRule,{from:{localPart:'editor',hostname:'news.cbsnews.com'},subject:'As seen on CBS News tonight'}),null,'genuine CBS domain is a counterexample');

console.log('Header parsing (Gmail, Microsoft, ARC, forged lower header), alignment, MS verdicts, Unicode, sender-rule safety and new signal evaluators passed.');

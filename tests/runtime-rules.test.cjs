'use strict';
// Loads the real rules/filter-rules.json exactly as fetch-rules delivers it and runs
// the analyzer on synthetic fixtures. Guards against rule shapes that crash runtime.
const assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const path=require('node:path');
const doc=require('../rules/filter-rules.json');
const {runtimeRuleSet,runtimeRules,classifyRule}=require('../scripts/rule-learning.cjs');
const {localRules}=require('../scripts/fetch-rules.cjs');
const {analyze,normalizeCampaignRules}=require('../scripts/Controle-Email.cjs');
const {loadedCache}=require('./helpers/fixtures.cjs');
const set=runtimeRuleSet(doc);
assert.ok(set.campaignRules.length>=1&&set.senderRules.length>=1&&set.signalRules.length>=1);
assert.doesNotThrow(()=>normalizeCampaignRules(set.campaignRules));
assert.deepEqual(runtimeRules(doc),set.campaignRules);
for(const r of set.campaignRules)assert.equal(classifyRule(doc.rules.find(x=>x.id===r.id)),'campaign');
assert.deepEqual(localRules().campaignRules,set.campaignRules);
const enabled=doc.rules.filter(r=>['active','signal_only'].includes(r.status)).length;
assert.equal(set.campaignRules.length+set.senderRules.length+set.signalRules.length,enabled,'every enabled rule is routed exactly once');
const loaded=loadedCache();
const run=(message)=>analyze({messages:[{mailbox:'Gmail',messageId:'synthetic-1',text:'',urls:[],...message}],...set},loaded);
// Benign fixture: aligned authentication, no signals.
const benign=run({fromAddress:'news@shop.example',displayName:'Shop',headers:[{name:'Authentication-Results',value:'mx.example; spf=pass smtp.mailfrom=bounce.shop.example; dkim=pass header.d=shop.example; dmarc=pass header.from=shop.example'}]});
assert.equal(benign.messages[0].review.status!=='review_recommended',true);
assert.equal(benign.messages[0].configuredSignalMatches.length,0);
assert.equal(benign.messages[0].coverage.authentication,'headers_parsed_not_cryptographically_verified');
assert.ok(benign.centralRules.manualReviewOnly.includes('social.urgency-threat-language.v1'));
// Rotating campaign sender shape (synthetic letters, real marker shape).
const rotating=run({fromAddress:'abcdefg.111.957097@abcdefgh.word.sample.biz'});
assert.ok(rotating.messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.rotating-marker-sender-pattern.v1'));
assert.equal(rotating.messages[0].review.status,'review_recommended');
assert.equal(run({fromAddress:'abcdefgh.111.957097@abcdefgh.word.sample.biz'}).messages[0].configuredSenderMatches.length,0,'eight-letter local part does not match');
assert.equal(run({fromAddress:'abcdefg.111.957097@abcdefgh.word.sample.com'}).messages[0].configuredSenderMatches.length,0,'other suffix does not match');
// Spoofed brand with auth failures, misalignment and confusables.
const spoof=run({fromAddress:'support@unrelated.example',displayName:'B\u0456nance Supp\u043ert\u200b',headers:[
 {name:'Authentication-Results',value:'spf=fail (sender IP is 192.0.2.1) smtp.mailfrom=unrelated.example; dkim=none (message not signed) header.d=none;dmarc=fail action=none header.from=unrelated.example;compauth=fail reason=001'},
 {name:'X-Forefront-Antispam-Report',value:'CIP:192.0.2.1;CTRY:;LANG:en;SCL:5;SRV:;IPV:NLI;SFV:SPM;CAT:PHSH;SFTY:9.25;'},
 {name:'X-Microsoft-Antispam',value:'BCL:0;'}]});
const ids=spoof.messages[0].configuredSignalMatches.map(m=>m.ruleId);
for(const id of ['auth.spf-fail-or-softfail.v1','auth.dkim-fail-or-none.v1','auth.dmarc-fail.v1','auth.dmarc-alignment-fail.v1','auth.ms-compauth-fail.v1','provider.ms-verdict.v1','identity.unicode-confusable-mixed-script.v1'])assert.ok(ids.includes(id),id);
assert.equal(spoof.messages[0].review.status,'review_recommended');
assert.equal(spoof.messages[0].classification,null);
assert.deepEqual(spoof.mailboxActions,[]);
// CLI path: --analyze with useBundledRules on the real file must not throw.
const helper=path.resolve(__dirname,'../scripts/Controle-Email.cjs');
const child=spawnSync(process.execPath,[helper,'--analyze'],{input:JSON.stringify({useBundledRules:true,messages:[{mailbox:'Outlook',messageId:'synthetic-cli',fromAddress:'abcdefg.111.957097@abcdefgh.word.sample.biz',text:'',urls:['https://storage.googleapis.com/worklinks/proforward.html?sq=111-957097']}]}),encoding:'utf8',env:{...process.env,ESF_CACHE_DIR:path.join(require('node:os').tmpdir(),'esf-empty-cache-test')}});
assert.equal(child.status,0,child.stderr);
const cli=JSON.parse(child.stdout).messages[0];
assert.ok(cli.configuredCampaignMatches.length===1&&cli.configuredCampaignMatches[0].supportingHosts.includes('storage.googleapis.com'));
assert.ok(cli.configuredSenderMatches.length===1);
// Casino campaign: Lucky Boom + outlet@ on a listed rotating domain, letter-for-digit
// amounts in the subject, and gambling lures in the body.
const casino=run({fromAddress:'outlet@buyharbor.me',displayName:'Lucky Boom',subject:'- UP TO €1,25O  +2OO FREE SPINS',text:'CLAIM BONUS\nDeposit just €20 and get €40 to play!\nWelcome Pack of up to €4,000 + 650 Free Spins\n100% First Deposit Bonus'});
const casinoIds=casino.messages[0].configuredSignalMatches.map(m=>m.ruleId);
for(const id of ['social.gambling-casino-lures.v1','obfuscation.letter-for-digit-amount.v1','campaign.lucky-boom-outlet-sender.v1'])assert.ok(casinoIds.includes(id),id);
assert.ok(casino.messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.repeated-malicious-sender-domain.v1'&&m.domain==='buyharbor.me'));
assert.equal(casino.messages[0].review.status,'review_recommended');
// Same campaign on an as-yet unseen rotating domain still matches the sender pattern.
const nextDomain=run({fromAddress:'outlet@newharbor.example',displayName:'Lucky Boom',subject:'+2OO FREE SPINS'});
assert.ok(nextDomain.messages[0].configuredSignalMatches.some(m=>m.ruleId==='campaign.lucky-boom-outlet-sender.v1'));
assert.equal(nextDomain.messages[0].configuredSenderMatches.length,0,'unlisted domain is not a domain block');
// Legitimate invoice with real amounts, and outlet@ without the campaign display name.
const invoice=run({fromAddress:'billing@shop.example',displayName:'Shop Billing',subject:'Invoice €1,250.00',text:'Thank you for your order. Total due: €1,250.00. Payment of $20.00 received. 200 items shipped.'});
assert.equal(invoice.messages[0].configuredSignalMatches.some(m=>['social.gambling-casino-lures.v1','obfuscation.letter-for-digit-amount.v1','campaign.lucky-boom-outlet-sender.v1'].includes(m.ruleId)),false);
assert.equal(invoice.messages[0].configuredSenderMatches.length,0);
assert.equal(run({fromAddress:'outlet@unrelated-shop.example',displayName:'Shop Outlet',text:'Your order is ready.'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='campaign.lucky-boom-outlet-sender.v1'),false);
// I/l stand-ins only count next to a currency marker; highway names are a counterexample.
assert.ok(run({subject:'Refund of €l00 pending'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='obfuscation.letter-for-digit-amount.v1'));
assert.equal(run({text:'Traffic update for highway I-95 and route I10'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='obfuscation.letter-for-digit-amount.v1'),false);
// Hyphen campaign marker and additional parent suffixes (.web.id, .us).
assert.ok(run({fromAddress:'abcdefg.111-957097@abcdefgh.word.sample.web.id'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.rotating-marker-sender-pattern.v1'));
assert.ok(run({fromAddress:'abcdefg.111-957097@abcdefgh.word.sample.my.id'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.rotating-marker-sender-pattern.v1'));
assert.ok(run({fromAddress:'abcdefg.111.957097@abcdefgh.word.sample.us'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.rotating-marker-sender-pattern.v1'));
assert.equal(run({fromAddress:'abcdefg.111-957097@abcdefgh.word.sample.com'}).messages[0].configuredSenderMatches.length,0,'hyphen marker still requires a configured suffix');
// Lucky Boom local-part variant and newly observed rotating domains.
const luckyVariant=run({fromAddress:'appliancebillow@campaignharbor.info',displayName:'Lucky Boom',subject:'+2OO FREE SPINS'});
assert.ok(luckyVariant.messages[0].configuredSignalMatches.some(m=>m.ruleId==='campaign.lucky-boom-outlet-sender.v1'));
assert.ok(luckyVariant.messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.repeated-malicious-sender-domain.v1'&&m.domain==='campaignharbor.info'));
assert.ok(run({fromAddress:'outlet@northforge.rent',displayName:'Lucky Boom'}).messages[0].configuredSenderMatches.some(m=>m.domain==='northforge.rent'));
// Hyphen-leading domain labels and 8-character local-part plus 28-32 character .com domain.
assert.ok(run({fromAddress:'info@-----mail.samplehost.com'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='obfuscation.hyphen-leading-domain-label.v1'));
assert.ok(run({fromAddress:'ab12cd34@---abcdefghijklmnopqrstuvwxyz12abcd.com'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='obfuscation.hyphen-leading-domain-label.v1'));
const randomShape=run({fromAddress:'ab12cd34@abcdefghijklmnopqrstuvwxyz12.com'});
assert.ok(randomShape.messages[0].configuredSenderMatches.some(m=>m.ruleId==='obfuscation.random-alnum-sender-shape.v1'));
assert.equal(run({fromAddress:'ab12cd34@shortname.com'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='obfuscation.random-alnum-sender-shape.v1'),false);
assert.equal(run({fromAddress:'info@mail.samplehost.com'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='obfuscation.hyphen-leading-domain-label.v1'),false);
// Retailer brand as local-part on an unrelated domain; genuine brand newsletters are counterexamples.
assert.ok(run({fromAddress:'walmart@thecuntionter.com'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.retailer-brand-local-part.v1'));
assert.ok(run({fromAddress:'bestbuy@ydezdlh.com'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.retailer-brand-local-part.v1'));
assert.ok(run({fromAddress:'samsclub@canderation.com'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.retailer-brand-local-part.v1'));
assert.ok(run({fromAddress:'costco@randomretailer.test'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.retailer-brand-local-part.v1'));
assert.equal(run({fromAddress:'newsletter@walmart.com'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.retailer-brand-local-part.v1'),false,'genuine newsletter local-part is not a match');
assert.equal(run({fromAddress:'walmart@mail.walmart.com'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.retailer-brand-local-part.v1'),false,'brand local-part at the genuine domain is not a match');
// Casino: spinkong-vip local-part on a hyphen-leading bonuses domain.
const spin=run({fromAddress:'spinkong-vip-offer@--spinkong-vip-bonuses.com'});
assert.ok(spin.messages[0].configuredSenderMatches.some(m=>m.ruleId==='social.spinkong-vip-sender.v1'));
assert.ok(spin.messages[0].configuredSenderMatches.some(m=>m.ruleId==='obfuscation.hyphen-leading-domain-label.v1'));
assert.equal(run({fromAddress:'newsletter@spinkong-news.com'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='social.spinkong-vip-sender.v1'),false);
// Dutch CJIB impersonation on an unrelated domain; genuine cjib.nl is a counterexample.
assert.ok(run({fromAddress:'Cjib-nietantwoorden-referentie-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@casi-app.com'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.cjib-impersonation-unrelated-domain.v1'));
assert.ok(run({fromAddress:'cjib-nietantwoorden-referentie-abcdef012345@renegades.sk'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.cjib-impersonation-unrelated-domain.v1'));
assert.equal(run({fromAddress:'cjib-nietantwoorden-referentie-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@mail.cjib.nl'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.cjib-impersonation-unrelated-domain.v1'),false);
// nooreply@ random 9-11 letter .us is the documented rotating-campaign variant.
assert.ok(run({fromAddress:'nooreply@icoutxooeem.us'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.rotating-marker-sender-pattern.v1'));
assert.ok(run({fromAddress:'nooreply@gupuapoolhb.us'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.rotating-marker-sender-pattern.v1'));
assert.equal(run({fromAddress:'noreply@icoutxooeem.us'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.rotating-marker-sender-pattern.v1'),false);
assert.equal(run({fromAddress:'nooreply@short.us'}).messages[0].configuredSenderMatches.some(m=>m.ruleId==='campaign.rotating-marker-sender-pattern.v1'),false);
// Brand label outside the registrable domain; genuine brand subdomains are counterexamples.
assert.ok(run({fromAddress:'ofubztd@iusivkzr.adobe.salilen.me'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.brand-label-in-unrelated-domain.v1'));
assert.equal(run({fromAddress:'noreply@mail.adobe.com'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.brand-label-in-unrelated-domain.v1'),false);
assert.equal(run({fromAddress:'alerts@storage.googleapis.com'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.brand-label-in-unrelated-domain.v1'),false);
// Packed multi-brand hostname in relay text; prose mentions and genuine Microsoft hosts are not.
const packed=run({fromAddress:'nooreply@icoutxooeem.us',text:'relay google-apple.microsoft.biz.cultivo.ro'});
assert.ok(packed.messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.packed-brand-hostname.v1'));
assert.equal(run({text:'Google, Apple and Microsoft announced a partnership.'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.packed-brand-hostname.v1'),false);
assert.equal(run({fromAddress:'notify@outlook.office.microsoft.com'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='identity.packed-brand-hostname.v1'),false);
// Unsolicited open-source marketing with a display-brand mismatch.
const oss=run({fromAddress:'market@mcpcnserver.com',displayName:'NiubiStar Support Team',subject:'Developer marketing plan for open-source projects',urls:['https://niubistar.com/']});
assert.ok(oss.messages[0].configuredSignalMatches.some(m=>m.ruleId==='social.oss-dev-marketing-mismatch.v1'));
assert.equal(oss.messages[0].review.status,'review_recommended');
assert.equal(run({fromAddress:'noreply@github.com',displayName:'GitHub Support Team',subject:'Developer marketing plan for open-source projects'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='social.oss-dev-marketing-mismatch.v1'),false);
assert.equal(run({fromAddress:'jane@gmail.com',displayName:'Jane Smith',text:'I maintain open-source projects.'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='social.oss-dev-marketing-mismatch.v1'),false);
// Watch-before-deleted urgency and fake media endorsement (supporting unless combined).
const honey=run({fromAddress:'ofubztd@iusivkzr.adobe.salilen.me',displayName:'HoneyBoost',subject:'Watch before deleted: The simple shower trick that ended ED for men over 60',text:'As seen on CBS News & Men\'s Health\n111-957097'});
const honeyIds=honey.messages[0].configuredSignalMatches.map(m=>m.ruleId);
for(const id of ['identity.brand-label-in-unrelated-domain.v1','social.watch-before-deleted.v1','social.fake-media-endorsement.v1'])assert.ok(honeyIds.includes(id),id);
assert.equal(honey.messages[0].review.status,'review_recommended');
assert.equal(run({fromAddress:'editor@news.cbsnews.com',subject:'As seen on CBS News tonight'}).messages[0].configuredSignalMatches.some(m=>m.ruleId==='social.fake-media-endorsement.v1'),false);
console.log('Real rule document: routing, runtime load, sender/auth/provider/Unicode/casino rules and CLI --analyze passed.');

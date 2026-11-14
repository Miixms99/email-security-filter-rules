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
console.log('Real rule document: routing, runtime load, sender/auth/provider/Unicode rules and CLI --analyze passed.');

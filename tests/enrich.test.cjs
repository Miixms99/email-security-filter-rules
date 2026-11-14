'use strict';
// Enrichment (RDAP, URLhaus, Spamhaus DBL, first contact) with stubbed network only,
// and attachment evaluators on the real rule file. Synthetic data only.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
process.env.ESF_CACHE_DIR=fs.mkdtempSync(path.join(os.tmpdir(),'esf-enrich-cache-'));
const E=require('../scripts/enrich.cjs');
const {analyze}=require('../scripts/Controle-Email.cjs');
const {runtimeRuleSet}=require('../scripts/rule-learning.cjs');
const {loadedCache}=require('./helpers/fixtures.cjs');
(async()=>{
 // Spamhaus answer interpretation: 127.255.255.x is an error, never a listing.
 assert.deepEqual(E.interpretDbl(['127.0.1.4']),{status:'listed',codes:['127.0.1.4']});
 assert.equal(E.interpretDbl(['127.255.255.254']).status,'error');
 assert.equal(E.interpretDbl(['127.255.255.252','127.0.1.2']).status,'error');
 assert.equal(E.interpretDbl(['10.0.0.1']).status,'error');
 const nx=async()=>{const e=new Error('nx');e.code='ENOTFOUND';throw e;};
 assert.equal((await E.queryDbl('ok.example','abcdefghijklmnopqrstuvwxyz',nx)).status,'not_listed');
 let queried='';
 await E.queryDbl('bad.example','abcdefghijklmnopqrstuvwxyz',async n=>{queried=n;return ['127.0.1.2'];});
 assert.equal(queried,'bad.example.abcdefghijklmnopqrstuvwxyz.dbl.dq.spamhaus.net');
 assert.equal((await E.queryDbl('x.example','bad key!',nx)).reason,'invalid_dqs_key_format');
 // RDAP and URLhaus parsing.
 const now=Date.parse('2026-11-14T12:00:00Z');
 assert.deepEqual(E.interpretRdap({events:[{eventAction:'registration',eventDate:'2026-11-04T00:00:00Z'}]},now),{status:'known',registeredAt:'2026-11-04',ageDays:10});
 assert.equal(E.interpretRdap({events:[]}).status,'unknown');
 assert.equal(E.interpretRdap({ldhName:'MY.ID',events:[{eventAction:'registration',eventDate:'2013-01-01T00:00:00Z'}]},now,'sample.my.id').status,'unknown');
 assert.equal(E.interpretUrlhaus({query_status:'ok',url_count:'3'}).status,'listed');
 assert.equal(E.interpretUrlhaus({query_status:'no_results'}).status,'not_listed');
 assert.equal(E.interpretUrlhaus({query_status:'unknown_auth_key'}).status,'error');
 // Full enrich run with stubs; keys absent => URLhaus/Spamhaus inactive.
 const calls=[];
 const fetchImpl=async(url,opts)=>{calls.push(String(url));
  if(String(url).startsWith('https://rdap.org/domain/')){const d=decodeURIComponent(String(url).split('/').pop());return {ok:true,status:200,text:async()=>JSON.stringify({events:[{eventAction:'registration',eventDate:d.startsWith('young')?'2026-11-10T00:00:00Z':'2015-01-01T00:00:00Z'}]})};}
  if(String(url).includes('urlhaus')){assert.equal(opts.headers['Auth-Key'],'synthetic-key');return {ok:true,status:200,text:async()=>JSON.stringify(opts.body.includes('malware.example')?{query_status:'ok',url_count:2}:{query_status:'no_results'})};}
  throw new Error('unexpected '+url);};
 const messages=[{mailbox:'Gmail',messageId:'s1',fromAddress:'billing@young-shop.example',displayName:'PayPal Billing',text:'',urls:['https://malware.example/file','https://old.example/a']}];
 const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'esf-data-'));
 const base={now,fetchImpl,persist:false,cache:{schemaVersion:1,entries:{}}};
 const inactive=await E.enrich({messages},{...base,env:{},resolve4:nx});
 assert.equal(inactive.sources.spamhausDbl,'inactive_no_SPAMHAUS_DQS_KEY');
 assert.equal(inactive.sources.urlhaus,'inactive_no_URLHAUS_AUTH_KEY');
 assert.equal(inactive.domains['young-shop.example'].registration.ageDays,4);
 assert.equal(inactive.domains['young-shop.example'].dbl,undefined);
 assert.ok(calls.every(c=>!c.includes('urlhaus')),'no URLhaus call without key');
 assert.ok(calls.every(c=>!c.includes('billing')),'addresses are never sent');
 const env={SPAMHAUS_DQS_KEY:'abcdefghijklmnopqrstuvwxyz',URLHAUS_AUTH_KEY:'synthetic-key',EMAILCONTROL_DATA_DIR:dataDir};
 const full=await E.enrich({messages,recordContacts:false},{...base,env,resolve4:async n=>n.startsWith('young-shop.example.')?['127.0.1.2']:(()=>{const e=new Error();e.code='ENOTFOUND';throw e;})()});
 assert.equal(full.domains['young-shop.example'].dbl.status,'listed');
 assert.equal(full.hosts['malware.example'].urlhaus.status,'listed');
 assert.equal(full.senders['young-shop.example'].firstContact,true);
 // Recording contacts stores only salted hashes.
 await E.enrich({messages,recordContacts:true},{...base,env,persist:true,offline:true});
 const stored=fs.readFileSync(path.join(dataDir,'contact-history.json'),'utf8');
 assert.ok(!stored.includes('young-shop'),'no plain domain stored');
 const again=await E.enrich({messages},{...base,env,offline:true});
 assert.equal(again.senders['young-shop.example'].firstContact,false);
 // Analyzer with enrichment on the real rules.
 const set=runtimeRuleSet(require('../rules/filter-rules.json'));
 const ids=(msg,enrichment)=>analyze({messages:[{mailbox:'Gmail',messageId:'s',text:'',urls:[],...msg}],...set,...(enrichment?{enrichment}:{})},loadedCache()).messages[0].configuredSignalMatches.map(m=>m.ruleId);
 const hit=ids(messages[0],full);
 for(const id of ['domain.newly-registered.v1','link.urlhaus-listed.v1','domain.spamhaus-dbl.v1','identity.first-contact-brand-claim.v1'])assert.ok(hit.includes(id),id);
 const none=ids(messages[0]);
 for(const id of ['domain.newly-registered.v1','link.urlhaus-listed.v1','domain.spamhaus-dbl.v1','identity.first-contact-brand-claim.v1'])assert.ok(!none.includes(id),'inactive without enrichment: '+id);
 assert.ok(!ids(messages[0],{...full,senders:{'young-shop.example':{firstContact:false}}}).includes('identity.first-contact-brand-claim.v1'));
 // Attachment evaluators (metadata only).
 assert.ok(ids({attachments:[{filename:'Invoice.html',mime:'text/html'}],text:'See attached'}).includes('attachment.html-smuggling-or-qr.v1'));
 assert.ok(ids({attachments:[{filename:'scan.png',mime:'image/png'}],text:'Scan the code'}).includes('attachment.qr-image-bait.v1'));
 assert.ok(!ids({attachments:[{filename:'scan.png',mime:'image/png'}],text:'x'.repeat(300)}).includes('attachment.qr-image-bait.v1'));
 assert.ok(ids({attachments:[{filename:'archive.zip',mime:'application/zip'}]}).includes('attachment.unexpected-html-zip-iso.v1'));
 assert.ok(ids({fromAddress:'events@host.example',attachments:[{filename:'invite.ics',mime:'text/calendar'}],urls:['https://login.other.example/x']}).includes('attachment.ics-invite-lure.v1'));
 assert.ok(!ids({fromAddress:'events@host.example',attachments:[{filename:'invite.ics',mime:'text/calendar'}],urls:['https://meet.google.com/abc']}).includes('attachment.ics-invite-lure.v1'));
 assert.ok(!ids({attachments:[{filename:'report.pdf',mime:'application/pdf'}],text:'Here is the quarterly report you asked for, with the figures discussed in our meeting. '.repeat(3)}).includes('attachment.qr-image-bait.v1'));
 fs.rmSync(dataDir,{recursive:true,force:true});
 console.log('Enrichment (RDAP, URLhaus, Spamhaus DBL error codes, inactive without keys, hashed first contact) and attachment evaluators passed.');
})().catch(e=>{console.error(e);process.exit(1);});

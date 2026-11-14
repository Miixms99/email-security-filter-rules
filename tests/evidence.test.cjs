'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {canonical,digest,analyzerDigest,verifyEvidence}=require('../scripts/verify-evidence.cjs');
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
const rule={id:'synthetic.evidence.v1',status:'candidate',category:'campaign_correlation',privateDataExcluded:true,indicators:{markers:['synthetic-campaign'],exactPaths:['/synthetic/campaign']}};
const cases=[true,true,true,false,false,false].map((expectedMatch,i)=>({provider:i%2?'Outlook':'Gmail',expectedMatch,sourceDigest:digest({fictionalSource:i}),independentGroup:'group-'+i,text:expectedMatch?'synthetic-campaign':'ordinary document',urls:['https://example.com/synthetic/campaign']}));
function sign(cs=cases,changes={}){const manifest={schemaVersion:1,audience:'email-security-filter-rules',ruleDigest:digest(rule),analyzerDigest:analyzerDigest(),casesDigest:digest(cs),issuedAt:1000,expiresAt:10000,synthetic:true,...changes};return {manifest,cases:cs,signature:crypto.sign(null,Buffer.from(canonical(manifest)),privateKey).toString('base64')};}
const options={now:2000,allowSynthetic:true};let passed=0;
assert.equal(verifyEvidence(rule,sign(),publicKey,options).verified,true);passed++;
function rejects(fn){assert.throws(fn);passed++;}
rejects(()=>verifyEvidence(rule,sign(),publicKey,{now:2000}));
rejects(()=>verifyEvidence(rule,sign(),null,options));
rejects(()=>verifyEvidence({...rule,id:'changed'},sign(),publicKey,options));
rejects(()=>verifyEvidence(rule,sign(cases,{analyzerDigest:'forged'}),publicKey,options));
rejects(()=>verifyEvidence(rule,sign(),publicKey,{...options,now:20000}));
const altered=sign();altered.cases[0]={...altered.cases[0],text:'changed'};
rejects(()=>verifyEvidence(rule,altered,publicKey,options));
const duplicate=structuredClone(cases);duplicate[1].sourceDigest=duplicate[0].sourceDigest;
rejects(()=>verifyEvidence(rule,sign(duplicate),publicKey,options));
const correlated=structuredClone(cases);correlated.forEach(c=>c.independentGroup='group-same');
rejects(()=>verifyEvidence(rule,sign(correlated),publicKey,options));
rejects(()=>verifyEvidence(rule,sign(cases.slice(0,3)),publicKey,options));
const bad=structuredClone(cases);bad[3].text='synthetic-campaign';
rejects(()=>verifyEvidence(rule,sign(bad),publicKey,options));
const other=crypto.generateKeyPairSync('ed25519');
rejects(()=>verifyEvidence(rule,sign(),other.publicKey,options));
const {prepare}=require('../scripts/prepare-publication.cjs');
const document=require('../rules/filter-rules.json');
const next=prepare(document,{rule,bundle:sign()},{publicKey,now:2000,allowSynthetic:true});
assert.equal(next.rules.at(-1).status,'signal_only');passed++;
rejects(()=>prepare(document,{rule,bundle:sign()},{publicKey,now:2000}));
rejects(()=>prepare(document,{rule,review:{ruleSpecificTestsPassed:true}},{publicKey,now:2000}));
console.log(JSON.stringify({passed,failed:0,syntheticOnly:true,privateKeyPersisted:false,productionAuthorized:false}));


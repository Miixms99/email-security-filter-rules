'use strict';
const assert=require('node:assert/strict');
const {prepare}=require('../scripts/prepare-publication.cjs');
const {digest,canonical}=require('../scripts/chat-review.cjs');
assert.equal(canonical({b:1,a:[{d:2,c:3}]}),canonical({a:[{c:3,d:2}],b:1}));
assert.notEqual(digest({a:1}),digest({a:2}));
const doc=require('../rules/filter-rules.json');
const rule={id:'synthetic.chat.v1',status:'candidate',category:'campaign_correlation',privateDataExcluded:true,indicators:{markers:['synthetic-campaign'],exactPaths:['/synthetic/campaign']}};
const cases=[true,true,true,false,false,false].map((expectedMatch,i)=>({provider:i%2?'Gmail':'Outlook',observationRef:'obs-'+String(i).padStart(32,'0'),reviewedGroup:'group-'+i,expectedMatch,text:expectedMatch?'synthetic-campaign':'ordinary document',urls:['https://example.com/synthetic/campaign']}));
const review={mode:'active_chat_review',ruleDigest:digest(rule),privacyReviewed:true,rationale:'Fictional campaign with three reviewed groups and legitimate counterexamples.',cases};
const before=JSON.stringify(doc);
assert.equal(prepare(doc,{rule,review}).rules.at(-1).status,'signal_only');
assert.equal(JSON.stringify(doc),before);
for(const submission of [null,{}, {rule,review:{ruleSpecificTestsPassed:true}}, {rule:{...rule,id:'changed'},review}, {rule,review:{...review,cases:[cases[0],cases[0],...cases.slice(2)]}}, {rule,review:{...review,cases:cases.map(c=>({...c,reviewedGroup:'group-same'}))}}, {rule,review:{...review,cases:cases.map(c=>({...c,text:'synthetic-campaign'}))}}])assert.throws(()=>prepare(doc,submission));
console.log('Chat-reviewed publication: valid case and seven rejection cases passed; source unchanged.');


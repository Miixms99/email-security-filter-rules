'use strict';
const assert=require('node:assert/strict');
const {discover,runtimeRules}=require('../scripts/rule-learning.cjs');
const observations=['Gmail','Outlook','Gmail'].map((provider,i)=>({observationRef:'obs-'+String(i).padStart(32,'0'),provider,marker:'synthetic-campaign',exactPath:'/synthetic/campaign',verdict:'confirmed_suspicious',publicSafeReviewed:true}));
assert.equal(discover([observations[0],observations[0],observations[0]]).length,0);
assert.throws(()=>discover([observations[0],{...observations[0],provider:'Outlook'}]));
assert.equal(discover(observations.slice(0,2)).length,0);
const candidates=discover(observations);assert.equal(candidates.length,1);
assert.equal(candidates[0].publicationEligible,false);
assert.equal(discover([...observations,{...observations[0],observationRef:'obs-'+ 'f'.repeat(32),verdict:'legitimate'}]).length,0);
assert.throws(()=>discover([{...observations[0],publicSafeReviewed:false}]));
assert.throws(()=>discover([{...observations[0],marker:'private@example.com'}]));
const doc={schemaVersion:'1.0.0',privacy:{privateDataAllowed:false},activationPolicy:{automaticMailboxActions:false},rules:candidates};
assert.equal(runtimeRules(doc).length,0);
doc.rules[0].status='signal_only';assert.equal(runtimeRules(doc).length,1);
doc.rules[0].status='disabled';assert.equal(runtimeRules(doc).length,0);
console.log('Candidate discovery, privacy input guards, counterexamples and status gating passed.');


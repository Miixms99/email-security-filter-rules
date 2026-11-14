'use strict';
const assert=require('node:assert/strict');
const {prepare}=require('../scripts/prepare-publication.cjs');
const doc=require('../rules/filter-rules.json');
const before=JSON.stringify(doc);
for(const input of [null,{}, {rule:{publicationEligible:true,evidence:{independence:'verified'}},review:{privacyReviewed:true,independentEvidenceReviewed:true,legitimateCounterexamplesReviewed:true,ruleSpecificTestsPassed:true}}]){
 assert.throws(()=>prepare(doc,input),/Automatic publication disabled/);
 assert.equal(JSON.stringify(doc),before);
}
console.log('Publication fails closed with forged review assertions; source unchanged.');


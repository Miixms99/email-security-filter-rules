'use strict';
const assert=require('node:assert/strict');
const {prepare}=require('../scripts/prepare-publication.cjs');
const doc=require('../rules/filter-rules.json');
const submission={rule:{id:'synthetic.publication.v1',status:'candidate',category:'campaign_correlation',privateDataExcluded:true,indicators:{markers:['synthetic-marker'],exactPaths:['/synthetic/path']}},review:{privacyReviewed:true,independentEvidenceReviewed:true,legitimateCounterexamplesReviewed:true,ruleSpecificTestsPassed:true}};
const before=JSON.stringify(doc),next=prepare(doc,submission);
assert.equal(JSON.stringify(doc),before);
assert.equal(next.rules.at(-1).status,'signal_only');
for(const key of Object.keys(submission.review))assert.throws(()=>prepare(doc,{...submission,review:{...submission.review,[key]:false}}));
assert.throws(()=>prepare(next,submission));
assert.throws(()=>prepare(doc,{...submission,rule:{...submission.rule,indicators:{markers:['private@example.com'],exactPaths:['/synthetic/path']}}}));
console.log('Publication gate: positive path, four missing-review gates, duplicates, privacy syntax and immutable source passed.');


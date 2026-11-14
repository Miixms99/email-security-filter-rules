'use strict';
const {normalizeCampaignRules}=require('./Controle-Email.cjs');
function prepare(document,submission){
 const {rule,review}=submission;
 if(!review||review.privacyReviewed!==true||review.independentEvidenceReviewed!==true||review.legitimateCounterexamplesReviewed!==true||review.ruleSpecificTestsPassed!==true)throw Error('Publication evidence incomplete');
 if(!rule||rule.privateDataExcluded!==true||rule.category!=='campaign_correlation'||rule.status!=='candidate')throw Error('Invalid candidate');
 const {markers=[],exactPaths=[]}=rule.indicators||{};
 if(markers.length!==1||exactPaths.length!==1||!/^[a-z][a-z-]{2,60}$/.test(markers[0])||!/^\/[a-z/-]{3,100}$/.test(exactPaths[0]))throw Error('Unsupported public abstraction');
 normalizeCampaignRules([{id:rule.id,markers,exactPaths}]);
 if(document.rules.some(r=>r.id===rule.id))throw Error('Duplicate rule');
 const next=structuredClone(document);
 next.rules.push({id:rule.id,status:'signal_only',category:'campaign_correlation',indicators:{markers,exactPaths},requiredCombination:'Reviewed marker and exact path together.',verdictEffect:'Review signal only; no automatic mailbox actions.',privateDataExcluded:true});
 next.filterRevision=document.filterRevision+'.'+rule.id.replace(/[^a-z0-9]/gi,'').slice(-16);
 delete next.generatedAt;
 return next;
}
module.exports={prepare};
if(require.main===module){
 const fs=require('node:fs');
 const submission=JSON.parse(process.env.RULE_SUBMISSION||'null');
 const file='rules/filter-rules.json';
 fs.writeFileSync(file,JSON.stringify(prepare(JSON.parse(fs.readFileSync(file,'utf8')),submission),null,2)+'\n');
}


'use strict';
const {analyze}=require('./Controle-Email.cjs');
const {digest}=require('./verify-evidence.cjs');
function verifyChatReview(rule,review){
 if(!review||review.mode!=='active_chat_review'||review.ruleDigest!==digest(rule)||review.privacyReviewed!==true||typeof review.rationale!=='string'||review.rationale.trim().length<20)throw Error('Active chat assessment required');
 if(!Array.isArray(review.cases)||review.cases.length<6||review.cases.length>100)throw Error('At least six test cases required');
 const refs=new Set(),groups=new Set(),providers=new Set();let positive=0,negative=0;
 for(const c of review.cases){
  if(!c||!/^obs-[a-f0-9]{32}$/.test(c.observationRef)||refs.has(c.observationRef))throw Error('Unique observation references required');
  refs.add(c.observationRef);
  if(!['Gmail','Outlook'].includes(c.provider)||typeof c.expectedMatch!=='boolean'||typeof c.text!=='string'||!Array.isArray(c.urls))throw Error('Invalid case');
  providers.add(c.provider);
  const found=analyze({messages:[{mailbox:c.provider,messageId:'review-test',text:c.text,urls:c.urls}],campaignRules:[{id:rule.id,...rule.indicators}]}).messages[0].configuredCampaignMatches.length>0;
  if(found!==c.expectedMatch)throw Error('Rule-specific counterexample test failed');
  if(c.expectedMatch){if(!/^group-[a-z0-9-]{1,64}$/.test(c.reviewedGroup))throw Error('Reviewed evidence group required');groups.add(c.reviewedGroup);positive++;}else negative++;
 }
 if(positive<3||negative<3||groups.size<3||providers.size!==2)throw Error('Insufficient reviewed coverage');
 return {positive,negative,independence:'assessed_by_chat_not_independently_verified'};
}
module.exports={verifyChatReview};


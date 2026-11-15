'use strict';
// Operates only on reviewed, public-safe abstractions, never raw mail.
const crypto=require('node:crypto');
function discover(observations){
 if(!Array.isArray(observations)||observations.length>1000)throw Error('Invalid observations');
 const groups=new Map(), seen=new Map();
 for(const o of observations){
  if(o.publicSafeReviewed!==true||!['Gmail','Outlook'].includes(o.provider)||!['confirmed_suspicious','legitimate'].includes(o.verdict))throw Error('Reviewed provenance required');
  if(!/^[a-z][a-z-]{2,60}$/.test(o.marker)||!/^\/[a-z/-]{3,100}$/.test(o.exactPath))throw Error('Only abstract alphabetic markers and paths allowed');
  if(typeof o.observationRef!=='string'||!/^obs-[a-f0-9]{32}$/.test(o.observationRef))throw Error('Opaque observation reference required');
  const canonical=JSON.stringify([o.provider,o.marker,o.exactPath,o.verdict]);
  if(seen.has(o.observationRef)){
   if(seen.get(o.observationRef)!==canonical)throw Error('Conflicting duplicate observation');
   continue;
  }
  seen.set(o.observationRef,canonical);
  const key=JSON.stringify([o.marker,o.exactPath]);
  const g=groups.get(key)||{marker:o.marker,exactPath:o.exactPath,suspicious:0,legitimate:0,providers:new Set()};
  g[o.verdict==='legitimate'?'legitimate':'suspicious']++;g.providers.add(o.provider);groups.set(key,g);
 }
 return [...groups.values()].filter(g=>g.suspicious>=3&&g.legitimate===0).map(g=>({
  id:'candidate.'+crypto.createHash('sha256').update(g.marker+'\n'+g.exactPath).digest('hex').slice(0,16),
  status:'candidate',category:'campaign_correlation',indicators:{markers:[g.marker],exactPaths:[g.exactPath]},
  requiredCombination:'Reviewed marker and exact path in the same message.',verdictEffect:'Review signal only.',privateDataExcluded:true,
  evidence:{observations:g.suspicious,providers:[...g.providers].sort(),independence:'not_verified'},
  publicationEligible:false
 }));
}
function assertRuntimeDocument(document){
 if(document?.schemaVersion!=='1.0.0'||document.privacy?.privateDataAllowed!==false||document.activationPolicy?.automaticMailboxActions!==false||!Array.isArray(document.rules))throw Error('Unsafe rule document');
}
const enabled=r=>['active','signal_only'].includes(r.status);
// Routes a rule to the analyzer input that can evaluate it, by indicator shape:
// campaign = marker/URL parameter plus exact path; sender = exact sender domains
// or an anchored sender-address shape; everything else = generic signal rule.
function classifyRule(r){
 const i=r.indicators||{};
 const has=k=>Array.isArray(i[k])&&i[k].length>0;
 if(has('exactPaths')&&(has('markers')||has('urlParameters')))return 'campaign';
 if(has('senderDomains')||(i.senderAddressRegex&&typeof i.senderAddressRegex==='object')||(i.variantSenderAddressRegex&&typeof i.variantSenderAddressRegex==='object')||(Array.isArray(i.senderAddressRegexes)&&i.senderAddressRegexes.length))return 'sender';
 return 'signal';
}
function runtimeRuleSet(document){
 assertRuntimeDocument(document);
 const set={campaignRules:[],senderRules:[],signalRules:[]};
 for(const r of document.rules.filter(enabled)){
  const kind=classifyRule(r),i=r.indicators||{};
  if(kind==='campaign')set.campaignRules.push({id:r.id,markers:i.markers||[],urlParameters:i.urlParameters||[],exactPaths:i.exactPaths,...(i.hosts?{hosts:i.hosts}:{})});
  else if(kind==='sender')set.senderRules.push({id:r.id,severity:r.severity,weight:r.weight,...(i.senderDomains?{senderDomains:i.senderDomains}:{}),...(i.senderAddressRegex?{senderAddressRegex:i.senderAddressRegex}:{}),...(i.variantSenderAddressRegex?{variantSenderAddressRegex:i.variantSenderAddressRegex}:{}),...(Array.isArray(i.senderAddressRegexes)&&i.senderAddressRegexes.length?{senderAddressRegexes:i.senderAddressRegexes}:{})});
  else set.signalRules.push({id:r.id,category:r.category,severity:r.severity,weight:r.weight,...(r.evaluator?{evaluator:r.evaluator}:{}),indicators:i});
 }
 return set;
}
// Backwards compatible: only the campaign rules the marker/path matcher accepts.
function runtimeRules(document){return runtimeRuleSet(document).campaignRules;}
module.exports={discover,runtimeRules,runtimeRuleSet,classifyRule};


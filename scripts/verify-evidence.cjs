'use strict';
const crypto=require('node:crypto');
const fs=require('node:fs');
const {analyze}=require('./Controle-Email.cjs');
function canonical(v){if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';if(v&&typeof v==='object')return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';return JSON.stringify(v);}
const digest=v=>crypto.createHash('sha256').update(canonical(v)).digest('hex');
const analyzerDigest=()=>crypto.createHash('sha256').update(fs.readFileSync(require.resolve('./Controle-Email.cjs'))).digest('hex');
function verifyEvidence(rule,bundle,trustedPublicKey,{now=Date.now(),allowSynthetic=false}={}){
 if(!trustedPublicKey)throw Error('No trusted evidence authority configured');
 if(!bundle||!bundle.manifest||typeof bundle.signature!=='string')throw Error('Signed manifest required');
 const m=bundle.manifest;
 if(!crypto.verify(null,Buffer.from(canonical(m)),trustedPublicKey,Buffer.from(bundle.signature,'base64')))throw Error('Invalid evidence signature');
 if(m.schemaVersion!==1||m.audience!=='email-security-filter-rules'||m.ruleDigest!==digest(rule)||m.analyzerDigest!==analyzerDigest()||m.casesDigest!==digest(bundle.cases))throw Error('Evidence binding mismatch');
 if(!Number.isFinite(m.issuedAt)||!Number.isFinite(m.expiresAt)||m.issuedAt>now||m.expiresAt<=now||m.expiresAt-m.issuedAt>86400000)throw Error('Expired or invalid evidence time');
 if(typeof m.synthetic!=='boolean'||(m.synthetic&&!allowSynthetic))throw Error('Synthetic evidence cannot authorize production');
 if(!Array.isArray(bundle.cases)||bundle.cases.length>100)throw Error('Invalid evidence cases');
 const sources=new Set(),groups=new Set(),providers=new Set();let positives=0,negatives=0;
 const candidate={id:rule.id,...rule.indicators};
 for(const c of bundle.cases){
  if(!['Gmail','Outlook'].includes(c.provider)||typeof c.expectedMatch!=='boolean'||!Array.isArray(c.urls)||typeof c.text!=='string')throw Error('Invalid case');
  if(!/^[a-f0-9]{64}$/.test(c.sourceDigest)||!/^group-[a-z0-9-]{1,64}$/.test(c.independentGroup))throw Error('Missing source provenance');
  if(sources.has(c.sourceDigest))throw Error('Duplicate source evidence');sources.add(c.sourceDigest);
  const matches=analyze({messages:[{mailbox:c.provider,messageId:'verification',text:c.text,urls:c.urls}],campaignRules:[candidate]}).messages[0].configuredCampaignMatches.length>0;
  if(matches!==c.expectedMatch)throw Error('Rule-specific test failed');
  providers.add(c.provider);
  if(c.expectedMatch){positives++;groups.add(c.independentGroup);}else negatives++;
 }
 if(positives<3||groups.size<3||negatives<3||providers.size!==2)throw Error('Insufficient independent evidence or counterexamples');
 return {verified:true,synthetic:m.synthetic,ruleDigest:m.ruleDigest,positiveCases:positives,negativeCases:negatives};
}
module.exports={canonical,digest,analyzerDigest,verifyEvidence};


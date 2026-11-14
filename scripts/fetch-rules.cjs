'use strict';
const {runtimeRules}=require('./rule-learning.cjs');
const URL='https://raw.githubusercontent.com/miixmss/email-security-filter-rules/main/rules/filter-rules.json';
async function fetchRules(){
 const response=await fetch(URL,{redirect:'error',signal:AbortSignal.timeout(10000)});
 if(!response.ok)throw Error('Central rules unavailable: '+response.status);
 const text=await response.text();if(text.length>262144)throw Error('Rule document too large');
 const document=JSON.parse(text);return {filterRevision:document.filterRevision,campaignRules:runtimeRules(document)};
}
if(require.main===module)fetchRules().then(r=>console.log(JSON.stringify(r))).catch(e=>{console.error(e.message);process.exitCode=1;});
module.exports={fetchRules};


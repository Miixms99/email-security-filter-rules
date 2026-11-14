'use strict';
// Fetches the central public rules (or reads the repository copy with --local),
// validates them like CI does, and prints analyzer-ready rule sets as JSON.
const fs=require('node:fs');
const path=require('node:path');
const {runtimeRuleSet}=require('./rule-learning.cjs');
const {validateDocument}=require('./validate-rules.cjs');
const URL='https://raw.githubusercontent.com/miixmss/email-security-filter-rules/main/rules/filter-rules.json';
const ROOT=path.resolve(__dirname,'..');
function toRuleSet(document){
 validateDocument(document,JSON.parse(fs.readFileSync(path.join(ROOT,'rules/filter-rules.schema.json'),'utf8')));
 return {filterRevision:document.filterRevision,...runtimeRuleSet(document)};
}
async function fetchRules(){
 const response=await fetch(URL,{redirect:'error',signal:AbortSignal.timeout(10000)});
 if(!response.ok)throw Error('Central rules unavailable: '+response.status);
 const text=await response.text();if(text.length>262144)throw Error('Rule document too large');
 return toRuleSet(JSON.parse(text));
}
function localRules(){return toRuleSet(JSON.parse(fs.readFileSync(path.join(ROOT,'rules/filter-rules.json'),'utf8')));}
if(require.main===module){
 const args=process.argv.slice(2);
 if(args.some(a=>a!=='--local'))throw Error('Usage: node scripts/fetch-rules.cjs [--local]');
 Promise.resolve(args.includes('--local')?localRules():fetchRules()).then(r=>console.log(JSON.stringify(r))).catch(e=>{console.error(e.message);process.exitCode=1;});
}
module.exports={fetchRules,localRules,toRuleSet};

'use strict';
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const path = require('node:path');
const helper = path.resolve(__dirname,'../scripts/Controle-Email.cjs');
const rule={id:'synthetic.sync.v1',markers:['SYNTHETIC-SYNC-ONLY'],exactPaths:['/synthetic-sync-only']};
let checks=0;
function run(mailbox,text,url,rules){
 const child=spawnSync(process.execPath,[helper,'--analyze'],{input:JSON.stringify({messages:[{mailbox,messageId:'synthetic',text,urls:[url]}],campaignRules:rules}),encoding:'utf8'});
 assert.equal(child.status,0,child.stderr);
 return JSON.parse(child.stdout).messages[0].configuredCampaignMatches.length;
}
for(const provider of ['Gmail','Outlook']){
 const cases=[
  [[], 'SYNTHETIC-SYNC-ONLY','https://example.com/synthetic-sync-only',0],
  [[rule],'SYNTHETIC-SYNC-ONLY','https://example.com/synthetic-sync-only',1],
  [[rule],'ordinary message','https://example.com/synthetic-sync-only',0],
  [[rule],'SYNTHETIC-SYNC-ONLY','https://example.com/ordinary-document',0],
  [[rule],'SYNTHETIC-SYNC-ONLY','https://example.com/synthetic-sync-only.bak',0],
  [[], 'SYNTHETIC-SYNC-ONLY','https://example.com/synthetic-sync-only',0]
 ];
 for(const [rules,text,url,expected] of cases){assert.equal(run(provider,text,url,rules),expected);checks++;}
}
console.log(JSON.stringify({passed:checks,failed:0,providers:['Gmail','Outlook'],freshProcesses:checks,scope:'Explicit runtime rule injection and rollback; not independent ChatGPT chats or automatic discovery/publication',mailboxActions:0}));


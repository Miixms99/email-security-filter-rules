'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const helper = require('../scripts/Controle-Email.cjs');
const rules = require('../rules/filter-rules.json');
assert.equal(rules.activationPolicy.automaticMailboxActions, false);
assert.equal(rules.privacy.privateDataAllowed, false);
assert.equal(new Set(rules.rules.map(r=>r.id)).size,rules.rules.length);
for(const r of rules.rules) {
 assert.ok(['candidate','signal_only','active','disabled'].includes(r.status));
 assert.equal(r.privateDataExcluded,true);
}
const result=helper.selfTest();
assert.equal(result.failed,0);
assert.equal(result.networkRequests,0);
assert.equal(result.privateDataWrites,0);
JSON.parse(fs.readFileSync('plugin/plugin.json','utf8'));
console.log('Project policy and offline detection tests passed.');


// Documentation and plugin metadata must match the code and rules.
const plugin=JSON.parse(fs.readFileSync('plugin/plugin.json','utf8'));
const skill=fs.readFileSync('plugin/skills/email-security-review/SKILL.md','utf8');
assert.ok(skill.includes('**Code version:** `'+plugin.version+'`'),'skill code version matches plugin.json');
assert.ok(skill.includes('**Bundled filter revision:** `'+rules.filterRevision+'`'),'skill filter revision matches rules');
const readme=fs.readFileSync('README.md','utf8');
assert.ok(readme.includes('revision '+rules.filterRevision),'README names the current filter revision');
for(const r of rules.rules)assert.ok(readme.includes('`'+r.id+'`'),'README lists '+r.id);
console.log('Plugin version, skill revision and README rule table are consistent.');

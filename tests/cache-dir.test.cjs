'use strict';
// Portable public-source cache location and containment checks (no network).
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {defaultCacheDir,assertStorage}=require('../scripts/Controle-Email.cjs');
assert.equal(defaultCacheDir('linux',{XDG_CACHE_HOME:'/xdg'},'/home/u'),path.join('/xdg','email-security'));
assert.equal(defaultCacheDir('linux',{},'/home/u'),path.join('/home/u','.cache','email-security'));
assert.equal(defaultCacheDir('linux',{XDG_CACHE_HOME:'relative'},'/home/u'),path.join('/home/u','.cache','email-security'));
assert.equal(defaultCacheDir('win32',{},'C:\\Users\\u'),path.resolve(__dirname,'../scripts'));
// Windows default keeps the fixed D: requirement; an explicit override may differ.
assert.throws(()=>assertStorage('C:\\tools\\scripts\\cache.json','C:\\tools\\scripts',{platform:'win32',explicit:false}),/D:/);
assert.ok(assertStorage('D:\\tools\\scripts\\cache.json','D:\\tools\\scripts',{platform:'win32',explicit:false}));
assert.ok(assertStorage('C:\\cache\\cache.json','C:\\cache',{platform:'win32',explicit:true}));
assert.throws(()=>assertStorage('D:\\other\\cache.json','D:\\tools',{platform:'win32',explicit:false}));
// Linux containment, traversal and symlink escape.
const root=fs.mkdtempSync(path.join(os.tmpdir(),'esf-cache-'));
const outside=fs.mkdtempSync(path.join(os.tmpdir(),'esf-outside-'));
assert.ok(assertStorage(path.join(root,'publieke-bronnen.json'),root,{platform:process.platform,explicit:true}));
assert.throws(()=>assertStorage(path.join(root,'..','escape.json'),root,{platform:process.platform,explicit:true}));
assert.throws(()=>assertStorage('cache.json','relative-root',{platform:process.platform,explicit:true}));
if(process.platform!=='win32'){
 fs.symlinkSync(outside,path.join(root,'link'));
 assert.throws(()=>assertStorage(path.join(root,'link','x.json'),root,{platform:process.platform,explicit:true}),/Symbolic link/);
}
// The CLI status works on this platform with an explicit cache dir (no network).
const helper=path.resolve(__dirname,'../scripts/Controle-Email.cjs');
const child=spawnSync(process.execPath,[helper,'--status'],{encoding:'utf8',env:{...process.env,ESF_CACHE_DIR:fs.mkdtempSync(path.join(os.tmpdir(),'esf-status-'))}});
assert.equal(child.status,0,child.stderr);
assert.equal(JSON.parse(child.stdout).sources.cache,'unavailable');
fs.rmSync(root,{recursive:true,force:true});fs.rmSync(outside,{recursive:true,force:true});
console.log('Cache directory: XDG/home defaults, Windows D: default, traversal and symlink refusal, CLI status passed.');

'use strict';
// Shared synthetic fixtures: example domains only, no real mail, addresses or IDs.
const crypto=require('node:crypto');
const {SOURCES,parsePsl}=require('../../scripts/Controle-Email.cjs');
const PSL='// ===BEGIN ICANN DOMAINS===\ncom\nnet\norg\nbiz\nid\nbiz.id\nmy.id\nexample\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\nblogspot.com\n// ===END PRIVATE DOMAINS===\n';
function record(name,text,count){const now=new Date().toISOString();return {sourceUrl:SOURCES[name].url,text,sha256:crypto.createHash('sha256').update(text).digest('hex'),count,retrievedAt:now,validatedAt:now,publishedAt:null,etag:null,lastModified:null};}
function loadedCache(extra={}){
 const psl=parsePsl(PSL);
 return {status:'loaded',cache:{schemaVersion:1,sources:{psl:record('psl',PSL,psl.count),...extra}}};
}
module.exports={PSL,record,loadedCache};

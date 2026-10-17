'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { authorizedFileGrants, resolveAuthorizedFileGrants } = require('./b1Grants');

const owner='user-123', tenant='tenant-one';
const req = () => ({ user:{id:owner,tenantId:tenant} });
const file=(name,id,kind='user',rid=owner) => ({
  user:owner,tenantId:tenant,filename:name,bytes:64,
  metadata:{workspaceFileAttachment:kind==='project',
    codeEnvRef:{kind,id:rid,storage_session_id:'ul-file-bucket',file_id:id}},
});
const ref=(record) => ({
  kind:record.metadata.codeEnvRef.kind,resource_id:record.metadata.codeEnvRef.id,
  storage_session_id:record.metadata.codeEnvRef.storage_session_id,
  id:record.metadata.codeEnvRef.file_id,name:record.filename,
});
const a=file('proposal.docx','f-docx'),b=file('agreement.pdf','f-pdf'),c=file('budget.xlsx','f-xlsx');
function grants(files=[a,b,c],request=req()) {
 return authorizedFileGrants({req:request,sessionFiles:files.map(ref),dbFiles:files});
}
test('Personal DOCX PDF XLSX grants are exact DB provenance matches',()=>{
 const got=grants();
 assert.equal(got.length,3);
 assert.deepEqual(got.map(g=>g.name),['proposal.docx','agreement.pdf','budget.xlsx']);
 assert.equal(Object.isFrozen(got),true);
 assert.deepEqual(Object.keys(got[0]).sort(),['bytes','file_id','kind','name','owner','session_id']);
});
test('authorized Project attached PDF requires bound project context and attachment marker',()=>{
 const reqProject=req();reqProject.workspaceContext={kind:'project',workspaceId:'project-ok'};
 const record=file('report.pdf','f-project','project','project-ok');
 assert.equal(grants([record],reqProject)[0].owner,'project-ok');
 assert.throws(()=>grants([record],req()),/UNVERIFIED/);
 assert.throws(()=>grants([{...record,metadata:{...record.metadata,workspaceFileAttachment:false}}],reqProject),/UNVERIFIED/);
});
test('Personal source allowed in authenticated Project conversation when user-owned',()=>{
 const pr=req();pr.workspaceContext={kind:'project',workspaceId:'project-ok'};
 assert.equal(grants([a],pr)[0].kind,'user');
});
test('mismatched user/tenant/resource/session and filename all fail closed',()=>{
 for(const changed of [
   {...a,user:'foreign'}, {...a,tenantId:'other'},
   {...a,metadata:{codeEnvRef:{...a.metadata.codeEnvRef,id:'other'},workspaceFileAttachment:false}},
   {...a,metadata:{codeEnvRef:{...a.metadata.codeEnvRef,storage_session_id:'ul-other'},workspaceFileAttachment:false}},
   {...a,filename:'other.docx'}
 ]) assert.throws(()=>authorizedFileGrants({req:req(),sessionFiles:[ref(a)],dbFiles:[changed]}),/UNVERIFIED/);
});
test('reject model forged ref, missing DB, ambiguous duplicates and bad extension',()=>{
 assert.throws(()=>authorizedFileGrants({req:req(),sessionFiles:[{...ref(a),id:'f-forged'}],dbFiles:[a]}),/UNVERIFIED/);
 assert.throws(()=>authorizedFileGrants({req:req(),sessionFiles:[ref(a)],dbFiles:[]}),/UNVERIFIED/);
 assert.throws(()=>authorizedFileGrants({req:req(),sessionFiles:[ref(a)],dbFiles:[a,a]}),/UNVERIFIED/);
 const csv=file('other.csv','f-csv');
 assert.throws(()=>grants([csv]),/UNVERIFIED/);
});
test('oversized, zero-byte and too-many inputs cannot be signed',()=>{
 assert.throws(()=>grants([{...a,bytes:0}]),/UNVERIFIED/);
 assert.throws(()=>grants([{...a,bytes:25*1024*1024+1}]),/UNVERIFIED/);
 assert.throws(()=>authorizedFileGrants({req:req(),sessionFiles:Array.from({length:21},()=>ref(a)),dbFiles:[a]}),/UNVERIFIED/);
});
test('backend helper performs read-only bounded per-ref query and verifies results', async ()=>{
 const session={get:()=>({files:[ref(a)]})};let seen;
 const out=await resolveAuthorizedFileGrants({req:req(),initialSessions:session,getFiles:async query=>{
  seen=query;return [a];
 },hashFile:async()=> 'a'.repeat(64)});
 assert.deepEqual(seen,{user:owner,'metadata.codeEnvRef.file_id':{$in:['f-docx']}});
 assert.equal(out.length,1);
 assert.equal(out[0].sha256,'a'.repeat(64));
});
test('no imported refs does not query DB or manufacture file grants',async()=>{
 const out=await resolveAuthorizedFileGrants({req:req(),initialSessions:new Map(),getFiles:async()=>{throw Error('UNSAFE')}});
 assert.deepEqual(out,[]);
});
test('DB unavailable for actual refs fails closed',async()=>{
 await assert.rejects(resolveAuthorizedFileGrants({req:req(),
  initialSessions:{get:()=>({files:[ref(a)]})}}),/DB_UNAVAILABLE/);
});
test('unhashable, altered, or invalid-digest file source never becomes a signed grant',async()=>{
 const session={get:()=>({files:[ref(a)]})};
 for(const badHash of [undefined,'short','G'.repeat(64)]){
  await assert.rejects(resolveAuthorizedFileGrants({req:req(),initialSessions:session,
   getFiles:async()=>[a],hashFile:async()=>{
    if(badHash===undefined) throw Error('source unavailable');
    return badHash;
   }}));
 }
});

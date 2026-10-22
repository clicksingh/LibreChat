'use strict';
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const h=require('../trust/harness.cjs');
const W=h.WORKTREE;
const srcDir=path.join(W,'api/server/services/Device');
const pins=Object.freeze({
 'authorityService.js':'539BE58694FB42213263BF1164818ACA3C39BE57977E289FEA5D6CAB68F2C248',
 'registrationService.js':'140AB38B68D3CA9208ED4EB0E2DF839DD9671FA328F14A47483875D675C40D2C',
 'pairingSessionService.js':'D6484C3B6FFB5A25089F44FCB8C7A688F704497A71C98A1E2ABDBD9C9B59933A'
});
function digest(p){return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex').toUpperCase();}
function hashGate(){return Object.fromEntries(Object.entries(pins).map(([n,v])=>[n,{expected:v,actual:digest(path.join(srcDir,n))}]));}
const init=hashGate();
if(!Object.values(init).every(x=>x.expected===x.actual))throw Error('F5_PREIMAGE_MISMATCH');
const tag='f5test-'+crypto.randomBytes(4).toString('hex');
const outDir=path.join(W,'tests/device/_phase1_evidence/w3b-r2/t3-f5-principal',tag);
fs.mkdirSync(outDir,{recursive:true});
const results=[];
function safeErr(v){return v?.error ? {code:v.error.code||null,httpStatus:v.error.httpStatus||null}:null;}
const probes=[
 {id:'F5-01',name:'caller-admin-role-must-not-retire',
  seed:ctx=>({ownerId:ctx.OWNER_A}),
  args:ctx=>({tenantId:ctx.TENANT,deviceId:'f5-01-device',actor:ctx.OWNER_B,role:'admin'}),
  defect:r=>r.matched===1&&r.changed&&r.calls>0},
 {id:'F5-02',name:'forged-actor-must-not-override-trusted-owner',
  seed:ctx=>({ownerId:ctx.OWNER_A}),
  args:ctx=>({tenantId:ctx.TENANT,deviceId:'f5-02-device',
    principal:{kind:'owner',principalId:ctx.OWNER_B,tenantId:ctx.TENANT,sessionRef:'server-session'},
    actor:ctx.OWNER_A,role:'owner'}),
  defect:r=>r.matched===1&&r.changed&&r.calls>0},
 {id:'F5-03',name:'trusted-owner-only-form-not-supported-yet',
  seed:ctx=>({ownerId:ctx.OWNER_A}),
  args:ctx=>({tenantId:ctx.TENANT,deviceId:'f5-03-device',
    principal:{kind:'owner',principalId:ctx.OWNER_A,tenantId:ctx.TENANT,sessionRef:'server-session'}}),
  defect:r=>r.matched===0&&r.error?.code==='NOT_OWNER'&&r.changed===false},
 {id:'F5-04',name:'admin-zero-match-must-have-error',
  seed:ctx=>({ownerId:ctx.OWNER_A,identityState:'retired',retiredAt:new Date('2026-10-01T00:00:00Z')}),
  args:ctx=>({tenantId:ctx.TENANT,deviceId:'f5-04-device',actor:ctx.OWNER_B,role:'admin'}),
  defect:r=>r.matched===0&&r.error===null&&r.changed===false},
 {id:'F1-05',name:'retire-must-bump-epoch-even-if-lease-not-active',
  seed:ctx=>({ownerId:ctx.OWNER_A,epoch:4,leaseState:'never'}),
  args:ctx=>({tenantId:ctx.TENANT,deviceId:'f1-05-device',actor:ctx.OWNER_A,role:'owner'}),
  defect:r=>r.matched===1&&r.changed&&r.epochAfter===r.epochBefore}
];
async function executeProbe(def){
 return h.withRowDb(def.id.toLowerCase()+'-'+tag, async ctx=>{
   const deviceId=def.id.toLowerCase()+'-device';
   await ctx.seedAuthority({_id:deviceId,...def.seed(ctx)});
   const before=await ctx.rawDocView('deviceauthorities',{_id:deviceId});
   const mark=ctx.counter.mark();
   const svc=ctx.composeAuthority({tenantContext:ctx.tenantContextFor(false)});
   const result=await ctx.als.tenantStorage.run({tenantId:ctx.TENANT},async()=>
     svc.retireIdentity(def.args(ctx)));
   const calls=ctx.countsSince(mark,['DeviceAuthority','Challenge']);
   const after=await ctx.rawDocView('deviceauthorities',{_id:deviceId});
   return {
     matched:result?.matched??null,
     error:safeErr(result),
     responseOk:result?.ok===true,
     calls:calls.total,
     changed:!h.sameDoc(before,after),
     epochBefore:before?.epoch??null,epochAfter:after?.epoch??null,
     stateBefore:before?.identityState??null,stateAfter:after?.identityState??null,
     retiredBy:after?.retiredBy??null,
     source:'genuine Model.create + real ALS + real Mongo',
   };
 });
}
async function main(){
 const namespaceBefore=await h.fence.listDatabaseNames();
 const fatal=[];
 for(const def of probes){
   try{
     const result=await executeProbe(def);
     const observation=result.outcome;
     const reproduced=def.defect(observation);
     const entry={id:def.id,name:def.name,classification:reproduced?'EXPECTED_RED':'NOT_REPRODUCED',
      reproduced,observation,dbName:result.dbName,dropped:result.dropped?.dropped===true};
     results.push(entry);
     fs.writeFileSync(path.join(outDir,def.id+'.json'),JSON.stringify(entry,null,2)+'\n');
     console.log(def.id+' '+entry.classification+' matched='+observation.matched+' calls='+observation.calls);
   }catch(e){fatal.push({id:def.id,error:String(e)});console.log(def.id+' HARNESS_FAIL '+e.message);}
 }
 const namespaceAfter=await h.fence.listDatabaseNames();
 const integrity=hashGate();
 const sourceClean=Object.values(integrity).every(x=>x.expected===x.actual);
 const sameNames=JSON.stringify(namespaceBefore.slice().sort())===JSON.stringify(namespaceAfter.slice().sort());
 const leftovers=namespaceAfter.filter(x=>x.startsWith('cbhr_rdc_phase1_r2_t2f4_')&&!namespaceBefore.includes(x));
 const passed=results.length===probes.length&&results.every(x=>x.reproduced&&x.dropped)&&fatal.length===0&&sourceClean&&sameNames&&leftovers.length===0;
 const receipt={schema:'cbhr-rdc/f5-test-first/v1',runId:tag,commission:'PHASE1-LOCAL-AUTHORITY-001',
    historicalExpectedRed:probes.length,observedRed:results.filter(x=>x.reproduced).length,
    passed,rows:results,fatal,integrity,namespace:{sameNames,leftovers,before:namespaceBefore,after:namespaceAfter},
    note:'Failing-before observations only; neither F5 nor F1 is repaired here. No production writes.'};
 fs.writeFileSync(path.join(outDir,'F5-LEDGER.json'),JSON.stringify(receipt,null,2)+'\n');
 console.log('F5_PROBE_FINAL '+JSON.stringify({passed,rows:results.length,red:receipt.observedRed,
   fatal:fatal.length,sourceClean,sameNames,leftovers}));
 process.exitCode=passed?0:2;
}
main().catch(e=>{console.error('F5_PROBE_FATAL',e.stack||e);process.exitCode=2;});

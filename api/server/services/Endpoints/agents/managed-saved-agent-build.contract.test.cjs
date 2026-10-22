'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const root=path.join(__dirname,'../../..');
const enforceSource=fs.readFileSync(path.join(__dirname,'../../../middleware/enforceManagedChatEndpoint.js'),'utf8');
const policy={module:{exports:{}},require(name){
 if(name==='@librechat/data-schemas')return {logger:{info(){},error(){}}};
 if(name==='librechat-data-provider')return {
  Constants:{EPHEMERAL_AGENT_ID:'ephemeral'},SystemRoles:{ADMIN:'ADMIN',USER:'USER'},
  EModelEndpoint:{custom:'custom'},isAgentsEndpoint:v=>v==='agents',
  isEphemeralAgentId:v=>v==='ephemeral',
 };
 throw Error('Unknown policy import '+name);
}};
vm.runInNewContext(enforceSource,policy);
const source=fs.readFileSync(path.join(__dirname,'build.js'),'utf8');
const holder={current:null};
const logs=[];
const scope={module:{exports:{}},require(name){
 if(name==='@librechat/data-schemas')return {logger:{error(...x){logs.push(x)}}};
 if(name==='@librechat/api')return {loadAgent:async()=>holder.current};
 if(name==='librechat-data-provider')return {
  isAgentsEndpoint:v=>v==='agents',removeNullishValues:v=>v,Constants:{EPHEMERAL_AGENT_ID:'ephemeral'}
 };
 if(name==='~/server/services/Config')return {getMCPServerTools(){}};
 if(name==='~/models')return {getAgent(){}};
 if(name==='~/server/middleware/enforceManagedChatEndpoint')return policy.module.exports;
 throw Error('Unknown agent build import '+name);
}};
vm.runInNewContext(source,scope);
const {buildOptions}=scope.module.exports;
const approved={id:'agent_ok',endpoint:'Open Model Service',model:'manufacturer:model-5'};
const base=()=>({id:approved.id,provider:approved.endpoint,model:approved.model,
 model_parameters:{model:approved.model,temperature:0.5,reasoning_effort:'extreme',
 thinkingBudget:9999,reasoning_mode:'pro'}});
async function run(auth,agent){holder.current=agent;const req={body:{},managedSavedAgentAuth:auth};
 const result=buildOptions(req,'agents',{agent_id:'agent_ok',model:'ignored'},'agents');
 return await result.agent;
}
test('matching saved-agent request uses stored record without extra reasoning override',async()=>{
 const agent=base();const result=await run(approved,agent);
 assert.equal(result.model,approved.model);
 assert.equal(result.model_parameters.temperature,0.5);
 for(const key of ['reasoning_effort','thinkingBudget','reasoning_mode'])
  assert.equal(Object.hasOwn(result.model_parameters,key),false);
 assert.equal(agent.model_parameters.reasoning_effort,'extreme','DB record untouched');
});
test('second read of changed model is denied',async()=>{
 const result=await run(approved,{...base(),model:'another-model'});
 assert.equal(result,undefined);
});
test('second read of changed multi-agent graph is denied',async()=>{
 const result=await run(approved,{...base(),edges:[{target:'secret'}]});
 assert.equal(result,undefined);
});
test('unmanaged admin agent is unchanged',async()=>{
 const agent=base();
 const result=await run(undefined,agent);
 assert.equal(result,agent);
 assert.equal(result.model_parameters.reasoning_effort,'extreme');
});

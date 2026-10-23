'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'enforceManagedChatEndpoint.js'),'utf8');
const sandbox={
 module:{exports:{}},
 require(n){
  if(n==='@librechat/data-schemas')return {logger:{info(){},error(){}}};
  if(n==='librechat-data-provider')return {
   Constants:{EPHEMERAL_AGENT_ID:'ephemeral'},EModelEndpoint:{custom:'custom'},
   SystemRoles:{USER:'USER',ADMIN:'ADMIN'},
   isAgentsEndpoint:x=>x==='agents',isEphemeralAgentId:x=>x==='ephemeral',
  };
  throw Error('UNEXPECTED_IMPORT_'+n);
 }};
vm.runInNewContext(source,sandbox,{filename:'enforceManagedChatEndpoint.js'});
const {enforceManagedChatEndpoint,resolveFundedDefault}=sandbox.module.exports;
function cfg(model='v2/omega',old='v1/alpha'){
 return {modelSpecs:{list:[{name:'company-default',default:true,preset:{endpoint:'CBHR AI',model:old}}]},
 endpoints:{custom:[{name:'CBHR AI',apiKey:'server-side-key',baseURL:'http://aibridge:4103/v1',
 models:{default:model?[model,'v3/beta']:[]}}]}};
}
function check(body,config=cfg(),role='USER'){
 let status=null,called=false;
 const req={user:{id:'u1',role},config,body:{...body}};
 const res={status(n){status=n;return this;},json(){}};
 enforceManagedChatEndpoint(req,res,()=>{called=true});
 return {body:req.body,status,called};
}
test('admin selected model applies without matching YAML or provider slug',()=>{
 const x=check({endpoint:'stale',model:'v1/alpha',text:'hello'});
 assert.equal(x.called,true);assert.equal(x.body.model,'v2/omega');
 assert.equal(x.body.endpoint,'CBHR AI');
});
test('after switching provider, user enforced model switches automatically',()=>{
 const x=check({model:'v2/omega'},cfg('future-adapter/model-gamma'));
 assert.equal(x.body.model,'future-adapter/model-gamma');
});
test('ordinary user cannot send a forged model effort override',()=>{
 const x=check({endpoint:'CBHR AI',model:'v2/omega',reasoning_effort:'xhigh',
   thinkingBudget:999999,thinking:{level:'high'},text:'hello'});
 assert.equal(x.called,true);
 for(const key of ['reasoning_effort','thinkingBudget','thinking'])
   assert.equal(Object.hasOwn(x.body,key),false);
 const admin=check({reasoning_effort:'xhigh'},cfg(),'ADMIN');
 assert.equal(admin.body.reasoning_effort,'xhigh');
});
test('empty or invalid effective default refuses operation',()=>{
 for(const m of ['',null,'<invalid>']) {
  const x=check({model:'v1/alpha'},cfg(m));
  assert.equal(x.called,false);assert.equal(x.status,503);
 }
});
test('saved agent is deferred until AFTER the resource VIEW ACL',()=>{
 const x=check({endpoint:'agents',agent_id:'saved-agent',model:'other-model'},cfg(),'USER');
 assert.equal(x.called,true);
 assert.equal(x.body.agent_id,'saved-agent');
});
test('multi-conversation model graph is refused before generation',()=>{
 const x=check({endpoint:'agents',agent_id:'ephemeral',
 addedConvo:{endpoint:'agents',agent_id:'secret-agent'}});
 assert.equal(x.called,false);assert.equal(x.status,403);
});
test('non-admin custom roles inherit the same staff model and effort policy',()=>{
 const x=check({endpoint:'untrusted',model:'unauthorized',reasoning_effort:'xhigh'},cfg(),'E2E_NOCODE');
 assert.equal(x.called,true);
 assert.equal(x.body.model,'v2/omega');
 assert.equal(Object.hasOwn(x.body,'reasoning_effort'),false);
});
test('configured funded endpoint is not tied to a fixed brand name',()=>{
 const alternate=cfg();
 alternate.modelSpecs.list[0].preset.endpoint='Studio Engine';
 alternate.endpoints.custom[0].name='Studio Engine';
 const x=check({endpoint:'old',model:'v1/alpha'},alternate);
 assert.equal(x.called,true);assert.equal(x.body.endpoint,'Studio Engine');
});
test('admin selection untouched',()=>{
 const x=check({endpoint:'external',model:'some-model'},cfg(), 'ADMIN');
 assert.equal(x.body.model,'some-model');assert.equal(x.called,true);
});

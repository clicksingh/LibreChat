'use strict';
const assert=require('node:assert/strict'),test=require('node:test');
const fs=require('node:fs'),vm=require('node:vm');
const ts=require('typescript'),path=require('node:path');
const file=path.join(__dirname,'modelReasoningControls.ts');
const js=ts.transpileModule(fs.readFileSync(file,'utf8'),{
 compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}
}).outputText;
const scope={module:{exports:{}},exports:{}};
scope.exports=scope.module.exports;
vm.runInNewContext(js,scope,{filename:'modelReasoningControls.js'});
const fn=scope.module.exports.resolveModelReasoningControls;
const base=[{key:'temperature',component:'slider'},{key:'reasoning_effort',component:'slider',options:['hardcoded-one','hardcoded-two']}];
const profile={
 modelA:{transport:'chat.completions.reasoning_effort',options:['quick','thorough'],default:'quick'},
 modelB:{transport:'chat.completions.reasoning_effort',options:['brief','profound'],default:'profound'},
};
test('ordinary staff sees no configurable reasoning',()=>{
 const out=fn(base,profile,'modelA',false);
 assert.equal(out.some(x=>x.key==='reasoning_effort'),false);
});
test('admin sees only model-specific options, not global generic slider',()=>{
 for(const [name,expected] of [['modelA',['quick','thorough']],['modelB',['brief','profound']]]){
  const out=fn(base,profile,name,true);
  const ctl=out.find(x=>x.key==='reasoning_effort');
  assert.equal(ctl.component,'dropdown');
  assert.deepEqual(Array.from(ctl.options),expected);
 }
});
test('unsupported models do not display fake effort options',()=>{
 const out=fn(base,profile,'unlisted-model',true);
 assert.equal(out.some(x=>x.key==='reasoning_effort'),false);
});
test('unmanaged admin endpoints preserve native parameter settings',()=>{
 const out=fn(base,undefined,'arbitrary',true);
 assert.deepEqual(Array.from(out),base);
});

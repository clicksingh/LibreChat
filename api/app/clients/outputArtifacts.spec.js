const {latestAttachments,missingFinalArtifactResponse}=require('./outputArtifacts');
describe('Durable agent deliverables',()=>{
 it('persists one latest revision per file_id even across many tool calls',()=>{
  const result=latestAttachments([
   {file_id:'doc',filename:'Manual.docx',bytes:100,status:'pending'},
   {file_id:'pdf',filename:'Manual.pdf',bytes:200},
   {file_id:'doc',filename:'Manual.docx',bytes:120,toolCallId:'new-doc'},
   {file_id:'pdf',filename:'Manual.pdf',bytes:220,toolCallId:'new-pdf'},
   {file_id:'doc',filename:'Manual.docx',bytes:130,toolCallId:'final-doc'},
  ]);
  expect(result).toHaveLength(2);
  expect(result[0]).toMatchObject({file_id:'doc',bytes:130,toolCallId:'final-doc'});
  expect(result[1]).toMatchObject({file_id:'pdf',bytes:220,toolCallId:'new-pdf'});
 });
 it('does not dedupe unrelated attachments or hide memory artifacts',()=>{
  expect(latestAttachments([{type:'memory',note:'one'},{type:'memory',note:'two'},null]))
   .toEqual([{type:'memory',note:'one'},{type:'memory',note:'two'}]);
 });
 it('never fabricates prose if the agent answered or lacks output documents',()=>{
  const answered={text:'I have finished.',attachments:[{file_id:'x',filename:'a.docx'}]};
  expect(missingFinalArtifactResponse(answered)).toBe(false);
  expect(answered.text).toBe('I have finished.');
  const blank={text:'',attachments:[{file_id:'t',filename:'trace.log'}]};
  expect(missingFinalArtifactResponse(blank)).toBe(false);
 });
 it('adds only a truthful review instruction to an otherwise blank delivered file response',()=>{
  const msg={text:'',attachments:[{file_id:'x',filename:'Manual.docx',bytes:125}]};
  expect(missingFinalArtifactResponse(msg)).toBe(true);
  expect(msg.text).toMatch(/review/);
  expect(msg.text).not.toMatch(/approved|complete and verified/i);
 });
});

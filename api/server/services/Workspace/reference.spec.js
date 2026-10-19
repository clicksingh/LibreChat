const mockList = jest.fn();
const mockRead = jest.fn();
const mockMembership = jest.fn();
jest.mock('./proxy', () => ({
  listFiles:(...a)=>mockList(...a),
  readWorkspaceFile:(...a)=>mockRead(...a),
}));
jest.mock('~/server/services/Endpoints/agents/authorization',()=>({
  resolveWorkspaceContextExplicit:(...a)=>mockMembership(...a),
}));
jest.mock('~/models',()=>({getConvo:jest.fn()}));
const {readWorkspaceRefStream}=require('./reference');
const req={user:{id:'owner',role:'USER',tenantId:'tenant'}};
const file={path:'sid/fid',sessionId:'sid',fileId:'fid',name:'Doc.docx',size:6,role:'output'};
beforeEach(()=>{
 jest.clearAllMocks();
 mockList.mockResolvedValue({items:[file],nextCursor:null});
 mockRead.mockResolvedValue(Buffer.from('abc123'));
 mockMembership.mockResolvedValue({kind:'project',workspaceId:'proj'});
});
async function bytesOf(stream){
 const chunks=[];for await(const part of stream)chunks.push(part);return Buffer.concat(chunks);
}
it('reuses the owner original, zero persisted copy, readable byte stream',async()=>{
 const stream=await readWorkspaceRefStream(req,'cbhrwsref://user/owner/sid/fid');
 expect(await bytesOf(stream)).toEqual(Buffer.from('abc123'));
 expect(mockList).toHaveBeenCalledWith(req,'user',undefined,undefined,500);
 expect(mockRead).toHaveBeenCalledTimes(1);
});
it('refuses cross-account refs without any provider calls',async()=>{
 await expect(readWorkspaceRefStream(req,'cbhrwsref://user/other/sid/fid')).rejects.toMatchObject({status:403});
 expect(mockList).not.toHaveBeenCalled();expect(mockRead).not.toHaveBeenCalled();
});
it('revalidates project membership on every access, not only at attach time',async()=>{
 mockMembership.mockRejectedValue(Object.assign(new Error('revoked'),{status:403}));
 await expect(readWorkspaceRefStream(req,'cbhrwsref://project/proj/sid/fid')).rejects.toMatchObject({status:403});
 expect(mockRead).not.toHaveBeenCalled();
 mockMembership.mockResolvedValue({kind:'project',workspaceId:'proj'});
 const stream=await readWorkspaceRefStream(req,'cbhrwsref://project/proj/sid/fid');
 expect(await bytesOf(stream)).toEqual(Buffer.from('abc123'));
 expect(req.workspaceContext).toEqual({kind:'project',workspaceId:'proj'});
});
it('rejects deleted, tampered, malformed, or changed references',async()=>{
 for(const p of ['cbhrwsref://user/owner/../fid','cbhrwsref://user/owner/sid/../../etc']){
  await expect(readWorkspaceRefStream(req,p)).rejects.toMatchObject({status:403});
 }
 await expect(readWorkspaceRefStream(req,'/uploads/a')).rejects.toMatchObject({status:403});
 mockList.mockResolvedValue({items:[],nextCursor:null});
 await expect(readWorkspaceRefStream(req,'cbhrwsref://user/owner/sid/fid')).rejects.toMatchObject({status:404});
 mockList.mockResolvedValue({items:[file],nextCursor:null});
 mockRead.mockResolvedValue(Buffer.from('wrong size'));
 await expect(readWorkspaceRefStream(req,'cbhrwsref://user/owner/sid/fid')).rejects.toMatchObject({status:409});
});

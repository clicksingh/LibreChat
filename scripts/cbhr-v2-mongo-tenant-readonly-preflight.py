#!/usr/bin/env python3
"""Read-only Mongo readiness evidence. Never supplies or infers tenant identity."""
import json
import subprocess
import sys

JS = r'''
const C=db.getSiblingDB('LibreChat');
const names=C.getCollectionNames();
const roles=C.configs.find({principalType:'role'}, {principalId:1,tenantId:1,isActive:1}).toArray();
const indexes=C.configs.getIndexes();
const tenantIndex=indexes.some(x=>x.unique===true&&JSON.stringify(x.key)==='{"principalType":1,"principalId":1,"tenantId":1}');
const ids=['__base__','USER','ADMIN'];
const hist={};for(const id of ids)hist[id]=roles.filter(x=>x.principalId===id).length;
const result={mongoVersion:db.version(),replicaSet:db.hello().setName||null,
roleCounts:hist,roleTotal:roles.length,
roleTenants:roles.map(x=>({id:x.principalId,tenantId:x.tenantId||null,active:x.isActive!==false})),
nonRoleConfigs:C.configs.countDocuments({principalType:{$ne:'role'}}),
usersTotal:C.users.countDocuments({}),usersWithTenant:C.users.countDocuments({tenantId:{$exists:true}}),
tenantUniqueIndex:tenantIndex,
canonicalHeads: names.includes('modelpolicyheads')?C.modelpolicyheads.countDocuments({}):null,
canonicalRevisions: names.includes('modelpolicyrevisions')?C.modelpolicyrevisions.countDocuments({}):null};
print('CBHR_TENANT_PREFLIGHT_JSON='+JSON.stringify(result));
'''

def main():
    output = subprocess.check_output(['docker','exec','chat-mongodb','mongosh',
        '--quiet','LibreChat','--eval',JS],text=True,timeout=25)
    markers=[x for x in output.splitlines() if x.startswith('CBHR_TENANT_PREFLIGHT_JSON=')]
    if len(markers)!=1: raise RuntimeError('Could not parse readonly Mongo inventory')
    data=json.loads(markers[0].split('=',1)[1])
    blockers=[]
    if data['replicaSet'] is None: blockers.append('Production MongoDB is standalone: no transaction support')
    if not data['tenantUniqueIndex']: blockers.append('Tenant-scoped unique Config index not established')
    if data['roleTotal'] != 3 or any(data['roleCounts'].get(x)!=1 for x in ('__base__','USER','ADMIN')):
        blockers.append('Expected exactly one of each managed role; source drift')
    if any(x['tenantId'] is None for x in data['roleTenants']):
        blockers.append('Legacy role Configs have no tenant binding')
    # User tenancy is informational: the existing getApplicableConfigs lookup selects
    # __base__ and caller principals, not tenantId; this release migrates role Configs.
    if data['nonRoleConfigs'] != 0:
        blockers.append('Non-role Configs require independent conflict audit')
    if data['canonicalHeads'] is not None or data['canonicalRevisions'] is not None:
        blockers.append('Canonical policy collections already exist; reconcile existing revisions')
    blockers.append('Authoritative tenant identity and service binding not proven by database state')
    data['blockers']=blockers
    data['status']='BLOCKED' if blockers else 'OBSERVATION_PASS'
    print('CBHR_V2_PRODUCTION_TENANT_READONLY_AUDIT')
    print(json.dumps(data,indent=2,sort_keys=True))
    print('No database writes, migration, restart or credential export performed')
    return 2 if blockers else 0

if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as exc:
        print('CBHR_V2_TENANT_AUDIT_FAILED:',str(exc),file=sys.stderr)
        sys.exit(3)

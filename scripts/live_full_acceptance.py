"""Opt-in v0.3 acceptance on owned resources; no existing VM/host/storage power changes."""
import argparse
import asyncio
import base64
import hashlib
import json
import time
import uuid
from pathlib import Path
from file_client import call, session, wait

def stable_vms(value):
    return sorted([{key:vm.get(key) for key in ('vm_id','name','instance_uuid','power_state','cpu','memory_mb')}
                   for vm in value['vms']], key=lambda vm:vm['vm_id'])

async def main(args):
    if not args.execute:
        raise SystemExit('Use --execute only on a host authorized for disposable resource acceptance')
    run=uuid.uuid4().hex[:10]
    checks=[]
    output=Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    def record(name, **fields):
        checks.append({'check':name, 'status':'PASS', **fields})
        output.write_text(json.dumps({'status':'RUNNING','run':run,'checks':checks},indent=2))
    async with session(args.transport) as client:
        async def task(value):
            if value.get('task_id'):
                deadline=time.monotonic()+180
                while time.monotonic()<deadline:
                    current=await call(client,'esxi_get_task',{'task_id':value['task_id']})
                    if current['state']=='success':
                        return current
                    if current['state']=='error':
                        raise RuntimeError('Disposable task failed: '+str(current))
                    await asyncio.sleep(1)
                raise TimeoutError('Task outcome uncertain; inspect before cleanup')
            return value
        capabilities=await call(client,'esxi_capabilities')
        managers=await call(client,'esxi_managers')
        expected_host=managers['host']['name']
        # host.name may differ from connection address; caller must supply the configured target.
        if args.expected_host:
            expected_host=args.expected_host
        record('discover_capabilities_and_dependencies', api_version=capabilities['api_version'])
        await call(client,'esxi_dependencies')
        for domain in capabilities['domains']:
            await call(client,'esxi_resource_schema',{'domain':domain})
        record('all_dedicated_resource_catalogs')
        before=stable_vms(await call(client,'esxi_list_vms'))
        netref=managers['host_managers']['networkSystem']
        before_network=(await call(client,'esxi_api_get',{'target':netref,'properties':['networkConfig'],'max_items':1000}))['properties']['networkConfig']
        stores=(await call(client,'esxi_list_datastores'))['datastores']
        datastore=args.datastore or max((item for item in stores if item['accessible']),key=lambda item:item['free_mb'])['name']
        switch, pg, failed_pg='mcp-full-vs-'+run, 'mcp-full-pg-'+run, 'mcp-comp-pg-'+run
        filename='mcp-full-file-'+run+'.bin'
        vmname, imported_name='mcp-ovf-source-'+run, 'mcp-ovf-import-'+run
        existing_ids={vm['vm_id'] for vm in before}
        owned_vms=[]
        switch_created=pg_created=file_started=False
        failure=None
        async def network(action,arguments,request_id=None):
            spec={'action':action,'arguments':arguments,'expected_host':expected_host,'allow_disruption':True}
            if request_id:
                spec['request_id']=request_id
            await call(client,'esxi_network_manage',spec)
            return await task(await call(client,'esxi_network_manage',{**spec,'dry_run':False}))
        try:
            rid='switch-'+run
            await network('switch_create',{'vswitchName':switch,'spec':{'numPorts':128}},rid)
            switch_created=True
            assert (await network('switch_create',{'vswitchName':switch,'spec':{'numPorts':128}},rid))['replayed']
            record('dedicated_switch_create_and_request_id_replay')
            await network('portgroup_create',{'portgrp':{'name':pg,'vlanId':123,'vswitchName':switch,'policy':{}}})
            pg_created=True
            await network('portgroup_update',{'pgName':pg,'portgrp':{'name':pg,'vlanId':124,'vswitchName':switch,'policy':{}}})
            record('dedicated_portgroup_create_update')
            steps=[{'tool':'esxi_network_manage','arguments':{'action':'portgroup_create','arguments':{
                'portgrp':{'name':failed_pg,'vlanId':0,'vswitchName':switch,'policy':{}}},'expected_host':expected_host,'allow_disruption':True},
                'compensate':{'tool':'esxi_network_manage','arguments':{'action':'portgroup_remove','arguments':{'pgName':failed_pg},
                    'expected_host':expected_host,'allow_disruption':True}}},
                {'tool':'esxi_network_manage','arguments':{'action':'switch_remove','arguments':{'vswitchName':'mcp-absent-'+run},
                    'expected_host':expected_host,'allow_disruption':True}}]
            job=await call(client,'esxi_execute_plan',{'steps':steps,'rollback_on_failure':True,'dry_run':False})
            deadline=time.monotonic()+180
            while time.monotonic()<deadline:
                outcome=await call(client,'esxi_operation_status',{'operation_id':job['operation_id']})
                if outcome['status']=='needs_review':
                    break
                await asyncio.sleep(1)
            assert outcome['status']=='needs_review' and outcome['compensation'][0]['status']=='completed'
            record('explicit_compensation_after_deliberate_owned_workflow_failure')
            payload=(b'ESXi MCP full acceptance\n'*600000)[:12*1024**2]
            digest=hashlib.sha256(payload).hexdigest()
            stage=await call(client,'esxi_stage_upload',{'filename':filename,'total_bytes':len(payload),'expected_sha256':digest,'dry_run':False})
            for offset in range(0,len(payload),1024**2):
                await call(client,'esxi_stage_write_chunk',{'job_id':stage['job_id'],'offset':offset,
                    'data_base64':base64.b64encode(payload[offset:offset+1024**2]).decode(),'dry_run':False})
            await call(client,'esxi_stage_finalize',{'job_id':stage['job_id'],'dry_run':False})
            file_started=True
            job=await call(client,'esxi_transfer_start',{'kind':'datastore','operation':'upload','datastore':datastore,'path':filename,
                'source_job_id':stage['job_id'],'max_bytes':len(payload),'expected_sha256':digest,'dry_run':False})
            await wait(client,job['job_id'],transfer=True)
            job=await call(client,'esxi_transfer_start',{'kind':'datastore','operation':'download','datastore':datastore,'path':filename,
                'max_bytes':len(payload),'expected_sha256':digest,'dry_run':False})
            downloaded=await wait(client,job['job_id'],transfer=True)
            assert downloaded['sha256']==digest and downloaded['bytes']==len(payload)
            record('greater_than_8MiB_staged_upload_background_download_sha256',bytes=len(payload))
            await task(await call(client,'esxi_create_vm',{'name':vmname,'cpu':1,'memory_mb':256,'disk_gb':1,
                'datastore':datastore,'network':pg,'guest_id':'otherLinux64Guest','dry_run':False}))
            owned=next(vm for vm in (await call(client,'esxi_list_vms'))['vms'] if vm['name']==vmname)
            assert owned['vm_id'] not in existing_ids
            owned_vms.append(owned)
            job=await call(client,'esxi_ovf_export',{'vm_id':owned['vm_id'],'expected_name':vmname,'dry_run':False})
            exported=await wait(client,job['operation_id'])
            ovf=next(item for item in exported['files'] if item['filename'].endswith('.ovf'))
            descriptor=base64.b64decode((await call(client,'esxi_transfer_read_chunk',{'job_id':ovf['job_id']}))['data_base64']).decode()
            from esxi_mcp.workflows import validate_ovf
            references=validate_ovf(descriptor)
            disks={item['filename']:{'source_job_id':item['job_id'],'expected_sha256':item['sha256'],'max_bytes':max(1,item['bytes'])}
                   for item in exported['files'] if item['filename'] in references}
            # The isolated source has exactly one network, but its original OVF name must be read explicitly.
            import xml.etree.ElementTree as ET
            ns='http://schemas.dmtf.org/ovf/envelope/1'
            mappings={node.get('{'+ns+'}name'):pg for node in ET.fromstring(descriptor).findall('.//{'+ns+'}Network')}
            spec={'name':imported_name,'datastore':datastore,'ovf_descriptor':descriptor,'network_mappings':mappings,
                'disks':disks,'expected_host':expected_host}
            preview=await call(client,'esxi_ovf_import',spec)
            assert not preview['warnings'], 'Inspect OVF warnings explicitly before another acceptance run'
            job=await call(client,'esxi_ovf_import',{**spec,'dry_run':False})
            result=await wait(client,job['operation_id'])
            imported=next(vm for vm in (await call(client,'esxi_list_vms'))['vms'] if vm['vm_id']==result['imported_entity']['_moId'])
            assert imported['name']==imported_name and imported['vm_id'] not in existing_ids
            owned_vms.append(imported)
            record('complete_ovf_export_import_roundtrip')
        except BaseException as error:
            failure={'error_type':type(error).__name__,'message':str(error)[:1200]}
            output.write_text(json.dumps({'status':'FAIL_CLEANUP_PENDING','run':run,'checks':checks,'failure':failure},indent=2))
        finally:
            # Re-discover only exact names from this unpredictable run to recover a create whose reply was lost.
            current=(await call(client,'esxi_list_vms'))['vms']
            for vm in current:
                if vm['name'] in (vmname,imported_name) and vm['vm_id'] not in existing_ids:
                    known=next((item for item in owned_vms if item['vm_id']==vm['vm_id']),None)
                    if known:
                        assert vm['instance_uuid']==known['instance_uuid']
                    assert vm['power_state']=='poweredOff'
                    await task(await call(client,'esxi_delete_vm',{'vm_id':vm['vm_id'],'expected_name':vm['name'],'dry_run':False}))
            if file_started:
                target=managers['service_managers']['fileManager']
                await task(await call(client,'esxi_api_invoke',{'target':target,'method':'DeleteDatastoreFile_Task',
                    'arguments':{'name':'['+datastore+'] '+filename},'expected_target':target['_type']+':'+target['_moId'],
                    'allow_disruption':True,'dry_run':False}))
            info=(await call(client,'esxi_resource_get',{'domain':'network','properties':['networkInfo']}))['properties']['networkInfo']
            for name in (failed_pg,pg):
                if any(item['spec']['name']==name for item in info['portgroup']):
                    await network('portgroup_remove',{'pgName':name})
            if switch_created:
                await network('switch_remove',{'vswitchName':switch})
            after=stable_vms(await call(client,'esxi_list_vms'))
            after_network=(await call(client,'esxi_api_get',{'target':netref,'properties':['networkConfig'],'max_items':1000}))['properties']['networkConfig']
            assert after==before and after_network==before_network
            record('owned_resources_removed_existing_vm_and_network_unchanged')
        report={'status':'FAIL' if failure else 'PASS','run':run,'checks':checks,'failure':failure,
                'cleanup_complete':True,'existing_vm_count':len(before),
                'not_executed':['host reboot/shutdown','storage formatting','management network modification',
                    'guest success without OS/Tools credentials','SSH writes']}
        output.write_text(json.dumps(report,indent=2))
        if failure:
            raise RuntimeError('Acceptance failed; inspect saved report')
        return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--transport',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--datastore')
    parser.add_argument('--expected-host',required=True)
    parser.add_argument('--execute',action='store_true')
    print(json.dumps(asyncio.run(main(parser.parse_args())),indent=2))

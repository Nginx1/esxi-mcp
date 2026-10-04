import asyncio
import base64
import json
import time
import uuid
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE = Path.cwd()
TRANSPORT = {}
STATE = BASE / 'acceptance-nfc-result.json'
NAME = 'mcp-nfc-' + uuid.uuid4().hex[:8]
checks = []
def record(check, **fields):
    checks.append({'check': check, **fields})
    STATE.write_text(json.dumps({'status': 'RUNNING', 'checks': checks}, indent=2))
def unpack(value):
    data = value.structuredContent
    if data is None:
        data = json.loads('\n'.join(item.text for item in value.content if item.type == 'text'))
    while isinstance(data, dict) and set(data) == {'result'}:
        data = data['result']
    return data
async def main():
    params = StdioServerParameters(**TRANSPORT)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            async def call(tool, args=None):
                result = await session.call_tool(tool,args or {})
                if result.isError:
                    raise RuntimeError(tool + ': ' + str(result.content))
                return unpack(result)
            async def wait(value):
                while value.get('task_id') and value['state'] in ('queued','running'):
                    await asyncio.sleep(0.5)
                    value = await call('esxi_get_task',{'task_id':value['task_id']})
                if value.get('state') == 'error':
                    raise RuntimeError(str(value))
                return value
            async def invoke(target,method,arguments=None):
                return await call('esxi_api_invoke', {'target':target,'method':method,'arguments':arguments or {},
                    'expected_target':target['_type']+':'+target['_moId'],'dry_run':False,'allow_disruption':True})
            before = (await call('esxi_list_vms'))['vms']
            ds = max((item for item in (await call('esxi_list_datastores'))['datastores'] if item['accessible']),key=lambda item:item['free_mb'])['name']
            net = (await call('esxi_list_networks'))['networks'][0]
            owned = lease = None
            failure = None
            try:
                await wait(await call('esxi_create_vm',{'name':NAME,'cpu':1,'memory_mb':256,'disk_gb':1,'datastore':ds,'network':net,'dry_run':False}))
                owned = next(vm for vm in (await call('esxi_list_vms'))['vms'] if vm['name']==NAME)
                target = {'_type':'vim.VirtualMachine','_moId':owned['vm_id']}
                record('create_owned_export_vm',status='PASS')
                value = await invoke(target,'ExportVm')
                lease = value['result']
                assert lease['_type']=='vim.HttpNfcLease'
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    state=(await call('esxi_api_get',{'target':lease,'properties':['state']}))['properties']['state']
                    if state=='ready':
                        break
                    if state=='error':
                        raise RuntimeError('NFC lease entered error state')
                    await asyncio.sleep(0.5)
                assert state=='ready'
                record('export_vm_nfc_lease_ready',status='PASS')
                info=(await call('esxi_api_get',{'target':lease,'properties':['info'],'depth':6}))['properties']['info']
                url=info['deviceUrl'][0]['url']
                download=await call('esxi_api_transfer',{'transfer_url':url,'operation':'download','lease':lease,'max_bytes':8388608,'dry_run':False})
                data=base64.b64decode(download['data_base64'])
                assert len(data)>0
                record('download_nfc_export_bytes',status='PASS',bytes=len(data),sha256=download['sha256'])
                await invoke(lease,'HttpNfcLeaseComplete')
                state=(await call('esxi_api_get',{'target':lease,'properties':['state']}))['properties']['state']
                assert state=='done'
                record('complete_nfc_lease',status='PASS')
                lease=None
            except BaseException as error:
                failure=str(error)[:1200]
                record('failure',status='FAIL',error_type=type(error).__name__,error=failure)
            finally:
                if lease is not None:
                    try:
                        await invoke(lease,'HttpNfcLeaseAbort')
                        record('abort_owned_lease',status='PASS')
                    except Exception as error:
                        record('abort_owned_lease',status='FAIL',error_type=type(error).__name__)
                if owned is not None:
                    vm=await call('esxi_get_vm',{'vm_id':owned['vm_id']})
                    assert vm['instance_uuid']==owned['instance_uuid'] and vm['name']==NAME
                    assert owned['vm_id'] not in {item['vm_id'] for item in before}
                    await wait(await call('esxi_delete_vm',{'vm_id':owned['vm_id'],'expected_name':NAME,'dry_run':False}))
                    record('cleanup_owned_export_vm',status='PASS')
                after=(await call('esxi_list_vms'))['vms']
                keys=('vm_id','instance_uuid','name','power_state','cpu','memory_mb')
                stable=lambda values:sorted([{k:vm.get(k) for k in keys} for vm in values],key=lambda vm:vm['vm_id'])
                unchanged=stable(before)==stable(after)
                record('existing_vms_unchanged',status='PASS' if unchanged else 'FAIL')
                STATE.write_text(json.dumps({'status':'PASS' if failure is None and unchanged else 'FAIL',
                    'checks':checks,'failure':failure,'cleanup_complete':True,'existing_vms_unchanged':unchanged},indent=2))
if __name__=='__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--transport', required=True, help='Private stdio command/args/env JSON')
    parser.add_argument('--output-dir', required=True, help='Private directory for acceptance evidence')
    parser.add_argument('--execute', action='store_true', help='Authorize successful writes on new disposable test resources')
    args = parser.parse_args()
    if not args.execute:
        parser.error('--execute is required; this test creates, modifies and deletes its own resources')
    TRANSPORT = json.loads(Path(args.transport).read_text(encoding='utf-8'))
    if 'mcpServers' in TRANSPORT:
        TRANSPORT = TRANSPORT['mcpServers']['esxi']
    BASE = Path(args.output_dir).resolve()
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE = BASE / 'acceptance-nfc-result.json'
    asyncio.run(main())
    result = json.loads(STATE.read_text())
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']), 'cleanup_complete': result.get('cleanup_complete')}))
    if result['status'] != 'PASS':
        raise SystemExit(1)

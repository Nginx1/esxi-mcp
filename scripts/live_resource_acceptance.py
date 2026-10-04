"""Live MCP resource tests: isolated switch/PG, owned file and disposable VM hardware."""
import asyncio
import base64
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE = Path.cwd()
TRANSPORT = {}
RUN = uuid.uuid4().hex[:8]
SWITCH = 'mcp-vs-' + RUN
PG = 'mcp-pg-' + RUN
VMNAME = 'mcp-hardware-' + RUN
FILENAME = 'mcp-file-' + RUN + '.txt'
STATE = BASE / 'acceptance-resource-result.json'
checks = []

def record(check, **fields):
    checks.append({'check': check, 'at': datetime.now(timezone.utc).isoformat(), **fields})
    STATE.write_text(json.dumps({'status': 'RUNNING', 'checks': checks}, indent=2))

def unpack(value):
    data = value.structuredContent
    if data is None:
        data = json.loads('\n'.join(item.text for item in value.content if item.type == 'text'))
    while isinstance(data, dict) and set(data) == {'result'}:
        data = data['result']
    return data

async def main():
    parameters = StdioServerParameters(**TRANSPORT)
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            async def call(tool, args=None):
                result = await session.call_tool(tool, args or {})
                if result.isError:
                    raise RuntimeError(tool + ': ' + str(result.content))
                return unpack(result)
            async def wait(value):
                if value.get('task_id'):
                    deadline = time.monotonic() + 180
                    while time.monotonic() < deadline:
                        result = await call('esxi_get_task', {'task_id': value['task_id']})
                        if result['state'] == 'success':
                            return result
                        if result['state'] == 'error':
                            raise RuntimeError(str(result))
                        await asyncio.sleep(1)
                    raise TimeoutError(str(value))
                return value
            async def invoke(target, method, arguments):
                return await wait(await call('esxi_api_invoke', {'target': target, 'method': method,
                    'arguments': arguments, 'expected_target': target['_type'] + ':' + target['_moId'],
                    'dry_run': False, 'allow_disruption': True}))
            managers = await call('esxi_managers')
            network = managers['host_managers']['networkSystem']
            file_manager = managers['service_managers']['fileManager']
            inventory = await call('esxi_inventory')
            record('discover_all_managed_entities', status='PASS', count=inventory['count'])
            record('discover_host_and_service_managers', status='PASS', host_manager_count=len(managers['host_managers']),
                   service_manager_count=len(managers['service_managers']), api_version=managers['api_version'])
            for key, properties in [('networkSystem', ['networkInfo']), ('storageSystem', ['storageDeviceInfo']),
                                    ('serviceSystem', ['serviceInfo']), ('firewallSystem', ['firewallInfo']),
                                    ('pciPassthruSystem', ['pciPassthruInfo'])]:
                if key in managers['host_managers']:
                    await call('esxi_api_get', {'target': managers['host_managers'][key], 'properties': properties})
                    record('read_' + key, status='PASS')
            await call('esxi_api_get', {'target': {k: v for k, v in managers['host'].items() if k != 'name'},
                                      'properties': ['hardware', 'capability', 'runtime']})
            record('read_host_hardware_capabilities_runtime', status='PASS')
            for type_name, method in [('vim.host.NetworkSystem','AddVirtualSwitch'), ('vim.host.DatastoreSystem','RemoveDatastore'),
                ('vim.host.ServiceSystem','StartService'), ('vim.host.PciPassthruSystem','UpdatePassthruConfig'),
                ('vim.HostSystem','RebootHost_Task'), ('vim.vm.guest.ProcessManager','StartProgramInGuest')]:
                await call('esxi_api_schema', {'type_name': type_name, 'method': method})
            record('schemas_for_network_storage_services_pci_host_and_guest', status='PASS')

            original_vms = (await call('esxi_list_vms'))['vms']
            before = (await call('esxi_api_get', {'target': network, 'properties': ['networkConfig']}))['properties']['networkConfig']
            switched = grouped = uploaded = False
            owned = None
            failure = None
            ds = max((item for item in (await call('esxi_list_datastores'))['datastores'] if item['accessible']), key=lambda item: item['free_mb'])['name']
            ds_ref = next(item for item in (await call('esxi_inventory', {'resource_type': 'vim.Datastore'}))['items'] if item['name'] == ds)
            ds_ref = {key: ds_ref[key] for key in ('_type','_moId')}
            try:
                await invoke(network, 'AddVirtualSwitch', {'vswitchName': SWITCH, 'spec': {'numPorts': 128}})
                switched = True
                record('create_isolated_vswitch_without_uplink', status='PASS')
                await invoke(network, 'AddPortGroup', {'portgrp': {'name': PG, 'vlanId': 123, 'vswitchName': SWITCH, 'policy': {}}})
                grouped = True
                record('create_test_portgroup', status='PASS')
                await invoke(network, 'UpdatePortGroup', {'pgName': PG, 'portgrp': {'name': PG, 'vlanId': 124, 'vswitchName': SWITCH, 'policy': {}}})
                info = (await call('esxi_api_get', {'target': network, 'properties': ['networkInfo']}))['properties']['networkInfo']
                assert any(item['spec']['name'] == PG and item['spec']['vlanId'] == 124 for item in info['portgroup'])
                record('update_test_portgroup_vlan', status='PASS')

                data = b'ESXi MCP owned transfer acceptance\n'
                await call('esxi_datastore_transfer', {'datastore': ds, 'path': FILENAME, 'operation': 'upload',
                                                      'data_base64': base64.b64encode(data).decode(), 'dry_run': False})
                uploaded = True
                record('upload_owned_datastore_file', status='PASS')
                downloaded = await call('esxi_datastore_transfer', {'datastore': ds, 'path': FILENAME, 'operation': 'download', 'dry_run': False})
                assert base64.b64decode(downloaded['data_base64']) == data
                record('download_owned_file_exact_bytes', status='PASS')

                assert VMNAME not in [vm['name'] for vm in original_vms]
                await wait(await call('esxi_create_vm', {'name': VMNAME, 'cpu': 1, 'memory_mb': 256, 'disk_gb': 1,
                                                       'datastore': ds, 'network': PG, 'guest_id': 'otherLinux64Guest', 'dry_run': False}))
                owned = next(vm for vm in (await call('esxi_list_vms'))['vms'] if vm['name'] == VMNAME)
                target = {'_type': 'vim.VirtualMachine', '_moId': owned['vm_id']}
                vm_network = next(item for item in (await call('esxi_inventory', {'resource_type': 'vim.Network'}))['items'] if item['name'] == PG)
                vm_network = {key: vm_network[key] for key in ('_type','_moId')}
                await invoke(target, 'ReconfigVM_Task', {'spec': {'deviceChange': [
                    {'operation': 'add', 'fileOperation': 'create', 'device': {'_type': 'vim.vm.device.VirtualDisk',
                       'key': -4, 'controllerKey': 1000, 'unitNumber': 1, 'capacityInKB': 1024**2,
                       'backing': {'_type': 'vim.vm.device.VirtualDisk.FlatVer2BackingInfo', 'fileName': '[' + ds + ']',
                                   'datastore': ds_ref, 'diskMode': 'persistent', 'thinProvisioned': True}}},
                    {'operation': 'add', 'device': {'_type': 'vim.vm.device.VirtualVmxnet3', 'key': -5,
                       'backing': {'_type': 'vim.vm.device.VirtualEthernetCard.NetworkBackingInfo', 'deviceName': PG, 'network': vm_network},
                       'connectable': {'startConnected': True, 'connected': False, 'allowGuestControl': True}, 'addressType': 'generated'}}]}})
                config = (await call('esxi_api_get', {'target': target, 'properties': ['config'], 'depth': 6}))['properties']['config']
                disks = [item for item in config['hardware']['device'] if item['_type'] == 'vim.vm.device.VirtualDisk']
                nics = [item for item in config['hardware']['device'] if item['_type'] in ('vim.vm.device.VirtualE1000', 'vim.vm.device.VirtualVmxnet3')]
                assert len(disks) == 2 and len(nics) == 2
                record('typed_add_virtual_disk_and_vmxnet3', status='PASS')
                added_disk = next(item for item in disks if item['unitNumber'] == 1)
                added_nic = next(item for item in nics if item['_type'] == 'vim.vm.device.VirtualVmxnet3')
                await invoke(target, 'ReconfigVM_Task', {'spec': {'deviceChange': [
                    {'operation': 'remove', 'fileOperation': 'destroy', 'device': {'_type': added_disk['_type'], 'key': added_disk['key']}},
                    {'operation': 'remove', 'device': {'_type': added_nic['_type'], 'key': added_nic['key']}}]}})
                detail = await call('esxi_get_vm', {'vm_id': owned['vm_id']})
                assert len(detail['disks']) == 1
                record('typed_remove_owned_virtual_disk_and_nic', status='PASS')
            except BaseException as error:
                failure = str(error)[:2000]
                record('failure', status='FAIL', error_type=type(error).__name__, error=failure)
            finally:
                if owned is not None:
                    vm = await call('esxi_get_vm', {'vm_id': owned['vm_id']})
                    assert vm['name'] == VMNAME and vm['instance_uuid'] == owned['instance_uuid']
                    assert owned['vm_id'] not in {vm['vm_id'] for vm in original_vms}
                    await wait(await call('esxi_delete_vm', {'vm_id': owned['vm_id'], 'expected_name': VMNAME, 'dry_run': False}))
                    record('cleanup_owned_hardware_vm', status='PASS')
                if uploaded:
                    await invoke(file_manager, 'DeleteDatastoreFile_Task', {'name': '[' + ds + '] ' + FILENAME})
                    assert not (await call('esxi_datastore_transfer', {'datastore': ds, 'path': FILENAME, 'operation': 'stat', 'dry_run': False}))['exists']
                    record('delete_owned_datastore_file', status='PASS')
                if grouped:
                    await invoke(network, 'RemovePortGroup', {'pgName': PG})
                    record('remove_owned_portgroup', status='PASS')
                if switched:
                    await invoke(network, 'RemoveVirtualSwitch', {'vswitchName': SWITCH})
                    record('remove_owned_vswitch', status='PASS')
                after = (await call('esxi_api_get', {'target': network, 'properties': ['networkConfig']}))['properties']['networkConfig']
                unchanged = before == after
                record('existing_network_config_unchanged', status='PASS' if unchanged else 'FAIL')
                current = (await call('esxi_list_vms'))['vms']
                fields = ('vm_id','instance_uuid','name','power_state','cpu','memory_mb')
                stable = lambda values: sorted([{key: vm.get(key) for key in fields} for vm in values], key=lambda vm: vm['vm_id'])
                vm_unchanged = stable(current) == stable(original_vms)
                record('existing_vm_inventory_unchanged', status='PASS' if vm_unchanged else 'FAIL')
                STATE.write_text(json.dumps({'status': 'PASS' if failure is None and unchanged and vm_unchanged else 'FAIL',
                    'checks': checks, 'failure': failure, 'cleanup_complete': True,
                    'existing_network_config_unchanged': unchanged, 'existing_vm_inventory_unchanged': vm_unchanged,
                    'original_vm_count': len(original_vms)}, indent=2))

if __name__ == '__main__':
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
    STATE = BASE / 'acceptance-resource-result.json'
    asyncio.run(main())
    result = json.loads(STATE.read_text())
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']), 'cleanup_complete': result.get('cleanup_complete')}))
    if result['status'] != 'PASS':
        raise SystemExit(1)

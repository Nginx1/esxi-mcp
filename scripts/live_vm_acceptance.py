"""Successful live writes through MCP, restricted to our new disposable VM."""
import asyncio
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE = Path.cwd()
TRANSPORT = {}
RUN = uuid.uuid4().hex[:10]
NAME = 'mcp-live-' + RUN
RENAMED = NAME + '-r'
LOG = BASE / 'acceptance-vm-events.jsonl'
STATE = BASE / 'acceptance-vm-result.json'
LEDGER = BASE / 'acceptance-vm-owner.json'
checks = []
owned = None
original = []

def write_state(status, **fields):
    STATE.write_text(json.dumps({'status': status, 'checks': checks, **fields}, indent=2))

def record(check, **fields):
    event = {'at': datetime.now(timezone.utc).isoformat(), 'check': check, **fields}
    checks.append(event)
    with LOG.open('a') as file:
        file.write(json.dumps(event) + '\n')
    write_state('RUNNING', test_name=NAME)

def unpack(result):
    data = result.structuredContent
    if data is None:
        data = json.loads('\n'.join(item.text for item in result.content if item.type == 'text'))
    while isinstance(data, dict) and set(data) == {'result'}:
        data = data['result']
    return data

def stable(vms):
    keys = ('vm_id', 'name', 'instance_uuid', 'power_state', 'cpu', 'memory_mb')
    return sorted([{key: vm.get(key) for key in keys} for vm in vms], key=lambda item: item['vm_id'])

async def main():
    global owned, original
    params = StdioServerParameters(**TRANSPORT)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            async def call(name, args=None, expect_error=False):
                result = await session.call_tool(name, args or {})
                if expect_error:
                    assert result.isError, (name, result)
                    return {'rejected': True}
                if result.isError:
                    raise RuntimeError(name + ': ' + str(result.content))
                return unpack(result)

            async def wait(value, timeout=180):
                task_id = value.get('task_id')
                if task_id:
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        task = await call('esxi_get_task', {'task_id': task_id})
                        if task['state'] == 'success':
                            return task
                        if task['state'] == 'error':
                            raise RuntimeError(str(task))
                        await asyncio.sleep(1)
                    raise TimeoutError('Task did not finish: ' + task_id)
                return value

            async def details():
                result = await call('esxi_get_vm', {'vm_id': owned['vm_id']})
                assert result['instance_uuid'] == owned['instance_uuid']
                assert result['name'] in (NAME, RENAMED)
                return result

            async def mutate(tool, **values):
                vm = await details()
                result = await wait(await call(tool, {'vm_id': vm['vm_id'], 'expected_name': vm['name'],
                                                    'dry_run': False, **values}))
                return result

            original = (await call('esxi_list_vms'))['vms']
            assert NAME not in [vm['name'] for vm in original]
            datastores = (await call('esxi_list_datastores'))['datastores']
            datastore = max((item for item in datastores if item['accessible']), key=lambda item: item['free_mb'])
            network = (await call('esxi_list_networks'))['networks'][0]
            record('preflight', status='PASS', original_vm_count=len(original), disk_gb=1, memory_mb=256)
            submitted = False
            failure = None
            try:
                create_args = {'name': NAME, 'cpu': 1, 'memory_mb': 256, 'disk_gb': 1,
                               'datastore': datastore['name'], 'network': network, 'dry_run': False}
                LEDGER.write_text(json.dumps({'test_name': NAME, 'original_ids': [vm['vm_id'] for vm in original]}))
                submitted = True
                await wait(await call('esxi_create_vm', create_args))
                matches = [vm for vm in (await call('esxi_list_vms'))['vms'] if vm['name'] == NAME]
                assert len(matches) == 1 and matches[0]['vm_id'] not in {vm['vm_id'] for vm in original}
                owned = matches[0]
                LEDGER.write_text(json.dumps({'owned': owned, 'names': [NAME, RENAMED]}))
                vm = await details()
                assert (vm['cpu'], vm['memory_mb']) == (1, 256)
                assert vm['disks'][0]['capacity_gb'] == 1
                record('create_vm', status='PASS')

                await mutate('esxi_configure_vm', cpu=2, memory_mb=512, cpu_mhz_limit=1500,
                             cpu_mhz_reservation=0, memory_mb_limit=512, memory_mb_reservation=0)
                vm = await details()
                assert (vm['cpu'], vm['memory_mb']) == (2, 512)
                assert vm['cpu_allocation']['limit'] == 1500 and vm['memory_allocation']['limit'] == 512
                record('configure_cpu_memory_and_allocations', status='PASS')

                await mutate('esxi_rename_vm', new_name=RENAMED)
                assert (await details())['name'] == RENAMED
                record('rename_vm', status='PASS')

                await mutate('esxi_power_vm', operation='power_on')
                assert (await details())['power_state'] == 'poweredOn'
                record('power_on', status='PASS')
                await mutate('esxi_power_vm', operation='reset')
                assert (await details())['power_state'] == 'poweredOn'
                record('reset', status='PASS')

                for operation in ('shutdown', 'reboot_guest'):
                    await call('esxi_power_vm', {'vm_id': owned['vm_id'], 'expected_name': RENAMED,
                                               'operation': operation, 'dry_run': False}, expect_error=True)
                    assert (await details())['power_state'] == 'poweredOn'
                    record(operation + '_without_tools_rejected', status='PASS')

                await mutate('esxi_create_snapshot', name='mcp-owned-baseline', memory=False, quiesce=False)
                snapshots = (await call('esxi_list_snapshots', {'vm_id': owned['vm_id']}))
                roots = snapshots.get('snapshots') or snapshots.get('snapshot_tree') or []
                assert len(roots) == 1, snapshots
                snapshot_id = roots[0]['snapshot_id']
                record('create_snapshot', status='PASS')

                await mutate('esxi_power_vm', operation='power_off')
                assert (await details())['power_state'] == 'poweredOff'
                record('power_off', status='PASS')
                await mutate('esxi_configure_vm', cpu=1)
                assert (await details())['cpu'] == 1
                await mutate('esxi_revert_snapshot', snapshot_id=snapshot_id)
                assert (await details())['cpu'] == 2
                record('revert_snapshot_restores_configuration', status='PASS')
                if (await details())['power_state'] == 'poweredOn':
                    await mutate('esxi_power_vm', operation='power_off')

                await mutate('esxi_delete_snapshot', snapshot_id=snapshot_id)
                snapshots = await call('esxi_list_snapshots', {'vm_id': owned['vm_id']})
                assert not (snapshots.get('snapshots') or snapshots.get('snapshot_tree'))
                record('delete_snapshot', status='PASS')
                vm = await details()
                key = vm['disks'][0]['device_key']
                await mutate('esxi_expand_disk', device_key=key, new_size_gb=2)
                assert (await details())['disks'][0]['capacity_gb'] == 2
                record('expand_disk', status='PASS')
            except BaseException as error:
                failure = str(error)
                record('failure', status='FAIL', error_type=type(error).__name__, error=failure[:1800])
            finally:
                # Only our unique newly-created VM is eligible for cleanup.
                if submitted and owned is None:
                    matches = [vm for vm in (await call('esxi_list_vms'))['vms']
                               if vm['name'] in (NAME, RENAMED)
                               and vm['vm_id'] not in {item['vm_id'] for item in original}]
                    if len(matches) == 1:
                        owned = matches[0]
                if owned is not None:
                    vm = await details()
                    if vm['power_state'] != 'poweredOff':
                        await mutate('esxi_power_vm', operation='power_off')
                    await mutate('esxi_delete_vm')
                    current = (await call('esxi_list_vms'))['vms']
                    assert owned['vm_id'] not in {vm['vm_id'] for vm in current}
                    record('delete_owned_vm_and_cleanup', status='PASS')
                else:
                    current = (await call('esxi_list_vms'))['vms']
                unchanged = stable(original) == stable(current)
                record('existing_vm_inventory_unchanged', status='PASS' if unchanged else 'FAIL')
                write_state('PASS' if failure is None and unchanged else 'FAIL',
                            checked_at=datetime.now(timezone.utc).isoformat(),
                            cleanup_complete=True, original_vm_count=len(original),
                            existing_vm_inventory_unchanged=unchanged,
                            live_successful_vm_writes=True, failure=failure)

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
    LOG = BASE / 'acceptance-vm-events.jsonl'
    STATE = BASE / 'acceptance-vm-result.json'
    LEDGER = BASE / 'acceptance-vm-owner.json'
    asyncio.run(main())
    result = json.loads(STATE.read_text())
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']), 'cleanup_complete': result.get('cleanup_complete')}))
    if result['status'] != 'PASS':
        raise SystemExit(1)

"""Validate an operator-supplied stdio transport using reads and dry-runs only."""
import argparse
import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED = {
    'esxi_health', 'esxi_list_vms', 'esxi_get_vm', 'esxi_host_summary',
    'esxi_list_datastores', 'esxi_list_networks', 'esxi_list_snapshots', 'esxi_get_task',
    'esxi_power_vm', 'esxi_configure_vm', 'esxi_create_vm', 'esxi_rename_vm',
    'esxi_create_snapshot', 'esxi_revert_snapshot', 'esxi_delete_snapshot',
    'esxi_expand_disk', 'esxi_delete_vm',
}

def unpack(result):
    if result.structuredContent is not None:
        data = result.structuredContent
    else:
        texts = [c.text for c in result.content if c.type == 'text']
        data = json.loads('\n'.join(texts)) if texts else None
    while isinstance(data, dict) and set(data) == {'result'}:
        data = data['result']
    return data

def vms_from(data):
    if isinstance(data, list):
        return data
    for key in ('vms', 'result', 'virtual_machines'):
        if isinstance(data, dict) and key in data:
            return vms_from(data[key])
    raise AssertionError('VM list payload does not contain a VM list')

def stable(vms):
    keys = ('vm_id', 'name', 'instance_uuid', 'power_state', 'cpu', 'memory_mb')
    return sorted([{k: vm.get(k) for k in keys} for vm in vms], key=lambda v: str(v['vm_id']))

async def verify(args):
    transport = json.loads(Path(args.transport).read_text(encoding='utf-8'))
    params = StdioServerParameters(**transport)
    checks = []
    started = time.monotonic()
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.instructions, 'Server workflow instructions are missing'
            tools = (await session.list_tools()).tools
            names = {tool.name for tool in tools}
            assert EXPECTED <= names, f'Missing tools: {sorted(EXPECTED - names)}'
            for tool in tools:
                assert tool.annotations is not None, f'Missing annotations: {tool.name}'
                if tool.name in EXPECTED:
                    is_read = tool.name in {'esxi_health', 'esxi_list_vms', 'esxi_get_vm', 'esxi_host_summary',
                                           'esxi_list_datastores', 'esxi_list_networks', 'esxi_list_snapshots', 'esxi_get_task'}
                    assert tool.annotations.readOnlyHint == is_read, tool.name
                    if not is_read:
                        assert tool.annotations.destructiveHint is True, tool.name
                        assert tool.inputSchema['properties']['dry_run'].get('default') is True, tool.name
            checks.append({'check': 'initialize/list_tools/schema/annotations', 'status': 'PASS', 'tool_count': len(tools)})
            Path(args.schema).write_text(json.dumps([t.model_dump(mode='json') for t in tools], ensure_ascii=False, indent=2), encoding='utf-8')

            async def call(name, params=None, expect_error=False):
                begin = time.monotonic()
                result = await session.call_tool(name, params or {})
                if expect_error:
                    assert result.isError is True, f'{name} must return MCP isError'
                    checks.append({'check': name, 'status': 'PASS', 'expected_error': True,
                                   'seconds': round(time.monotonic() - begin, 3)})
                    return None
                assert not result.isError, f'{name} failed: {result.content}'
                data = unpack(result)
                checks.append({'check': name, 'status': 'PASS', 'seconds': round(time.monotonic() - begin, 3)})
                return data

            await call('esxi_health')
            before = vms_from(await call('esxi_list_vms'))
            assert before and all(vm.get('vm_id') and vm.get('name') for vm in before)
            host = await call('esxi_host_summary')
            await call('esxi_list_datastores')
            await call('esxi_list_networks')
            vm = next((v for v in before if v.get('power_state') == 'poweredOff'), before[0])
            detail = await call('esxi_get_vm', {'vm_id': vm['vm_id']})
            assert detail.get('disks') is not None, 'VM details must expose disk device keys'
            await call('esxi_list_snapshots', {'vm_id': vm['vm_id']})
            await call('esxi_get_vm', {'vm_id': '__missing_vm__'}, expect_error=True)
            plan = await call('esxi_power_vm', {'vm_id': vm['vm_id'], 'expected_name': vm['name'],
                                               'operation': 'power_on', 'dry_run': True})
            await call('esxi_rename_vm', {'vm_id': vm['vm_id'], 'expected_name': vm['name'],
                                         'new_name': 'mcp-plan-only-' + uuid.uuid4().hex[:12], 'dry_run': True})
            await call('esxi_power_vm', {'vm_id': vm['vm_id'], 'expected_name': vm['name'] + '--intentional-mismatch',
                                         'operation': 'power_on', 'dry_run': False}, expect_error=True)
            after = vms_from(await call('esxi_list_vms'))
            assert stable(before) == stable(after), 'Stable VM inventory changed during acceptance'
            checks.append({'check': 'stable_vm_inventory_unchanged', 'status': 'PASS', 'vm_count': len(before)})
    return {'status': 'PASS', 'checked_at': datetime.now(timezone.utc).isoformat(),
            'server': init.serverInfo.model_dump(mode='json'), 'protocol_version': init.protocolVersion,
            'vm_count': len(before), 'tool_count': len(tools), 'checks': checks,
            'duration_seconds': round(time.monotonic() - started, 3),
            'live_mutation_tested': False, 'power_dry_run': plan, 'host_summary': host}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--transport', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--schema', required=True)
    args = parser.parse_args()
    async def bounded():
        return await asyncio.wait_for(verify(args), timeout=120)
    result = asyncio.run(bounded())
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('status', 'vm_count', 'tool_count', 'duration_seconds')}, ensure_ascii=False))

if __name__ == '__main__':
    main()

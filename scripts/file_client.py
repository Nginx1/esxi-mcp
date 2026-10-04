"""Portable file/OVF client. Private --transport JSON uses StdioServerParameters fields."""
import argparse
import asyncio
import base64
import hashlib
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

CHUNK = 1024 * 1024

@asynccontextmanager
async def session(transport):
    params = StdioServerParameters(**json.loads(Path(transport).read_text(encoding='utf-8')))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as client:
            await client.initialize()
            yield client

async def call(client, name, arguments=None):
    result = await client.call_tool(name, arguments or {})
    if result.isError:
        raise RuntimeError(name + ': ' + '\n'.join(item.text for item in result.content if item.type == 'text'))
    value = result.structuredContent
    if value is None:
        value = json.loads('\n'.join(item.text for item in result.content if item.type == 'text'))
    while isinstance(value, dict) and set(value) == {'result'}:
        value = value['result']
    return value

async def wait(client, handle, timeout=7200, transfer=False):
    deadline = time.monotonic() + timeout
    tool = 'esxi_transfer_status' if transfer else 'esxi_operation_status'
    key = 'job_id' if transfer else 'operation_id'
    while time.monotonic() < deadline:
        value = await call(client, tool, {key: handle})
        if value['status'] == 'completed':
            return value
        if value['status'] not in ('queued', 'running', 'submitted', 'executing'):
            raise RuntimeError('Operation ' + handle + ' requires inspection: ' + value['status'])
        await asyncio.sleep(1)
    raise TimeoutError('Operation still pending: ' + handle + '; inspect before retrying')

def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b''):
            digest.update(chunk)
    return digest.hexdigest()

async def stage(client, path):
    path = Path(path)
    size, digest = path.stat().st_size, sha256(path)
    args = {'filename': path.name, 'total_bytes': size, 'expected_sha256': digest}
    await call(client, 'esxi_stage_upload', args)
    value = await call(client, 'esxi_stage_upload', {**args, 'dry_run': False})
    handle, offset = value['job_id'], 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b''):
            await call(client, 'esxi_stage_write_chunk', {'job_id': handle, 'offset': offset,
                'data_base64': base64.b64encode(chunk).decode(), 'dry_run': False})
            offset += len(chunk)
    value = await call(client, 'esxi_stage_finalize', {'job_id': handle, 'dry_run': False})
    if value['bytes'] != size or value['sha256'] != digest:
        raise RuntimeError('Finalized stage differs from local file')
    return handle, digest, size

async def fetch(client, handle, destination, overwrite=False):
    """Download a completed private handle; locally interrupted .part files can resume by offset."""
    destination = Path(destination)
    if destination.exists() and not overwrite:
        raise FileExistsError('Local output exists: ' + str(destination))
    info = await call(client, 'esxi_transfer_status', {'job_id': handle})
    if info['status'] != 'completed':
        raise RuntimeError('File handle is not complete')
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + '.part-' + handle)
    offset = partial.stat().st_size if partial.exists() else 0
    if offset > info['bytes']:
        raise RuntimeError('Local partial file exceeds completed remote file size')
    with partial.open('ab') as output:
        while True:
            value = await call(client, 'esxi_transfer_read_chunk', {'job_id': handle, 'offset': offset, 'length': CHUNK})
            chunk = base64.b64decode(value['data_base64'], validate=True)
            if value['offset'] != offset or value['bytes'] != len(chunk) or value['next_offset'] != offset + len(chunk):
                raise RuntimeError('Remote chunk offset/length mismatch')
            output.write(chunk)
            offset += len(chunk)
            if value['eof']:
                break
            if not chunk:
                raise RuntimeError('Remote chunk made no progress')
    if offset != info['bytes'] or sha256(partial) != info['sha256']:
        raise RuntimeError('Downloaded bytes/SHA256 differ from completed remote file')
    partial.replace(destination)
    return {'file': str(destination), 'bytes': offset, 'sha256': info['sha256']}

def contained_file(directory, relative):
    root = Path(directory).resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise ValueError('OVF file reference escapes the selected bundle or is missing')
    return target

async def main(args):
    async with session(args.transport) as client:
        if args.operation == 'upload':
            path = Path(args.file)
            if not args.execute:
                return {'dry_run': True, 'local_bytes': path.stat().st_size, 'sha256': sha256(path),
                        'datastore': args.datastore, 'path': args.path}
            handle, digest, size = await stage(client, path)
            spec = {'kind': 'datastore', 'operation': 'upload', 'datastore': args.datastore, 'path': args.path,
                    'source_job_id': handle, 'expected_sha256': digest, 'max_bytes': max(1, size), 'overwrite': args.overwrite}
            await call(client, 'esxi_transfer_start', spec)
            job = await call(client, 'esxi_transfer_start', {**spec, 'dry_run': False})
            return await wait(client, job['job_id'], transfer=True)
        if args.operation == 'download':
            spec = {'kind': 'datastore', 'operation': 'download', 'datastore': args.datastore,
                    'path': args.path, 'max_bytes': args.max_bytes}
            await call(client, 'esxi_transfer_start', spec)
            job = await call(client, 'esxi_transfer_start', {**spec, 'dry_run': False})
            await wait(client, job['job_id'], transfer=True)
            return await fetch(client, job['job_id'], args.output, args.overwrite)
        if args.operation == 'fetch':
            return await fetch(client, args.job_id, args.output, args.overwrite)
        if args.operation == 'export':
            spec = {'vm_id': args.vm_id, 'expected_name': args.expected_name, 'max_disk_bytes': args.max_bytes}
            preview = await call(client, 'esxi_ovf_export', spec)
            if not args.execute:
                return preview
            value = await call(client, 'esxi_ovf_export', {**spec, 'dry_run': False})
            value = await wait(client, value['operation_id'])
            files = []
            for item in value['files']:
                if Path(item['filename']).name != item['filename']:
                    raise RuntimeError('Export filename must be a simple basename')
                files.append(await fetch(client, item['job_id'], Path(args.output_dir)/item['filename'], args.overwrite))
            return {'operation_id': value['id'], 'files': files, 'lease_completed': value['lease_completed']}
        from esxi_mcp.workflows import validate_ovf
        descriptor_path = Path(args.ovf)
        descriptor = descriptor_path.read_text(encoding='utf-8')
        references = validate_ovf(descriptor)
        local = {name: contained_file(descriptor_path.parent, name) for name in references}
        if not args.execute:
            return {'dry_run': True, 'name': args.name, 'datastore': args.datastore,
                    'files': [{'path': name, 'bytes': path.stat().st_size} for name, path in local.items()],
                    'note': 'Local bundle validation only; execute stages files then previews against the target host'}
        disks = {}
        for name, path in local.items():
            handle, digest, size = await stage(client, path)
            disks[name] = {'source_job_id': handle, 'expected_sha256': digest, 'max_bytes': max(1, size)}
        spec = {'name': args.name, 'datastore': args.datastore, 'ovf_descriptor': descriptor,
                'network_mappings': json.loads(Path(args.network_map).read_text(encoding='utf-8')),
                'disks': disks, 'expected_host': args.expected_host, 'power_on': args.power_on,
                'accept_warnings': args.accept_warnings}
        await call(client, 'esxi_ovf_import', spec)
        value = await call(client, 'esxi_ovf_import', {**spec, 'dry_run': False})
        return await wait(client, value['operation_id'])

def parser():
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument('--transport', required=True, help='Private stdio connection JSON; never commit it')
    sub = root.add_subparsers(dest='operation', required=True)
    for operation in ('upload', 'download'):
        item = sub.add_parser(operation)
        item.add_argument('--datastore', required=True)
        item.add_argument('--path', required=True)
        item.add_argument('--overwrite', action='store_true')
        if operation == 'upload':
            item.add_argument('--file', required=True)
            item.add_argument('--execute', action='store_true')
        else:
            item.add_argument('--output', required=True)
            item.add_argument('--max-bytes', type=int, default=8589934592)
    item = sub.add_parser('fetch')
    item.add_argument('--job-id', required=True)
    item.add_argument('--output', required=True)
    item.add_argument('--overwrite', action='store_true')
    item = sub.add_parser('export')
    item.add_argument('--vm-id', required=True)
    item.add_argument('--expected-name', required=True)
    item.add_argument('--output-dir', required=True)
    item.add_argument('--max-bytes', type=int, default=8589934592)
    item.add_argument('--execute', action='store_true')
    item.add_argument('--overwrite', action='store_true')
    item = sub.add_parser('import')
    for option in ('ovf', 'name', 'datastore', 'network-map', 'expected-host'):
        item.add_argument('--' + option, required=True)
    item.add_argument('--power-on', action='store_true')
    item.add_argument('--accept-warnings', action='store_true')
    item.add_argument('--execute', action='store_true')
    return root

if __name__ == '__main__':
    print(json.dumps(asyncio.run(main(parser().parse_args())), ensure_ascii=False, indent=2))

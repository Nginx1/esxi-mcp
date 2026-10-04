"""Background OVF import/export and explicitly compensated multi-step plans."""
from __future__ import annotations
import hashlib
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional
from pyVmomi import vim
from mcp.server.fastmcp.exceptions import ToolError
from . import api, codec, state, transfers
from .config import load_config
from .tools import mcp, WRITE, _audited, _get_host, _resolve_vm, _guard_protected, _guard_writes
from .security import validate_vm_name

def validate_ovf(descriptor):
    if not isinstance(descriptor, str) or len(descriptor.encode()) > 2 * 1024**2:
        raise ToolError('OVF descriptor must be <=2MiB')
    if '<!DOCTYPE' in descriptor.upper() or '<!ENTITY' in descriptor.upper():
        raise ToolError('External entities and DTDs are refused')
    try:
        root = ET.fromstring(descriptor)
    except ET.ParseError as error:
        raise ToolError('Malformed OVF descriptor: ' + str(error)) from None
    if root.tag != '{http://schemas.dmtf.org/ovf/envelope/1}Envelope':
        raise ToolError('Expected an OVF Envelope')
    files = []
    for node in root.findall('.//{http://schemas.dmtf.org/ovf/envelope/1}File'):
        path = node.get('{http://schemas.dmtf.org/ovf/envelope/1}href', '')
        decoded = urllib.parse.unquote(path)
        if not path or '://' in path or decoded.startswith('/') or '\\' in decoded or any(
                part in ('', '.', '..') for part in decoded.split('/')):
            raise ToolError('OVF file references must be relative paths without traversal or external URLs')
        files.append(path)
    if len(files) != len(set(files)):
        raise ToolError('Duplicate OVF file references')
    return files

def artifact(cfg, filename, payload):
    job_id, _ = state.begin(cfg, 'stage_upload', {'filename': filename, 'total_bytes': len(payload)})
    path = transfers.directory(cfg, job_id) / 'body'
    with open(path, 'wb') as output:
        output.write(payload)
    if __import__('os').name != 'nt':
        path.chmod(0o600)
    digest = hashlib.sha256(payload).hexdigest()
    state.update(cfg, job_id, 'completed', bytes=len(payload), total_bytes=len(payload), sha256=digest)
    return {'filename': filename, 'job_id': job_id, 'bytes': len(payload), 'sha256': digest}

def lease_ready(lease, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = str(lease.state)
        if status == 'ready':
            return lease.info
        if status in ('error', 'done'):
            raise ToolError('NFC lease entered ' + status)
        time.sleep(0.25)
    raise ToolError('NFC lease did not become ready before timeout')

def inline_transfer(cfg, spec):
    job_id, _ = state.begin(cfg, 'transfer', spec)
    transfers.save_spec(cfg, job_id, spec)
    state.update(cfg, job_id, 'queued', bytes=0, cancel_requested=False)
    with transfers._LOCK:
        transfers._RUNNING.add(job_id)
    transfers.worker(cfg, job_id)
    entry = state.get(cfg, job_id)
    if entry['status'] != 'completed':
        raise ToolError('Transfer ' + job_id + ' failed: ' + str(entry.get('error', entry['status'])))
    return job_id, entry

def transfer_spec(kind, operation, lease, url, max_bytes, **fields):
    return {'kind': kind, 'operation': operation, 'lease': lease, 'transfer_url': url,
            'max_bytes': max_bytes, 'expected_sha256': None, 'overwrite': False,
            'http_method': 'PUT', 'content_type': 'application/octet-stream', **fields}

def export_worker(cfg, operation_id, vm_ref, lease_ref, max_disk_bytes):
    files = []
    try:
        state.update(cfg, operation_id, 'running', phase='waiting_for_lease')
        with api.service_instance(cfg, target=lease_ref) as si:
            lease = codec.reference(lease_ref, si._stub)
            info = lease_ready(lease)
            ovf_files = []
            for index, device in enumerate(info.deviceUrl):
                lease.HttpNfcLeaseProgress(1)
                filename = 'disk-' + str(index) + ('.vmdk' if device.disk else '.bin')
                state.update(cfg, operation_id, phase='exporting_files', files=files)
                job_id, entry = inline_transfer(cfg, transfer_spec('nfc', 'download', lease_ref, device.url, max_disk_bytes))
                files.append({'filename': filename, 'job_id': job_id, 'bytes': entry['bytes'], 'sha256': entry['sha256']})
                ovf_files.append(vim.OvfManager.OvfFile(deviceId=device.key, path=filename, size=entry['bytes']))
            manager = si.RetrieveContent().ovfManager
            result = manager.CreateDescriptor(codec.reference(vm_ref, si._stub),
                                              vim.OvfManager.CreateDescriptorParams(ovfFiles=ovf_files))
            if result.error:
                raise ToolError('OVF descriptor generation failed: ' + str(codec.encode(result.error)))
            descriptor = artifact(cfg, 'vm.ovf', result.ovfDescriptor.encode('utf-8'))
            files.append(descriptor)
            manifest = '\n'.join('SHA256(' + item['filename'] + ')= ' + item['sha256'] for item in files) + '\n'
            files.append(artifact(cfg, 'vm.mf', manifest.encode()))
            lease.HttpNfcLeaseComplete()
            state.update(cfg, operation_id, 'completed', phase='completed', files=files,
                         warning=codec.encode(result.warning), lease_completed=True)
    except Exception as error:
        aborted = False
        try:
            with api.service_instance(cfg, target=lease_ref) as si:
                codec.reference(lease_ref, si._stub).HttpNfcLeaseAbort()
                aborted = True
        except Exception:
            pass
        state.update(cfg, operation_id, 'failed' if aborted else 'needs_review', error=state.safe(cfg, str(error))[:800], files=files,
                     lease_aborted=aborted, cleanup_needs_review=not aborted)

@mcp.tool(annotations=WRITE)
@_audited
def esxi_ovf_export(vm_id: str, expected_name: str, max_disk_bytes: int = 8589934592,
                     dry_run: bool = True, request_id: Optional[str] = None) -> Dict[str, Any]:
    """完整OVF导出：VM须已关机，后台导出磁盘、生成OVF与SHA256 manifest，并Complete/Abort租约。operation_status查询，transfer_read_chunk取回files句柄。"""
    cfg = load_config()
    transfers.ensure_advanced(cfg, dry_run)
    if not 1 <= max_disk_bytes <= transfers.MAX_FILE:
        raise ToolError('max_disk_bytes must be1..64TiB')
    if not dry_run:
        replay = state.replay(cfg, 'ovf_export', {'vm_id':vm_id, 'expected_name':expected_name,
                                                'max_disk_bytes':max_disk_bytes}, request_id)
        if replay:
            return replay
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        _guard_protected(vm_id, vm.name, cfg, dry_run, 'esxi_ovf_export')
        if str(vm.runtime.powerState) != 'poweredOff':
            raise ToolError('OVF export requires poweredOff; the tool will not power off workloads automatically')
        if dry_run:
            return {'dry_run': True, 'vm_id': vm_id, 'expected_name': expected_name,
                    'max_disk_bytes': max_disk_bytes, 'artifacts': ['OVF', 'disk files', 'SHA256 manifest']}
        operation_id, replay = state.begin(cfg, 'ovf_export', {'vm_id': vm_id, 'expected_name': expected_name,
                                                              'max_disk_bytes': max_disk_bytes}, request_id)
        if replay:
            return replay
        try:
            lease = vm.ExportVm()
            api.hold_task_session(lease)
        except Exception:
            state.update(cfg, operation_id, 'needs_review', phase='lease_creation_failed')
            raise
        vm_ref, lease_ref = codec.encode(vm), codec.encode(lease)
        state.update(cfg, operation_id, 'queued', result={'operation_id': operation_id, 'state': 'queued'})
        threading.Thread(target=export_worker, args=(cfg, operation_id, vm_ref, lease_ref, max_disk_bytes), daemon=True).start()
    return {'operation_id': operation_id, 'state': 'queued'}

def import_worker(cfg, operation_id, lease_ref, file_items, disks, power_on):
    imported_vm = None
    try:
        state.update(cfg, operation_id, 'running', phase='waiting_for_lease')
        with api.service_instance(cfg, target=lease_ref) as si:
            lease = codec.reference(lease_ref, si._stub)
            info = lease_ready(lease)
            imported_vm = codec.encode(info.entity)
            completed = []
            for item in file_items:
                device = next((url for url in info.deviceUrl if url.importKey == item.deviceId), None)
                if device is None:
                    raise ToolError('NFC upload URL not found for an OVF disk')
                source = disks[item.path]
                lease.HttpNfcLeaseProgress(1)
                max_bytes = max(int(item.size or 0), int(source.get('max_bytes', 8589934592)))
                spec = transfer_spec('nfc', 'upload', lease_ref, device.url, max_bytes,
                                     source_url=source.get('source_url'), source_job_id=source.get('source_job_id'),
                                     expected_sha256=source.get('expected_sha256'), http_method='PUT' if item.create else 'POST',
                                     overwrite=bool(item.create),
                                     content_type='application/octet-stream' if item.create else 'application/x-vnd.vmware-streamVmdk')
                job_id, entry = inline_transfer(cfg, spec)
                completed.append({'path': item.path, 'job_id': job_id, 'bytes': entry['bytes'], 'sha256': entry['sha256']})
                state.update(cfg, operation_id, phase='uploading_files', files=completed, imported_entity=imported_vm)
            lease.HttpNfcLeaseComplete()
        if power_on:
            with api.service_instance(cfg) as si:
                vm = codec.reference(imported_vm, si._stub)
                if not isinstance(vm, vim.VirtualMachine):
                    raise ToolError('Optional power-on supports a single imported VM')
                task = vm.PowerOnVM_Task()
                api.hold_task_session(task)
                deadline = time.monotonic() + 180
                while str(task.info.state) in ('queued', 'running') and time.monotonic() < deadline:
                    time.sleep(0.5)
                if str(task.info.state) != 'success':
                    raise ToolError('Imported VM power-on did not finish successfully')
        state.update(cfg, operation_id, 'completed', phase='completed', imported_entity=imported_vm, lease_completed=True)
    except Exception as error:
        aborted = False
        try:
            with api.service_instance(cfg, target=lease_ref) as si:
                codec.reference(lease_ref, si._stub).HttpNfcLeaseAbort()
                aborted = True
        except Exception:
            pass
        message = str(error)
        for secret in codec.secret_values(disks) + [cfg.password]:
            if secret:
                message = message.replace(secret, '[REDACTED]')
        state.update(cfg, operation_id, 'needs_review' if not aborted else 'failed', error=message[:800],
                     lease_aborted=aborted, imported_entity=imported_vm, cleanup_needs_review=not aborted)

@mcp.tool(annotations=WRITE)
@_audited
def esxi_ovf_import(name: str, datastore: str, ovf_descriptor: str,
                     network_mappings: Dict[str, str], disks: Dict[str, Dict[str, Any]],
                     expected_host: Optional[str] = None, deployment_option: str = '',
                     properties: Optional[Dict[str, str]] = None, power_on: bool = False,
                     accept_warnings: bool = False, dry_run: bool = True,
                     request_id: Optional[str] = None) -> Dict[str, Any]:
    """完整OVF导入：验证描述符/网络/数据存储/文件映射，后台NFC上传、完成租约；失败Abort，不删除已有VM。disks按OVF文件path映射source_job_id或HTTPS source_url。"""
    cfg = load_config()
    transfers.ensure_advanced(cfg, dry_run)
    if validate_vm_name(name):
        raise ToolError('Invalid new VM name')
    references = validate_ovf(ovf_descriptor)
    if not set(references).issubset(set(disks)):
        raise ToolError('Every OVF file reference needs an explicit disk/source mapping')
    for source in disks.values():
        if bool(source.get('source_url')) == bool(source.get('source_job_id')):
            raise ToolError('Each file needs exactly one HTTPS source_url or completed source_job_id')
        if source.get('source_url') and urllib.parse.urlparse(source['source_url']).scheme != 'https':
            raise ToolError('OVF file sources must use HTTPS')
        if not 1 <= source.get('max_bytes', 8589934592) <= transfers.MAX_FILE:
            raise ToolError('Every OVF source max_bytes must be1..64TiB')
        if source.get('source_job_id') and state.get(cfg, source['source_job_id'])['status'] != 'completed':
            raise ToolError('OVF source handle is not complete')
    if not dry_run and expected_host != cfg.host:
        raise ToolError('expected_host must exactly match configured ESXi host')
    journal_arguments = {'name':name, 'datastore':datastore, 'descriptor':ovf_descriptor,
                         'network_mappings':network_mappings, 'disks':disks, 'properties':properties, 'power_on':power_on}
    if not dry_run:
        replay = state.replay(cfg, 'ovf_import', journal_arguments, request_id)
        if replay:
            return replay
    if datastore in cfg.protected_datastores:
        raise ToolError('Target datastore is deployment-protected')
    with api.service_instance(cfg) as si:
        content, dc, host = _get_host(si)
        if api.find_vm_by_name(si, name):
            raise ToolError('New VM name already exists')
        ds = next((item for item in dc.datastore if item.name == datastore), None)
        if ds is None or not ds.summary.accessible:
            raise ToolError('Target datastore is absent or inaccessible')
        network_refs = {net.name: net for net in dc.network}
        if set(network_mappings.values()) - set(network_refs):
            raise ToolError('A requested target network is absent from host inventory')
        pool = host.parent.resourcePool
        params = vim.OvfManager.CreateImportSpecParams(entityName=name, locale='en_US', deploymentOption=deployment_option,
            hostSystem=host, diskProvisioning='thin',
            networkMapping=[vim.OvfManager.NetworkMapping(name=key, network=network_refs[value]) for key, value in network_mappings.items()],
            propertyMapping=[vim.KeyValue(key=key, value=value) for key, value in (properties or {}).items()])
        result = content.ovfManager.CreateImportSpec(ovf_descriptor, pool, ds, params)
        if result.error or result.importSpec is None:
            raise ToolError('OVF import validation failed: ' + str(codec.encode(result.error)))
        if result.warning and not accept_warnings and not dry_run:
            raise ToolError('OVF contains warnings; inspect dry-run then explicitly accept_warnings')
        for item in result.fileItem:
            if item.path not in disks:
                raise ToolError('ImportSpec fileItem lacks a provided disk/source: ' + item.path)
            if int(item.size or 0) > transfers.MAX_FILE:
                raise ToolError('OVF disk file exceeds64TiB transfer limit')
        if dry_run:
            return {'dry_run': True, 'name': name, 'datastore': datastore,
                    'files': codec.encode(result.fileItem, 5, 500), 'warnings': codec.encode(result.warning),
                    'power_on': power_on, 'validated_against_host': True}
        operation_id, replay = state.begin(cfg, 'ovf_import', journal_arguments, request_id)
        if replay:
            return replay
        try:
            lease = pool.ImportVApp(result.importSpec, dc.vmFolder, host)
            api.hold_task_session(lease)
        except Exception:
            state.update(cfg, operation_id, 'needs_review', phase='lease_creation_failed')
            raise
        lease_ref = codec.encode(lease)
        state.update(cfg, operation_id, 'queued', result={'operation_id': operation_id, 'state': 'queued'})
        threading.Thread(target=import_worker, args=(cfg, operation_id, lease_ref, result.fileItem, disks, power_on), daemon=True).start()
    return {'operation_id': operation_id, 'state': 'queued'}

def wait_task(cfg, value, timeout):
    if not value.get('task_id'):
        return value
    deadline = time.monotonic() + timeout
    with api.service_instance(cfg) as si:
        while time.monotonic() < deadline:
            task = api.get_task_by_id(si, value['task_id'])
            if task is None:
                raise ToolError('Submitted task is unavailable; inspect actual resource state')
            result = api.task_to_dict(task)
            if result['state'] == 'success':
                return result
            if result['state'] == 'error':
                raise ToolError(str(result['error']))
            time.sleep(0.5)
    raise ToolError('Task completion is uncertain after workflow timeout')

def resolve_references(value, completed):
    if isinstance(value, dict) and '$step' in value:
        if set(value) != {'$step', 'path'} or not isinstance(value['$step'], int) or isinstance(value['$step'], bool):
            raise ToolError('A step reference must contain exactly integer $step and path list')
        if not 0 <= value['$step'] < len(completed) or not isinstance(value['path'], list):
            raise ToolError('Step reference must select a completed earlier step')
        result = completed[value['$step']]['result']
        for key in value['path']:
            if not isinstance(key, (str, int)) or isinstance(key, bool):
                raise ToolError('Reference path accepts only JSON keys or array indices')
            try:
                result = result[key]
            except (KeyError, IndexError, TypeError):
                raise ToolError('Step reference path is absent from the recorded result') from None
        return result
    if isinstance(value, dict):
        return {key: resolve_references(item, completed) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_references(item, completed) for item in value]
    return value

def references_in(value):
    if isinstance(value, dict):
        if '$step' in value:
            yield value
        else:
            for item in value.values():
                yield from references_in(item)
    elif isinstance(value, list):
        for item in value:
            yield from references_in(item)

def plan_worker(cfg, operation_id, steps, rollback_on_failure, timeout):
    completed = []
    compensation = []
    try:
        state.update(cfg, operation_id, 'running', phase='executing_steps', completed_steps=[])
        for index, step in enumerate(steps):
            fn = mcp._tool_manager.get_tool(step['tool']).fn
            arguments = resolve_references(step['arguments'], completed)
            fn(**{**arguments, 'dry_run': True})  # Recheck current state at the time of execution.
            result = wait_task(cfg, fn(**{**arguments, 'dry_run': False}), timeout)
            completed.append({'index': index, 'tool': step['tool'], 'result': codec.scrub(result)})
            state.update(cfg, operation_id, completed_steps=completed)
        state.update(cfg, operation_id, 'completed', phase='completed')
    except Exception as error:
        uncertain = state.uncertain_error(error)
        if rollback_on_failure and not uncertain:
            for item in reversed(completed):
                undo = steps[item['index']].get('compensate')
                if not undo:
                    compensation.append({'index': item['index'], 'status': 'manual_review', 'reason': 'No compensation supplied'})
                    continue
                try:
                    fn = mcp._tool_manager.get_tool(undo['tool']).fn
                    arguments = resolve_references(undo['arguments'], completed)
                    fn(**{**arguments, 'dry_run': True})
                    value = wait_task(cfg, fn(**{**arguments, 'dry_run': False}), timeout)
                    compensation.append({'index': item['index'], 'status': 'completed', 'result': codec.scrub(value)})
                except Exception as failure:
                    compensation.append({'index': item['index'], 'status': 'failed', 'error_type': type(failure).__name__})
                state.update(cfg, operation_id, compensation=compensation)
        state.update(cfg, operation_id, 'needs_review', error_type=type(error).__name__,
                     completed_steps=completed, compensation=compensation,
                     compensation_skipped_for_uncertain_effect=uncertain,
                     note='Inspect the failing step for partial effects; compensation is not an atomic transaction')

@mcp.tool(annotations=WRITE)
@_audited
def esxi_execute_plan(steps: List[Dict[str, Any]], rollback_on_failure: bool = False,
                        timeout_per_step: int = 180, dry_run: bool = True,
                        request_id: Optional[str] = None) -> Dict[str, Any]:
    """后台顺序执行明确步骤；每步先预览，异步任务等到成功再下一步。可指定compensate，失败按逆序执行；不承诺原子回滚、不自动重试。"""
    cfg = load_config()
    _guard_writes(cfg, dry_run)
    if not 1 <= len(steps) <= 50 or not 1 <= timeout_per_step <= 3600:
        raise ToolError('Expected1..50 steps and1..3600s per-step timeout')
    if not dry_run:
        replay = state.replay(cfg, 'execute_plan', {'steps':steps, 'rollback_on_failure':rollback_on_failure,
                              'timeout_per_step':timeout_per_step}, request_id)
        if replay:
            return replay
    previews = []
    for index, step in enumerate(steps):
        for candidate in (step, step.get('compensate')):
            if candidate is None:
                continue
            name = candidate.get('tool', '')
            fn = mcp._tool_manager.get_tool(name)
            if fn is None or name in ('esxi_execute_plan', 'esxi_ovf_import', 'esxi_ovf_export') or name.startswith(('esxi_transfer_', 'esxi_stage_')):
                raise ToolError('Workflow step must be a synchronous resource/VM mutation tool')
            if not isinstance(candidate.get('arguments'), dict) or 'dry_run' not in fn.parameters.get('properties', {}):
                raise ToolError('Workflow steps require arguments and a dry_run-capable tool')
            for reference in references_in(candidate['arguments']):
                if set(reference) != {'$step','path'} or not isinstance(reference['$step'], int) or not 0 <= reference['$step'] <= index:
                    raise ToolError('Only backward step references are permitted; compensation may reference its own completed step')
            if name == 'esxi_api_invoke' and candidate['arguments'].get('method') in ('ExportVm','ExportVApp','ImportVApp','ExportSnapshot'):
                raise ToolError('Lease workflows must use the dedicated OVF tools, not a synchronous plan step')
        dynamic = bool(list(references_in(step['arguments'])))
        if any(ref['$step'] >= index for ref in references_in(step['arguments'])):
            raise ToolError('Forward steps cannot reference themselves or a future step')
        previews.append({'index': index, 'tool': step['tool'],
                         'preview': {'deferred_until_previous_steps_complete': True} if dynamic else
                         mcp._tool_manager.get_tool(step['tool']).fn(**{**step['arguments'], 'dry_run': True})})
    if dry_run:
        return {'dry_run': True, 'steps': previews, 'rollback_on_failure': rollback_on_failure,
                'atomic': False}
    operation_id, replay = state.begin(cfg, 'execute_plan', {'steps': steps, 'rollback_on_failure': rollback_on_failure,
                                                           'timeout_per_step': timeout_per_step}, request_id)
    if replay:
        return replay
    state.update(cfg, operation_id, 'queued', result={'operation_id': operation_id, 'state': 'queued'})
    threading.Thread(target=plan_worker, args=(cfg, operation_id, steps, rollback_on_failure, timeout_per_step), daemon=True).start()
    return {'operation_id': operation_id, 'state': 'queued', 'atomic': False}

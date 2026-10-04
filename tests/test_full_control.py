"""Failure, ownership and workflow contracts which cannot be inferred from a tool count."""
import base64
import hashlib
import importlib.util
import os
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
import pytest
from pyVmomi import vim
from mcp.server.fastmcp.exceptions import ToolError
from esxi_mcp import state, transfers, workflows, advanced, files
from test_mock import make_cfg
from test_advanced import Stub, connection

@pytest.fixture
def cfg(tmp_path):
    return replace(make_cfg(enable_writes=True), state_dir=str(tmp_path/'private'))

def test_opaque_ssh_payload_and_output_never_enter_durable_journal(cfg):
    secret = 'ARBITRARY_TEST_SECRET'
    op, _ = state.begin(cfg, 'esxi_shell', {'command': 'set-password ' + secret})
    state.finish(cfg, op, {'state':'completed', 'stdout':secret, 'stderr':secret})
    assert secret not in str(state.get(cfg, op))
    op, _ = state.begin(cfg, 'execute_plan', {'steps':[{'tool':'esxi_esxcli', 'arguments':{'arguments':['--password='+secret]}}]})
    assert secret not in str(state.get(cfg, op))

def test_background_request_replay_returns_same_handle_without_relaunch(cfg):
    op, _ = state.begin(cfg, 'transfer', {'path':'test'}, 'same-job')
    state.update(cfg, op, 'running')
    value = state.begin(cfg, 'transfer', {'path':'test'}, 'same-job')[1]
    assert value['job_id'] == op and value['state'] == 'running' and value['replayed']

def test_completed_delete_replays_without_reconnecting_to_missing_vm(cfg, monkeypatch):
    target={'_type':'vim.VirtualMachine','_moId':'deleted'}
    op,_=state.begin(cfg,'vim.VirtualMachine:Destroy_Task',{'target':target,'arguments':{}},'delete-once')
    state.finish(cfg,op,{'state':'completed'})
    monkeypatch.setenv('ESXI_ENABLE_ADVANCED_WRITES','true')
    with patch.object(advanced,'load_config',return_value=cfg), patch('esxi_mcp.tools.load_config',return_value=cfg), \
         patch.object(advanced.api,'service_instance') as connect:
        value=advanced.esxi_api_invoke(target,'Destroy_Task',expected_target='vim.VirtualMachine:deleted',
            dry_run=False,request_id='delete-once')
    assert value['replayed']
    connect.assert_not_called()

def test_vm_reconfiguration_cannot_indirectly_attach_protected_backing_files(cfg):
    from esxi_mcp import policy
    graph={'vms':[{'vm_id':'protected','protected':True,'files':['[store] management/vm.vmx','[store] external/disk.vmdk']}]}
    vm=vim.VirtualMachine('ordinary',None)
    with patch.object(policy,'snapshot',return_value=graph):
        report=policy.impact(None,cfg,vm,'ReconfigVM_Task',{'spec':{'deviceChange':[
            {'device':{'backing':{'fileName':'[store] external/disk.vmdk'}}}]}})
    assert report['protected_vm_ids']==['protected']
    with pytest.raises(ToolError,match='every affected'):
        policy.enforce_impact(cfg,report)

def test_host_tools_iso_is_not_treated_as_a_datastore_path():
    from esxi_mcp import policy
    vm={'files':['[] /usr/lib/vmware/isoimages/linux.iso','[store] vm/disk.vmdk']}
    assert not policy.owns_file(vm,'store','unrelated.bin')
    assert policy.owns_file(vm,'store','vm/disk.vmdk')

@pytest.mark.parametrize('module',['files','api_transfer','transfers','workflows','advanced','resources','guest','admin'])
def test_independent_module_imports_register_all_tools_without_circular_import(module):
    import subprocess,sys
    project=Path(__file__).parents[1]
    code="import importlib; importlib.import_module('esxi_mcp.'+"+repr(module)+"); from esxi_mcp.tools import mcp; assert len(mcp._tool_manager._tools)==63"
    result=subprocess.run([sys.executable,'-c',code],env={**os.environ,'PYTHONPATH':str(project/'src')},
                          capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr

def test_resume_claim_is_exclusive_across_connections(cfg):
    op, _ = state.begin(cfg, 'transfer', {})
    state.update(cfg, op, 'failed')
    state.claim_transfer(cfg, op)
    with pytest.raises(ToolError, match='no longer resumable'):
        state.claim_transfer(cfg, op)
    assert state.get(cfg, op)['status'] == 'queued'

def test_process_probe_recognizes_current_process_without_killing_it():
    assert transfers.process_alive(os.getpid())
    assert not transfers.process_alive(-1)

def test_protected_vm_external_disk_directory_is_also_protected(cfg):
    cfg = replace(cfg, protected_vm_ids=['p'])
    vm = NS(config=NS(files=NS(vmPathName='[store] vm/vm.vmx'),
        hardware=NS(device=[NS(backing=NS(fileName='[store] external/disk.vmdk'))])))
    with patch.object(files.api, 'find_vm_by_id', return_value=vm):
        with pytest.raises(ToolError, match='protected VM'):
            files.protected_path(None, cfg, 'store', 'external/disk.vmdk')
        files.protected_path(None, cfg, 'store', 'unrelated/test.bin')

def test_explicit_administrator_override_can_control_a_protected_vm(cfg, monkeypatch):
    cfg = replace(cfg, protected_vm_ids=['p'], policy_profile='administrator', allow_protected_impact=True)
    stub = Stub()
    monkeypatch.setenv('ESXI_ENABLE_ADVANCED_WRITES', 'true')
    with patch.object(advanced, 'load_config', return_value=cfg), patch('esxi_mcp.tools.load_config', return_value=cfg), \
        patch.object(advanced.api, 'service_instance', lambda *_a, **_k: connection(stub)), \
        patch.object(vim.VirtualMachine, 'name', new_callable=lambda: property(lambda _vm:'protected')):
        result = advanced.esxi_api_invoke({'_type':'vim.VirtualMachine','_moId':'p'}, 'Destroy_Task',
            expected_target='vim.VirtualMachine:p', dry_run=False, allow_protected_impact=True)
    assert result['state'] == 'completed' and len(stub.calls) == 1

def test_uncertain_failing_step_does_not_automatically_compensate(cfg):
    calls = []
    def run(**args):
        if args['dry_run']:
            return {'dry_run':True}
        calls.append(args['name'])
        if args['name'] == 'uncertain':
            raise ConnectionError('Connection lost during mutation')
        return {'state':'completed'}
    steps = [{'tool':'fake','arguments':{'name':'first'}, 'compensate':{'tool':'fake','arguments':{'name':'undo'}}},
             {'tool':'fake','arguments':{'name':'uncertain'}}]
    op, _ = state.begin(cfg, 'execute_plan', {})
    with patch.object(workflows.mcp._tool_manager, 'get_tool', return_value=NS(fn=run)):
        workflows.plan_worker(cfg, op, steps, True, 1)
    assert calls == ['first','uncertain']
    assert state.get(cfg, op)['compensation_skipped_for_uncertain_effect']

@contextmanager
def fake_connection(si):
    yield si

def test_ovf_export_creates_descriptor_manifest_and_completes_original_lease(cfg):
    events = []
    lease = NS(info=NS(deviceUrl=[NS(key='disk-key', disk=True, url='https://host/nfc/disk')]),
               state='ready', HttpNfcLeaseProgress=lambda _p:events.append('progress'),
               HttpNfcLeaseComplete=lambda:events.append('complete'))
    def descriptor(vm, params):
        assert params.ovfFiles[0].deviceId == 'disk-key' and params.ovfFiles[0].path == 'disk-0.vmdk'
        events.append('descriptor')
        return NS(error=[], warning=[], ovfDescriptor='<OVF-test/>')
    si = NS(_stub=None, RetrieveContent=lambda:NS(ovfManager=NS(CreateDescriptor=descriptor)))
    disk = workflows.artifact(cfg, 'disk-0.vmdk', b'disk-content')
    op, _ = state.begin(cfg, 'ovf_export', {})
    with patch.object(workflows.api, 'service_instance', lambda *_a, **_k:fake_connection(si)), \
         patch.object(workflows.codec, 'reference', side_effect=lambda ref,_stub:lease if ref=='lease' else vim.VirtualMachine('v',None)), \
         patch.object(workflows, 'inline_transfer', return_value=(disk['job_id'], state.get(cfg,disk['job_id']))):
        workflows.export_worker(cfg, op, 'vm', 'lease', 100)
    entry = state.get(cfg, op)
    assert entry['status'] == 'completed' and entry['lease_completed']
    assert events[-2:] == ['descriptor','complete']
    manifest = entry['files'][-1]
    assert b'SHA256(disk-0.vmdk)' in (transfers.directory(cfg,manifest['job_id'])/'body').read_bytes()

@pytest.mark.parametrize('create,method,content_type',[
    (False,'POST','application/x-vnd.vmware-streamVmdk'),
    (True,'PUT','application/octet-stream'),
])
def test_ovf_import_matches_device_id_uses_sdk_file_semantics_then_completes(cfg,create,method,content_type):
    specs, events = [], []
    vm = vim.VirtualMachine('new-vm',None)
    lease = NS(state='ready', info=NS(entity=vm, deviceUrl=[NS(importKey='disk-id',url='https://host/nfc/disk')]),
        HttpNfcLeaseProgress=lambda _p:None, HttpNfcLeaseComplete=lambda:events.append('complete'))
    si = NS(_stub=None)
    op, _ = state.begin(cfg, 'ovf_import', {})
    def transfer(_cfg,spec):
        specs.append(spec)
        return 'disk-job', {'bytes':4,'sha256':hashlib.sha256(b'disk').hexdigest()}
    with patch.object(workflows.api, 'service_instance', lambda *_a, **_k:fake_connection(si)), \
         patch.object(workflows.codec, 'reference', return_value=lease), patch.object(workflows,'inline_transfer',side_effect=transfer):
        workflows.import_worker(cfg,op,'lease',[NS(path='disk.vmdk',deviceId='disk-id',size=4,create=create)],
            {'disk.vmdk':{'source_job_id':'source','max_bytes':4}},False)
    assert specs[0]['http_method'] == method and specs[0]['content_type'] == content_type
    assert specs[0]['overwrite'] == create
    assert events == ['complete'] and state.get(cfg,op)['imported_entity']['_moId'] == 'new-vm'

def test_ovf_failure_aborts_owned_import_lease_and_reports_cleanup(cfg):
    events=[]
    lease = NS(state='ready',info=NS(entity=vim.VirtualMachine('new',None),deviceUrl=[]),
               HttpNfcLeaseAbort=lambda:events.append('abort'))
    op,_=state.begin(cfg,'ovf_import',{})
    with patch.object(workflows.api,'service_instance',lambda *_a,**_k:fake_connection(NS(_stub=None))), \
         patch.object(workflows.codec,'reference',return_value=lease):
        workflows.import_worker(cfg,op,'lease',[NS(path='disk',deviceId='missing')],{'disk':{}},False)
    assert events == ['abort'] and state.get(cfg,op)['status'] == 'failed'
    assert not state.get(cfg,op)['cleanup_needs_review']

def test_portable_client_fetch_resumes_partial_and_checks_complete_sha256(cfg, tmp_path):
    import asyncio
    path = Path(__file__).parents[1]/'scripts'/'file_client.py'
    spec = importlib.util.spec_from_file_location('file_client',path)
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    payload = b'portable-client-test'
    output=tmp_path/'result.bin'
    handle='handle'
    output.with_name(output.name+'.part-'+handle).write_bytes(payload[:4])
    async def call(_client,name,args):
        if name=='esxi_transfer_status':
            return {'status':'completed','bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
        offset=args['offset']
        data=payload[offset:]
        return {'offset':offset,'next_offset':len(payload),'bytes':len(data),'eof':True,'data_base64':base64.b64encode(data).decode()}
    with patch.object(client,'call',side_effect=call):
        result=asyncio.run(client.fetch(None,handle,output))
    assert output.read_bytes()==payload and result['bytes']==len(payload)

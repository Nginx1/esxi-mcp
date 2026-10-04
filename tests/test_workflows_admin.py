from dataclasses import replace
from unittest.mock import patch
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from esxi_mcp import admin, workflows, state
from test_mock import make_cfg

def test_esxcli_arguments_cannot_become_shell_code():
    command = admin.arguments_command(['system','hostname','set','--host=literal; echo injection'])
    assert "'--host=literal; echo injection'" in command
    with pytest.raises(ToolError):
        admin.arguments_command(['system','version','get\nshutdown'])

@pytest.mark.parametrize('descriptor', [
    '<!DOCTYPE Envelope [<!ENTITY x SYSTEM "file:///etc/passwd">]><Envelope/>',
    '<Envelope/>',
    '<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:o="http://schemas.dmtf.org/ovf/envelope/1"><References><File o:href="../disk.vmdk"/></References></Envelope>',
])
def test_ovf_external_entities_and_traversal_are_rejected(descriptor):
    with pytest.raises(ToolError):
        workflows.validate_ovf(descriptor)

def test_ovf_valid_relative_file_reference_is_preserved():
    xml = '<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:o="http://schemas.dmtf.org/ovf/envelope/1"><References><File o:href="disk-0.vmdk"/></References></Envelope>'
    assert workflows.validate_ovf(xml) == ['disk-0.vmdk']

def test_plan_failure_runs_only_explicit_compensations_in_reverse_order(tmp_path):
    from types import SimpleNamespace
    cfg = replace(make_cfg(enable_writes=True), state_dir=str(tmp_path/'private'))
    calls = []
    def run(**arguments):
        if arguments.get('dry_run'):
            return {'dry_run': True}
        calls.append(arguments['name'])
        if arguments['name'] == 'fail':
            raise ToolError('failure')
        return {'state':'completed'}
    step = lambda name: {'tool':'fake', 'arguments':{'name':name}}
    first, second = step('first'), step('second')
    first['compensate'], second['compensate'] = step('undo-first'), step('undo-second')
    op, _ = state.begin(cfg, 'execute_plan', {})
    with patch.object(workflows.mcp._tool_manager, 'get_tool', return_value=SimpleNamespace(fn=run)):
        workflows.plan_worker(cfg, op, [first,second,step('fail')], True, 1)
    assert calls == ['first','second','fail','undo-second','undo-first']
    entry = state.get(cfg, op)
    assert entry['status'] == 'needs_review' and len(entry['completed_steps']) == 2

def test_step_references_use_json_paths_and_never_eval_code():
    completed = [{'result': {'result': {'_type': 'vim.VirtualMachine', '_moId':'new-vm'}}}]
    args = {'vm_id': {'$step':0, 'path':['result','_moId']}, 'expected_name':'new-name'}
    assert workflows.resolve_references(args, completed)['vm_id'] == 'new-vm'
    with pytest.raises(ToolError):
        workflows.resolve_references({'$step':2,'path':[]}, completed)
    with pytest.raises(ToolError):
        workflows.resolve_references({'$step':0,'path':['__class__']}, completed)

def test_readonly_esxcli_catalog_does_not_trust_caller_claims(tmp_path):
    cfg = replace(make_cfg(), ssh_admin_enabled=True, policy_profile='administrator')
    with patch.object(admin, 'load_config', return_value=cfg), patch('esxi_mcp.tools.load_config', return_value=cfg), patch.object(admin, 'run') as run:
        with pytest.raises(ToolError, match='read-only'):
            admin.esxi_esxcli_query(['storage','filesystem','unmount','--volume-label=test'])
        run.assert_not_called()

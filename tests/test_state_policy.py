import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from pyVmomi import vim
from mcp.server.fastmcp.exceptions import ToolError
from esxi_mcp import policy, state
from esxi_mcp.resources import CATALOG
from esxi_mcp.advanced import methods
from esxi_mcp.codec import resolve_type
from test_mock import make_cfg

@pytest.fixture
def cfg(tmp_path):
    return replace(make_cfg(enable_writes=True), state_dir=str(tmp_path / 'private'))

def test_request_id_cannot_reexecute_an_inflight_operation(cfg):
    op, replay = state.begin(cfg, 'change', {'value': 1}, 'stable-id')
    assert replay is None
    with pytest.raises(ToolError, match='already executing'):
        state.begin(cfg, 'change', {'value': 1}, 'stable-id')
    state.finish(cfg, op, {'state': 'completed', 'ok': True})
    assert state.begin(cfg, 'change', {'value': 1}, 'stable-id')[1]['replayed']
    with pytest.raises(ToolError, match='different'):
        state.begin(cfg, 'change', {'value': 2}, 'stable-id')

def test_journal_is_account_bound_and_redacts_sensitive_arguments(cfg):
    op, _ = state.begin(cfg, 'change', {'password': 'GUEST_TEST_SECRET', 'label': cfg.password,
                                       'source_url': 'https://example.invalid/?token=SECRET'})
    raw = json.dumps(state.get(cfg, op))
    assert 'GUEST_TEST_SECRET' not in raw and cfg.password not in raw and 'token=SECRET' not in raw
    with pytest.raises(ToolError, match='not found'):
        state.get(replace(cfg, host='another-host'), op)

def test_dependency_protection_requires_both_config_and_call_acknowledgement(cfg):
    report = {'affected_vm_ids': ['ordinary', 'management'], 'protected_vm_ids': ['management'],
              'networks': [], 'datastores': [], 'management_disruption': True, 'unknown_impact': False}
    admin = replace(cfg, policy_profile='administrator', allow_management_disruption=True, allow_protected_impact=True)
    with pytest.raises(ToolError, match='every affected'):
        policy.enforce_impact(admin, report, ['ordinary'], True, False, True)
    with pytest.raises(ToolError, match='both explicitly'):
        policy.enforce_impact(admin, report, ['ordinary','management'], True)
    policy.enforce_impact(admin, report, ['ordinary','management'], True, False, True)
    policy.enforce_impact(cfg, report, dry_run=True)

def test_shared_network_and_file_deletion_detect_indirect_protected_vm(cfg):
    graph = {'vms': [{'vm_id':'protected', 'protected':True, 'networks':['management-pg'],
                     'datastores':['store'], 'files':['[store] protected/protected.vmx','[store] protected/disk.vmdk']}],
             'vmkernel': [{'device':'vmk0','portgroup':'management-pg','management':True}],
             'switches':[{'name':'vSwitch0','portgroups':['management-pg']}]}
    with patch.object(policy, 'snapshot', return_value=graph):
        report = policy.impact(None, cfg, vim.host.NetworkSystem('network', None), 'RemoveVirtualSwitch', {'vswitchName':'vSwitch0'})
        assert report['protected_vm_ids'] == ['protected'] and report['management_disruption']
        report = policy.impact(None, cfg, vim.FileManager('files', None), 'DeleteDatastoreFile_Task', {'name':'[store] protected'})
        assert report['protected_vm_ids'] == ['protected']

def test_operation_allowlist_and_admin_profile_are_enforced(cfg):
    restricted = replace(cfg, allowed_operations=['vim.host.NetworkSystem:*'], denied_operations=['*:Remove*'])
    policy.check_operation(restricted, 'vim.host.NetworkSystem:AddPortGroup')
    with pytest.raises(ToolError, match='denied'):
        policy.check_operation(restricted, 'vim.host.NetworkSystem:RemovePortGroup')
    with pytest.raises(ToolError, match='outside'):
        policy.check_operation(restricted, 'vim.HostSystem:RebootHost_Task')
    with pytest.raises(ToolError, match='administrator'):
        policy.check_operation(cfg, 'vim.HostSystem:RebootHost_Task', administrator=True)

def test_every_dedicated_catalog_method_exists_in_actual_pyvmomi_schema():
    for domain, (_, type_name, actions) in CATALOG.items():
        declared = methods(resolve_type(type_name))
        assert set(actions.values()).issubset(declared), domain

@pytest.mark.parametrize('value', ['../escape', '/absolute', '', 'id/child'])
def test_state_handles_cannot_address_arbitrary_server_paths(value):
    with pytest.raises(ToolError):
        state.validate_id(value)

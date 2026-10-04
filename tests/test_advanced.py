from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from pyVmomi import vim, VmomiSupport as V
from mcp.server.fastmcp.exceptions import ToolError
from esxi_mcp import advanced as A, codec
from test_mock import make_cfg

def test_typed_network_and_vm_devices():
    spec = codec.decode({'name': 'test-pg', 'vlanId': 123, 'vswitchName': 'test-vswitch', 'policy': {}},
                        vim.host.PortGroup.Specification, None)
    assert isinstance(spec, vim.host.PortGroup.Specification) and spec.vlanId == 123
    device = codec.decode({'_type': 'vim.vm.device.VirtualVmxnet3', 'key': -1}, vim.vm.device.VirtualDevice, None)
    assert isinstance(device, vim.vm.device.VirtualVmxnet3)

@pytest.mark.parametrize('payload,expected', [
    ({'_type': 'os.system'}, vim.vm.ConfigSpec),
    ({'unknown': 1}, vim.vm.ConfigSpec),
    ({'_type': 'vim.host.PortGroup.Specification'}, vim.vm.ConfigSpec),
    ('1', int), (True, int), (1, bool), (float('inf'), float),
    ('invalid-state', vim.VirtualMachinePowerState),
])
def test_untyped_and_invalid_arguments_rejected(payload, expected):
    with pytest.raises(ToolError):
        codec.decode(payload, expected, None)

def test_reference_has_exact_fields_and_type():
    value = codec.reference({'_type': 'vim.VirtualMachine', '_moId': 'vm-1'}, None)
    assert isinstance(value, vim.VirtualMachine)
    with pytest.raises(ToolError):
        codec.reference({'_type': 'vim.VirtualMachine', '_moId': 'vm-1', 'extra': True}, None)

def test_authentication_and_option_secrets_redacted():
    auth = vim.vm.guest.NamePasswordAuthentication(username='test', password='FAKE_GUEST_PASSWORD', interactiveSession=False)
    assert codec.encode(auth)['password'] == '[REDACTED]'
    option = vim.option.OptionValue(key='guestinfo.password', value='FAKE_GUEST_PASSWORD')
    assert codec.encode(option)['value'] == '[REDACTED]'
    assert codec.scrub({'arguments': {'auth': {'password': 'FAKE_GUEST_PASSWORD'}}})['arguments']['auth']['password'] == '[REDACTED]'

class Stub:
    def __init__(self):
        self.calls = []
    def InvokeMethod(self, obj, info, args):
        self.calls.append((obj._moId, info.name, args))
        return None

@contextmanager
def connection(stub):
    yield SimpleNamespace(_stub=stub)

def invoke(monkeypatch, **values):
    cfg = make_cfg(enable_writes=True)
    stub = Stub()
    monkeypatch.setenv('ESXI_ENABLE_ADVANCED_WRITES', 'true')
    with patch.object(A, 'load_config', return_value=cfg), \
         patch('esxi_mcp.tools.load_config', return_value=cfg), \
         patch.object(A.api, 'service_instance', lambda _cfg, **_kwargs: connection(stub)):
        result = A.esxi_api_invoke(target={'_type': 'vim.host.NetworkSystem', '_moId': 'network-test'},
                                  method='AddVirtualSwitch', arguments={'vswitchName': 'mcp-test', 'spec': {'numPorts': 64}},
                                  **values)
    return result, stub

def test_default_preview_never_invokes_sdk(monkeypatch):
    result, stub = invoke(monkeypatch)
    assert result['dry_run'] and stub.calls == []

def test_real_typed_execution_calls_correct_managed_object(monkeypatch):
    result, stub = invoke(monkeypatch, dry_run=False, allow_disruption=True,
                          expected_target='vim.host.NetworkSystem:network-test')
    assert result['state'] == 'completed'
    assert stub.calls[0][:2] == ('network-test', 'AddVirtualSwitch')
    assert isinstance(stub.calls[0][2][1], vim.host.VirtualSwitch.Specification)

@pytest.mark.parametrize('values', [
    {'dry_run': False, 'allow_disruption': True, 'expected_target': 'wrong'},
    {'dry_run': False, 'expected_target': 'vim.host.NetworkSystem:network-test'},
])
def test_execution_requires_identity_and_disruption_opt_in(monkeypatch, values):
    with pytest.raises(ToolError):
        invoke(monkeypatch, **values)

def test_schema_matches_official_sdk():
    cfg = make_cfg()
    with patch('esxi_mcp.tools.load_config', return_value=cfg):
        result = A.esxi_api_schema('vim.host.NetworkSystem', 'AddVirtualSwitch')
    method = result['methods'][0]
    assert method['parameters']['vswitchName']['type'] == 'str'
    assert method['parameters']['spec']['type'] == 'vim.host.VirtualSwitch.Specification'

def test_generic_call_cannot_mutate_a_protected_vm(monkeypatch):
    cfg = make_cfg(protected=['protected-test'], enable_writes=True)
    stub = Stub()
    monkeypatch.setenv('ESXI_ENABLE_ADVANCED_WRITES', 'true')
    with patch.object(A, 'load_config', return_value=cfg), \
         patch('esxi_mcp.tools.load_config', return_value=cfg), \
         patch.object(A.api, 'service_instance', lambda _cfg, **_kwargs: connection(stub)), \
         patch.object(vim.VirtualMachine, 'name', new_callable=lambda: property(lambda _vm: 'management')):
        with pytest.raises(ToolError, match='受保护'):
            A.esxi_api_invoke(target={'_type': 'vim.VirtualMachine', '_moId': 'protected-test'},
                              method='Destroy_Task', expected_target='vim.VirtualMachine:protected-test',
                              dry_run=False)
    assert stub.calls == []

def test_advanced_calls_need_additional_write_opt_in(monkeypatch):
    cfg = make_cfg(enable_writes=True)
    monkeypatch.delenv('ESXI_ENABLE_ADVANCED_WRITES', raising=False)
    with patch.object(A, 'load_config', return_value=cfg), patch('esxi_mcp.tools.load_config', return_value=cfg):
        with pytest.raises(ToolError, match='ESXI_ENABLE_ADVANCED_WRITES'):
            A.esxi_api_invoke(target={'_type': 'vim.host.NetworkSystem', '_moId': 'test'},
                              method='AddVirtualSwitch', arguments={'vswitchName': 'test'}, dry_run=False)

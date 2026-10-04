import json
import types
from unittest.mock import patch
import pytest
from pyVmomi import vim
from mcp.server.fastmcp.exceptions import ToolError
from esxi_mcp import tools as T
from esxi_mcp.config import load_config
from test_mock import FakeVM, make_cfg, _patch, _run_with

def test_false_environment_overrides_true_deployment(tmp_path):
    creds = tmp_path/'credentials.json'
    creds.write_text(json.dumps({'host':'unused','user':'unused','password':'TEST_SECRET'}))
    (tmp_path/'config.json').write_text(json.dumps({'enable_writes':True}))
    cfg = load_config({'ESXI_CONFIG_FILE':str(creds),'ESXI_ENABLE_WRITES':'false'})
    assert cfg.enable_writes is False
    assert 'TEST_SECRET' not in repr(cfg)

@pytest.mark.parametrize('changes',[{'cpu_mhz_limit':40},{'cpu_mhz_reservation':120}])
def test_effective_resource_allocation_is_validated(changes):
    vm = FakeVM('vm-1','web-01')
    vm.config.cpuAllocation = vim.ResourceAllocationInfo(limit=100,reservation=80)
    vm.config.memoryAllocation = vim.ResourceAllocationInfo(limit=-1,reservation=0)
    with pytest.raises(ToolError):
        _run_with(_patch(vm,make_cfg(enable_writes=True)),
                  lambda:T.esxi_configure_vm('vm-1','web-01',dry_run=True,**changes))

def test_rejected_operation_has_redacted_outcome_audit():
    vm=FakeVM('vm-1','web-01')
    cfg=make_cfg(enable_writes=True)
    records=[]
    def capture(entry,_path):
        records.append(entry)
    with patch.object(T,'audit',capture), pytest.raises(ToolError) as error:
        _run_with(_patch(vm,cfg),lambda:T.esxi_power_vm('vm-1','power_off',cfg.password,dry_run=False))
    assert records[-1]['state']=='error'
    assert cfg.password not in json.dumps(records)
    assert cfg.password not in str(error.value)

def test_successful_dry_run_has_outcome_audit():
    vm=FakeVM('vm-1','web-01')
    records=[]
    with patch.object(T,'audit',lambda entry,_path:records.append(entry)):
        result=_run_with(_patch(vm,make_cfg()),lambda:T.esxi_rename_vm('vm-1','web-01','web-new',dry_run=True))
    assert result['dry_run'] is True
    assert records[-1]['state']=='dry_run'

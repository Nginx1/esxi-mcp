"""Exercise mutation branches using real pyVmomi managed types and a non-network stub."""
import datetime
import json
import tempfile
from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace as NS
from unittest.mock import patch
from pyVmomi import vim
from esxi_mcp import tools as T
from esxi_mcp.config import Config

class Stub:
    def __init__(self):
        self.values = {}
        self.calls = []
    def InvokeAccessor(self, obj, info):
        return self.values[obj._moId][info.name]
    def InvokeMethod(self, obj, info, args):
        self.calls.append((obj._moId, info.name, args))
        return vim.Task('task-contract', self)

stub = Stub()
task_info = vim.TaskInfo(key='task-contract', task=vim.Task('task-contract', stub),
                         descriptionId='contract', state='queued',
                         cancelled=False, cancelable=True, reason=vim.TaskReasonUser(userName='test'),
                         queueTime=datetime.datetime.now(datetime.timezone.utc), eventChainId=1)
stub.values['task-contract'] = {'info': task_info}
snap_mo = vim.VirtualMachineSnapshot('snapshot-contract', stub)
tree = vim.vm.SnapshotTree(id=1, name='baseline', description='', snapshot=snap_mo,
                           createTime=datetime.datetime.now(datetime.timezone.utc), state='poweredOff',
                           childSnapshotList=[])
disk = vim.vm.device.VirtualDisk(key=2000, capacityInKB=20 * 1024 * 1024,
                                backing=vim.vm.device.VirtualDisk.FlatVer2BackingInfo(fileName='[ds] vm/disk.vmdk'))
cfg_info = vim.vm.ConfigInfo(name='contract-vm', instanceUuid='contract-uuid',
                             hardware=vim.vm.VirtualHardware(numCPU=2, memoryMB=2048, device=[disk]),
                             cpuHotAddEnabled=False, memoryHotAddEnabled=False,
                             cpuAllocation=vim.ResourceAllocationInfo(limit=1200, reservation=100,
                                  shares=vim.SharesInfo(shares=1000, level='custom')),
                             memoryAllocation=vim.ResourceAllocationInfo(limit=2048, reservation=256))
stub.values['vm-contract'] = {'name':'contract-vm', 'config':cfg_info,
    'runtime':vim.vm.RuntimeInfo(powerState='poweredOff'),
    'guest':vim.vm.GuestInfo(toolsRunningStatus='guestToolsRunning',net=[]),
    'snapshot':vim.vm.SnapshotInfo(rootSnapshotList=[tree],currentSnapshot=snap_mo)}
vm = vim.VirtualMachine('vm-contract', stub)
cfg = Config(host='unused',user='unused',password='CONTRACT_SECRET',enable_writes=True,
              protected_vm_ids=[],audit_file=str(Path(tempfile.gettempdir()) / 'esxi-contract-audit.jsonl'))

@contextmanager
def connection(_cfg):
    yield NS()

results = []
def run(label, function, target='vm-contract'):
    before=len(stub.calls)
    value=function()
    assert value.get('task_id') == 'task-contract', (label,value)
    assert len(stub.calls) == before + 1, label
    assert stub.calls[-1][0] == target, (label,stub.calls[-1])
    results.append({'check':label,'managed_type':target,'method':stub.calls[-1][1],'status':'PASS'})

with patch.object(T,'load_config',return_value=cfg), patch.object(T.api,'service_instance',connection), \
     patch.object(T.api,'find_vm_by_id',return_value=vm), patch.object(T.api,'find_vm_by_name',return_value=None):
    run('power_on',lambda:T.esxi_power_vm('vm-contract','power_on','contract-vm',dry_run=False))
    run('configure_preserves_omitted_fields',lambda:T.esxi_configure_vm('vm-contract','contract-vm',cpu_mhz_limit=1600,dry_run=False))
    spec=stub.calls[-1][2][0]
    assert spec.numCPUs is None and spec.memoryMB is None, 'Unspecified CPU/memory must stay unspecified'
    assert spec.cpuAllocation.limit == 1600 and spec.cpuAllocation.reservation == 100
    assert spec.cpuAllocation.shares.level == 'custom' and spec.cpuAllocation.shares.shares == 1000
    assert spec.memoryAllocation is None, 'Unspecified memory allocation must stay unspecified'
    run('create_snapshot',lambda:T.esxi_create_snapshot('vm-contract','contract-vm','new-snapshot',dry_run=False))
    run('revert_snapshot_typed_api',lambda:T.esxi_revert_snapshot('vm-contract','contract-vm','1',dry_run=False),target='snapshot-contract')
    run('delete_snapshot_typed_api',lambda:T.esxi_delete_snapshot('vm-contract','contract-vm','1',dry_run=False),target='snapshot-contract')
    run('rename',lambda:T.esxi_rename_vm('vm-contract','contract-vm','new-vm-name',dry_run=False))
    run('delete',lambda:T.esxi_delete_vm('vm-contract','contract-vm',dry_run=False))
    stub.values['vm-contract']['snapshot']=None
    run('expand_disk',lambda:T.esxi_expand_disk('vm-contract','contract-vm',2000,30,dry_run=False))

    ds=vim.Datastore('datastore-contract',stub)
    net=vim.Network('network-contract',stub)
    pool=vim.ResourcePool('pool-contract',stub)
    folder=vim.Folder('folder-contract',stub)
    stub.values['datastore-contract']={'name':'ds','summary':vim.Datastore.Summary(name='ds',accessible=True,capacity=100*1024**3,freeSpace=90*1024**3,type='VMFS')}
    stub.values['network-contract']={'name':'net'}
    dc=NS(datastore=[ds],network=[net],hostFolder=NS(childEntity=[NS(resourcePool=pool)]),vmFolder=folder)
    with patch.object(T,'_get_host',return_value=(NS(),dc,NS())):
        run('create_vm_requires_resource_pool',lambda:T.esxi_create_vm('new-contract-vm',2,2048,20,datastore='ds',network='net',dry_run=False),target='folder-contract')
        assert any(arg is pool for arg in stub.calls[-1][2]), 'CreateVM must pass a real ResourcePool'
        create_spec = stub.calls[-1][2][0]
        devices = [change.device for change in create_spec.deviceChange]
        assert len({device.key for device in devices}) == len(devices), 'New devices need unique temporary keys'
        created_disk = next(device for device in devices if isinstance(device, vim.vm.device.VirtualDisk))
        assert created_disk.backing.fileName == '[ds]', 'New disk backing must specify its datastore'

assert 'CONTRACT_SECRET' not in repr(cfg), 'Config repr must redact password'
print(json.dumps({'status':'PASS','network_calls':0,'checks':results},ensure_ascii=False))

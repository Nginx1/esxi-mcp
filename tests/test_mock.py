"""mock 测试：不连接真实 ESXi，验证护栏与逻辑分支。

覆盖：错误 id/name、重名、protected、dry-run 零写、未启用写拒绝、
snapshot 归属、有快照拒扩盘、任务状态、pool 参数、shutdown 不降级、
缩容/开机拒绝、连接/ContainerView 释放、秘密不进输出。
"""
import json
import types
import tempfile
from pathlib import Path
from contextlib import contextmanager

import pytest
from unittest import mock

from esxi_mcp import security
from esxi_mcp.config import Config
from esxi_mcp import tools as T
from mcp.server.fastmcp.exceptions import ToolError


def make_cfg(protected=None, enable_writes=False):
    return Config(host="h", user="u", password="SECRETPW", port=443, verify_ssl=False,
                  protected_vm_ids=protected or [], enable_writes=enable_writes,
                  audit_file=str(Path(tempfile.gettempdir()) / "esxi-mcp-test-audit.jsonl"),
                  state_dir=str(Path(tempfile.gettempdir()) / 'esxi-mcp-test-state'))


class FakeVM:
    def __init__(self, mo_id, name, power="poweredOff", tools_ok=True,
                 cpu=2, mem=4096, cpu_hot=False, mem_hot=False, snapshots=None,
                 devices=None, cpu_alloc=None, mem_alloc=None):
        self._moId = mo_id
        self.name = name
        self.runtime = types.SimpleNamespace(powerState=power)
        g = types.SimpleNamespace(toolsStatus="toolsOk" if tools_ok else "toolsNotRunning",
                                  toolsRunningStatus="guestToolsRunning" if tools_ok else "guestToolsNotRunning")
        self.guest = g
        import esxi_mcp.api  # noqa
        self.config = types.SimpleNamespace(
            instanceUuid=f"uuid-{mo_id}",
            hardware=types.SimpleNamespace(numCPU=cpu, memoryMB=mem,
                                           device=devices or []),
            cpuHotAddEnabled=cpu_hot, memoryHotAddEnabled=mem_hot,
            cpuAllocation=cpu_alloc, memoryAllocation=mem_alloc,
        )
        if snapshots is None:
            self.snapshot = None
        else:
            self.snapshot = types.SimpleNamespace(rootSnapshotList=snapshots, currentSnapshot=None)
        self.last_spec = None

    def ReconfigVM_Task(self, spec):
        self.last_spec = spec
        return _task("success")


def _patch(fake_vm=None, cfg=None, clashing=None):
    cfg = cfg or make_cfg()
    fake_si = types.SimpleNamespace()

    @contextmanager
    def _si(_cfg):
        yield fake_si

    p = []
    p.append(mock.patch.object(T, "load_config", return_value=cfg))
    p.append(mock.patch.object(T.api, "service_instance", _si))
    p.append(mock.patch.object(T.api, "find_vm_by_id", return_value=fake_vm))
    p.append(mock.patch.object(T.api, "find_vm_by_name", return_value=clashing))
    return p

def test_validate_name_rejects_path_chars():
    for bad in ["a/b", "a\\b", "a[b", "a]b", "..", ".", "a b "]:
        assert security.validate_vm_name(bad) is not None, bad
    for good in ["web-01", "中文主机", "a-b_c.1"]:
        assert security.validate_vm_name(good) is None, good


def test_check_protected():
    assert security.check_protected("vm-5", ["vm-5", "vm-6"])
    assert not security.check_protected("vm-7", ["vm-5", "vm-6"])


def _task(state, error=None):
    from pyVmomi import vim
    info = types.SimpleNamespace(
        state=getattr(vim.TaskInfo.State, state),
        descriptionId="desc", progress=100, error=error, result=None)
    return types.SimpleNamespace(_moId="task-1", info=info)


def test_task_to_dict_states():
    from esxi_mcp.api import task_to_dict
    assert task_to_dict(_task("success"))["state"] == "success"
    assert task_to_dict(_task("running"))["state"] == "running"
    assert task_to_dict(_task("queued"))["state"] == "queued"
    err = types.SimpleNamespace(msg="boom")
    d = task_to_dict(_task("error", err))
    assert d["state"] == "error" and d["error"]["message"] == "boom"


# --------------------------------------------------------------------------
# power_vm
# --------------------------------------------------------------------------

def _run_with(p, fn):
    for mgr in p:
        mgr.start()
    try:
        return fn()
    finally:
        for mgr in p:
            mgr.stop()


def test_power_shutdown_without_tools_no_downgrade():
    vm = FakeVM("vm-1", "web-01", power="poweredOn", tools_ok=False)
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=True))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_power_vm("vm-1", "shutdown", "web-01", dry_run=False))
    assert "Tools" in str(e.value)


def test_power_dry_run_protected():
    vm = FakeVM("vm-5", "management-vm", power="poweredOn", tools_ok=True)
    ps = _patch(fake_vm=vm, cfg=make_cfg(protected=["vm-5"], enable_writes=True))
    r = _run_with(ps, lambda: T.esxi_power_vm("vm-5", "power_off", "management-vm", dry_run=True))
    assert r["dry_run"] is True and r["protected"] is True


def test_power_execute_protected_rejects():
    vm = FakeVM("vm-5", "management-vm", power="poweredOn", tools_ok=True)
    ps = _patch(fake_vm=vm, cfg=make_cfg(protected=["vm-5"], enable_writes=True))
    with pytest.raises(ToolError):
        _run_with(ps, lambda: T.esxi_power_vm("vm-5", "power_off", "management-vm", dry_run=False))


def test_write_not_enabled_rejects():
    vm = FakeVM("vm-1", "web-01", power="poweredOn", tools_ok=True)
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=False))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_power_vm("vm-1", "power_off", "web-01", dry_run=False))
    assert "ESXI_ENABLE_WRITES" in str(e.value)


def test_wrong_vm_id_raises():
    ps = _patch(fake_vm=None, cfg=make_cfg(enable_writes=True))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_get_vm("vm-999"))
    assert "vm-999" in str(e.value)


def test_name_mismatch_raises():
    vm = FakeVM("vm-1", "actual-name")
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=True))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_power_vm("vm-1", "power_off", "wrong-name", dry_run=False))
    assert "名称不匹配" in str(e.value)


def test_dry_run_does_zero_write():
    vm = FakeVM("vm-1", "web-01", power="poweredOn", tools_ok=True)
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=True))
    r = _run_with(ps, lambda: T.esxi_power_vm("vm-1", "power_off", "web-01", dry_run=True))
    assert r["dry_run"] is True and "planned_operation" in r
    # PowerOffVM_Task 未调用：FakeVM 没有该方法，若被调用会 AttributeError


# --------------------------------------------------------------------------
# configure_vm
# --------------------------------------------------------------------------

def test_shrink_while_on_rejects():
    vm = FakeVM("vm-1", "web-01", power="poweredOn", cpu=8, mem=16384)
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=True))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_configure_vm("vm-1", "web-01", cpu=2, dry_run=False))
    assert "关机" in str(e.value)


def test_grow_no_hotadd_while_on_rejects():
    vm = FakeVM("vm-1", "web-01", power="poweredOn", cpu=2, mem=4096, cpu_hot=False)
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=True))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_configure_vm("vm-1", "web-01", cpu=8, dry_run=False))
    assert "hot-add" in str(e.value)


# --------------------------------------------------------------------------
# create_vm / rename
# --------------------------------------------------------------------------

def _fake_dc(pool_moid="resgroup-1"):
    datastore = types.SimpleNamespace(name="datastore1", summary=types.SimpleNamespace(
        accessible=True, freeSpace=100 * 1024 * 1024 * 1024, type="VMFS"))
    network = types.SimpleNamespace(name="VM Network")
    pool = types.SimpleNamespace(_moId=pool_moid)
    host = types.SimpleNamespace(_moId="host-1")
    hm = types.SimpleNamespace(name="datastore1")
    dc = types.SimpleNamespace(
        datastore=[datastore], network=[network],
        hostFolder=types.SimpleNamespace(childEntity=[types.SimpleNamespace(resourcePool=pool, host=[host])]),
        vmFolder=types.SimpleNamespace(_moId="group-v3"))
    return dc, pool


def test_create_vm_duplicate_name_rejects():
    ps = _patch(fake_vm=None, clashing=FakeVM("vm-2", "new-vm"), cfg=make_cfg(enable_writes=True))
    ps.append(mock.patch.object(T, "_get_host", lambda si: (None, _fake_dc()[0], None)))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_create_vm("new-vm", 2, 4096, 20,
                                             datastore="datastore1", network="VM Network", dry_run=True))
    assert "重名" in str(e.value)


def test_create_vm_dry_run_returns_pool():
    dc, pool = _fake_dc(pool_moid="resgroup-42")
    ps = _patch(fake_vm=None, clashing=None, cfg=make_cfg(enable_writes=True))
    ps.append(mock.patch.object(T, "_get_host", lambda si: (None, dc, None)))
    r = _run_with(ps, lambda: T.esxi_create_vm("new-vm", 2, 4096, 20, datastore="datastore1",
                                               network="VM Network", dry_run=True))
    assert r["dry_run"] is True
    assert r["resource_pool"] == "resgroup-42"


def test_create_vm_bad_datastore_rejects():
    dc, pool = _fake_dc()
    ps = _patch(fake_vm=None, clashing=None, cfg=make_cfg(enable_writes=True))
    ps.append(mock.patch.object(T, "_get_host", lambda si: (None, dc, None)))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_create_vm("new-vm", 2, 4096, 20,
                                             datastore="nope", network="VM Network", dry_run=True))
    assert "datastore" in str(e.value)


# --------------------------------------------------------------------------
# snapshots / expand disk
# --------------------------------------------------------------------------

def _snap(i, name="s1", children=None):
    return types.SimpleNamespace(id=i, name=name, description="", state="poweredOn",
                                 createTime="2026-01-01", childSnapshotList=children or [])


def test_expand_disk_with_snapshot_rejects():
    sn = [_snap(10)]
    vm = FakeVM("vm-1", "web-01", snapshots=sn)
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=True))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_expand_disk("vm-1", "web-01", device_key=2000,
                                                 new_size_gb=60, dry_run=False))
    assert "快照" in str(e.value)


def test_revert_snapshot_not_in_tree_rejects():
    vm = FakeVM("vm-1", "web-01", snapshots=[_snap(10)])
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=True))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_revert_snapshot("vm-1", "web-01", "999", dry_run=False))
    assert "999" in str(e.value)


def test_create_snapshot_duplicate_name_rejects():
    vm = FakeVM("vm-1", "web-01", snapshots=[_snap(10, name="dup")])
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=True))
    with pytest.raises(ToolError) as e:
        _run_with(ps, lambda: T.esxi_create_snapshot("vm-1", "web-01", "dup", dry_run=False))
    assert "重复" in str(e.value)


# --------------------------------------------------------------------------
# 寻址/释放/秘密
# --------------------------------------------------------------------------

def test_revert_snapshot_uses_correct_vm():
    vm = FakeVM("vm-1", "web-01", snapshots=[_snap(10)])
    ps = _patch(fake_vm=vm, cfg=make_cfg(enable_writes=True))
    # dry-run 归属正确
    r = _run_with(ps, lambda: T.esxi_revert_snapshot("vm-1", "web-01", "10", dry_run=True))
    assert r["planned"]["revert_to"] == "10"


def test_secrets_not_in_output():
    vm = FakeVM("vm-1", "web-01", power="poweredOn", tools_ok=True)
    cfg = make_cfg(enable_writes=True)
    ps = _patch(fake_vm=vm, cfg=cfg)
    r = _run_with(ps, lambda: T.esxi_power_vm("vm-1", "power_off", "web-01", dry_run=True))
    out = json.dumps(r, ensure_ascii=False)
    assert "SECRETPW" not in out


def test_service_instance_disconnects():
    """api.service_instance 必须在退出时 Disconnect。"""
    from esxi_mcp import api
    fake_si = mock.MagicMock()
    with mock.patch.object(api, "SmartConnect", return_value=fake_si) as sc, \
            mock.patch.object(api, "Disconnect") as disc:
        with api.service_instance(make_cfg()) as si:
            assert si is fake_si
        disc.assert_called_once_with(fake_si)


def test_container_view_destroys():
    """api.container_view 必须在退出时 Destroy。"""
    from esxi_mcp.api import container_view
    si = mock.MagicMock()
    view = mock.MagicMock()
    content = mock.MagicMock()
    content.viewManager.CreateContainerView.return_value = view
    si.RetrieveContent.return_value = content
    with container_view(si, object) as v:
        assert v is view
    view.Destroy.assert_called_once()


def test_snapshot_tree_recursive():
    from esxi_mcp.api import snapshot_tree
    tree = snapshot_tree([_snap(1, "root", [_snap(2, "child")])])
    assert tree[0]["snapshot_id"] == "1"
    assert tree[0]["children"][0]["snapshot_id"] == "2"

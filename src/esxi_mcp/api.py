"""vSphere API 封装：连接、ContainerView、VM 序列化、快照树、任务查询。

约定：
- 普通读取及时断开；异步任务与会话绑定 NFC 租约保留连接至完成。
- 所有 VM 查询使用递归 ContainerView（本机 ESXi 上递归 folder 遍历会返回 0 台）。
- guest.net.ipAddress 展平并去重。
- 返回值为可 JSON 序列化的 dict/list。
"""
from __future__ import annotations

import ssl
import threading
import time
from contextvars import ContextVar
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

from .config import Config

_SESSION_SCOPE = ContextVar('esxi_service_session', default=None)
_LEASE_SESSIONS = {}
_LEASE_LOCK = threading.RLock()

def _lease_key(cfg, target):
    if target and target.get('_type') == 'vim.HttpNfcLease':
        return (cfg.host, cfg.port, cfg.user, str(target['_moId']))
    return None

def hold_task_session(task):
    """Some host tasks check privileges after returning; retain their authenticated session."""
    scope = _SESSION_SCOPE.get()
    if scope and getattr(task, '_stub', None) is scope[0]._stub:
        scope[1].append(task)
        if isinstance(task, vim.HttpNfcLease):
            key = (scope[2].host, scope[2].port, scope[2].user, str(task._moId))
            with _LEASE_LOCK:
                _LEASE_SESSIONS[key] = (scope[0], threading.RLock())

def _finish_task_session(si, tasks, timeout=3600, lease_grace=30):
    deadline = time.monotonic() + timeout
    try:
        for task in tasks:
            while time.monotonic() < deadline:
                if isinstance(task, vim.HttpNfcLease):
                    with _LEASE_LOCK:
                        entry = next((value for value in _LEASE_SESSIONS.values() if value[0] is si), None)
                    if entry:
                        with entry[1]:
                            state = str(task.state)
                    else:
                        state = str(task.state)
                else:
                    state = str(task.info.state)
                if state not in ('queued', 'running', 'initializing', 'ready'):
                    break
                time.sleep(0.5)
    except Exception:
        # Task faults remain available through esxi_get_task; never print credentials.
        pass
    finally:
        if any(isinstance(task, vim.HttpNfcLease) for task in tasks):
            # Allow a final state query after Complete/Abort, before discarding the session.
            time.sleep(lease_grace)
        with _LEASE_LOCK:
            for key in [key for key, value in _LEASE_SESSIONS.items() if value[0] is si]:
                del _LEASE_SESSIONS[key]
        Disconnect(si)


def _ssl_context(cfg: Config) -> ssl.SSLContext:
    if cfg.verify_ssl is False:
        return ssl._create_unverified_context()
    if cfg.verify_ssl is True:
        return ssl.create_default_context()
    # 字符串路径 → CA 文件
    return ssl.create_default_context(cafile=str(cfg.verify_ssl))


@contextmanager
def service_instance(cfg: Config, target=None):
    key = _lease_key(cfg, target)
    if key is not None:
        with _LEASE_LOCK:
            entry = _LEASE_SESSIONS.get(key)
        if entry is None:
            raise RuntimeError('NFC lease is unavailable in this MCP session; create a new lease')
        with entry[1]:
            yield entry[0]
        return
    si = None
    token = None
    tasks = []
    try:
        si = SmartConnect(
            host=cfg.host,
            user=cfg.user,
            pwd=cfg.password,
            port=cfg.port,
            sslContext=_ssl_context(cfg),
            httpConnectionTimeout=cfg.connect_timeout,
        )
        token = _SESSION_SCOPE.set((si, tasks, cfg))
        yield si
    finally:
        if token is not None:
            _SESSION_SCOPE.reset(token)
        if si is not None:
            if tasks:
                threading.Thread(target=_finish_task_session, args=(si, tasks, cfg.lease_session_timeout), daemon=True).start()
            else:
                Disconnect(si)


@contextmanager
def container_view(si, obj_type):
    content = si.RetrieveContent()
    view = content.viewManager.CreateContainerView(content.rootFolder, [obj_type], True)
    try:
        yield view
    finally:
        view.Destroy()


# --------------------------------------------------------------------------
# VM 序列化
# --------------------------------------------------------------------------

def _flatten_ips(vm) -> List[str]:
    ips: List[str] = []
    try:
        for nic in (vm.guest.net or []):
            for a in (nic.ipAddress or []):
                ips.append(str(a))
    except Exception:
        pass
    # 去重且保序
    seen = set()
    out = []
    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def vm_to_dict(vm) -> Dict[str, Any]:
    power = str(vm.runtime.powerState) if vm.runtime and vm.runtime.powerState else ""
    return {
        "vm_id": str(vm._moId),
        "name": str(vm.name),
        "instance_uuid": str(vm.config.instanceUuid) if vm.config and vm.config.instanceUuid else "",
        "power_state": power,
        "cpu": int(vm.config.hardware.numCPU) if vm.config and vm.config.hardware else 0,
        "memory_mb": int(vm.config.hardware.memoryMB) if vm.config and vm.config.hardware else 0,
        "IPs": _flatten_ips(vm),
    }


def _allocation_info(alloc) -> Dict[str, Any]:
    """把 ResourceAllocationInfo 转成 dict；limit=-1 表示无限。"""
    if alloc is None:
        return {"limit": None, "reservation": None, "shares": None}
    shares = None
    if alloc.shares is not None:
        try:
            shares = {"level": str(alloc.shares.level), "shares": int(alloc.shares.shares)}
        except Exception:
            shares = str(alloc.shares)
    return {
        "limit": int(alloc.limit) if alloc.limit is not None else None,
        "reservation": int(alloc.reservation) if alloc.reservation is not None else None,
        "shares": shares,
    }


def vm_to_dict_detailed(vm) -> Dict[str, Any]:
    """单台 VM 详情：磁盘（device_key）、CPU/内存 allocation、hot-add、tools 状态。

    必须在连接作用域内调用（会触发 SOAP 属性读取）。
    """
    d = vm_to_dict(vm)
    disks: List[Dict[str, Any]] = []
    hw = vm.config.hardware if vm.config else None
    if hw is not None:
        for dev in (hw.device or []):
            if isinstance(dev, vim.vm.device.VirtualDisk):
                cap_mb = int(dev.capacityInKB) // 1024 if dev.capacityInKB else 0
                disks.append(
                    {
                        "device_key": int(dev.key),
                        "label": str(getattr(dev.deviceInfo, "label", "")) if dev.deviceInfo else "",
                        "capacity_gb": round(cap_mb / 1024, 2),
                        "datastore": str(dev.backing.datastore.name) if getattr(dev.backing, "datastore", None) else "",
                        "backing_file": str(dev.backing.fileName) if getattr(dev.backing, "fileName", None) else "",
                    }
                )
    cpu_alloc = None
    mem_alloc = None
    if vm.config is not None:
        cpu_alloc = _allocation_info(vm.config.cpuAllocation)
        mem_alloc = _allocation_info(vm.config.memoryAllocation)

    tools = vm.guest.toolsStatus if vm.guest else None
    d.update(
        {
            "disks": disks,
            "cpu_allocation": cpu_alloc,
            "memory_allocation": mem_alloc,
            "cpu_hot_add_enabled": bool(vm.config.cpuHotAddEnabled) if vm.config else None,
            "memory_hot_add_enabled": bool(vm.config.memoryHotAddEnabled) if vm.config else None,
            "tools_status": str(tools) if tools else None,
        }
    )
    return d


def find_vm_by_id(si, vm_id: str):
    with container_view(si, vim.VirtualMachine) as view:
        for vm in view.view:
            if str(vm._moId) == str(vm_id):
                return vm
    return None


def find_vm_by_name(si, name: str) -> Optional[Any]:
    with container_view(si, vim.VirtualMachine) as view:
        for vm in view.view:
            if vm.name == name:
                return vm
    return None


def list_vm_dicts(si, name_filter: Optional[str] = None, ip_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with container_view(si, vim.VirtualMachine) as view:
        for vm in sorted(view.view, key=lambda v: (v.name or "")):
            d = vm_to_dict(vm)
            if name_filter and name_filter.lower() not in d["name"].lower():
                continue
            if ip_filter and ip_filter not in d["IPs"]:
                continue
            out.append(d)
    return out


# --------------------------------------------------------------------------
# 快照树
# --------------------------------------------------------------------------

def snapshot_tree(snap_list) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in snap_list or []:
        out.append(
            {
                "snapshot_id": str(s.id),
                "name": str(s.name),
                "description": str(s.description) if s.description else "",
                "state": str(s.state) if s.state else "",
                "create_time": str(s.createTime) if s.createTime else "",
                "children": snapshot_tree(s.childSnapshotList),
            }
        )
    return out


def find_snapshot_in_tree(snap_list, snapshot_id: str):
    for s in snap_list or []:
        if str(s.id) == str(snapshot_id):
            return s
        r = find_snapshot_in_tree(s.childSnapshotList, snapshot_id)
        if r is not None:
            return r
    return None


def snapshot_id_exists(snap_list, name: str) -> bool:
    for s in snap_list or []:
        if s.name == name:
            return True
        if snapshot_id_exists(s.childSnapshotList, name):
            return True
    return False


# --------------------------------------------------------------------------
# 任务查询
# --------------------------------------------------------------------------

_TASK_STATE_MAP = {
    "queued": "queued",
    "running": "running",
    "success": "success",
    "error": "error",
}


def task_to_dict(task) -> Dict[str, Any]:
    info = task.info
    state = str(info.state) if info and info.state else "unknown"
    out: Dict[str, Any] = {
        "task_id": str(task._moId),
        "state": _TASK_STATE_MAP.get(state, state),
        "description_id": str(info.descriptionId) if info and info.descriptionId else "",
        "progress": int(info.progress) if info and info.progress is not None else None,
        "error": None,
        "result": None,
    }
    if info and info.state == vim.TaskInfo.State.error and info.error is not None:
        out["error"] = {
            "fault": type(info.error).__name__,
            "message": str(info.error.msg) if getattr(info.error, "msg", None) else str(info.error),
            "privilege_id": getattr(info.error, "privilegeId", None),
        }
    if info and info.state == vim.TaskInfo.State.success:
        from .codec import encode
        out["result"] = encode(info.result) if info.result is not None else None
    return out


def get_task_by_id(si, task_id: str):
    try:
        t = vim.Task(task_id, si._stub)
        _ = t.info  # 触发属性抓取，确保 info 已填充
        return t
    except Exception:
        return None

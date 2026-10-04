"""MCP 工具定义（FastMCP）。

- 只读工具 readOnlyHint=True，管理工具 destructiveHint=True。
- 写操作 dry_run=True 默认，执行须 dry_run=False 且 ESXI_ENABLE_WRITES=true。
- 写操作精确匹配 vm_id + expected_name，不猜名；保护管理链路 VM。
"""
from __future__ import annotations

import copy
import datetime
import inspect
from functools import wraps
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pyVmomi import vim

from . import api, codec, state, policy
from .config import Config, load_config
from .security import (
    check_name_match,
    check_protected,
    validate_vm_name,
    audit,
)

mcp = FastMCP(
    "esxi-mcp",
    instructions=(
        "本服务管理一台 ESXi 主机。写操作必须来自用户明确请求：先查询 esxi_list_vms / "
        "esxi_get_vm 确认 vm_id 与 expected_name，并先用 dry_run=True 提交计划，确认后再 "
        "dry_run=False 执行。绝不隐式强制关机或删快照。异步写任务提交后用 esxi_get_task 核实 "
        "真实状态（queued/running/success/error），不要当作已完成。"
        "其他资源先 esxi_inventory/esxi_managers 发现准确引用，再 esxi_api_schema/esxi_api_get "
        "查类型和状态，用 esxi_api_invoke 的 dry_run 预览。高级执行要求两个写开关、准确 "
        "expected_target；共享资源变更核对 dependencies 并确认全部受影响 VM。管理链路变更需要 "
        "administrator 配置及调用双方允许。operation_status 查询持久化操作和工作流。"
        "大文件用 transfer/stage 工具，完整部署用 ovf_import/export；NFC 租约须在同一 MCP "
        "进程使用，传输后 Complete/Abort。ESXCLI/shell 为独立开启的管理员后端。"
    ),
)

READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)


def _now() -> str:
    return datetime.datetime.now().astimezone().isoformat()


def _audit(cfg: Config, command: str, **fields: Any) -> None:
    def scrub(value):
        if isinstance(value, str):
            return value.replace(cfg.password, "[REDACTED]") if cfg.password else value
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [scrub(item) for item in value]
        return value
    try:
        audit(scrub(codec.scrub({"ts": _now(), "command": command, **fields})), cfg.audit_file)
    except Exception:
        pass


def _audited(function):
    """Record outcomes and emit concise, redacted standard MCP errors."""
    @wraps(function)
    def invoke(*args, **kwargs):
        cfg = load_config()
        bound = inspect.signature(function).bind(*args, **kwargs)
        bound.apply_defaults()
        parameters = dict(bound.arguments)
        journal_parameters = state.journal_arguments(function.__name__, parameters)
        operation_id = None
        # Dedicated controllers delegate to API policy and journaling with their canonical SDK identity.
        delegated = function.__name__ in ('esxi_api_invoke', 'esxi_vm_hardware', 'esxi_vm_register',
                    'esxi_guest_process', 'esxi_guest_files') or function.__name__.endswith('_manage')
        read_transfer = function.__name__ in ('esxi_datastore_transfer', 'esxi_api_transfer', 'esxi_transfer_start') and parameters.get('operation') in ('stat', 'download')
        if parameters.get('dry_run') is False and not delegated and not read_transfer:
            policy.check_operation(cfg, function.__name__)
        if parameters.get('dry_run') is False and not delegated and function.__name__ not in ('esxi_execute_plan', 'esxi_ovf_export', 'esxi_ovf_import') and not function.__name__.startswith(('esxi_transfer_', 'esxi_stage_')):
            operation_id, _ = state.begin(cfg, function.__name__, parameters)
        try:
            result = function(*args, **kwargs)
        except Exception as error:
            message = str(getattr(error, "msg", None) or error)
            if cfg.password:
                message = message.replace(cfg.password, "[REDACTED]")
            for secret in codec.secret_values(parameters):
                message = message.replace(secret, "[REDACTED]")
            message = message[:1200]
            _audit(cfg, function.__name__, state="error", parameters=journal_parameters,
                   error_type=type(error).__name__, error=message)
            if operation_id:
                state.update(cfg, operation_id, 'needs_review' if state.uncertain_error(error) else 'failed',
                             error=message, error_type=type(error).__name__)
            raise ToolError(message if isinstance(error, ToolError)
                            else f"{type(error).__name__}: {message}") from None
        outcome = "dry_run" if result.get("dry_run") else result.get("state", "success")
        _audit(cfg, function.__name__, state=outcome, parameters=journal_parameters,
               task_id=result.get("task_id"))
        return state.finish(cfg, operation_id, result) if operation_id else result
    return invoke


def _get_host(si):
    content = si.RetrieveContent()
    dc = content.rootFolder.childEntity[0]
    return content, dc, dc.hostFolder.childEntity[0].host[0]


def _pstate_on(vm) -> bool:
    return vm.runtime is not None and vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn


def _tools_ok(vm) -> bool:
    try:
        return vm.guest is not None and vm.guest.toolsRunningStatus == "guestToolsRunning"
    except Exception:
        return False


def _resolve_vm(si, vm_id: str, expected_name: Optional[str] = None):
    vm = api.find_vm_by_id(si, vm_id)
    if vm is None:
        raise ToolError(f"未找到 vm_id={vm_id}（请用 esxi_list_vms 确认，VM 名/ID 不按相似猜测）")
    if expected_name is not None and not check_name_match(expected_name, vm.name):
        raise ToolError(f"vm_id={vm_id} 名称不匹配：期望 {expected_name!r}，实际 {vm.name!r}")
    return vm


def _guard_writes(cfg: Config, dry_run: bool) -> None:
    """写执行必须 ESXI_ENABLE_WRITES=true；dry-run 在未启用写入时仍可用。"""
    if not dry_run and (not cfg.enable_writes or cfg.policy_profile == 'read_only'):
        _audit(cfg, "guard_writes", dry_run=dry_run, state="rejected",
               reason="writes_not_enabled")
        raise ToolError("写操作未启用：设置 ESXI_ENABLE_WRITES=true（参考 run-stdio.sh 部署启动脚本）")


def _guard_protected(vm_id: str, vm_name: str, cfg: Config, dry_run: bool, command: str,
                     allow_protected_impact: bool = False) -> bool:
    """返回是否受保护。dry_run 时标明 protected；执行时抛 ToolError。"""
    if check_protected(vm_id, cfg.protected_vm_ids):
        _audit(cfg, command, vm_id=vm_id, vm_name=vm_name, dry_run=dry_run, protected=True, state="rejected")
        allowed = cfg.policy_profile == 'administrator' and cfg.allow_protected_impact and allow_protected_impact
        if not dry_run and not allowed:
            raise ToolError(f"vm_id={vm_id}（{vm_name}）是受保护的管理链路 VM，拒绝写操作")
        return True
    return False


def _validate_resource_args(cpu_mhz_limit, cpu_mhz_reservation, memory_mb_limit, memory_mb_reservation) -> None:
    """验证 limit/reservation 合法范围：limit ∈ {-1(无限)} ∪ [0,∞)，reservation ≥ 0，
    reservation 不超过有限的 limit。非法即抛 ToolError。"""
    triples = [
        ("cpu_mhz_limit", cpu_mhz_limit, "cpu_mhz_reservation", cpu_mhz_reservation),
        ("memory_mb_limit", memory_mb_limit, "memory_mb_reservation", memory_mb_reservation),
    ]
    for lim_name, lim, res_name, res in triples:
        if lim is not None:
            if lim < -1:
                raise ToolError(f"{lim_name} 非法：应 >= 0（或 -1 表示无限），得到 {lim}")
        if res is not None:
            if res < 0:
                raise ToolError(f"{res_name} 非法：应 >= 0，得到 {res}")
        if lim is not None and res is not None and lim >= 0 and res > lim:
            raise ToolError(f"{res_name}={res} 不能超过有限的 {lim_name}={lim}")


def _submit(cfg: Config, command: str, vm_id: str, expected_name: str, task) -> Dict[str, Any]:
    """统一记录异步任务提交：submitted/task_id/state（脱敏，不含凭据/全量 traceback）。"""
    api.hold_task_session(task)
    d = api.task_to_dict(task)
    _audit(cfg, command, vm_id=vm_id, expected_name=expected_name, state="submitted",
           task_id=d.get("task_id"), task_state=d.get("state"))
    return d


# ==========================================================================
# 只读工具
# ==========================================================================

@mcp.tool(annotations=READ)
@_audited
def esxi_health() -> Dict[str, Any]:
    """ESXi 主机整体健康状态（连接态/维护模式/overallStatus/uptime/quickStats 即时负载）。"""
    cfg = load_config()
    _audit(cfg, "esxi_health")
    with api.service_instance(cfg) as si:
        _c, _dc, host = _get_host(si)
        s = host.summary
        qs = s.quickStats
        return {
            "host": str(host.name),
            "connection_state": str(s.runtime.connectionState),
            "in_maintenance_mode": bool(s.runtime.inMaintenanceMode),
            "overall_status": str(host.overallStatus),
            "uptime_seconds": int(qs.uptime) if qs.uptime is not None else None,
            "cpu_usage_mhz_quickstats": int(qs.overallCpuUsage) if qs.overallCpuUsage is not None else None,
            "memory_usage_mb_quickstats": int(qs.overallMemoryUsage) if qs.overallMemoryUsage is not None else None,
        }


@mcp.tool(annotations=READ)
@_audited
def esxi_list_vms(
    name_filter: Optional[str] = None,
    ip_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """列出所有 VM（可按名称/IP 过滤）。内存字段为配置值，非物理内存占用。"""
    cfg = load_config()
    _audit(cfg, "esxi_list_vms", name_filter=name_filter, ip_filter=ip_filter)
    with api.service_instance(cfg) as si:
        vms = api.list_vm_dicts(si, name_filter=name_filter, ip_filter=ip_filter)
    return {"count": len(vms), "vms": vms}


@mcp.tool(annotations=READ)
@_audited
def esxi_get_vm(vm_id: str) -> Dict[str, Any]:
    """按 vm_id（MoRef）查询单台 VM 详情。"""
    cfg = load_config()
    _audit(cfg, "esxi_get_vm", vm_id=vm_id)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id)
        return api.vm_to_dict_detailed(vm)


@mcp.tool(annotations=READ)
@_audited
def esxi_host_summary() -> Dict[str, Any]:
    """主机容量摘要。quickstats_* 为物理已用量；VM 配置内存总和另列，勿混淆。"""
    cfg = load_config()
    _audit(cfg, "esxi_host_summary")
    with api.service_instance(cfg) as si:
        content, dc, host = _get_host(si)
        s = host.summary
        qs = s.quickStats
        with api.container_view(si, vim.VirtualMachine) as view:
            vm_count = len(view.view)
            configured_mem_mb = sum(
                int(getattr(v.config.hardware, "memoryMB", 0) or 0) for v in view.view
            )
        return {
            "host": str(host.name),
            "model": str(s.hardware.model) if s.hardware.model else "",
            "cpu_model": str(s.hardware.cpuModel) if s.hardware.cpuModel else "",
            "num_cpu_cores": int(s.hardware.numCpuCores),
            "cpu_mhz_per_core": int(s.hardware.cpuMhz),
            "memory_total_mb": int(s.hardware.memorySize) // (1024 * 1024),
            "quickstats_cpu_usage_mhz": int(qs.overallCpuUsage) if qs.overallCpuUsage is not None else None,
            "quickstats_memory_usage_mb": int(qs.overallMemoryUsage) if qs.overallMemoryUsage is not None else None,
            "uptime_seconds": int(qs.uptime) if qs.uptime is not None else None,
            "vm_count": vm_count,
            "vm_configured_memory_mb_total": configured_mem_mb,
            "datastore_count": len(dc.datastore),
        }


@mcp.tool(annotations=READ)
@_audited
def esxi_list_datastores() -> Dict[str, Any]:
    cfg = load_config()
    _audit(cfg, "esxi_list_datastores")
    with api.service_instance(cfg) as si:
        content, dc, _h = _get_host(si)
        out = []
        for ds in dc.datastore:
            info = ds.summary
            out.append(
                {
                    "name": str(ds.name),
                    "type": str(ds.summary.type),
                    "capacity_mb": int(info.capacity) // (1024 * 1024),
                    "free_mb": int(info.freeSpace) // (1024 * 1024),
                    "accessible": bool(info.accessible),
                }
            )
    return {"count": len(out), "datastores": out}


@mcp.tool(annotations=READ)
@_audited
def esxi_list_networks() -> Dict[str, Any]:
    cfg = load_config()
    _audit(cfg, "esxi_list_networks")
    with api.service_instance(cfg) as si:
        content, dc, _h = _get_host(si)
        names = [str(n.name) for n in dc.network]
    return {"count": len(names), "networks": names}


@mcp.tool(annotations=READ)
@_audited
def esxi_list_snapshots(vm_id: str) -> Dict[str, Any]:
    """递归列出指定 VM 的快照树，输出 snapshot_id。"""
    cfg = load_config()
    _audit(cfg, "esxi_list_snapshots", vm_id=vm_id)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id)
        vm_name = vm.name  # 在连接块内读取，退出 Disconnect 后不再触发 SOAP 属性
        tree = api.snapshot_tree(vm.snapshot.rootSnapshotList if vm.snapshot else [])
        return {"vm_id": vm_id, "name": vm_name, "count": _count_snaps(tree), "snapshots": tree}


def _count_snaps(tree: List[Dict[str, Any]]) -> int:
    n = 0
    for t in tree:
        n += 1 + _count_snaps(t.get("children", []))
    return n


@mcp.tool(annotations=READ)
@_audited
def esxi_get_task(task_id: str) -> Dict[str, Any]:
    """查询异步任务状态：queued/running/success/error。"""
    cfg = load_config()
    _audit(cfg, "esxi_get_task", task_id=task_id)
    with api.service_instance(cfg) as si:
        task = api.get_task_by_id(si, task_id)
        if task is None:
            raise ToolError(f"无法查询 task_id={task_id}（可能已清理或非本机任务）")
        return api.task_to_dict(task)


# ==========================================================================
# 管理工具
# ==========================================================================

@mcp.tool(annotations=WRITE)
@_audited
def esxi_power_vm(
    vm_id: str,
    operation: str,
    expected_name: str,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """电源操作：power_on / shutdown(优雅,需Tools) / power_off / reboot_guest(需Tools) / reset。"""
    _VALID = {"power_on", "shutdown", "power_off", "reboot_guest", "reset"}
    if operation not in _VALID:
        raise ToolError(f"operation 非法，允许：{sorted(_VALID)}")

    cfg = load_config()
    _guard_writes(cfg, dry_run)
    _audit(cfg, "esxi_power_vm", vm_id=vm_id, operation=operation, expected_name=expected_name, dry_run=dry_run)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        protected = _guard_protected(vm_id, vm.name, cfg, dry_run, "esxi_power_vm")
        powered_on = _pstate_on(vm)
        tools_ok = _tools_ok(vm)

        # 优雅关机/重启需要 VMware Tools，缺则拒绝，不降级到强制 power_off/reset
        needs_tools = operation in ("shutdown", "reboot_guest")
        if needs_tools and not tools_ok:
            msg = f"{operation} 需要 VMware Tools，但 VM {vm.name} 无可用 Tools（不降级为强制操作）"
            _audit(cfg, "esxi_power_vm", vm_id=vm_id, state="error", reason="tools_unavailable")
            raise ToolError(msg)

        if dry_run:
            return {
                "dry_run": True,
                "protected": protected,
                "vm_id": vm_id,
                "name": vm.name,
                "planned_operation": operation,
                "current_power_state": "poweredOn" if powered_on else "poweredOff",
            }

        if operation == "power_on":
            if powered_on:
                raise ToolError(f"VM {vm.name} 已处于开机状态")
            task = vm.PowerOnVM_Task()
        elif operation == "shutdown":
            vm.ShutdownGuest()
            return {"vm_id": vm_id, "name": vm.name, "state": "submitted", "task_id": None,
                    "note": "ShutdownGuest 为同步 guest 请求，无 vSphere task；请用 get_vm 轮询电源状态"}
        elif operation == "reboot_guest":
            vm.RebootGuest()
            return {"vm_id": vm_id, "name": vm.name, "state": "submitted", "task_id": None,
                    "note": "RebootGuest 为同步 guest 请求，无 vSphere task"}
        elif operation == "power_off":
            task = vm.PowerOffVM_Task()
        else:  # reset
            task = vm.ResetVM_Task()

        return _submit(cfg, "esxi_power_vm", vm_id, expected_name, task)


@mcp.tool(annotations=WRITE)
@_audited
def esxi_configure_vm(
    vm_id: str,
    expected_name: str,
    cpu: Optional[int] = None,
    memory_mb: Optional[int] = None,
    cpu_mhz_limit: Optional[int] = None,
    cpu_mhz_reservation: Optional[int] = None,
    memory_mb_limit: Optional[int] = None,
    memory_mb_reservation: Optional[int] = None,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """修改 CPU/内存（核数、MHz limit/reservation、MB limit/reservation）。未传字段不变。"""
    if cpu is None and memory_mb is None and cpu_mhz_limit is None and cpu_mhz_reservation is None \
            and memory_mb_limit is None and memory_mb_reservation is None:
        raise ToolError("未指定任何要修改的字段")

    cfg = load_config()
    _guard_writes(cfg, dry_run)
    _audit(cfg, "esxi_configure_vm", vm_id=vm_id, expected_name=expected_name, cpu=cpu,
           memory_mb=memory_mb, dry_run=dry_run)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        protected = _guard_protected(vm_id, vm.name, cfg, dry_run, "esxi_configure_vm")
        powered_on = _pstate_on(vm)
        cur_cpu = int(vm.config.hardware.numCPU)
        cur_mem = int(vm.config.hardware.memoryMB)

        # 缩容必须关机；开机且不支持 hot-add 的扩容也拒绝
        changes = []
        if cpu is not None and cpu <= 0:
            raise ToolError("cpu 必须 >= 1")
        if memory_mb is not None and memory_mb <= 0:
            raise ToolError("memory_mb 必须 >= 1")

        shrinking = (cpu is not None and cpu < cur_cpu) or (memory_mb is not None and memory_mb < cur_mem)
        growing = (cpu is not None and cpu > cur_cpu) or (memory_mb is not None and memory_mb > cur_mem)

        if powered_on and shrinking:
            raise ToolError("缩容 CPU/内存必须关机执行")
        if powered_on and growing:
            cpu_hot = vm.config.cpuHotAddEnabled
            mem_hot = vm.config.memoryHotAddEnabled
            if (cpu is not None and cpu > cur_cpu and not cpu_hot) or \
               (memory_mb is not None and memory_mb > cur_mem and not mem_hot):
                raise ToolError("开机状态扩容且未启用 hot-add，需先显式关机")

        cpu_current = getattr(vm.config, "cpuAllocation", None)
        memory_current = getattr(vm.config, "memoryAllocation", None)
        cpu_changed = cpu_mhz_limit is not None or cpu_mhz_reservation is not None
        memory_changed = memory_mb_limit is not None or memory_mb_reservation is not None
        _validate_resource_args(
            (cpu_mhz_limit if cpu_mhz_limit is not None else getattr(cpu_current, "limit", None)) if cpu_changed else None,
            (cpu_mhz_reservation if cpu_mhz_reservation is not None else getattr(cpu_current, "reservation", None)) if cpu_changed else None,
            (memory_mb_limit if memory_mb_limit is not None else getattr(memory_current, "limit", None)) if memory_changed else None,
            (memory_mb_reservation if memory_mb_reservation is not None else getattr(memory_current, "reservation", None)) if memory_changed else None,
        )

        if dry_run:
            return {
                "dry_run": True,
                "protected": protected,
                "vm_id": vm_id,
                "name": vm.name,
                "planned": {
                    "cpu": cpu, "memory_mb": memory_mb, "cpu_mhz_limit": cpu_mhz_limit,
                    "cpu_mhz_reservation": cpu_mhz_reservation,
                    "memory_mb_limit": memory_mb_limit, "memory_mb_reservation": memory_mb_reservation,
                },
                "current": {"cpu": cur_cpu, "memory_mb": cur_mem, "power_state": "poweredOn" if powered_on else "poweredOff"},
            }

        spec = vim.vm.ConfigSpec()
        if cpu is not None:
            spec.numCPUs = cpu
        if memory_mb is not None:
            spec.memoryMB = memory_mb

        # 只创建实际更改的 allocation，深拷贝当前 allocation 保留未指定的 limit/reservation/shares
        cpu_changes = cpu_mhz_limit is not None or cpu_mhz_reservation is not None
        mem_changes = memory_mb_limit is not None or memory_mb_reservation is not None
        if cpu_changes:
            cur = vm.config.cpuAllocation
            new_alloc = copy.deepcopy(cur) if cur is not None else vim.ResourceAllocationInfo()
            if cpu_mhz_limit is not None:
                new_alloc.limit = cpu_mhz_limit
            if cpu_mhz_reservation is not None:
                new_alloc.reservation = cpu_mhz_reservation
            spec.cpuAllocation = new_alloc
        if mem_changes:
            cur = vm.config.memoryAllocation
            new_alloc = copy.deepcopy(cur) if cur is not None else vim.ResourceAllocationInfo()
            if memory_mb_limit is not None:
                new_alloc.limit = memory_mb_limit
            if memory_mb_reservation is not None:
                new_alloc.reservation = memory_mb_reservation
            spec.memoryAllocation = new_alloc

        task = vm.ReconfigVM_Task(spec)
        return _submit(cfg, "esxi_configure_vm", vm_id, expected_name, task)


@mcp.tool(annotations=WRITE)
@_audited
def esxi_create_vm(
    name: str,
    cpu: int,
    memory_mb: int,
    disk_gb: int,
    datastore: Optional[str] = None,
    network: Optional[str] = None,
    guest_id: str = "otherGuest",
    dry_run: bool = True,
) -> Dict[str, Any]:
    """创建 VM（明确名称/CPU/内存/磁盘/datastore/network/guest_id，使用正确 resourcePool）。

    新建 VM 的 name 就是目标本身，无需额外 expected_name。datastore 和 network 必须
    从查询结果中明确指定。创建空 VM，不安装操作系统；不包含 clone/migrate。
    """
    err = validate_vm_name(name)
    if err:
        raise ToolError(err)
    if cpu <= 0 or memory_mb <= 0 or disk_gb <= 0:
        raise ToolError("cpu/memory_mb/disk_gb 必须为正数")
    if not datastore or not network:
        raise ToolError("请先查询 esxi_list_datastores / esxi_list_networks，明确指定 datastore 和 network")

    cfg = load_config()
    _guard_writes(cfg, dry_run)
    _audit(cfg, "esxi_create_vm", name=name, cpu=cpu, memory_mb=memory_mb, disk_gb=disk_gb,
           datastore=datastore, network=network, guest_id=guest_id, dry_run=dry_run)
    if not dry_run and (datastore in cfg.protected_datastores or network in cfg.protected_networks):
        raise ToolError('Target datastore/network is protected by deployment policy')
    with api.service_instance(cfg) as si:
        content, dc, _h = _get_host(si)

        # 禁止与现有 VM 重名
        existing = api.find_vm_by_name(si, name)
        if existing is not None:
            raise ToolError(f"已存在同名 VM {name!r}（vm_id={existing._moId}），禁止重名创建")

        # datastore/network 从实际 inventory 匹配并验证空间。
        ds_name = datastore
        datastore_obj = None
        for d in dc.datastore:
            if d.name == ds_name:
                datastore_obj = d
                break
        if datastore_obj is None:
            names = [d.name for d in dc.datastore]
            raise ToolError(f"未找到 datastore {ds_name!r}，现有：{names}")
        if not datastore_obj.summary.accessible:
            raise ToolError(f"datastore {ds_name} 不可访问")
        free_mb = int(datastore_obj.summary.freeSpace) // (1024 * 1024)
        if disk_gb * 1024 > free_mb:
            raise ToolError(f"datastore {ds_name} 剩余 {free_mb}MB < 所需 {disk_gb * 1024}MB")

        net_name = network
        network_obj = None
        for n in dc.network:
            if n.name == net_name:
                network_obj = n
                break
        if network_obj is None:
            names = [n.name for n in dc.network]
            raise ToolError(f"未找到 network {net_name!r}，现有：{names}")

        pool = dc.hostFolder.childEntity[0].resourcePool

        if dry_run:
            return {
                "dry_run": True,
                "protected": False,
                "name": name,
                "planned": {
                    "cpu": cpu, "memory_mb": memory_mb, "disk_gb": disk_gb,
                    "datastore": ds_name, "network": net_name, "guest_id": guest_id,
                },
                "resource_pool": str(pool._moId),
                "vm_folder": str(dc.vmFolder._moId),
            }

        # 组装独立 ESXi 的 ConfigSpec。
        config = vim.vm.ConfigSpec()
        config.name = name
        config.numCPUs = cpu
        config.memoryMB = memory_mb
        config.guestId = guest_id
        config.files = vim.vm.FileInfo()
        config.files.vmPathName = f"[{ds_name}] {name}/{name}.vmx"

        scsi_spec = vim.vm.device.VirtualDeviceSpec()
        scsi_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        scsi_device = vim.vm.device.VirtualLsiLogicController()
        scsi_device.key = 1000
        scsi_device.busNumber = 0
        scsi_device.sharedBus = vim.vm.device.VirtualSCSIController.Sharing.noSharing
        scsi_spec.device = scsi_device

        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
        disk_device = vim.vm.device.VirtualDisk()
        disk_device.key = -1
        disk_device.controllerKey = 1000
        disk_device.unitNumber = 0
        disk_device.capacityInKB = disk_gb * 1024 * 1024
        disk_device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        disk_device.backing.diskMode = "persistent"
        disk_device.backing.thinProvisioned = True
        disk_device.backing.datastore = datastore_obj
        disk_device.backing.fileName = f"[{ds_name}]"
        disk_spec.device = disk_device

        nic_spec = vim.vm.device.VirtualDeviceSpec()
        nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        nic_device = vim.vm.device.VirtualE1000()
        nic_device.key = -2
        nic_device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
        nic_device.backing.deviceName = network_obj.name
        nic_device.backing.network = network_obj
        nic_device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        nic_device.connectable.startConnected = True
        nic_device.connectable.allowGuestControl = True
        nic_device.connectable.connected = True
        nic_device.wakeOnLanEnabled = True
        nic_device.addressType = "generated"
        nic_spec.device = nic_device

        config.deviceChange = [scsi_spec, disk_spec, nic_spec]

        task = dc.vmFolder.CreateVM_Task(config=config, pool=pool)
        return _submit(cfg, "esxi_create_vm", "", name, task)


@mcp.tool(annotations=WRITE)
@_audited
def esxi_rename_vm(vm_id: str, expected_name: str, new_name: str, dry_run: bool = True) -> Dict[str, Any]:
    err = validate_vm_name(new_name)
    if err:
        raise ToolError(err)
    cfg = load_config()
    _guard_writes(cfg, dry_run)
    _audit(cfg, "esxi_rename_vm", vm_id=vm_id, expected_name=expected_name, new_name=new_name, dry_run=dry_run)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        protected = _guard_protected(vm_id, vm.name, cfg, dry_run, "esxi_rename_vm")
        clash = api.find_vm_by_name(si, new_name)
        if clash is not None and clash._moId != str(vm_id):
            raise ToolError(f"目标名 {new_name!r} 已被 vm_id={clash._moId} 占用，禁止重命名")
        if dry_run:
            return {"dry_run": True, "protected": protected, "vm_id": vm_id,
                    "planned": {"from": vm.name, "to": new_name}}
        task = vm.Rename_Task(new_name)
        return _submit(cfg, "esxi_rename_vm", vm_id, expected_name, task)


@mcp.tool(annotations=WRITE)
@_audited
def esxi_create_snapshot(
    vm_id: str,
    expected_name: str,
    name: str,
    description: str = "",
    memory: bool = False,
    quiesce: bool = False,
    dry_run: bool = True,
) -> Dict[str, Any]:
    cfg = load_config()
    _guard_writes(cfg, dry_run)
    _audit(cfg, "esxi_create_snapshot", vm_id=vm_id, expected_name=expected_name, name=name,
           memory=memory, quiesce=quiesce, dry_run=dry_run)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        protected = _guard_protected(vm_id, vm.name, cfg, dry_run, "esxi_create_snapshot")
        root = vm.snapshot.rootSnapshotList if vm.snapshot else []
        if api.snapshot_id_exists(root, name):
            raise ToolError(f"快照名 {name!r} 已存在（同树内重复名会混淆，拒绝）")
        if dry_run:
            return {"dry_run": True, "protected": protected, "vm_id": vm_id, "name": vm.name,
                    "planned": {"snapshot_name": name, "memory": memory, "quiesce": quiesce}}
        task = vm.CreateSnapshot_Task(name=name, description=description or "esxi-mcp", memory=memory, quiesce=quiesce)
        return _submit(cfg, "esxi_create_snapshot", vm_id, expected_name, task)


@mcp.tool(annotations=WRITE)
@_audited
def esxi_revert_snapshot(vm_id: str, expected_name: str, snapshot_id: str, dry_run: bool = True) -> Dict[str, Any]:
    cfg = load_config()
    _guard_writes(cfg, dry_run)
    _audit(cfg, "esxi_revert_snapshot", vm_id=vm_id, expected_name=expected_name, snapshot_id=snapshot_id, dry_run=dry_run)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        protected = _guard_protected(vm_id, vm.name, cfg, dry_run, "esxi_revert_snapshot")
        root = vm.snapshot.rootSnapshotList if vm.snapshot else []
        snap = api.find_snapshot_in_tree(root, snapshot_id)
        if snap is None:
            raise ToolError(f"snapshot_id={snapshot_id} 不在 VM {vm_id} 的快照树内（勿传入其他 VM 的快照）")
        if dry_run:
            return {"dry_run": True, "protected": protected, "vm_id": vm_id,
                    "planned": {"revert_to": str(snapshot_id), "snapshot_name": snap.name}}
        task = snap.snapshot.RevertToSnapshot_Task()
        return _submit(cfg, "esxi_revert_snapshot", vm_id, expected_name, task)


@mcp.tool(annotations=WRITE)
@_audited
def esxi_delete_snapshot(
    vm_id: str,
    expected_name: str,
    snapshot_id: str,
    remove_children: bool = False,
    dry_run: bool = True,
) -> Dict[str, Any]:
    cfg = load_config()
    _guard_writes(cfg, dry_run)
    _audit(cfg, "esxi_delete_snapshot", vm_id=vm_id, expected_name=expected_name,
           snapshot_id=snapshot_id, remove_children=remove_children, dry_run=dry_run)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        protected = _guard_protected(vm_id, vm.name, cfg, dry_run, "esxi_delete_snapshot")
        root = vm.snapshot.rootSnapshotList if vm.snapshot else []
        snap = api.find_snapshot_in_tree(root, snapshot_id)
        if snap is None:
            raise ToolError(f"snapshot_id={snapshot_id} 不在 VM {vm_id} 的快照树内")
        if dry_run:
            return {"dry_run": True, "protected": protected, "vm_id": vm_id,
                    "planned": {"delete": str(snapshot_id), "snapshot_name": snap.name,
                                "remove_children": remove_children}}
        task = snap.snapshot.RemoveSnapshot_Task(removeChildren=remove_children)
        return _submit(cfg, "esxi_delete_snapshot", vm_id, expected_name, task)


@mcp.tool(annotations=WRITE)
@_audited
def esxi_expand_disk(
    vm_id: str,
    expected_name: str,
    device_key: int,
    new_size_gb: int,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """仅允许增长，由 device_key 精确定位；有快照时拒绝。"""
    if device_key <= 0:
        raise ToolError("device_key 必须为正整数，用于精确定位 VirtualDisk")
    if new_size_gb <= 0:
        raise ToolError("new_size_gb 必须为正数")
    cfg = load_config()
    _guard_writes(cfg, dry_run)
    _audit(cfg, "esxi_expand_disk", vm_id=vm_id, expected_name=expected_name, device_key=device_key,
           new_size_gb=new_size_gb, dry_run=dry_run)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        protected = _guard_protected(vm_id, vm.name, cfg, dry_run, "esxi_expand_disk")

        # 有快照拒绝扩盘
        has_snap = bool(vm.snapshot and vm.snapshot.rootSnapshotList)
        if has_snap:
            raise ToolError("VM 存在快照，ESXi 禁止对有快照的 VM 扩盘（需先删快照，不自动删除）")

        disk = None
        for dev in vm.config.hardware.device:
            if isinstance(dev, vim.vm.device.VirtualDisk) and dev.key == device_key:
                disk = dev
                break
        if disk is None:
            raise ToolError(f"未找到 device_key={device_key} 的 VirtualDisk")

        cur_kb = int(disk.capacityInKB)
        new_kb = new_size_gb * 1024 * 1024
        if new_kb <= cur_kb:
            raise ToolError(f"只能扩容：当前 {cur_kb}KB，请求 {new_kb}KB")

        if dry_run:
            return {"dry_run": True, "protected": protected, "vm_id": vm_id,
                    "planned": {"device_key": device_key, "from_kb": cur_kb, "to_kb": new_kb}}

        disk.capacityInKB = new_kb
        spec = vim.vm.ConfigSpec()
        dev_chg = vim.vm.device.VirtualDeviceSpec()
        dev_chg.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
        dev_chg.device = disk
        spec.deviceChange = [dev_chg]
        task = vm.ReconfigVM_Task(spec)
        return _submit(cfg, "esxi_expand_disk", vm_id, expected_name, task)


@mcp.tool(annotations=WRITE)
@_audited
def esxi_delete_vm(vm_id: str, expected_name: str, dry_run: bool = True) -> Dict[str, Any]:
    """删除 VM（必须已关机；dry-run 明示删除磁盘）。"""
    cfg = load_config()
    _guard_writes(cfg, dry_run)
    _audit(cfg, "esxi_delete_vm", vm_id=vm_id, expected_name=expected_name, dry_run=dry_run)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        protected = _guard_protected(vm_id, vm.name, cfg, dry_run, "esxi_delete_vm")
        powered_on = _pstate_on(vm)
        if powered_on:
            raise ToolError(f"VM {vm.name} 处于开机状态，删除前必须显式关机")
        if dry_run:
            return {"dry_run": True, "protected": protected, "vm_id": vm_id, "name": vm.name,
                    "planned": {"destroy_disk": True, "note": "Destroy_Task 将删除磁盘文件"}}
        task = vm.Destroy_Task()
        return _submit(cfg, "esxi_delete_vm", vm_id, expected_name, task)


# Register the typed API resource tools after the shared helpers are defined.
from . import advanced  # noqa: E402,F401
from . import files  # noqa: E402,F401
from . import api_transfer  # noqa: E402,F401
from . import resources  # noqa: E402,F401
from . import transfers  # noqa: E402,F401
from . import guest  # noqa: E402,F401
from . import admin  # noqa: E402,F401
from . import workflows  # noqa: E402,F401

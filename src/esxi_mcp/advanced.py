"""Discover and control declared vSphere API resources with typed JSON."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from pyVmomi import vim, VmomiSupport as V
from mcp.server.fastmcp.exceptions import ToolError
from . import api, codec, policy, state
from .config import load_config
from .tools import mcp, READ, WRITE, _audited, _guard_writes, _guard_protected, _get_host

def methods(cls):
    return {alias: method for method in cls._GetMethodList()
            for alias in (method.name, method.wsdlName)}

def guard_snapshot_owner(si, obj, cfg, dry_run, allow_protected_impact=False):
    if not isinstance(obj, vim.VirtualMachineSnapshot) or not cfg.protected_vm_ids:
        return False
    def contains(nodes):
        for node in nodes or []:
            if str(node.snapshot._moId) == str(obj._moId) or contains(node.childSnapshotList):
                return True
        return False
    with api.container_view(si, vim.VirtualMachine) as view:
        for vm in view.view:
            if str(vm._moId) in [str(item) for item in cfg.protected_vm_ids] and vm.snapshot:
                if contains(vm.snapshot.rootSnapshotList):
                    return _guard_protected(str(vm._moId), str(vm.name), cfg, dry_run, 'esxi_api_invoke', allow_protected_impact)
    return False

@mcp.tool(annotations=READ)
@_audited
def esxi_inventory(resource_type: str = 'vim.ManagedEntity', limit: int = 200) -> Dict[str, Any]:
    """列出 SDK 管理实体的准确类型/ID/名称：VM、HostSystem、Datastore、Network、Folder、ResourcePool。"""
    cls = codec.resolve_type(resource_type)
    if not issubclass(cls, vim.ManagedEntity) or not 1 <= limit <= 1000:
        raise ToolError('Inventory requires a ManagedEntity type and limit 1..1000')
    with api.service_instance(load_config()) as si:
        with api.container_view(si, cls) as view:
            objects = list(view.view)
            result = [{**codec.encode(obj), 'name': str(obj.name)} for obj in objects[:limit]]
    return {'count': len(objects), 'items': result, 'truncated': len(objects) > limit}

@mcp.tool(annotations=READ)
@_audited
def esxi_managers() -> Dict[str, Any]:
    """发现服务与 HostConfigManager 的网络、存储、服务、防火墙、账户、硬件等管理器引用。"""
    with api.service_instance(load_config()) as si:
        content, dc, host = _get_host(si)
        service = {prop.name: codec.encode(getattr(content, prop.name, None))
                   for prop in content._GetPropertyList()
                   if isinstance(getattr(content, prop.name, None), V.ManagedObject)}
        manager = host.configManager
        host_managers = {prop.name: codec.encode(getattr(manager, prop.name, None))
                         for prop in manager._GetPropertyList()
                         if isinstance(getattr(manager, prop.name, None), V.ManagedObject)}
        return {'host': {**codec.encode(host), 'name': str(host.name)},
                'datacenter': codec.encode(dc), 'service_managers': service, 'host_managers': host_managers,
                'api_version': str(content.about.apiVersion), 'product': str(content.about.fullName)}

@mcp.tool(annotations=READ)
@_audited
def esxi_api_schema(type_name: str, method: Optional[str] = None, depth: int = 2) -> Dict[str, Any]:
    """查看官方 SDK 类型、属性、方法、参数及返回类型。SDK 包含的方法仍可能不被当前 ESXi 支持。"""
    if not 0 <= depth <= 4:
        raise ToolError('Schema depth must be 0..4')
    cls = codec.resolve_type(type_name)
    result = codec.type_schema(cls, depth)
    if issubclass(cls, V.ManagedObject):
        result['properties'] = {prop.name: codec.type_schema(prop.type, 0) for prop in cls._GetPropertyList()}
        catalog = methods(cls)
        if method and method not in catalog:
            raise ToolError('Unknown declared API method: ' + method)
        selected = [catalog[method]] if method else cls._GetMethodList()
        result['methods'] = [{'name': item.name, 'wsdl_name': item.wsdlName,
                              'parameters': {param.name: {**codec.type_schema(param.type, depth),
                                                         'optional': bool(param.flags & V.F_OPTIONAL)}
                                             for param in item.params},
                              'result': codec.type_schema(item.result, 0)} for item in selected]
    return result

@mcp.tool(annotations=READ)
@_audited
def esxi_api_get(target: Dict[str, Any], properties: List[str], depth: int = 4,
                 max_items: int = 100) -> Dict[str, Any]:
    """读取发现引用的已声明属性；可查询硬件、PCI、VM 设备、网络、存储、服务、账户信息。秘密字段脱敏。"""
    if not 1 <= len(properties) <= 30 or not 1 <= depth <= 8 or not 1 <= max_items <= 1000:
        raise ToolError('Expected 1..30 properties, depth 1..8, max_items 1..1000')
    with api.service_instance(load_config(), target=target) as si:
        obj = codec.reference(target, si._stub)
        declared = {prop.name for prop in obj._GetPropertyList()}
        if set(properties) - declared:
            raise ToolError('Only declared properties may be read')
        return {'target': codec.encode(obj), 'properties': {
            key: '[REDACTED]' if codec.secret_field(key) else codec.encode(getattr(obj, key), depth, max_items)
            for key in properties}}

@mcp.tool(annotations=WRITE)
@_audited
def esxi_api_invoke(target: Dict[str, Any], method: str, arguments: Optional[Dict[str, Any]] = None,
                    expected_target: Optional[str] = None, dry_run: bool = True,
                    allow_disruption: bool = False, acknowledged_vm_ids: Optional[List[str]] = None,
                    allow_unknown_impact: bool = False, allow_protected_impact: bool = False,
                    request_id: Optional[str] = None) -> Dict[str, Any]:
    """高级类型化调用：覆盖服务器支持的 vSphere API 管理方法（网络/存储/硬件/服务/账户/guest/主机）。

    先 managers/inventory → schema/get → dry_run。真实调用需要写开关、
    ESXI_ENABLE_ADVANCED_WRITES=true、expected_target='准确_type:准确_moId'。
    非 VM 对象的调用需 allow_disruption=true，可能影响主机/共享资源/管理链路。
    直接 VM 引用仍受 protected_vm_ids 限制；共享资源修改须由调用者审查其依赖。
    不执行任意 Python 或 shell。异步返回 task_id 后继续查询状态。
    """
    import os
    cfg = load_config()
    _guard_writes(cfg, dry_run)
    if not dry_run and os.environ.get('ESXI_ENABLE_ADVANCED_WRITES', '').lower() not in ('1', 'true', 'yes', 'on'):
        raise ToolError('Advanced execution requires ESXI_ENABLE_ADVANCED_WRITES=true')
    reference = codec.reference(target, None)
    declared = methods(type(reference))
    if method not in declared:
        raise ToolError('Only a declared SDK method may be invoked')
    canonical = type(reference).__name__ + ':' + declared[method].wsdlName
    if not dry_run:
        if expected_target != type(reference).__name__ + ':' + str(reference._moId):
            raise ToolError('expected_target must exactly match target type and ID')
        policy.check_operation(cfg, canonical, administrator=type(reference).__name__ in policy.ADMIN_TYPES
                               and not policy.is_query(declared[method].wsdlName))
        replayed = state.replay(cfg, canonical, {'target':target, 'arguments':arguments or {}}, request_id)
        if replayed is not None:
            return replayed
    with api.service_instance(cfg, target=target) as si:
        obj = codec.reference(target, si._stub)
        identity = type(obj).__name__ + ':' + str(obj._moId)
        if not dry_run and expected_target != identity:
            raise ToolError('expected_target must exactly match ' + identity)
        if not dry_run and not isinstance(obj, vim.VirtualMachine) and not allow_disruption:
            raise ToolError('Shared/host/manager API execution requires allow_disruption=true')
        catalog = methods(type(obj))
        if method not in catalog:
            raise ToolError('Only a declared SDK method may be invoked')
        info = catalog[method]
        supplied = arguments or {}
        parameters = {param.name: param for param in info.params}
        if set(supplied) - set(parameters):
            raise ToolError('Unknown method arguments: ' + ', '.join(sorted(set(supplied) - set(parameters))))
        missing = [name for name, param in parameters.items() if not param.flags & V.F_OPTIONAL
                   and (name not in supplied or supplied[name] is None)]
        if missing:
            raise ToolError('Missing required arguments: ' + ', '.join(missing))
        converted = {name: codec.decode(value, parameters[name].type, si._stub) for name, value in supplied.items()}
        policy.check_operation(cfg, type(obj).__name__ + ':' + info.wsdlName,
                               administrator=type(obj).__name__ in policy.ADMIN_TYPES and not policy.is_query(info.wsdlName), dry_run=dry_run)
        protected = guard_snapshot_owner(si, obj, cfg, dry_run, allow_protected_impact)
        for vm in codec.vm_references([obj, converted]):
            protected |= _guard_protected(str(vm._moId), str(vm.name), cfg, dry_run, 'esxi_api_invoke', allow_protected_impact)
        dependency = policy.impact(si, cfg, obj, info.wsdlName, converted)
        policy.enforce_impact(cfg, dependency, acknowledged_vm_ids, allow_disruption,
                              allow_unknown_impact, allow_protected_impact, dry_run)
        if dry_run:
            return {'dry_run': True, 'target': codec.encode(obj), 'expected_target': identity,
                    'method': info.wsdlName, 'arguments': codec.scrub(supplied), 'protected': protected,
                    'shared_or_host_resource': not isinstance(obj, vim.VirtualMachine), 'dependencies': dependency}
        operation_id, replayed = state.begin(cfg, type(obj).__name__ + ':' + info.wsdlName,
                                            {'target': target, 'arguments': supplied}, request_id)
        if replayed is not None:
            return replayed
        try:
            value = getattr(obj, info.name)(**converted)
        except Exception as error:
            state.update(cfg, operation_id, 'needs_review' if state.uncertain_error(error) else 'failed', error_type=type(error).__name__)
            raise
        if isinstance(value, vim.Task):
            api.hold_task_session(value)
            return state.finish(cfg, operation_id, api.task_to_dict(value))
        if isinstance(value, vim.HttpNfcLease):
            api.hold_task_session(value)
            return state.finish(cfg, operation_id, {'state': 'lease_created', 'target': codec.encode(obj), 'method': info.wsdlName,
                    'result': codec.encode(value), 'note': 'Wait for lease ready; transfer files; call Complete or Abort'})
        return state.finish(cfg, operation_id, {'state': 'completed', 'target': codec.encode(obj), 'method': info.wsdlName,
                'result': codec.encode(value, depth=6, max_items=200)})

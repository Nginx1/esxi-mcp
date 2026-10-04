"""Host resource tools with named operations, exact targets and dependency previews."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from pyVmomi import vim
from mcp.server.fastmcp.exceptions import ToolError
from . import api, codec, policy, state
from .config import load_config
from .tools import mcp, READ, WRITE, _audited, _get_host, _resolve_vm, _guard_protected
from . import advanced

# (ServiceContent/HostConfigManager location, declared type, named actions)
CATALOG = {
 'network': ('host:networkSystem', 'vim.host.NetworkSystem', {
   'switch_create':'AddVirtualSwitch', 'switch_update':'UpdateVirtualSwitch', 'switch_remove':'RemoveVirtualSwitch',
   'portgroup_create':'AddPortGroup', 'portgroup_update':'UpdatePortGroup', 'portgroup_remove':'RemovePortGroup',
   'vmkernel_create':'AddVirtualNic', 'vmkernel_update':'UpdateVirtualNic', 'vmkernel_remove':'RemoveVirtualNic',
   'dns_update':'UpdateDnsConfig', 'route_update':'UpdateIpRouteConfig', 'routes_update':'UpdateIpRouteTableConfig',
   'physical_link_update':'UpdatePhysicalNicLinkSpeed', 'configuration_update':'UpdateNetworkConfig'}),
 'datastore': ('host:datastoreSystem', 'vim.host.DatastoreSystem', {
   'nfs_create':'CreateNasDatastore', 'vmfs_create':'CreateVmfsDatastore', 'vmfs_expand':'ExpandVmfsDatastore',
   'vmfs_extend':'ExtendVmfsDatastore', 'remove':'RemoveDatastore', 'local_create':'CreateLocalDatastore',
   'vvol_create':'CreateVvolDatastore', 'swap_update':'UpdateLocalSwapDatastore'}),
 'storage': ('host:storageSystem', 'vim.host.StorageSystem', {
   'rescan':'RescanAllHba', 'rescan_vmfs':'RescanVmfs', 'vmfs_format':'FormatVmfs', 'partition_update':'UpdateDiskPartitions',
   'vmfs_mount':'MountVmfsVolume', 'vmfs_unmount':'UnmountVmfsVolume', 'lun_attach':'AttachScsiLun', 'lun_detach':'DetachScsiLun',
   'iscsi_enable':'UpdateSoftwareInternetScsiEnabled', 'iscsi_discovery':'UpdateInternetScsiDiscoveryProperties',
   'iscsi_authentication':'UpdateInternetScsiAuthenticationProperties', 'iscsi_send_targets_add':'AddInternetScsiSendTargets',
   'iscsi_send_targets_remove':'RemoveInternetScsiSendTargets', 'multipath_policy':'SetMultipathLunPolicy',
   'nvme_connect':'ConnectNvmeController', 'nvme_disconnect':'DisconnectNvmeController'}),
 'service': ('host:serviceSystem', 'vim.host.ServiceSystem', {
   'start':'StartService', 'stop':'StopService', 'restart':'RestartService', 'startup_policy':'UpdateServicePolicy'}),
 'firewall': ('host:firewallSystem', 'vim.host.FirewallSystem', {
   'enable':'EnableRuleset', 'disable':'DisableRuleset', 'rules_update':'UpdateRuleset', 'default_policy':'UpdateDefaultPolicy'}),
 'account': ('host:accountManager', 'vim.host.LocalAccountManager', {
   'create':'CreateUser', 'update':'UpdateUser', 'remove':'RemoveUser', 'password_change':'ChangePassword'}),
 'permissions': ('service:authorizationManager', 'vim.AuthorizationManager', {
   'role_create':'AddAuthorizationRole', 'role_update':'UpdateAuthorizationRole', 'role_remove':'RemoveAuthorizationRole',
   'permission_set':'SetEntityPermissions', 'permission_remove':'RemoveEntityPermission'}),
 'license': ('service:licenseManager', 'vim.LicenseManager', {
   'add':'AddLicense', 'remove':'RemoveLicense', 'update':'UpdateLicense', 'labels_update':'UpdateLicenseLabel'}),
 'time': ('host:dateTimeSystem', 'vim.host.DateTimeSystem', {
   'configuration_update':'UpdateDateTimeConfig', 'clock_update':'UpdateDateTime'}),
 'pci': ('host:pciPassthruSystem', 'vim.host.PciPassthruSystem', {'configuration_update':'UpdatePassthruConfig', 'refresh':'Refresh'}),
 'certificate': ('host:certificateManager', 'vim.host.CertificateManager', {
   'csr_create':'GenerateCertificateSigningRequest', 'csr_by_dn':'GenerateCertificateSigningRequestByDn',
   'install':'InstallServerCertificate', 'ca_replace':'ReplaceCACertificatesAndCRLs', 'notify_services':'NotifyAffectedServices'}),
 'patch': ('host:patchManager', 'vim.host.PatchManager', {
   'check':'CheckHostPatch_Task', 'scan':'ScanHostPatchV2_Task', 'stage':'StageHostPatch_Task',
   'install':'InstallHostPatchV2_Task', 'uninstall':'UninstallHostPatch_Task', 'query':'QueryHostPatch_Task'}),
 'host': ('host:self', 'vim.HostSystem', {'maintenance_enter':'EnterMaintenanceMode_Task',
   'maintenance_exit':'ExitMaintenanceMode_Task', 'reboot':'RebootHost_Task', 'shutdown':'ShutdownHost_Task',
   'lockdown_enter':'EnterLockdownMode', 'lockdown_exit':'ExitLockdownMode', 'disconnect':'DisconnectHost_Task',
   'reconnect':'ReconnectHost_Task'}),
 'options': ('host:advancedOption', 'vim.option.OptionManager', {'update':'UpdateOptions'}),
}

def discover(si, domain):
    if domain not in CATALOG:
        raise ToolError('Unknown resource domain: ' + domain)
    content, dc, host = _get_host(si)
    location = CATALOG[domain][0]
    scope, name = location.split(':')
    obj = host if name == 'self' else getattr(host.configManager if scope == 'host' else content, name, None)
    if obj is None:
        raise ToolError('This ESXi does not expose the requested resource manager: ' + domain)
    return obj

@mcp.tool(annotations=READ)
@_audited
def esxi_resource_schema(domain: str, action: Optional[str] = None, depth: int = 2) -> Dict[str, Any]:
    """专用资源操作目录和准确参数：network/datastore/storage/service/firewall/account/permissions/license/time/pci/certificate/patch/host。"""
    if domain not in CATALOG:
        raise ToolError('Unknown resource domain')
    _, type_name, actions = CATALOG[domain]
    if action is None:
        return {'domain': domain, 'type': type_name, 'actions': actions,
                'note': 'Schema availability is not proof of server/license support'}
    if action not in actions:
        raise ToolError('Unknown action; first query this domain without action')
    return {'domain': domain, 'action': action, **advanced.esxi_api_schema(type_name, actions[action], depth)}

@mcp.tool(annotations=READ)
@_audited
def esxi_resource_get(domain: str, properties: List[str], depth: int = 5, max_items: int = 200) -> Dict[str, Any]:
    """按资源域直接查询状态，无需手工拼管理器 ID；只允许已声明属性。"""
    from .advanced import esxi_api_get
    with api.service_instance(load_config()) as si:
        target = codec.encode(discover(si, domain))
    return esxi_api_get(target, properties, depth, max_items)

def operate(domain, action, arguments, expected_host, dry_run, allow_disruption, acknowledged_vm_ids,
            allow_unknown_impact, allow_protected_impact, request_id):
    cfg = load_config()
    if action not in CATALOG[domain][2]:
        raise ToolError('Unknown ' + domain + ' action; query esxi_resource_schema')
    if not dry_run and expected_host != cfg.host:
        raise ToolError('expected_host must exactly match the configured ESXi host')
    with api.service_instance(cfg) as si:
        target = codec.encode(discover(si, domain))
    return advanced.esxi_api_invoke(target, CATALOG[domain][2][action], arguments,
                           target['_type'] + ':' + target['_moId'], dry_run, allow_disruption,
                           acknowledged_vm_ids, allow_unknown_impact, allow_protected_impact, request_id)

def make_controller(domain):
    def controller(action: str, arguments: Optional[Dict[str, Any]] = None,
                   expected_host: Optional[str] = None, dry_run: bool = True,
                   allow_disruption: bool = False, acknowledged_vm_ids: Optional[List[str]] = None,
                   allow_unknown_impact: bool = False, allow_protected_impact: bool = False,
                   request_id: Optional[str] = None) -> Dict[str, Any]:
        return operate(domain, action, arguments or {}, expected_host, dry_run, allow_disruption,
                       acknowledged_vm_ids, allow_unknown_impact, allow_protected_impact, request_id)
    controller.__name__ = 'esxi_' + domain + '_manage'
    controller.__doc__ = ('专用 ' + domain + ' 管理：' + ', '.join(CATALOG[domain][2]) +
                          '。先 resource_schema/get 和默认预览；实际执行精确 expected_host、写开关与依赖确认，支持 request_id 防止重复执行。')
    return mcp.tool(annotations=WRITE)(_audited(controller))

CONTROLLERS = {domain: make_controller(domain) for domain in CATALOG}

@mcp.tool(annotations=READ)
@_audited
def esxi_dependencies() -> Dict[str, Any]:
    """VM→网络/存储/文件依赖及管理 VMkernel 连接，供共享资源变更前审查。"""
    cfg = load_config()
    with api.service_instance(cfg) as si:
        return policy.snapshot(si, cfg)

@mcp.tool(annotations=READ)
@_audited
def esxi_capabilities() -> Dict[str, Any]:
    """实际主机版本、许可证、可发现管理器、工具操作目录及部署开关；不把 SDK schema 当作实测支持。"""
    cfg = load_config()
    with api.service_instance(cfg) as si:
        content, _, host = _get_host(si)
        managers = {domain: codec.encode(discover(si, domain)) for domain in CATALOG
                    if domain == 'host' or getattr(host.configManager if CATALOG[domain][0].startswith('host:') else content,
                                                 CATALOG[domain][0].split(':')[1], None) is not None}
        licenses = codec.encode(content.licenseManager.licenses, 4, 100) if content.licenseManager else None
        licenses = [{key: '[REDACTED]' if key == 'licenseKey' else value for key, value in item.items()}
                    for item in licenses or []]
        return {'product': str(content.about.fullName), 'api_version': str(content.about.apiVersion),
                'host_capabilities': codec.encode(host.capability, 4), 'licenses': licenses, 'managers': managers,
                'policy_profile': cfg.policy_profile, 'writes_enabled': cfg.enable_writes,
                'ssh_admin_enabled': cfg.ssh_admin_enabled, 'protected_vm_ids': cfg.protected_vm_ids,
                'domains': list(CATALOG), 'note': 'A capability/SDK method can still fail for privilege, license, state or hardware reasons'}

@mcp.tool(annotations=READ)
@_audited
def esxi_operation_status(operation_id: str, refresh_task: bool = True) -> Dict[str, Any]:
    """持久化操作记录：submitted 任务可重新连接查询；中断的 executing 操作不自动重复。"""
    cfg = load_config()
    entry = state.get(cfg, operation_id)
    if entry['status'] in ('queued', 'running', 'executing'):
        from .transfers import process_alive
        if not process_alive(entry.get('owner_pid')):
            state.update(cfg, operation_id, 'needs_review', note='Worker process is gone; inspect resources/lease before issuing a new operation')
            entry = state.get(cfg, operation_id)
    result = entry.get('result') or {}
    if refresh_task and result.get('task_id') and entry['status'] == 'submitted':
        with api.service_instance(cfg) as si:
            task = api.get_task_by_id(si, result['task_id'])
            if task is None:
                state.update(cfg, operation_id, 'needs_review', note='Task is unavailable; inspect actual resource state before retrying')
            else:
                fresh = api.task_to_dict(task)
                state.finish(cfg, operation_id, fresh)
        entry = state.get(cfg, operation_id)
    return entry

@mcp.tool(annotations=READ)
@_audited
def esxi_operation_history(limit: int = 50) -> Dict[str, Any]:
    """查询当前主机/账户的持久化操作清单；不会输出密码或 signed URL。"""
    return {'operations': state.recent(load_config(), limit)}

@mcp.tool(annotations=WRITE)
@_audited
def esxi_vm_hardware(vm_id: str, expected_name: str, device_changes: List[Dict[str, Any]],
                     dry_run: bool = True, request_id: Optional[str] = None) -> Dict[str, Any]:
    """增删/编辑虚拟磁盘、网卡、光驱、控制器、PCI 设备。device_changes 使用官方 VirtualDeviceSpec，保留其余 VM 配置。"""
    cfg = load_config()
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        _guard_protected(vm_id, str(vm.name), cfg, dry_run, 'esxi_vm_hardware')
        if not 1 <= len(device_changes) <= 64:
            raise ToolError('Expected 1..64 explicit device changes')
        target = codec.encode(vm)
    return advanced.esxi_api_invoke(target, 'ReconfigVM_Task', {'spec': {'deviceChange': device_changes}},
                           target['_type'] + ':' + target['_moId'], dry_run=dry_run, request_id=request_id)

@mcp.tool(annotations=WRITE)
@_audited
def esxi_vm_register(datastore: str, vmx_path: str, name: str, expected_host: Optional[str] = None,
                     dry_run: bool = True, request_id: Optional[str] = None) -> Dict[str, Any]:
    """将已有 VMX 注册到该 ESXi 的 VM 文件夹与资源池；不创建或覆盖 VM 文件。"""
    from .files import validate_path
    from .security import validate_vm_name
    cfg = load_config()
    validate_path(vmx_path)
    if not vmx_path.endswith('.vmx') or validate_vm_name(name):
        raise ToolError('Expected a valid VM name and datastore-relative .vmx path')
    if not dry_run and expected_host != cfg.host:
        raise ToolError('expected_host must exactly match configured host')
    with api.service_instance(cfg) as si:
        _, dc, host = _get_host(si)
        if datastore not in [ds.name for ds in dc.datastore]:
            raise ToolError('Datastore not found')
        if api.find_vm_by_name(si, name):
            raise ToolError('VM name already exists')
        target = codec.encode(dc.vmFolder)
        arguments = {'path': '[' + datastore + '] ' + vmx_path, 'name': name, 'asTemplate': False,
                     'pool': codec.encode(host.parent.resourcePool), 'host': codec.encode(host)}
    return advanced.esxi_api_invoke(target, 'RegisterVM_Task', arguments, target['_type'] + ':' + target['_moId'],
                           dry_run=dry_run, allow_disruption=True, allow_unknown_impact=True, request_id=request_id)

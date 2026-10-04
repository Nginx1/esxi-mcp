"""Account-local operation policy and conservative shared-resource dependency checks."""
from __future__ import annotations
import fnmatch
import re
from pathlib import PurePosixPath
from pyVmomi import vim, VmomiSupport as V
from mcp.server.fastmcp.exceptions import ToolError
from . import api, codec

ADMIN_TYPES = {'vim.HostSystem', 'vim.host.AccountManager', 'vim.host.LocalAccountManager', 'vim.AuthorizationManager',
               'vim.LicenseManager', 'vim.host.CertificateManager', 'vim.host.PatchManager',
               'vim.host.PciPassthruSystem', 'vim.host.FirewallSystem', 'vim.host.StorageSystem',
               'vim.host.AdvancedOptionManager', 'vim.host.KernelModuleSystem'}
READ_METHODS = {'RefreshNetworkSystem', 'RefreshStorageSystem', 'RefreshDatastore', 'RefreshServices',
                'CreateImportSpec', 'CreateDescriptor', 'ParseDescriptor', 'ValidateHost',
                'HttpNfcLeaseGetManifest', 'HttpNfcLeaseProgress', 'HttpNfcLeaseComplete', 'HttpNfcLeaseAbort'}

def is_query(method):
    return method in READ_METHODS or method.startswith(('Query', 'Retrieve', 'Fetch', 'List'))

def check_operation(cfg, operation, administrator=False, dry_run=False):
    if dry_run:
        return
    if cfg.policy_profile == 'read_only':
        raise ToolError('Policy profile is read_only')
    if any(fnmatch.fnmatchcase(operation, pattern) for pattern in cfg.denied_operations):
        raise ToolError('Operation denied by deployment policy: ' + operation)
    if cfg.allowed_operations and not any(fnmatch.fnmatchcase(operation, pattern) for pattern in cfg.allowed_operations):
        raise ToolError('Operation is outside deployment allowed_operations: ' + operation)
    if administrator and cfg.policy_profile != 'administrator':
        raise ToolError('This operation requires policy_profile=administrator')

def field(value, name, default=None):
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)

def datastore_path(value):
    match = re.fullmatch(r'\[([^\]]+)\]\s+(.+)', str(value))
    if not match:
        raise ToolError('Expected an exact [datastore] relative/path')
    name, path = match.groups()
    if path.startswith('/') or '\\' in path or any(part in ('', '.', '..') for part in path.split('/')):
        raise ToolError('Invalid datastore-relative path')
    return name, path

def snapshot(si, cfg):
    from .tools import _get_host
    _, _, host = _get_host(si)
    vms = []
    with api.container_view(si, vim.VirtualMachine) as view:
        for vm in view.view:
            if vm.config is None:
                raise ToolError('Dependency scan cannot inspect VM ' + str(vm._moId))
            paths = [str(vm.config.files.vmPathName)] if vm.config.files else []
            networks = {str(net.name) for net in vm.network or []}
            for device in vm.config.hardware.device or []:
                backing = getattr(device, 'backing', None)
                if getattr(backing, 'fileName', None):
                    paths.append(str(backing.fileName))
                if getattr(backing, 'deviceName', None):
                    networks.add(str(backing.deviceName))
            vms.append({'vm_id': str(vm._moId), 'name': str(vm.name),
                        'protected': str(vm._moId) in list(map(str, cfg.protected_vm_ids)),
                        'datastores': [str(ds.name) for ds in vm.datastore or []],
                        'networks': sorted(networks), 'files': paths})
    info = host.configManager.networkSystem.networkInfo
    selected = set()
    selection_known = False
    manager = getattr(host.configManager, 'virtualNicManager', None)
    if manager:
        selection = manager.QueryNetConfig('management')
        selected = set(map(str, selection.selectedVnic or []))
        selection_known = bool(selected)
    vmknics = []
    for nic in info.vnic or []:
        ip = field(field(nic.spec, 'ip'), 'ipAddress', '')
        management = str(nic.key) in selected or str(nic.device) in selected or ip == cfg.host
        if not selection_known:
            management = True  # Unknown management selection fails closed.
        vmknics.append({'device': str(nic.device), 'portgroup': str(nic.portgroup),
                        'ip': str(ip), 'management': management})
    switches = [{'name': str(switch.name), 'pnics': list(map(str, switch.pnic or [])),
                 'portgroups': [str(pg.spec.name) for pg in info.portgroup or [] if pg.spec.vswitchName == switch.name]}
                for switch in info.vswitch or []]
    return {'vms': vms, 'vmkernel': vmknics, 'switches': switches,
            'management_selection_known': selection_known, 'host': codec.encode(host)}

def referenced_resources(value):
    """Inspect embedded device/config references without treating a VM edit as a host-wide change."""
    datastores, networks, paths = set(), set(), []
    def visit(item, key=None):
        if isinstance(item, vim.Datastore):
            datastores.add(str(item.name))
        elif isinstance(item, vim.Network):
            networks.add(str(item.name))
        elif isinstance(item, V.DataObject):
            for prop in item._GetPropertyList():
                visit(getattr(item, prop.name, None), prop.name)
        elif isinstance(item, dict):
            for name, member in item.items():
                visit(member, name)
        elif isinstance(item, (list, tuple)):
            for member in item:
                visit(member, key)
        elif isinstance(item, str):
            match = re.fullmatch(r'\[([^\]]+)\](?:\s+(.+))?', item)
            if match:
                datastores.add(match[1])
                if match[2]:
                    paths.append(datastore_path(item))
            elif key == 'deviceName':
                networks.add(item)
    visit(value)
    return datastores, networks, paths

def owns_file(vm, datastore, path):
    for location in vm['files']:
        if not location.startswith('[') or location.startswith('[]'):
            # ESXi's VMware Tools CD uses [] /usr/lib/... on the host, not a datastore path.
            continue
        vm_ds, vm_path = datastore_path(location)
        directory = str(PurePosixPath(vm_path).parent)
        if vm_ds == datastore and (path == vm_path or path == directory or vm_path.startswith(path.rstrip('/') + '/')
                                   or (directory != '.' and path.startswith(directory + '/'))):
            return True
    return False

def impact(si, cfg, obj, method, arguments):
    kind = type(obj).__name__
    report = {'affected_vm_ids': [], 'protected_vm_ids': [], 'datastores': [], 'networks': [],
              'management_disruption': False, 'unknown_impact': False}
    if kind == 'vim.HttpNfcLease' or is_query(method):
        return report
    if isinstance(obj, vim.VirtualMachine) or (kind == 'vim.Folder' and method in ('CreateVM_Task','RegisterVM_Task')):
        ds, nets, paths = referenced_resources(arguments)
        report.update(datastores=sorted(ds), networks=sorted(nets))
        if paths:
            affected = [vm for vm in snapshot(si, cfg)['vms'] if str(obj._moId) != vm['vm_id']
                        and any(owns_file(vm, store, path) for store, path in paths)]
            report.update(affected_vm_ids=sorted(vm['vm_id'] for vm in affected),
                          protected_vm_ids=sorted(vm['vm_id'] for vm in affected if vm['protected']))
        return report
    if kind.startswith('vim.vm.guest.') and isinstance(arguments.get('vm'), vim.VirtualMachine):
        return report  # Direct guest VM references are checked by the caller.
    if kind == 'vim.host.NetworkSystem' and method == 'AddVirtualSwitch':
        bridge = field(arguments.get('spec'), 'bridge')
        if not bridge or not field(bridge, 'nicDevice'):
            return report
    if kind == 'vim.host.ServiceSystem' and method == 'StartService':
        return report
    if kind in ('vim.OvfManager', 'vim.ResourcePool') and method in ('ImportVApp', 'CreateResourcePool'):
        return report
    graph = snapshot(si, cfg)
    networks, datastores, paths = set(), set(), []
    all_vms = False
    if kind == 'vim.host.NetworkSystem':
        if method in ('AddPortGroup', 'UpdatePortGroup', 'RemovePortGroup'):
            name = arguments.get('pgName') or field(arguments.get('portgrp'), 'name')
            networks.add(str(name))
        elif method in ('RemoveVirtualSwitch', 'UpdateVirtualSwitch', 'AddVirtualSwitch'):
            name = arguments.get('vswitchName')
            for switch in graph['switches']:
                if switch['name'] == name or method == 'AddVirtualSwitch':
                    networks.update(switch['portgroups'])
        elif method in ('RemoveVirtualNic', 'UpdateVirtualNic'):
            for nic in graph['vmkernel']:
                if nic['device'] == arguments.get('device'):
                    networks.add(nic['portgroup'])
                    report['management_disruption'] |= nic['management']
        elif method == 'AddVirtualNic':
            address = field(field(arguments.get('nic'), 'ip'), 'ipAddress')
            report['management_disruption'] = address == cfg.host
        else:
            all_vms = True
            report['management_disruption'] = True
        report['management_disruption'] |= any(nic['management'] and nic['portgroup'] in networks for nic in graph['vmkernel'])
    elif kind in ('vim.FileManager', 'vim.VirtualDiskManager'):
        keys = ('destinationName',) if method.startswith(('Copy', 'Move')) else ('name', 'sourceName')
        if method.startswith('Move'):
            keys += ('sourceName',)
        for key in keys:
            if arguments.get(key):
                ds, path = datastore_path(arguments[key])
                paths.append((ds, path))
        if not paths:
            report['unknown_impact'] = all_vms = True
    elif kind == 'vim.host.DatastoreSystem' and arguments.get('datastore'):
        datastores.add(str(arguments['datastore'].name))
    elif kind == 'vim.host.ServiceSystem':
        report['management_disruption'] = arguments.get('id') in ('hostd', 'vpxa', 'rhttpproxy', 'TSM-SSH')
        all_vms = report['management_disruption']
    elif kind == 'vim.Folder' and method in ('CreateVM_Task', 'RegisterVM_Task'):
        return report
    else:
        # Formatting/HBA changes, host power, opaque strings and unknown managers are host-wide.
        all_vms = True
        report['unknown_impact'] = kind not in ADMIN_TYPES
        report['management_disruption'] = kind in ('vim.HostSystem', 'vim.host.AccountManager',
                                                   'vim.AuthorizationManager', 'vim.host.CertificateManager',
                                                   'vim.host.FirewallSystem', 'vim.host.PatchManager')
    affected = []
    for vm in graph['vms']:
        owns_path = False
        for ds, path in paths:
            owns_path |= owns_file(vm, ds, path)
        if all_vms or networks.intersection(vm['networks']) or datastores.intersection(vm['datastores']) or owns_path:
            affected.append(vm)
    report.update(affected_vm_ids=sorted(vm['vm_id'] for vm in affected),
                  protected_vm_ids=sorted(vm['vm_id'] for vm in affected if vm['protected']),
                  networks=sorted(networks), datastores=sorted(datastores | {ds for ds, _ in paths}))
    return report

def enforce_impact(cfg, report, acknowledged_vm_ids=None, allow_disruption=False,
                   allow_unknown_impact=False, allow_protected_impact=False, dry_run=False):
    if dry_run:
        return
    if set(report['datastores']).intersection(cfg.protected_datastores) or set(report['networks']).intersection(cfg.protected_networks):
        raise ToolError('Operation affects a deployment-protected datastore/network')
    if report['management_disruption'] and not (allow_disruption and cfg.allow_management_disruption and cfg.policy_profile == 'administrator'):
        raise ToolError('Management connectivity may be disrupted; requires administrator profile, deployment allow_management_disruption and allow_disruption=true')
    if report['unknown_impact'] and not (allow_unknown_impact and cfg.policy_profile == 'administrator'):
        raise ToolError('Dependency impact is unknown; administrator must explicitly set allow_unknown_impact=true')
    required = set(report['affected_vm_ids'])
    if required and not required.issubset(set(map(str, acknowledged_vm_ids or []))):
        raise ToolError('acknowledged_vm_ids must include every affected VM: ' + ','.join(sorted(required)))
    if report['protected_vm_ids'] and not (cfg.allow_protected_impact and allow_protected_impact and cfg.policy_profile == 'administrator'):
        raise ToolError('Operation affects protected VMs; deployment and call must both explicitly allow protected impact')

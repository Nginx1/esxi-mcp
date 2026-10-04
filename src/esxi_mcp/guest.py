"""Guest process and filesystem workflows with explicit VM and guest authentication."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from pyVmomi import vim
from mcp.server.fastmcp.exceptions import ToolError
from . import api, codec
from .config import load_config
from .tools import mcp, READ, WRITE, _audited, _resolve_vm, _guard_protected, _tools_ok
from . import advanced

FILE_ACTIONS = {'mkdir':'MakeDirectoryInGuest', 'delete_file':'DeleteFileInGuest',
                'delete_directory':'DeleteDirectoryInGuest', 'move_file':'MoveFileInGuest',
                'move_directory':'MoveDirectoryInGuest', 'attributes':'ChangeFileAttributesInGuest',
                'download_url':'InitiateFileTransferFromGuest', 'upload_url':'InitiateFileTransferToGuest',
                'list':'ListFilesInGuest'}

def context(vm_id, expected_name, auth, manager_name, dry_run, writable=True):
    cfg = load_config()
    authentication = codec.decode(auth, vim.vm.guest.GuestAuthentication, None)
    with api.service_instance(cfg) as si:
        vm = _resolve_vm(si, vm_id, expected_name)
        if not _tools_ok(vm):
            raise ToolError('Guest operations require a running OS and VMware Tools; no forced power or shell fallback')
        if writable:
            _guard_protected(vm_id, str(vm.name), cfg, dry_run, 'esxi_guest')
        manager = getattr(si.RetrieveContent().guestOperationsManager, manager_name, None)
        if manager is None:
            raise ToolError('This host does not expose the guest operation manager')
        return codec.encode(manager), codec.encode(vm)

@mcp.tool(annotations=WRITE)
@_audited
def esxi_guest_process(vm_id: str, expected_name: str, authentication: Dict[str, Any],
                        action: str, program_path: Optional[str] = None, arguments: str = '',
                        working_directory: Optional[str] = None, environment: Optional[List[str]] = None,
                        pid: Optional[int] = None, dry_run: bool = True, request_id: Optional[str] = None) -> Dict[str, Any]:
    """Guest 进程start/terminate：显式OS内路径和认证；start返回PID，再process_status查看exitCode。不会自动用ESXi shell替代guest。"""
    target, vm = context(vm_id, expected_name, authentication, 'processManager', dry_run)
    args = {'vm': vm, 'auth': authentication}
    if action == 'start':
        if not program_path:
            raise ToolError('Guest start requires explicit program_path')
        args['spec'] = {'programPath': program_path, 'arguments': arguments,
                        **({'workingDirectory': working_directory} if working_directory else {}),
                        **({'envVariables': environment} if environment is not None else {})}
        method = 'StartProgramInGuest'
    elif action == 'terminate' and pid is not None and pid > 0:
        args['pid'], method = pid, 'TerminateProcessInGuest'
    else:
        raise ToolError('Expected start or terminate with a positive pid')
    return advanced.esxi_api_invoke(target, method, args, target['_type'] + ':' + target['_moId'],
                           dry_run=dry_run, allow_disruption=True, request_id=request_id)

@mcp.tool(annotations=READ)
@_audited
def esxi_guest_process_status(vm_id: str, expected_name: str, authentication: Dict[str, Any],
                               pids: Optional[List[int]] = None) -> Dict[str, Any]:
    """查询guest进程状态、PID、启动/结束时间与exitCode；只读，可检查受保护VM。"""
    target, vm = context(vm_id, expected_name, authentication, 'processManager', True, False)
    cfg = load_config()
    with api.service_instance(cfg) as si:
        manager = codec.reference(target, si._stub)
        value = manager.ListProcessesInGuest(codec.reference(vm, si._stub),
                                              codec.decode(authentication, vim.vm.guest.GuestAuthentication, si._stub), pids)
        return {'vm_id': vm_id, 'processes': codec.encode(value, 5, 500)}

@mcp.tool(annotations=WRITE)
@_audited
def esxi_guest_files(vm_id: str, expected_name: str, authentication: Dict[str, Any],
                      action: str, arguments: Dict[str, Any], dry_run: bool = True,
                      request_id: Optional[str] = None) -> Dict[str, Any]:
    """Guest 文件list/mkdir/delete/move/attributes/upload_url/download_url。HTTP传输用后台transfer_start(kind=guest)，大文件不经LLM传整个base64。"""
    if action not in FILE_ACTIONS:
        raise ToolError('Unknown guest file action')
    if set(arguments).intersection(('vm', 'auth')):
        raise ToolError('vm/auth must come from explicit VM and authentication parameters')
    target, vm = context(vm_id, expected_name, authentication, 'fileManager', dry_run)
    return advanced.esxi_api_invoke(target, FILE_ACTIONS[action], {'vm': vm, 'auth': authentication, **arguments},
                           target['_type'] + ':' + target['_moId'], dry_run=dry_run,
                           allow_disruption=True, request_id=request_id)

"""Optional ESXi SSH administration with pinned host keys, explicit scope and no auto retry."""
from __future__ import annotations
import base64
import hashlib
import json
import os
import shlex
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from mcp.server.fastmcp.exceptions import ToolError
from . import api, policy
from .config import load_config
from .tools import mcp, READ, WRITE, _audited, _guard_writes

QUERY_PATHS = [path.split() for path in (
 'system version get', 'system hostname get', 'system maintenanceMode get', 'system settings advanced list',
 'system account list', 'network nic list', 'network vswitch standard list', 'network vswitch standard portgroup list',
 'network ip interface list', 'network ip interface ipv4 get', 'network firewall get', 'network firewall ruleset list',
 'storage filesystem list', 'storage core adapter list', 'storage core device list', 'hardware cpu list',
 'hardware memory get', 'software vib list', 'software profile get')]

def arguments_command(arguments):
    if not isinstance(arguments, list) or not 1 <= len(arguments) <= 128 or any(
            not isinstance(item, str) or '\0' in item or '\n' in item or '\r' in item or len(item) > 8192 for item in arguments):
        raise ToolError('Expected 1..128 single-line esxcli argv strings')
    return '/bin/esxcli ' + shlex.join(arguments)

def connect(cfg):
    try:
        import paramiko
    except ImportError:
        raise ToolError('SSH backend requires installing esxi-mcp[admin]') from None
    path = Path(cfg.ssh_credentials_file)
    if not path.is_file():
        raise ToolError('Private SSH credentials file is missing; configure ESXI_SSH_CREDENTIALS_FILE')
    doc = json.loads(path.read_text(encoding='utf-8'))
    if doc.get('host') not in (None, cfg.host):
        raise ToolError('SSH credentials identify a different host')
    pin = doc.get('host_key_sha256')
    known = doc.get('known_hosts_file')
    if not pin and not known:
        raise ToolError('SSH requires a pinned SHA256 host key or configured known_hosts_file')
    if pin and known:
        raise ToolError('Choose one SSH host trust source: SHA256 pin or known_hosts_file')
    class Pin(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            digest = hashlib.sha256(key.asbytes()).digest()
            candidates = {digest.hex(), 'SHA256:' + base64.b64encode(digest).decode().rstrip('=')}
            if pin not in candidates:
                raise paramiko.SSHException('ESXi SSH host identity does not match the configured pin')
    client = paramiko.SSHClient()
    if known:
        client.load_host_keys(known)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(Pin())
    try:
        client.connect(cfg.host, port=int(doc.get('port', 22)), username=doc.get('user', cfg.user),
                       password=doc.get('password'), key_filename=doc.get('key_filename'),
                       look_for_keys=False, allow_agent=False, timeout=cfg.connect_timeout,
                       auth_timeout=cfg.connect_timeout, banner_timeout=cfg.connect_timeout)
    except BaseException:
        client.close()
        raise
    return client, doc

def run(cfg, command, timeout, max_output_bytes):
    if not 1 <= timeout <= 3600 or not 1024 <= max_output_bytes <= 1024 * 1024:
        raise ToolError('Timeout must be1..3600s; returned output bound must be1KiB..1MiB')
    client, secrets = connect(cfg)
    try:
        channel = client.get_transport().open_session(timeout=cfg.connect_timeout)
        channel.exec_command(command)
        stdout, stderr, total = bytearray(), bytearray(), 0
        deadline = time.monotonic() + timeout
        while True:
            for ready, receive, output in ((channel.recv_ready, channel.recv, stdout),
                                            (channel.recv_stderr_ready, channel.recv_stderr, stderr)):
                if ready():
                    chunk = receive(65536)
                    total += len(chunk)
                    if len(output) < max_output_bytes:
                        output.extend(chunk[:max_output_bytes - len(output)])
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() > deadline:
                channel.close()
                raise ToolError('SSH command timeout; remote state is uncertain, inspect before retrying')
            time.sleep(0.02)
        def redact(value):
            text = value.decode('utf-8', 'replace')
            for secret in (cfg.password, secrets.get('password')):
                if secret:
                    text = text.replace(secret, '[REDACTED]')
            return text
        return {'state': 'completed', 'exit_code': channel.recv_exit_status(), 'stdout': redact(stdout),
                'stderr': redact(stderr), 'output_truncated': total > len(stdout) + len(stderr)}
    finally:
        client.close()

def guard(cfg, expected_host, dry_run, allow_disruption, acknowledged_vm_ids, allow_protected_impact):
    _guard_writes(cfg, dry_run)
    policy.check_operation(cfg, 'ssh:administration', administrator=True, dry_run=dry_run)
    if not dry_run:
        if not cfg.ssh_admin_enabled or os.environ.get('ESXI_ENABLE_ADVANCED_WRITES', '').lower() not in ('true', '1', 'yes', 'on'):
            raise ToolError('SSH execution requires ssh_admin_enabled and advanced write opt-in')
        if expected_host != cfg.host:
            raise ToolError('expected_host must exactly match configured ESXi host')
    with api.service_instance(cfg) as si:
        graph = policy.snapshot(si, cfg)
    report = {'affected_vm_ids': [vm['vm_id'] for vm in graph['vms']],
              'protected_vm_ids': [vm['vm_id'] for vm in graph['vms'] if vm['protected']],
              'datastores': list({ds for vm in graph['vms'] for ds in vm['datastores']}),
              'networks': list({net for vm in graph['vms'] for net in vm['networks']}),
              'management_disruption': True, 'unknown_impact': True}
    policy.enforce_impact(cfg, report, acknowledged_vm_ids, allow_disruption, True, allow_protected_impact, dry_run)
    return report

@mcp.tool(annotations=READ)
@_audited
def esxi_esxcli_query(arguments: List[str], timeout: int = 60, max_output_bytes: int = 65536) -> Dict[str, Any]:
    """可选SSH后端的固定只读ESXCLI查询。查询白名单由服务器判断，不接受调用者自报read_only。"""
    cfg = load_config()
    command = arguments_command(arguments)
    if not any(arguments[:len(prefix)] == prefix for prefix in QUERY_PATHS):
        raise ToolError('Command is outside the read-only ESXCLI query catalog')
    if not cfg.ssh_admin_enabled:
        raise ToolError('Optional SSH backend is disabled')
    policy.check_operation(cfg, 'ssh:query', administrator=True)
    return run(cfg, command, timeout, max_output_bytes)

@mcp.tool(annotations=WRITE)
@_audited
def esxi_esxcli(arguments: List[str], expected_host: Optional[str] = None, dry_run: bool = True,
                 allow_disruption: bool = False, acknowledged_vm_ids: Optional[List[str]] = None,
                 allow_protected_impact: bool = False, timeout: int = 300,
                 max_output_bytes: int = 65536) -> Dict[str, Any]:
    """ESXCLI完整argv入口，用于SDK之外的主机配置/补丁/驱动/存储操作。SSH默认关闭，执行需管理员、独立host-key校验与全部影响确认。"""
    cfg = load_config()
    command = arguments_command(arguments)
    report = guard(cfg, expected_host, dry_run, allow_disruption, acknowledged_vm_ids, allow_protected_impact)
    if dry_run:
        return {'dry_run': True, 'command': command, 'dependencies': report}
    return run(cfg, command, timeout, max_output_bytes)

@mcp.tool(annotations=WRITE)
@_audited
def esxi_shell(command: str, expected_host: Optional[str] = None, dry_run: bool = True,
                 allow_disruption: bool = False, acknowledged_vm_ids: Optional[List[str]] = None,
                 allow_protected_impact: bool = False, timeout: int = 300,
                 max_output_bytes: int = 65536) -> Dict[str, Any]:
    """显式整台ESXi shell管理入口，仅administrator+SSH独立开关+管理链路/保护影响双重允许。任意shell无法做完整依赖推断，不自动重试。"""
    if not command or '\0' in command or len(command) > 65536:
        raise ToolError('Expected a nonempty command <=64KiB without NUL')
    cfg = load_config()
    report = guard(cfg, expected_host, dry_run, allow_disruption, acknowledged_vm_ids, allow_protected_impact)
    if dry_run:
        return {'dry_run': True, 'dependencies': report, 'command_requires_operator_review': True}
    return run(cfg, command, timeout, max_output_bytes)

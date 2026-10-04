"""HTTP phase for SDK-issued guest-file and NFC lease URLs."""
from __future__ import annotations
import base64
import hashlib
import os
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional
from mcp.server.fastmcp.exceptions import ToolError
from pyVmomi import vim
from . import api, codec
from .config import load_config

def normalize_url(url, cfg, host_name):
    parsed = urllib.parse.urlparse(url)
    allowed = {cfg.host.strip('[]').lower(), str(host_name).lower(), '*'}
    if parsed.scheme != 'https' or parsed.hostname not in allowed or parsed.username or parsed.password:
        raise ToolError('Transfer URL must identify the configured ESXi host over HTTPS')
    endpoint = parsed.path == '/guestFile' or parsed.path.startswith(('/nfc/', '/ha-nfc/'))
    if parsed.port not in (None, cfg.port) or not endpoint:
        raise ToolError('Only SDK-issued guestFile/NFC endpoint URLs are accepted')
    if any(segment in ('.', '..') for segment in urllib.parse.unquote(parsed.path).split('/')):
        raise ToolError('Path traversal is refused')
    host = cfg.host.strip('[]')
    authority = ('[' + host + ']' if ':' in host else host) + ':' + str(cfg.port)
    return urllib.parse.urlunparse(parsed._replace(netloc=authority, fragment=''))

from .files import NoRedirect
from .tools import mcp, WRITE, _audited, _guard_writes, _get_host

@mcp.tool(annotations=WRITE)
@_audited
def esxi_api_transfer(transfer_url: str, operation: str, data_base64: Optional[str] = None,
                       source_url: Optional[str] = None, max_bytes: int = 8388608,
                       http_method: str = 'PUT', content_type: str = 'application/octet-stream',
                       lease: Optional[Dict[str, Any]] = None, dry_run: bool = True) -> Dict[str, Any]:
    """处理 GuestFileManager 或 HttpNfcLease 返回的 HTTPS URL，完成 guest 文件/OVF-NFC 的 HTTP 阶段。

    仅连接当前 ESXi 的 guestFile/NFC 路径。上传默认预览，执行需普通和高级写开关。
    lease 传发现的 HttpNfcLease 引用以在下载源文件/上传时刷新进度，最后用 API 调用 Complete/Abort。
    OVF 流式 VMDK 通常用 POST 和 application/x-vnd.vmware-streamVmdk；guest 文件用 PUT。
    该工具不是一键 OS 安装器；guest 需要 Tools 和认证，OVA 需先取得描述符和独立磁盘数据。
    """
    if operation not in ('upload', 'download') or http_method not in ('PUT', 'POST') or not 1 <= max_bytes <= 8 * 1024**3:
        raise ToolError('Invalid operation, HTTP method or file bound')
    if operation == 'download' and max_bytes > 8 * 1024**2:
        raise ToolError('Inline downloads are limited to 8MiB')
    if operation == 'upload' and (data_base64 is None) == (source_url is None):
        raise ToolError('Upload requires exactly one inline payload or HTTPS source URL')
    if source_url and urllib.parse.urlparse(source_url).scheme != 'https':
        raise ToolError('Source URL must use HTTPS')
    cfg = load_config()
    if operation == 'upload':
        _guard_writes(cfg, dry_run)
        if not dry_run and os.environ.get('ESXI_ENABLE_ADVANCED_WRITES', '').lower() not in ('1','true','yes','on'):
            raise ToolError('API upload requires ESXI_ENABLE_ADVANCED_WRITES=true')
    with api.service_instance(cfg, target=lease) as si:
        _, _, host = _get_host(si)
        url = normalize_url(transfer_url, cfg, host.name)
        lease_object = codec.reference(lease, si._stub) if lease else None
        if lease_object is not None and not isinstance(lease_object, vim.HttpNfcLease):
            raise ToolError('Lease reference must be a vim.HttpNfcLease')
        if dry_run:
            return {'dry_run': True, 'operation': operation, 'max_bytes': max_bytes,
                    'http_method': http_method, 'content_type': content_type, 'endpoint': urllib.parse.urlparse(url).path}
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=api._ssl_context(cfg)))
        headers = {'Cookie': str(si._stub.cookie)}
        if operation == 'download':
            with opener.open(urllib.request.Request(url, headers=headers), timeout=cfg.connect_timeout) as response:
                data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ToolError('Download exceeds bound')
            return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                    'data_base64': base64.b64encode(data).decode('ascii')}
        last_progress = 0.0
        def progress():
            nonlocal last_progress
            if lease_object and time.monotonic() - last_progress >= 10:
                lease_object.HttpNfcLeaseProgress(1)
                last_progress = time.monotonic()
        with tempfile.TemporaryFile() as staged:
            progress()
            if data_base64 is not None:
                if len(data_base64) > 4 * ((min(max_bytes, 8 * 1024**2) + 2) // 3):
                    raise ToolError('Inline payload exceeds bound')
                data = base64.b64decode(data_base64, validate=True)
                if len(data) > max_bytes:
                    raise ToolError('Payload exceeds bound')
                staged.write(data)
            else:
                with urllib.request.urlopen(source_url, timeout=cfg.connect_timeout) as response:
                    copied = 0
                    while True:
                        progress()
                        chunk = response.read(1024**2)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > max_bytes:
                            raise ToolError('Source exceeds bound')
                        staged.write(chunk)
            size = staged.tell()
            staged.seek(0)
            hasher = hashlib.sha256()
            for chunk in iter(lambda: staged.read(1024**2), b''):
                hasher.update(chunk)
            staged.seek(0)
            def chunks():
                for chunk in iter(lambda: staged.read(1024**2), b''):
                    progress()
                    yield chunk
            request = urllib.request.Request(url, data=chunks(), method=http_method,
                        headers={**headers, 'Content-Length': str(size), 'Content-Type': content_type})
            with opener.open(request, timeout=cfg.connect_timeout) as response:
                status = response.status
            return {'state': 'completed', 'http_status': status, 'bytes': size, 'sha256': hasher.hexdigest(),
                    'lease_complete_required': lease_object is not None}

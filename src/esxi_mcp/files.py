"""Authenticated ESXi datastore HTTP transfer; no arbitrary local file access."""
from __future__ import annotations
import base64
import hashlib
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import PurePosixPath
from typing import Any, Dict, Optional
from mcp.server.fastmcp.exceptions import ToolError
from . import api
from .config import load_config

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ToolError('Redirect refused to prevent session-cookie disclosure')

def validate_path(path):
    if not path or '\\' in path or path.startswith('/') or any(part in ('', '.', '..') for part in path.split('/')):
        raise ToolError('Datastore path must be a relative path without traversal')
    if any(ord(char) < 32 for char in path):
        raise ToolError('Control characters are not allowed in paths')

def protected_path(si, cfg, datastore, path):
    if datastore in cfg.protected_datastores:
        raise ToolError('Datastore is protected by deployment policy')
    for vm_id in cfg.protected_vm_ids:
        vm = api.find_vm_by_id(si, str(vm_id))
        if vm and vm.config:
            locations = [str(vm.config.files.vmPathName)] if vm.config.files else []
            for device in vm.config.hardware.device or []:
                backing = getattr(device, 'backing', None)
                if getattr(backing, 'fileName', None):
                    locations.append(str(backing.fileName))
            prefix = '[' + datastore + '] '
            for location in locations:
                if location.startswith(prefix):
                    directory = str(PurePosixPath(location[len(prefix):]).parent)
                    if directory == '.' or path == directory or path.startswith(directory + '/'):
                        raise ToolError('Writes to a protected VM file directory are refused')

from .tools import mcp, WRITE, _audited, _guard_writes, _get_host

@mcp.tool(annotations=WRITE)
@_audited
def esxi_datastore_transfer(datastore: str, path: str, operation: str,
                            data_base64: Optional[str] = None, source_url: Optional[str] = None,
                            max_bytes: int = 8388608, overwrite: bool = False,
                            dry_run: bool = True) -> Dict[str, Any]:
    """Datastore 文件 stat/download/upload。可上传 ISO/OVF/VMDK 等文件（不等于部署完成）。

    upload 用 base64 或 HTTPS source_url；默认只预览，真实写要求普通和高级写开关。
    默认不覆盖，保护管理 VM 目录。URL 上传可流式接收大文件；max_bytes 最大 8GiB。
    download 的 base64 响应最多 8MiB。服务端不读取任意本地文件。
    """
    validate_path(path)
    if operation not in ('stat', 'download', 'upload') or not 1 <= max_bytes <= 8 * 1024**3:
        raise ToolError('Invalid transfer operation or max_bytes')
    if operation == 'download' and max_bytes > 8 * 1024**2:
        raise ToolError('Inline downloads are limited to 8MiB')
    if operation == 'upload' and (data_base64 is None) == (source_url is None):
        raise ToolError('Upload requires exactly one of data_base64 or source_url')
    if source_url and urllib.parse.urlparse(source_url).scheme != 'https':
        raise ToolError('Source URL must use HTTPS')
    cfg = load_config()
    if operation == 'upload':
        _guard_writes(cfg, dry_run)
        if not dry_run and os.environ.get('ESXI_ENABLE_ADVANCED_WRITES', '').lower() not in ('1', 'true', 'yes', 'on'):
            raise ToolError('Datastore upload requires ESXI_ENABLE_ADVANCED_WRITES=true')
    with api.service_instance(cfg) as si:
        _, dc, _ = _get_host(si)
        if datastore not in [item.name for item in dc.datastore]:
            raise ToolError('Datastore not found in connected host inventory')
        if operation == 'upload':
            protected_path(si, cfg, datastore, path)
        if dry_run:
            return {'dry_run': True, 'datastore': datastore, 'path': path,
                    'operation': operation, 'max_bytes': max_bytes, 'overwrite': overwrite}
        host = cfg.host.strip('[]')
        authority = ('[' + host + ']' if ':' in host else host) + ':' + str(cfg.port)
        query = urllib.parse.urlencode({'dcPath': str(dc.name), 'dsName': datastore})
        url = 'https://' + authority + '/folder/' + urllib.parse.quote(path, safe='/') + '?' + query
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=api._ssl_context(cfg)))
        headers = {'Cookie': str(si._stub.cookie)}
        try:
            response = opener.open(urllib.request.Request(url, headers=headers, method='HEAD'), timeout=cfg.connect_timeout)
            with response:
                exists = True
                size = int(response.headers.get('Content-Length', '0'))
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            exists, size = False, None
        if operation == 'stat':
            return {'exists': exists, 'bytes': size, 'datastore': datastore, 'path': path}
        if operation == 'download':
            if not exists:
                raise ToolError('File does not exist')
            if size and size > max_bytes:
                raise ToolError('File exceeds download bound')
            with opener.open(urllib.request.Request(url, headers=headers), timeout=cfg.connect_timeout) as response:
                data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ToolError('File exceeds download bound')
            return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                    'data_base64': base64.b64encode(data).decode('ascii')}
        if exists and not overwrite:
            raise ToolError('File already exists; overwrite must be explicitly enabled')
        with tempfile.TemporaryFile() as staged:
            if data_base64 is not None:
                if len(data_base64) > 4 * ((min(max_bytes, 8 * 1024**2) + 2) // 3):
                    raise ToolError('Inline upload exceeds bound; use source_url for large files')
                data = base64.b64decode(data_base64, validate=True)
                if len(data) > max_bytes:
                    raise ToolError('File exceeds upload bound')
                staged.write(data)
            else:
                with urllib.request.urlopen(source_url, timeout=cfg.connect_timeout) as response:
                    length = response.headers.get('Content-Length')
                    if length and int(length) > max_bytes:
                        raise ToolError('Source file exceeds upload bound')
                    copied = 0
                    while True:
                        chunk = response.read(1024**2)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > max_bytes:
                            raise ToolError('Source file exceeds upload bound')
                        staged.write(chunk)
            size = staged.tell()
            staged.seek(0)
            hasher = hashlib.sha256()
            while True:
                chunk = staged.read(1024**2)
                if not chunk:
                    break
                hasher.update(chunk)
            digest = hasher.hexdigest()
            staged.seek(0)
            put_headers = {**headers, 'Content-Length': str(size), 'Content-Type': 'application/octet-stream'}
            with opener.open(urllib.request.Request(url, data=staged, headers=put_headers, method='PUT'), timeout=cfg.connect_timeout) as response:
                status = response.status
            return {'state': 'completed', 'http_status': status, 'bytes': size, 'sha256': digest,
                    'datastore': datastore, 'path': path}

"""Bounded-memory background transfers and private staged files with durable progress."""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import shutil
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Dict, Optional
from mcp.server.fastmcp.exceptions import ToolError
from pyVmomi import vim
from . import api, codec, state
from .config import load_config
from .files import NoRedirect, validate_path, protected_path
from .api_transfer import normalize_url
from .tools import mcp, READ, WRITE, _audited, _guard_writes, _get_host

CHUNK = 1024 * 1024
MAX_FILE = 64 * 1024**4
_RUNNING = set()
_LOCK = threading.RLock()
_SLOTS = threading.BoundedSemaphore(2)

class Cancelled(Exception):
    pass

def directory(cfg, job_id):
    state.validate_id(job_id)
    root = state.private_root(cfg) / 'transfers'
    root.mkdir(mode=0o700, exist_ok=True)
    path = root / job_id
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ToolError('Transfer directory escapes private state root')
    path.mkdir(mode=0o700, exist_ok=True)
    return path

def save_spec(cfg, job_id, spec):
    path = directory(cfg, job_id) / 'spec.json'
    with open(path, 'w', encoding='utf-8') as output:
        json.dump(spec, output)
    if os.name != 'nt':
        path.chmod(0o600)

def read_spec(cfg, job_id):
    state.get(cfg, job_id)  # Bind the handle to this configured host/account.
    return json.loads((directory(cfg, job_id) / 'spec.json').read_text(encoding='utf-8'))

def file_hash(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b''):
            digest.update(chunk)
    return digest.hexdigest()

@contextmanager
def stage_lock(cfg, job_id):
    """Serialize file writes across MCP processes, not just threads."""
    path = directory(cfg, job_id) / '.lock'
    with _LOCK, open(path, 'a+b') as lock:
        if path.stat().st_size == 0:
            lock.write(b'\0')
            lock.flush()
        lock.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            lock.seek(0)
            if os.name == 'nt':
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

@contextmanager
def lease_heartbeat(lease):
    stop = threading.Event()
    failures = []
    def heartbeat():
        while not stop.wait(5):
            try:
                lease.HttpNfcLeaseProgress(1)
            except Exception as error:
                failures.append(error)
                break
    if lease is not None:
        lease.HttpNfcLeaseProgress(1)
        thread = threading.Thread(target=heartbeat, daemon=True)
        thread.start()
    try:
        yield failures
    finally:
        stop.set()
        if lease is not None:
            thread.join(timeout=1)

def check_room(path, incoming):
    if shutil.disk_usage(path.parent).free < incoming + 64 * CHUNK:
        raise ToolError('Insufficient private staging disk space; 64MiB reserve is required')

def stream_download(opener, url, path, headers, max_bytes, timeout=30, offset=0, validator=None,
                    progress=lambda *_args: None, cancelled=lambda: False):
    """Resume only with an object validator and an exact Content-Range; otherwise restart."""
    request_headers = dict(headers)
    if offset and validator:
        request_headers.update({'Range': 'bytes=' + str(offset) + '-', 'If-Range': validator})
    else:
        offset = 0
    with opener.open(urllib.request.Request(url, headers=request_headers), timeout=timeout) as response:
        status = getattr(response, 'status', response.getcode())
        response_validator = response.headers.get('ETag') or response.headers.get('Last-Modified')
        if status == 206:
            match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+|\*)', response.headers.get('Content-Range', ''))
            if not match or int(match[1]) != offset or not validator or response_validator != validator:
                raise ToolError('Range response identity/offset mismatch; refusing to combine different file versions')
            total = int(match[3]) if match[3] != '*' else None
        elif status == 200:
            offset = 0
            total = int(response.headers['Content-Length']) if response.headers.get('Content-Length') else None
        else:
            raise ToolError('Unexpected download HTTP status: ' + str(status))
        if total is not None and total > max_bytes:
            raise ToolError('Source exceeds declared max_bytes')
        if total is not None:
            check_room(path, max(0, total - offset))
        copied = offset
        if offset and (not path.exists() or path.stat().st_size != offset):
            raise ToolError('Partial file size does not match the requested resume offset')
        with open(path, 'ab' if offset else 'wb') as output:
            if os.name != 'nt':
                path.chmod(0o600)
            while True:
                if cancelled():
                    raise Cancelled('Transfer cancelled; partial bytes retained')
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                if copied + len(chunk) > max_bytes:
                    raise ToolError('Source exceeds declared max_bytes')
                check_room(path, len(chunk))
                output.write(chunk)
                copied += len(chunk)
                progress(copied, total, response_validator)
        if total is not None and copied != total:
            raise EOFError('HTTP stream ended before the declared file length')
    return {'bytes': copied, 'validator': response_validator, 'sha256': file_hash(path)}

def opener(cfg, source=False):
    import ssl
    return urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(
        context=ssl.create_default_context() if source else api._ssl_context(cfg)))

def endpoint(si, cfg, spec):
    _, dc, host = _get_host(si)
    if spec['kind'] != 'datastore':
        return normalize_url(spec['transfer_url'], cfg, host.name)
    if spec['datastore'] not in [str(ds.name) for ds in dc.datastore]:
        raise ToolError('Datastore not found on configured host')
    validate_path(spec['path'])
    if spec['operation'] == 'upload':
        protected_path(si, cfg, spec['datastore'], spec['path'])
        if spec['datastore'] in cfg.protected_datastores:
            raise ToolError('Datastore is protected by deployment policy')
    host_name = cfg.host.strip('[]')
    authority = ('[' + host_name + ']' if ':' in host_name else host_name) + ':' + str(cfg.port)
    return 'https://' + authority + '/folder/' + urllib.parse.quote(spec['path'], safe='/') + '?' + urllib.parse.urlencode(
        {'dcPath': dc.name, 'dsName': spec['datastore']})

def cancellation(cfg, job_id):
    return bool(state.get(cfg, job_id).get('cancel_requested'))

def process_alive(pid):
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except ProcessLookupError:
        return False

def ensure_advanced(cfg, dry_run):
    _guard_writes(cfg, dry_run)
    if not dry_run and os.environ.get('ESXI_ENABLE_ADVANCED_WRITES', '').lower() not in ('true', '1', 'yes', 'on'):
        raise ToolError('File upload requires ESXI_ENABLE_ADVANCED_WRITES=true')

def spawn(cfg, job_id):
    with _LOCK:
        if job_id in _RUNNING:
            raise ToolError('Transfer already running in this MCP process')
        _RUNNING.add(job_id)
    threading.Thread(target=worker, args=(cfg, job_id), daemon=True).start()

def worker(cfg, job_id):
    lease_context = None
    try:
        with _SLOTS:
            spec = read_spec(cfg, job_id)
            if cancellation(cfg, job_id):
                raise Cancelled('Cancelled before connection')
            state.update(cfg, job_id, 'running', owner_pid=os.getpid())
            root = directory(cfg, job_id)
            with api.service_instance(cfg, target=spec.get('lease')) as si:
                url = endpoint(si, cfg, spec)
                lease = codec.reference(spec['lease'], si._stub) if spec.get('lease') else None
                context = lease_heartbeat(lease)
                heartbeat_errors = context.__enter__()
                lease_context = context
                last = 0.0
                def pulse():
                    nonlocal last
                    if heartbeat_errors:
                        raise ToolError('NFC lease heartbeat failed; inspect or create a new lease')
                    if lease and time.monotonic() - last >= 5:
                        lease.HttpNfcLeaseProgress(1)
                        last = time.monotonic()
                def checkpoint(count, total, validator):
                    pulse()
                    state.update(cfg, job_id, bytes=count, total_bytes=total, validator=validator)
                cookies = {'Cookie': str(si._stub.cookie)}
                http = opener(cfg)
                if spec['operation'] == 'download':
                    path = root / 'body.part'
                    entry = state.get(cfg, job_id)
                    info = stream_download(http, url, path, cookies, spec['max_bytes'], cfg.connect_timeout,
                                           path.stat().st_size if path.exists() else 0, entry.get('validator'),
                                           checkpoint, lambda: cancellation(cfg, job_id))
                    if spec.get('expected_sha256') and info['sha256'] != spec['expected_sha256']:
                        raise ToolError('Downloaded SHA256 differs from expected_sha256')
                    path.replace(root / 'body')
                    state.update(cfg, job_id, 'completed', **info)
                    return
                ensure_advanced(cfg, False)
                if spec.get('source_job_id'):
                    source = state.get(cfg, spec['source_job_id'])
                    if source['status'] != 'completed':
                        raise ToolError('Source stage/download is not completed')
                    path = directory(cfg, spec['source_job_id']) / 'body'
                else:
                    path = root / 'source.part'
                    stream_download(opener(cfg, source=True), spec['source_url'], path, {}, spec['max_bytes'],
                                    cfg.connect_timeout, progress=checkpoint, cancelled=lambda: cancellation(cfg, job_id))
                size = path.stat().st_size
                if size > spec['max_bytes']:
                    raise ToolError('Source exceeds declared max_bytes')
                digest = file_hash(path)
                if spec.get('expected_sha256') and digest != spec['expected_sha256']:
                    raise ToolError('Source SHA256 differs from expected_sha256')
                if spec['kind'] == 'datastore' and not spec['overwrite']:
                    try:
                        with http.open(urllib.request.Request(url, headers=cookies, method='HEAD'), timeout=cfg.connect_timeout):
                            raise ToolError('Destination exists; explicit overwrite is required')
                    except urllib.error.HTTPError as error:
                        if error.code != 404:
                            raise
                sent = 0
                def chunks(stream):
                    nonlocal sent
                    for chunk in iter(lambda: stream.read(CHUNK), b''):
                        if cancellation(cfg, job_id):
                            raise Cancelled('Upload cancelled; inspect remote file before retry')
                        pulse()
                        yield chunk
                        sent += len(chunk)
                        state.update(cfg, job_id, bytes=sent, total_bytes=size)
                with open(path, 'rb') as source_stream:
                    upload_headers = {**cookies, 'Content-Length': str(size), 'Content-Type': spec['content_type']}
                    if spec['kind'] == 'nfc' and spec['http_method'] == 'PUT' and spec['overwrite']:
                        upload_headers['Overwrite'] = 't'
                    request = urllib.request.Request(url, data=chunks(source_stream), method=spec['http_method'],
                        headers=upload_headers)
                    with http.open(request, timeout=cfg.connect_timeout) as response:
                        status = response.status
                state.update(cfg, job_id, 'completed', bytes=size, total_bytes=size, sha256=digest, http_status=status)
    except Cancelled as error:
        state.update(cfg, job_id, 'cancelled', error=str(error))
    except Exception as error:
        spec = read_spec(cfg, job_id)
        message = str(error)
        for secret in codec.secret_values(spec) + [cfg.password]:
            if secret:
                message = message.replace(secret, '[REDACTED]')
        state.update(cfg, job_id, 'failed', error=message[:800], error_type=type(error).__name__)
    finally:
        if lease_context is not None:
            lease_context.__exit__(None, None, None)
        with _LOCK:
            _RUNNING.discard(job_id)

@mcp.tool(annotations=WRITE)
@_audited
def esxi_transfer_start(kind: str, operation: str, datastore: Optional[str] = None,
                         path: Optional[str] = None, transfer_url: Optional[str] = None,
                         lease: Optional[Dict[str, Any]] = None, source_url: Optional[str] = None,
                         source_job_id: Optional[str] = None, max_bytes: int = 8589934592,
                         expected_sha256: Optional[str] = None, overwrite: bool = False,
                         http_method: str = 'PUT', content_type: str = 'application/octet-stream',
                         dry_run: bool = True, request_id: Optional[str] = None) -> Dict[str, Any]:
    """后台流式 datastore/guest/NFC 下载或上传（最多64TiB显式上限，受暂存磁盘空间约束）。立即返回 job_id，status 查询，read_chunk 分块取回。"""
    cfg = load_config()
    if kind not in ('datastore', 'guest', 'nfc') or operation not in ('download', 'upload') or not 1 <= max_bytes <= MAX_FILE:
        raise ToolError('Invalid transfer kind/operation/size')
    if http_method not in ('PUT', 'POST') or (expected_sha256 and not re.fullmatch('[0-9a-f]{64}', expected_sha256)):
        raise ToolError('Expected PUT/POST and lowercase SHA256')
    if kind == 'datastore':
        if not datastore or not path:
            raise ToolError('Datastore transfers require datastore and relative path')
        validate_path(path)
    elif not transfer_url:
        raise ToolError('Guest/NFC transfers require an SDK-issued transfer_url')
    if operation == 'upload':
        ensure_advanced(cfg, dry_run)
        if bool(source_url) == bool(source_job_id):
            raise ToolError('Upload requires exactly one source_url or completed source_job_id')
    if source_url and urllib.parse.urlparse(source_url).scheme != 'https':
        raise ToolError('Source URL must use HTTPS; redirects are refused')
    spec = dict(kind=kind, operation=operation, datastore=datastore, path=path, transfer_url=transfer_url,
                lease=lease, source_url=source_url, source_job_id=source_job_id, max_bytes=max_bytes,
                expected_sha256=expected_sha256, overwrite=overwrite, http_method=http_method, content_type=content_type)
    if not dry_run:
        replay = state.replay(cfg, 'transfer', spec, request_id)
        if replay:
            return replay
    with api.service_instance(cfg, target=lease) as si:
        endpoint(si, cfg, spec)
    if source_job_id:
        source = state.get(cfg, source_job_id)
        if source['status'] != 'completed':
            raise ToolError('Source handle must be completed')
    if dry_run:
        return {'dry_run': True, 'kind': kind, 'operation': operation, 'max_bytes': max_bytes,
                'overwrite': overwrite, 'requires_private_staging_space': True}
    job_id, replay = state.begin(cfg, 'transfer', spec, request_id)
    if replay:
        return replay
    save_spec(cfg, job_id, spec)
    state.update(cfg, job_id, 'queued', bytes=0, cancel_requested=False)
    spawn(cfg, job_id)
    return {'job_id': job_id, 'state': 'queued', 'operation_id': job_id}

@mcp.tool(annotations=READ)
@_audited
def esxi_transfer_status(job_id: str) -> Dict[str, Any]:
    """传输/暂存进度、字节数、校验和、错误；不输出 signed URL 或服务器任意路径。"""
    cfg = load_config()
    entry = state.get(cfg, job_id)
    if entry['operation'] not in ('transfer', 'stage_upload'):
        raise ToolError('Handle is not a transfer/staged file')
    if entry['status'] in ('queued', 'running') and entry.get('owner_pid') != os.getpid():
        if not process_alive(entry.get('owner_pid')):
            state.update(cfg, job_id, 'interrupted', note='Worker process is gone; explicit resume or new lease required')
            entry = state.get(cfg, job_id)
    return {key: value for key, value in entry.items() if key not in ('arguments', 'owner_pid', 'result')}

@mcp.tool(annotations=READ)
@_audited
def esxi_transfer_read_chunk(job_id: str, offset: int = 0, length: int = 1048576) -> Dict[str, Any]:
    """读取已完成的下载/暂存文件；每块最多1MiB，用offset拼接并核对最终SHA256。"""
    cfg = load_config()
    entry = state.get(cfg, job_id)
    if entry['operation'] not in ('transfer', 'stage_upload') or entry['status'] != 'completed':
        raise ToolError('Only completed file handles can be read')
    if offset < 0 or not 1 <= length <= CHUNK:
        raise ToolError('Expected nonnegative offset and chunk <=1MiB')
    path = directory(cfg, job_id) / 'body'
    if not path.is_file():
        raise ToolError('This completed operation has no downloadable body')
    with open(path, 'rb') as stream:
        stream.seek(offset)
        data = stream.read(length)
    return {'job_id': job_id, 'offset': offset, 'next_offset': offset + len(data),
            'eof': offset + len(data) >= path.stat().st_size, 'bytes': len(data),
            'data_base64': base64.b64encode(data).decode('ascii'), 'file_sha256': entry.get('sha256')}

@mcp.tool(annotations=WRITE)
@_audited
def esxi_transfer_cancel(job_id: str, dry_run: bool = True) -> Dict[str, Any]:
    """请求停止后台传输，保留部分数据；不会自动删除/覆盖远端文件。"""
    cfg = load_config()
    entry = state.get(cfg, job_id)
    if entry['operation'] != 'transfer':
        raise ToolError('Handle is not a transfer')
    if not dry_run:
        state.update(cfg, job_id, cancel_requested=True)
    return {'job_id': job_id, 'dry_run': dry_run, 'state': entry['status'], 'cancel_requested': not dry_run}

@mcp.tool(annotations=WRITE)
@_audited
def esxi_transfer_resume(job_id: str, overwrite: bool = False, dry_run: bool = True) -> Dict[str, Any]:
    """显式恢复失败/取消/中断传输。下载验证ETag/Last-Modified与Range；上传重新发送，远端已有文件需明确overwrite。NFC需原租约仍活着。"""
    cfg = load_config()
    entry = state.get(cfg, job_id)
    spec = read_spec(cfg, job_id)
    if entry['status'] not in ('failed', 'cancelled', 'interrupted'):
        raise ToolError('Only failed/cancelled/interrupted transfers can resume')
    if spec['operation'] == 'upload':
        ensure_advanced(cfg, dry_run)
        spec['overwrite'] = overwrite
    with api.service_instance(cfg, target=spec.get('lease')) as si:
        endpoint(si, cfg, spec)
    if not dry_run:
        with stage_lock(cfg, job_id):
            state.claim_transfer(cfg, job_id)
            try:
                save_spec(cfg, job_id, spec)
                spawn(cfg, job_id)
            except Exception:
                state.update(cfg, job_id, 'interrupted', note='Failed to restart worker')
                raise
    return {'job_id': job_id, 'dry_run': dry_run, 'state': 'queued' if not dry_run else entry['status']}

@mcp.tool(annotations=WRITE)
@_audited
def esxi_stage_upload(filename: str, total_bytes: int, expected_sha256: Optional[str] = None,
                       dry_run: bool = True) -> Dict[str, Any]:
    """创建私有大文件暂存句柄；客户端随后write_chunk并finalize，不接收任意服务器本地路径。"""
    cfg = load_config()
    ensure_advanced(cfg, dry_run)
    if not filename or '/' in filename or '\\' in filename or not 0 <= total_bytes <= MAX_FILE:
        raise ToolError('Expected a display filename and file size 0..64TiB')
    if expected_sha256 and not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ToolError('Expected lowercase SHA256')
    if dry_run:
        return {'dry_run': True, 'filename': filename, 'total_bytes': total_bytes}
    job_id, _ = state.begin(cfg, 'stage_upload', {'filename': filename, 'total_bytes': total_bytes, 'expected_sha256': expected_sha256})
    path = directory(cfg, job_id) / 'body.part'
    try:
        check_room(path, total_bytes)
        path.touch(mode=0o600)
        state.update(cfg, job_id, 'staging', bytes=0, total_bytes=total_bytes, expected_sha256=expected_sha256)
    except Exception:
        state.update(cfg, job_id, 'failed', error_type='StageCreationFailed')
        raise
    return {'job_id': job_id, 'state': 'staging', 'bytes': 0}

@mcp.tool(annotations=WRITE)
@_audited
def esxi_stage_write_chunk(job_id: str, offset: int, data_base64: str, dry_run: bool = True) -> Dict[str, Any]:
    """追加<=1MiB块；相同offset/内容的重试幂等，拒绝空洞或覆盖不同内容。"""
    cfg = load_config()
    ensure_advanced(cfg, dry_run)
    if len(data_base64) > 4 * ((CHUNK + 2) // 3):
        raise ToolError('Chunk exceeds 1MiB')
    data = base64.b64decode(data_base64, validate=True)
    if offset < 0:
        raise ToolError('offset must be nonnegative')
    with stage_lock(cfg, job_id):
        entry = state.get(cfg, job_id)
        if entry['operation'] != 'stage_upload' or entry['status'] != 'staging':
            raise ToolError('Expected a staging upload handle')
        path = directory(cfg, job_id) / 'body.part'
        current = path.stat().st_size
        if offset > current or offset + len(data) > entry['total_bytes']:
            raise ToolError('Chunk creates a hole or exceeds declared file size')
        if offset < current:
            with open(path, 'rb') as stream:
                stream.seek(offset)
                if stream.read(len(data)) != data:
                    raise ToolError('A repeated chunk differs from existing bytes')
            return {'job_id': job_id, 'dry_run': dry_run, 'bytes': current, 'replayed': True}
        if not dry_run:
            check_room(path, len(data))
            with open(path, 'ab') as stream:
                stream.write(data)
            state.update(cfg, job_id, bytes=path.stat().st_size)
        return {'job_id': job_id, 'dry_run': dry_run, 'bytes': current + (len(data) if not dry_run else 0)}

@mcp.tool(annotations=WRITE)
@_audited
def esxi_stage_finalize(job_id: str, dry_run: bool = True) -> Dict[str, Any]:
    """核对完整字节数及SHA256，完成暂存后可作为transfer_start的source_job_id。"""
    cfg = load_config()
    ensure_advanced(cfg, dry_run)
    with stage_lock(cfg, job_id):
        entry = state.get(cfg, job_id)
        if entry['operation'] != 'stage_upload' or entry['status'] != 'staging':
            raise ToolError('Expected a staging upload handle')
        path = directory(cfg, job_id) / 'body.part'
        if path.stat().st_size != entry['total_bytes']:
            raise ToolError('Staged byte count differs from declared total_bytes')
        digest = file_hash(path)
        if entry.get('expected_sha256') and digest != entry['expected_sha256']:
            raise ToolError('Staged SHA256 differs from expected_sha256')
        if not dry_run:
            path.replace(path.with_name('body'))
            state.update(cfg, job_id, 'completed', sha256=digest, bytes=entry['total_bytes'])
        return {'job_id': job_id, 'dry_run': dry_run, 'bytes': entry['total_bytes'], 'sha256': digest,
                'state': 'completed' if not dry_run else 'staging'}

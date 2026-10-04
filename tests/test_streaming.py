import base64
import io
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from esxi_mcp import state, transfers
from test_mock import make_cfg

class Response(io.BytesIO):
    def __init__(self, data, headers, status=200):
        super().__init__(data)
        self.headers, self.status, self.max_read = headers, status, 0
    def getcode(self):
        return self.status
    def read(self, size=-1):
        assert 0 <= size <= transfers.CHUNK, 'Streaming must never read an entire large body'
        self.max_read = max(self.max_read, size)
        return super().read(size)

class Opener:
    def __init__(self, response):
        self.response, self.requests = response, []
    def open(self, request, timeout):
        self.requests.append(request)
        return self.response

def test_nfc_created_file_upload_includes_required_overwrite_header(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace
    cfg = replace(make_cfg(enable_writes=True), state_dir=str(tmp_path/'private'))
    monkeypatch.setenv('ESXI_ENABLE_ADVANCED_WRITES','true')
    source,_ = state.begin(cfg,'stage_upload',{})
    (transfers.directory(cfg,source)/'body').write_bytes(b'file')
    state.update(cfg,source,'completed')
    job,_ = state.begin(cfg,'transfer',{})
    transfers.save_spec(cfg,job,{'kind':'nfc','operation':'upload','source_job_id':source,
        'max_bytes':4,'overwrite':True,'http_method':'PUT','content_type':'application/octet-stream'})
    http = Opener(Response(b'',{}))
    @contextmanager
    def connection(*_args,**_kwargs):
        yield SimpleNamespace(_stub=SimpleNamespace(cookie='session=test'))
    with patch.object(transfers.api,'service_instance',connection), \
         patch.object(transfers,'endpoint',return_value='https://host/nfc/file'), \
         patch.object(transfers,'opener',return_value=http):
        transfers.worker(cfg,job)
    assert http.requests[0].get_header('Overwrite') == 't'
    assert state.get(cfg,job)['status'] == 'completed'

def test_large_download_is_bounded_in_memory_and_verified(tmp_path):
    import hashlib
    data = b'large-file-test' * (1024 * 1024)
    response = Response(data, {'Content-Length': str(len(data)), 'ETag':'v1'})
    path = tmp_path / 'body.part'
    result = transfers.stream_download(Opener(response), 'https://host/file', path, {}, len(data))
    assert result['bytes'] > 8 * 1024**2 and result['sha256'] == hashlib.sha256(data).hexdigest()
    assert response.max_read <= 1024**2

def test_resume_requires_exact_range_and_matching_object_identity(tmp_path):
    path = tmp_path / 'body.part'
    path.write_bytes(b'abc')
    response = Response(b'def', {'Content-Range':'bytes 3-5/6', 'ETag':'v1'}, 206)
    http = Opener(response)
    result = transfers.stream_download(http, 'https://host/file', path, {}, 6, offset=3, validator='v1')
    assert path.read_bytes() == b'abcdef' and result['bytes'] == 6
    assert http.requests[0].get_header('Range') == 'bytes=3-'
    wrong = Response(b'xyz', {'Content-Range':'bytes 3-5/6', 'ETag':'v2'}, 206)
    with pytest.raises(ToolError, match='identity/offset'):
        transfers.stream_download(Opener(wrong), 'https://host/file', path, {}, 6, offset=3, validator='v1')

def test_changed_object_or_ignored_range_restarts_instead_of_corrupting_partial_file(tmp_path):
    path = tmp_path / 'body.part'
    path.write_bytes(b'old')
    response = Response(b'new-version', {'Content-Length':'11','ETag':'v2'})
    transfers.stream_download(Opener(response), 'https://host/file', path, {}, 100, offset=3, validator='v1')
    assert path.read_bytes() == b'new-version'

def test_incomplete_or_oversized_download_does_not_silently_succeed(tmp_path):
    with pytest.raises(EOFError):
        transfers.stream_download(Opener(Response(b'short', {'Content-Length':'10'})), 'https://host/file', tmp_path/'body', {}, 10)
    with pytest.raises(ToolError, match='max_bytes'):
        transfers.stream_download(Opener(Response(b'large', {'Content-Length':'5'})), 'https://host/file', tmp_path/'body', {}, 4)

def test_staged_chunks_are_idempotent_and_checksum_finalized(tmp_path, monkeypatch):
    cfg = replace(make_cfg(enable_writes=True), state_dir=str(tmp_path/'private'))
    monkeypatch.setenv('ESXI_ENABLE_ADVANCED_WRITES', 'true')
    with patch.object(transfers, 'load_config', return_value=cfg), patch('esxi_mcp.tools.load_config', return_value=cfg):
        stage = transfers.esxi_stage_upload('test.bin', 6, dry_run=False)
        handle = stage['job_id']
        payload = base64.b64encode(b'abc').decode()
        transfers.esxi_stage_write_chunk(handle, 0, payload, dry_run=False)
        assert transfers.esxi_stage_write_chunk(handle, 0, payload, dry_run=False)['replayed']
        with pytest.raises(ToolError, match='differs'):
            transfers.esxi_stage_write_chunk(handle, 0, base64.b64encode(b'xyz').decode(), dry_run=False)
        with pytest.raises(ToolError, match='hole'):
            transfers.esxi_stage_write_chunk(handle, 5, payload, dry_run=False)
        transfers.esxi_stage_write_chunk(handle, 3, base64.b64encode(b'def').decode(), dry_run=False)
        assert transfers.esxi_stage_finalize(handle, dry_run=False)['state'] == 'completed'
        assert base64.b64decode(transfers.esxi_transfer_read_chunk(handle)['data_base64']) == b'abcdef'

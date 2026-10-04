"""Private durable operation journal; retries never blindly repeat a mutation."""
from __future__ import annotations
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from mcp.server.fastmcp.exceptions import ToolError
from . import codec

ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$')

def private_root(cfg):
    root = Path(cfg.state_dir).expanduser().resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != 'nt':
        root.chmod(0o700)
    return root

@contextmanager
def database(cfg):
    path = private_root(cfg) / 'operations.sqlite3'
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    if os.name != 'nt':
        path.chmod(0o600)
    connection.execute('CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, host TEXT NOT NULL, operation TEXT NOT NULL, digest TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL, data TEXT NOT NULL)')
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()

def identity(cfg):
    return cfg.user + '@' + cfg.host + ':' + str(cfg.port)

def safe(cfg, value):
    value = codec.scrub(value)
    if isinstance(value, str):
        return value.replace(cfg.password, '[REDACTED]') if cfg.password else value
    if isinstance(value, dict):
        if value.get('tool') in ('esxi_shell', 'esxi_esxcli', 'esxi_esxcli_query') and isinstance(value.get('arguments'), dict):
            value = {**value, 'arguments': journal_arguments(value['tool'], value['arguments'])}
        return {key: safe(cfg, item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe(cfg, item) for item in value]
    return value

def journal_arguments(operation, arguments):
    """Opaque shell/argv can contain arbitrary credentials; retain a digest, never the payload."""
    value = dict(arguments)
    if operation in ('esxi_shell', 'esxi_esxcli', 'esxi_esxcli_query'):
        for key in ('command', 'arguments'):
            if key in value:
                payload = json.dumps(value[key], ensure_ascii=False).encode()
                value[key] = {'sha256': hashlib.sha256(payload).hexdigest(), 'payload_omitted': True}
    return value

def uncertain_error(error):
    """Transport failures and unavailable/unfinished tasks cannot establish whether a write happened."""
    text = str(error).lower()
    return isinstance(error, (OSError, ConnectionError, TimeoutError)) or any(
        marker in text for marker in ('state is uncertain', 'completion is uncertain', 'task is unavailable',
                                      'connection reset', 'connection aborted', 'timed out', 'remote disconnected'))

def validate_id(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ToolError('Operation ID must be 1..96 letters, digits, hyphens or underscores')
    return value

def argument_digest(arguments):
    return hashlib.sha256(json.dumps(arguments, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()

def existing_result(cfg, existing, operation, digest, operation_id):
    if existing['host'] != identity(cfg) or existing['operation'] != operation or existing['digest'] != digest:
        raise ToolError('request_id already belongs to a different host, operation or arguments')
    data = json.loads(existing['data'])
    if operation in ('transfer', 'ovf_export', 'ovf_import', 'execute_plan') and existing['status'] in ('queued', 'running', 'completed'):
        return {'operation_id': operation_id, 'state': existing['status'], 'replayed': True,
                **({'job_id': operation_id} if operation == 'transfer' else {})}
    if existing['status'] in ('completed', 'submitted', 'lease_created') and data.get('result') is not None:
        if existing['status'] == 'lease_created':
            raise ToolError('A lease request cannot be replayed; inspect the original operation or create a new lease')
        return {**data['result'], 'operation_id': operation_id, 'replayed': True}
    raise ToolError('request_id is already ' + existing['status'] + '; inspect esxi_operation_status before issuing another mutation')

def replay(cfg, operation, arguments, request_id):
    """Replay before inventory validation: a completed delete/import can change that inventory."""
    if request_id is None:
        return None
    operation_id = validate_id(request_id)
    with database(cfg) as db:
        row = db.execute('SELECT * FROM operations WHERE id=?', (operation_id,)).fetchone()
    return existing_result(cfg, row, operation, argument_digest(arguments), operation_id) if row else None

def begin(cfg, operation, arguments, request_id=None):
    operation_id = validate_id(request_id or uuid.uuid4().hex)
    digest = argument_digest(arguments)
    now = time.time()
    with database(cfg) as db:
        db.execute('BEGIN IMMEDIATE')
        existing = db.execute('SELECT * FROM operations WHERE id=?', (operation_id,)).fetchone()
        if existing:
            return operation_id, existing_result(cfg, existing, operation, digest, operation_id)
        data = {'arguments': safe(cfg, journal_arguments(operation, arguments)), 'owner_pid': os.getpid()}
        db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,?,?)',
                   (operation_id, identity(cfg), operation, digest, 'executing', now, now, json.dumps(data, default=str)))
    return operation_id, None

def update(cfg, operation_id, status=None, **fields):
    validate_id(operation_id)
    with database(cfg) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM operations WHERE id=? AND host=?', (operation_id, identity(cfg))).fetchone()
        if not row:
            raise ToolError('Operation not found for this configured host/account')
        data = json.loads(row['data'])
        if row['operation'] in ('esxi_shell', 'esxi_esxcli', 'esxi_esxcli_query') and isinstance(fields.get('result'), dict):
            fields['result'] = {key: ('[SSH output omitted from journal]' if key in ('stdout', 'stderr', 'command') else value)
                                for key, value in fields['result'].items()}
        data.update(safe(cfg, fields))
        db.execute('UPDATE operations SET status=?,updated=?,data=? WHERE id=?',
                   (status or row['status'], time.time(), json.dumps(data, default=str), operation_id))

def get(cfg, operation_id):
    validate_id(operation_id)
    with database(cfg) as db:
        row = db.execute('SELECT * FROM operations WHERE id=? AND host=?', (operation_id, identity(cfg))).fetchone()
    if not row:
        raise ToolError('Operation not found for this configured host/account')
    return {**{key: row[key] for key in ('id', 'operation', 'status', 'created', 'updated')}, **json.loads(row['data'])}

def recent(cfg, limit=50):
    if not 1 <= limit <= 200:
        raise ToolError('limit must be 1..200')
    with database(cfg) as db:
        rows = db.execute('SELECT id,operation,status,created,updated FROM operations WHERE host=? ORDER BY created DESC LIMIT ?', (identity(cfg), limit)).fetchall()
    return [dict(row) for row in rows]

def claim_transfer(cfg, operation_id):
    """Atomic restart ownership across MCP processes; a resume must not create two writers."""
    with database(cfg) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM operations WHERE id=? AND host=?',
                         (validate_id(operation_id), identity(cfg))).fetchone()
        if not row or row['operation'] != 'transfer' or row['status'] not in ('failed', 'cancelled', 'interrupted'):
            raise ToolError('Transfer is no longer resumable; another worker may have claimed it')
        data = json.loads(row['data'])
        data.update(cancel_requested=False, error=None, owner_pid=os.getpid())
        db.execute('UPDATE operations SET status=?,updated=?,data=? WHERE id=?',
                   ('queued', time.time(), json.dumps(data), operation_id))

def finish(cfg, operation_id, result):
    current = result.get('state', 'completed')
    status = 'submitted' if result.get('task_id') and current in ('queued', 'running', 'submitted') else (
        'failed' if current == 'error' else 'lease_created' if current == 'lease_created' else 'completed')
    update(cfg, operation_id, status, result=result)
    return {**result, 'operation_id': operation_id}

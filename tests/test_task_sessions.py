import threading
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from pyVmomi import vim
from esxi_mcp import api
from test_mock import make_cfg

def test_submitted_task_retains_session_until_terminal_state():
    si = SimpleNamespace(_stub=object())
    task = SimpleNamespace(_stub=si._stub, info=SimpleNamespace(state='running'))
    disconnected = threading.Event()
    with patch.object(api, 'SmartConnect', return_value=si), \
         patch.object(api, 'Disconnect', side_effect=lambda _si: disconnected.set()):
        with api.service_instance(make_cfg()):
            api.hold_task_session(task)
        assert not disconnected.is_set()
        task.info.state = 'success'
        assert disconnected.wait(timeout=3)

def test_failed_task_and_unrelated_stub_do_not_leak_sessions():
    si = SimpleNamespace(_stub=object())
    foreign = SimpleNamespace(_stub=object(), info=SimpleNamespace(state='running'))
    with patch.object(api, 'SmartConnect', return_value=si), patch.object(api, 'Disconnect') as disconnect:
        with api.service_instance(make_cfg()):
            api.hold_task_session(foreign)
        disconnect.assert_called_once_with(si)

def test_nfc_calls_reuse_original_authenticated_session():
    cfg = make_cfg()
    target = {'_type': 'vim.HttpNfcLease', '_moId': 'session-bound-test'}
    si = SimpleNamespace(_stub=object())
    key = api._lease_key(cfg, target)
    api._LEASE_SESSIONS[key] = (si, threading.RLock())
    try:
        with patch.object(api, 'SmartConnect') as connect, patch.object(api, 'Disconnect') as disconnect:
            with api.service_instance(cfg, target=target) as reused:
                assert reused is si
            connect.assert_not_called()
            disconnect.assert_not_called()
    finally:
        api._LEASE_SESSIONS.pop(key, None)

def test_unknown_nfc_lease_cannot_be_recreated_in_another_session():
    with patch.object(api, 'SmartConnect') as connect:
        with pytest.raises(RuntimeError, match='create a new lease'):
            with api.service_instance(make_cfg(), target={'_type': 'vim.HttpNfcLease', '_moId': 'unknown'}):
                pass
        connect.assert_not_called()

def test_completed_nfc_monitor_releases_registry_and_connection():
    cfg = make_cfg()
    si = SimpleNamespace(_stub=object())
    lease = vim.HttpNfcLease('complete-test', si._stub)
    key = api._lease_key(cfg, {'_type': 'vim.HttpNfcLease', '_moId': lease._moId})
    api._LEASE_SESSIONS[key] = (si, threading.RLock())
    with patch.object(vim.HttpNfcLease, 'state', new_callable=lambda: property(lambda _self: 'done')), \
         patch.object(api, 'Disconnect') as disconnect:
        api._finish_task_session(si, [lease], lease_grace=0)
        assert key not in api._LEASE_SESSIONS
        disconnect.assert_called_once_with(si)
    task = SimpleNamespace(info=SimpleNamespace(state='error'))
    with patch.object(api, 'Disconnect') as disconnect:
        api._finish_task_session(si, [task])
        disconnect.assert_called_once_with(si)

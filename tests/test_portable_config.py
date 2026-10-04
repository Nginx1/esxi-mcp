import json
from pathlib import Path
from unittest.mock import patch

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from esxi_mcp.config import Config, DEFAULT_CONFIG_DIR, load_config
from esxi_mcp import tools as T
from test_mock import make_cfg


def test_default_config_is_user_scoped_and_verifies_tls(tmp_path):
    assert DEFAULT_CONFIG_DIR == Path.home() / '.config' / 'esxi-mcp'
    credentials = tmp_path / 'credentials.json'
    credentials.write_text(json.dumps({'host': 'test.invalid', 'user': 'test', 'password': 'FAKE_TEST_PASSWORD'}))
    cfg = load_config({'ESXI_CONFIG_FILE': str(credentials)})
    assert cfg.verify_ssl is True
    assert cfg.enable_writes is False
    assert 'FAKE_TEST_PASSWORD' not in repr(cfg)
    assert Config('test.invalid', 'test', 'fake').verify_ssl is True


def test_explicit_private_ca_and_read_only_override(tmp_path):
    credentials = tmp_path / 'credentials.json'
    credentials.write_text(json.dumps({'host': 'test.invalid', 'user': 'test', 'password': 'fake'}))
    (tmp_path / 'config.json').write_text(json.dumps({'enable_writes': True, 'verify_ssl': False}))
    cfg = load_config({'ESXI_CONFIG_FILE': str(credentials), 'ESXI_ENABLE_WRITES': 'false', 'ESXI_CA_FILE': 'private-ca.pem'})
    assert cfg.verify_ssl == 'private-ca.pem'
    assert cfg.enable_writes is False


@pytest.mark.parametrize('datastore,network', [(None, 'network'), ('datastore', None), (None, None)])
def test_create_requires_explicit_inventory_targets(datastore, network):
    with patch.object(T, 'load_config', return_value=make_cfg()), \
            patch.object(T.api, 'service_instance') as connection:
        with pytest.raises(ToolError, match='明确指定'):
            T.esxi_create_vm('new-vm', 2, 2048, 20, datastore=datastore, network=network)
        connection.assert_not_called()

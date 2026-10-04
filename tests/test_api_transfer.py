import pytest
from mcp.server.fastmcp.exceptions import ToolError
from esxi_mcp.api_transfer import normalize_url
from test_mock import make_cfg

def test_sdk_url_is_pinned_to_configured_host():
    cfg = make_cfg()
    result = normalize_url('https://*/guestFile?id=example', cfg, 'host.example')
    assert result == 'https://h:443/guestFile?id=example'
    assert normalize_url('https://host.example/nfc/id/disk', cfg, 'host.example') == 'https://h:443/nfc/id/disk'

@pytest.mark.parametrize('url', [
    'https://untrusted.example/guestFile?id=test', 'http://h/guestFile?id=test',
    'https://h:8443/guestFile', 'https://user:password@h/guestFile',
    'https://h/folder/secret', 'https://h/nfc/%2e%2e/secret',
])
def test_arbitrary_http_destinations_and_cookie_leaks_refused(url):
    with pytest.raises(ToolError):
        normalize_url(url, make_cfg(), 'host.example')

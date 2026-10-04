import pytest
from mcp.server.fastmcp.exceptions import ToolError
from esxi_mcp import codec
from esxi_mcp.files import validate_path, NoRedirect

@pytest.mark.parametrize('path', ['../secret', 'a/../b', '/absolute', 'a\\b', 'a//b', 'a/./b', 'a\nb', ''])
def test_file_path_traversal_rejected(path):
    with pytest.raises(ToolError):
        validate_path(path)

def test_datastore_relative_path_and_audit_payload():
    validate_path('images/test.iso')
    value = codec.scrub({'data_base64': 'YWJj', 'source_url': 'https://example.invalid/file?token=secret'})
    assert value['data_base64'] == '[BASE64 PAYLOAD: 4 chars]'
    assert value['source_url'] == '[REDACTED]'

def test_session_cookie_cannot_be_forwarded_by_redirect():
    with pytest.raises(ToolError):
        NoRedirect().redirect_request(None, None, None, None, None, None)

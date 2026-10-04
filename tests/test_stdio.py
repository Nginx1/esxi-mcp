"""Real MCP handshake against a local subprocess; no ESXi connection or credentials."""
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_stdio_handshake_tool_contract_and_validation_without_esxi(tmp_path):
    async def verify():
        root = Path(__file__).resolve().parents[1]
        params = StdioServerParameters(
            command=sys.executable, args=['-m', 'esxi_mcp.server'],
            env={
                'PYTHONPATH': str(root / 'src'),
                'ESXI_CONFIG_FILE': str(tmp_path / 'missing-credentials.json'),
                'ESXI_DEPLOY_CONFIG_FILE': str(tmp_path / 'missing-config.json'),
                'ESXI_ENABLE_WRITES': 'false',
            },
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                assert init.serverInfo.name == 'esxi-mcp'
                assert init.instructions
                result = await session.list_tools()
                assert len(result.tools) == 63
                reads = writes = 0
                for tool in result.tools:
                    assert tool.annotations is not None
                    if tool.annotations.readOnlyHint:
                        reads += 1
                        assert tool.annotations.destructiveHint is False
                    else:
                        writes += 1
                        assert tool.annotations.destructiveHint is True
                        assert tool.inputSchema['properties']['dry_run']['default'] is True
                assert (reads, writes) == (22, 41)
                invalid = await session.call_tool('esxi_get_vm', {})
                assert invalid.isError  # Required argument validation happens before API connection.
                unconfigured = await session.call_tool('esxi_health', {})
                assert unconfigured.isError  # Missing credentials produce a protocol error, not a crash.
    async def bounded():
        await asyncio.wait_for(verify(), timeout=30)
    asyncio.run(bounded())

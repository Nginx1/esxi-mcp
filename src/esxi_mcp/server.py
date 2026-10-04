"""入口：stdio MCP 服务器。stdout 只输出协议消息，日志走 stderr。"""
from __future__ import annotations

import sys

from .tools import mcp


def main() -> None:
    # 强制日志走 stderr；FastMCP stdio 默认已如此，这里显式保证
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
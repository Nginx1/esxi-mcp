"""安全检查与审计。不含任何凭据。"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

# 禁止出现在 VM 名中的路径控制字符 / 片段
_BAD_NAME_CHARS = re.compile(r"[/\\\[\]\*\"'<>|]")
_BAD_NAME_TOKENS = ("..", ".", ".")


def validate_vm_name(name: Optional[str]) -> Optional[str]:
    """返回错误信息；合法返回 None。禁止斜线、点点路径、方括号等路径控制字符。"""
    if name is None or not str(name).strip():
        return "VM 名不能为空"
    n = str(name).strip()
    if n != name:
        return "VM 名首尾不能有空白"
    if _BAD_NAME_CHARS.search(n):
        return "VM 名包含禁止字符（/ \\ [ ] * \" ' < > | 等路径控制字符）"
    if n in ("..", ".") or len(n) > 80:
        return "VM 名非法或过长"
    return None


def is_integer_device_key(device_key: object) -> bool:
    return isinstance(device_key, int) and device_key > 0


def check_protected(vm_id: str, protected_ids: List[str]) -> bool:
    return str(vm_id) in [str(x) for x in protected_ids]


def check_name_match(expected_name: Optional[str], actual_name: str) -> bool:
    return expected_name is not None and expected_name == actual_name


def audit(entry: Dict[str, Any], audit_file: str) -> None:
    """追加一行 JSON 到审计文件（不含凭据），同时写 stderr。"""
    line = json.dumps(entry, ensure_ascii=False, default=str)
    try:
        d = os.path.dirname(audit_file)
        if d:
            os.makedirs(d, mode=0o700, exist_ok=True)
        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    import sys

    print("AUDIT " + line, file=sys.stderr)
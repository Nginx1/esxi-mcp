"""配置加载：凭据文件 + 部署配置 + 环境变量覆盖。

凭据只保存在 credentials.json（0700/0600），代码绝不打印 password。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Union

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "esxi-mcp"
DEFAULT_CREDENTIALS_FILE = str(DEFAULT_CONFIG_DIR / "credentials.json")
DEFAULT_CONFIG_FILE = str(DEFAULT_CONFIG_DIR / "config.json")
DEFAULT_AUDIT_FILE = str(DEFAULT_CONFIG_DIR / "audit.log")
DEFAULT_STATE_DIR = str(DEFAULT_CONFIG_DIR / 'state')

VerifySSL = Union[bool, str]  # False | True | CA 文件路径


def _truthy(v) -> bool:
    """把字符串/布尔值统一解析为布尔。字符串 "false"/"0"/"no"/"off" 都是 False。"""
    if isinstance(v, bool):
        return v
    return (str(v or "")).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    host: str
    user: str
    password: str = field(repr=False)
    port: int = 443
    verify_ssl: VerifySSL = True
    connect_timeout: int = 30
    protected_vm_ids: List[str] = field(default_factory=list)
    enable_writes: bool = False
    audit_file: str = DEFAULT_AUDIT_FILE
    state_dir: str = DEFAULT_STATE_DIR
    policy_profile: str = 'operator'
    allowed_operations: List[str] = field(default_factory=list)
    denied_operations: List[str] = field(default_factory=list)
    protected_datastores: List[str] = field(default_factory=list)
    protected_networks: List[str] = field(default_factory=list)
    allow_protected_impact: bool = False
    allow_management_disruption: bool = False
    ssh_admin_enabled: bool = False
    ssh_credentials_file: str = ''
    lease_session_timeout: int = 86400


def _merge_verify_ssl(env: dict, base: VerifySSL) -> VerifySSL:
    raw = env.get("ESXI_VERIFY_SSL")
    ca_file = env.get("ESXI_CA_FILE")
    if ca_file:
        return ca_file
    if raw is not None:
        r = raw.strip()
        if r.lower() in ("false", "0", "no", "off"):
            return False
        if r.lower() in ("true", "1", "yes", "on"):
            return True
        return r  # 当作 CA 路径
    return base


def load_config(env: Optional[dict] = None) -> Config:
    env = os.environ if env is None else env

    cred_file = os.path.expanduser(env.get("ESXI_CONFIG_FILE") or DEFAULT_CREDENTIALS_FILE)
    cfg_file = os.path.expanduser(
        env.get("ESXI_DEPLOY_CONFIG_FILE")
        or os.path.join(os.path.dirname(cred_file) or ".", "config.json")
    )

    creds: dict = {}
    deploy: dict = {}
    if os.path.exists(cred_file):
        with open(cred_file, encoding="utf-8") as f:
            creds = json.load(f)
    if os.path.exists(cfg_file):
        with open(cfg_file, encoding="utf-8") as f:
            deploy = json.load(f)

    host = env.get("ESXI_HOST") or creds.get("host")
    user = env.get("ESXI_USER") or creds.get("user")
    password = env.get("ESXI_PASSWORD") if env.get("ESXI_PASSWORD") is not None else creds.get("password")
    port = int(env.get("ESXI_PORT") or creds.get("port") or 443)

    if not host or not user or password is None or str(password) == "":
        raise RuntimeError(
            "ESXi 凭据未配置或密码为空：请确保 credentials.json 存在（含非空 password），"
            "或设置 ESXI_HOST/ESXI_USER/ESXI_PASSWORD。"
        )

    base_verify = deploy.get("verify_ssl", creds.get("verify_ssl", True))
    verify_ssl = _merge_verify_ssl(env, base_verify)

    prot = list(deploy.get("protected_vm_ids", []) or [])
    prot_env = env.get("ESXI_PROTECTED_VM_IDS", "")
    if prot_env:
        prot = [x.strip() for x in prot_env.split(",") if x.strip()]

    # 环境变量出现时严格优先；否则用部署配置的布尔值（字符串 "false" 不算 True）。
    env_writes = env.get("ESXI_ENABLE_WRITES")
    if env_writes is not None and str(env_writes).strip() != "":
        enable_writes = _truthy(env_writes)
    else:
        enable_writes = _truthy(deploy.get("enable_writes", False))

    profile = str(env.get('ESXI_POLICY_PROFILE') or deploy.get('policy_profile', 'operator'))
    if profile not in ('read_only', 'operator', 'administrator'):
        raise RuntimeError('ESXI_POLICY_PROFILE must be read_only, operator or administrator')
    return Config(
        host=host,
        user=user,
        password=password,
        port=port,
        verify_ssl=verify_ssl,
        connect_timeout=int(env.get("ESXI_CONNECT_TIMEOUT") or deploy.get("connect_timeout") or 30),
        protected_vm_ids=prot,
        enable_writes=enable_writes,
        audit_file=os.path.expanduser(
            env.get("ESXI_AUDIT_FILE") or deploy.get("audit_file") or DEFAULT_AUDIT_FILE
        ),
        state_dir=os.path.expanduser(env.get('ESXI_STATE_DIR') or deploy.get('state_dir') or str(Path(cfg_file).parent / 'state')),
        policy_profile=profile,
        allowed_operations=list(deploy.get('allowed_operations') or []),
        denied_operations=list(deploy.get('denied_operations') or []),
        protected_datastores=list(deploy.get('protected_datastores') or []),
        protected_networks=list(deploy.get('protected_networks') or []),
        allow_protected_impact=_truthy(env.get('ESXI_ALLOW_PROTECTED_IMPACT', deploy.get('allow_protected_impact', False))),
        allow_management_disruption=_truthy(env.get('ESXI_ALLOW_MANAGEMENT_DISRUPTION', deploy.get('allow_management_disruption', False))),
        ssh_admin_enabled=_truthy(env.get('ESXI_ENABLE_SSH_ADMIN', deploy.get('ssh_admin_enabled', False))),
        ssh_credentials_file=os.path.expanduser(env.get('ESXI_SSH_CREDENTIALS_FILE') or deploy.get('ssh_credentials_file') or str(Path(cfg_file).parent / 'ssh.json')),
        lease_session_timeout=int(env.get('ESXI_LEASE_SESSION_TIMEOUT') or deploy.get('lease_session_timeout') or 86400),
    )

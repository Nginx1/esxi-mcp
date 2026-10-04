# ESXi MCP

单台独立 ESXi 的 stdio MCP 管理服务，使用官方 MCP Python SDK 和 pyVmomi。**0.3.0 提供 63 个工具**，包括 VM、14 类主机资源控制器、Guest、完整 OVF 流程、大文件传输、持久化操作记录，以及可选 ESXCLI/shell 后端。

[English](README.md) · [MIT](LICENSE) · [能力与边界](docs/capabilities.md) · [资源与执行指南](docs/resources.md) · [测试证据](docs/testing.md)

## 安装与连接

需要 Python 3.10+。项目未发布到 PyPI，从源码安装：

```bash
python -m venv .venv
# Linux/macOS
.venv/bin/python -m pip install -e '.[dev]'
# Windows PowerShell
.venv/Scripts/python.exe -m pip install -e '.[dev]'
```

ESXi SSH 后端额外安装 `.[admin]` 或 `.[dev,admin]`。把 `credentials.example.json`、`config.example.json` 复制到仓库外的私人目录；默认是 `~/.config/esxi-mcp/credentials.json` 与同目录 `config.json`。Unix 下目录 0700、文件 0600；Windows 下限制 ACL。TLS 默认校验，写入默认关闭，私有 CA 可用 `ESXI_CA_FILE`。

客户端使用虚拟环境 Python 启动 `-m esxi_mcp.server`，配置格式见 [English README](README.md#connect-an-mcp-client)。Linux 可使用 `run-stdio.sh`；远程 stdio 可走限制为该启动器的 SSH 密钥。MCP 传输密钥与可选的 ESXi 管理 SSH 凭据各自独立。

## 管理范围

| 资源 | 控制入口 |
| --- | --- |
| VM | 电源、CPU/内存与配额、创建/注册/重命名/删除、快照、扩盘、虚拟硬件增删改 |
| 网络 | vSwitch、端口组/VLAN、VMkernel、DNS、路由、物理网卡与网络配置 |
| 存储 | VMFS/NFS/vVol 数据存储、分区/格式化、挂载、HBA/LUN、iSCSI、NVMe、多路径和文件 |
| 主机 | 维护模式、重启/关机、锁定模式、连接管理、高级设置、PCI 直通 |
| 系统 | 服务、防火墙、用户、角色/权限、许可证、时间、证书、补丁 |
| Guest | Tools 支持的进程启动/终止/查询、文件管理及认证后的传输 |
| 导入导出 | 完整 OVF 描述符与磁盘映射、NFC 上传/下载、租约 Complete/Abort、SHA256 manifest |
| 大文件 | 后台流式传输、客户端分块暂存、进度/取消、下载断点续传、SHA256 校验 |
| 故障恢复 | 持久化操作记录、request_id 防重复、异步任务复查、显式步骤及逆序补偿 |
| ESXi CLI | 可选固定只读 ESXCLI 查询、完整 ESXCLI argv 和管理员 shell |

“完整控制入口”表示可以表达 ESXi 实际提供的 API 和管理员命令。执行仍取决于版本、许可证、权限、硬件与状态；不等于所有方法都已实机验证。物理 BMC/BIOS、电源断开后开机、跨主机 vCenter 集群管理需要另外的接口。创建空 VM 不会安装 OS；Guest 控制需 OS、Tools 与 guest 认证。

## 开启整台主机管理

1. 用 `esxi_capabilities`、`esxi_dependencies` 查询实际能力和依赖，填写管理 VM 的准确 `protected_vm_ids`。
2. 普通写入开启 `ESXI_ENABLE_WRITES=true`，高级 API/文件/OVF 开启 `ESXI_ENABLE_ADVANCED_WRITES=true`。管理工具默认 `dry_run=true`。
3. 整机管理设置 `policy_profile=administrator`。影响管理链路或保护 VM 时，配置中的 `allow_management_disruption` / `allow_protected_impact` 与调用中的允许参数必须同时明确开启；共享资源操作还要传入全部 `acknowledged_vm_ids`。未知影响需 `allow_unknown_impact=true`。
4. 专用控制器要求准确 `expected_host`；通用 API 要求准确 `expected_target='_type:_moId'`。常规 VM 工具保留直接保护；管理员可经通用 API 双重允许后操作保护 VM。
5. CLI 后端另需 `ssh_admin_enabled=true`、`ssh.json` 和独立验证的 SSH host key。默认不开 SSH。shell 无法完整推断依赖，按整台主机影响处理。

部署 allow/deny 列表是操作级限制，详细匹配规则见 [执行指南](docs/resources.md)。ESXi 账户角色是实际权限边界。不会隐式断电或删快照；异步提交后必须查看任务/operation 状态，传输超时不能推断成已取消。补偿是明确的逆序操作，无法保证原子回滚；结果不确定时停止自动补偿。

## 文件与 OVF 客户端

私有 `transport.local.json` 只含 stdio 的 `command`、`args`、可选 `env`，不得提交。命令行客户端以 1MiB 块传输并核对 SHA256：

```bash
python scripts/file_client.py --transport transport.local.json upload --file installer.iso --datastore DATASTORE --path images/installer.iso --execute
python scripts/file_client.py --transport transport.local.json download --datastore DATASTORE --path images/installer.iso --output installer-downloaded.iso
python scripts/file_client.py --transport transport.local.json export --vm-id VM_ID --expected-name VM_NAME --output-dir ovf-bundle --execute
python scripts/file_client.py --transport transport.local.json import --ovf ovf-bundle/vm.ovf --name NEW_VM --datastore DATASTORE --network-map network-map.json --expected-host esxi.example.com --execute
```

`network-map.json` 将描述符内的网络名称映射到已发现的目标网络。导出要求 VM 已关机，不会自动关机。OVF 导入支持已解包的描述符与磁盘文件；OVA 需先在客户端解包。不要把 OVA 文件直接作为 VMDK 上传。下载本地 `.part-句柄` 可继续取回，远端失败下载用 `esxi_transfer_resume` 显式恢复。上传恢复会重传，不能保证远端 HTTP PUT 可续传。

## 验证与开源

```bash
python -m pytest -q
python scripts/verify_vmomi_contract.py
python -m build
```

0.3.0 已部署。Windows 和 Linux/Python 3.12 各通过 121 项自动测试，另通过 9 项离线 SDK 写调用、4 项临时本地 SSH 集成检查。API 8.0.2.0 实机通过 15 项临时 VM 检查、8 项完整流程检查（专用网络、重复请求、补偿、12MiB 文件传输及完整 OVF 导出/导入）和 3 项真实 ESXCLI 查询。临时资源已清理，本轮开始时的 33 台既有 VM 与原网络配置保持一致。这些结果不代表所有版本、硬件和破坏性操作都验证过；范围见 [测试证据](docs/testing.md)。

发布仅使用干净源码包；私人配置、state 数据库、传输暂存、审计和原始实机结果不得上传。GitHub Actions 已配置，未在 GitHub 执行。MIT 允许使用、修改和商业使用，分发需保留许可声明。安全问题见 [SECURITY](SECURITY.md)。

# ESXi MCP

Version **0.3.0** exposes **63 stdio tools** for a single standalone ESXi host using the official MCP Python SDK and pyVmomi. It covers VM operations, 14 host-resource controllers, guest operations, complete OVF workflows, background file transfers, durable operation tracking and an optional ESXCLI/shell backend.

[中文](README.zh-CN.md) · [MIT license](LICENSE) · [Capabilities](docs/capabilities.md) · [Execution guide](docs/resources.md) · [Test evidence](docs/testing.md)

## Install and configure

Python 3.10+ is required. This project is not published to PyPI:

```bash
python -m venv .venv
# Linux/macOS
.venv/bin/python -m pip install -e '.[dev]'
# Windows PowerShell
.venv/Scripts/python.exe -m pip install -e '.[dev]'
```

Install `.[admin]` or `.[dev,admin]` to use the optional ESXi SSH backend. `requirements-lock.txt` records the earlier Python 3.12 Linux core acceptance environment, excluding the optional SSH dependency; use pyproject resolution for other platforms and extras.

Copy `credentials.example.json` and `config.example.json` to a private directory outside the repository. Defaults are `~/.config/esxi-mcp/credentials.json` and a sibling `config.json`. Restrict directory/file permissions to 0700/0600 on Unix and use Windows ACLs. TLS verification is enabled and writes are disabled by default. Set `ESXI_CA_FILE` for a private CA.

| Setting | Meaning |
| --- | --- |
| `ESXI_CONFIG_FILE`, `ESXI_DEPLOY_CONFIG_FILE` | Private credentials and deployment settings |
| `ESXI_HOST`, `ESXI_USER`, `ESXI_PASSWORD`, `ESXI_PORT` | Credential overrides; avoid publishing them |
| `ESXI_ENABLE_WRITES` | Explicit ordinary write override; default false |
| `ESXI_ENABLE_ADVANCED_WRITES` | Additional API/upload/OVF/SSH write opt-in; default false |
| `ESXI_POLICY_PROFILE` | `read_only`, default `operator`, or `administrator` |
| `ESXI_PROTECTED_VM_IDS` | Exact comma-separated management VM IDs |
| `ESXI_ALLOW_PROTECTED_IMPACT` | Deployment opt-in; a call must also explicitly allow protected impact |
| `ESXI_ALLOW_MANAGEMENT_DISRUPTION` | Deployment opt-in; a call must also acknowledge disruption |
| `ESXI_ENABLE_SSH_ADMIN`, `ESXI_SSH_CREDENTIALS_FILE` | Optional ESXi SSH backend and private credentials |
| `ESXI_STATE_DIR` | Private SQLite journal and staged transfer files; default beside config |
| `ESXI_LEASE_SESSION_TIMEOUT` | Process-local task/lease retention upper bound, default 86400 seconds |
| `ESXI_VERIFY_SSL`, `ESXI_CA_FILE` | TLS validation override or private CA path |
| `ESXI_CONNECT_TIMEOUT`, `ESXI_AUDIT_FILE` | API HTTP timeout (30s default), private audit location |

Deployment JSON also supports `allowed_operations`, `denied_operations`, `protected_datastores` and `protected_networks`. Discover actual management VM IDs first; re-check them after re-registration.

## Connect an MCP client

Use the installed virtual environment's Python executable:

```json
{
  "mcpServers": {
    "esxi": {
      "command": "/absolute/path/esxi-mcp/.venv/bin/python",
      "args": ["-m", "esxi_mcp.server"],
      "env": {
        "ESXI_CONFIG_FILE": "/private/path/credentials.json",
        "ESXI_DEPLOY_CONFIG_FILE": "/private/path/config.json"
      }
    }
  }
}
```

On Windows use the `.venv/Scripts/python.exe` path. Clients may use their own configuration format. Reload the client after changing configuration. `esxi-mcp` is an alternative console entrypoint. `run-stdio.sh` is a portable Unix launcher; remote stdio may use a dedicated SSH key restricted to that launcher. The transport key and optional ESXi administration key are separate credentials.

## Control surfaces

| Tools | Coverage |
| --- | --- |
| 17 common VM/host tools | Inventory, health, power, CPU/memory/allocations, creation, rename, snapshots, disk expansion, deletion, tasks |
| inventory / managers / api_schema / api_get / api_invoke | Typed access to declared, server-supported vSphere methods and properties |
| 14 `esxi_*_manage` controllers | network, datastore, storage, service, firewall, account, permissions, license, time, pci, certificate, patch, host, options |
| resource_schema / resource_get / dependencies / capabilities | Named action discovery, exact parameters, current state, conservative impact analysis |
| operation_status / operation_history | Durable results and reconnectable task tracking |
| vm_hardware / vm_register | Explicit VirtualDeviceSpec changes and existing VMX registration |
| guest_process / guest_process_status / guest_files | Authenticated Tools-backed guest process/file workflows |
| datastore_transfer / api_transfer | Legacy bounded inline datastore/guest/NFC transfer |
| transfer_start / status / read_chunk / cancel / resume | Bounded-memory background transfer with progress, SHA256 and explicit resume |
| stage_upload / write_chunk / finalize | Private 1MiB chunk staging, identical-chunk replay and final checksum |
| ovf_export / ovf_import / execute_plan | Descriptor/disks/manifest/lease workflows and explicit compensated plans |
| esxcli_query / esxcli / shell | Optional fixed query catalog and explicit administrator commands |

## Execute

Preview by default; use exact VM ID/name, host address or SDK type/ID as the tool requires. Ordinary mutations require writes; advanced operations additionally require advanced writes. An administrator profile enables host-level administrative operations. Shared changes report dependencies: acknowledge every affected VM. Unknown impact requires explicit administrator acknowledgement. Management-disrupting or protected-impact operations require both deployment and call opt-ins. Default protection remains enforced.

Use `esxi_get_task` / `esxi_operation_status` to verify completion. Supported `request_id` parameters prevent duplicate submissions and return existing results/handles; uncertain requests require inspection. The server never implicitly powers off workloads or deletes snapshots. Guest shutdown does not fall back to power-off. Disk growth does not resize guest filesystems. Plans compensate only explicitly specified completed steps, in reverse order; compensation is not an atomic transaction and is skipped when the failing step has an uncertain result. See [resources](docs/resources.md).

For optional SSH administration, install the extra, configure private `ssh.json` using `ssh.example.json`, independently verify a host-key fingerprint (or configure a trusted known_hosts file), and enable the SSH backend. SSH writes are treated as affecting the whole host. Shell payloads and output are omitted from durable logs, retaining argument digests.

## Transfer and OVF client

`scripts/file_client.py` accepts a private stdio transport JSON containing `command`, `args` and optional `env`. Upload/import/export commands preview until `--execute` is supplied. It streams 1MiB chunks and checks SHA256:

```bash
python scripts/file_client.py --transport transport.local.json upload --file installer.iso --datastore DATASTORE --path images/installer.iso --execute
python scripts/file_client.py --transport transport.local.json download --datastore DATASTORE --path images/installer.iso --output copied.iso
python scripts/file_client.py --transport transport.local.json export --vm-id VM_ID --expected-name VM_NAME --output-dir bundle --execute
python scripts/file_client.py --transport transport.local.json import --ovf bundle/vm.ovf --name NEW_VM --datastore DATASTORE --network-map network-map.json --expected-host esxi.example.com --execute
```

OVF export requires an already powered-off VM. Import accepts an unpacked OVF bundle and explicit network/file mappings, not a raw OVA-as-VMDK upload. `fetch --job-id HANDLE --output FILE` can resume a local partial download of a completed handle. Remote download resume uses a matching ETag/Last-Modified and exact HTTP Range; uploads restart and require explicit overwrite when needed. Transfer bounds are explicit (up to 64TiB), with private disk space and a 64MiB reserve required; this maximum has not been tested at scale. Staged files remain private until an operator removes them; no automatic retention service is provided.

## Test and publish

```bash
python -m pytest -q
python scripts/verify_vmomi_contract.py
python -m build
```

Version 0.3.0 is deployed and passed 121 automatic tests on each of Windows and Linux/Python 3.12, nine offline SDK write checks and four ephemeral loopback SSH integration checks. On an ESXi reporting API 8.0.2.0, it passed 15 disposable-VM checks, eight full-workflow checks (including dedicated network writes, request replay, compensation, 12MiB file transfer and a complete OVF export/import roundtrip), and three real ESXCLI queries. Test resources were removed; the 33 existing VMs and original network configuration matched the run baseline. These checks are not exhaustive compatibility or destructive-operation coverage. See [test evidence](docs/testing.md). GitHub Actions passed all four Ubuntu/Windows and Python 3.10/3.12 combinations (121 tests, SDK contracts, SSH loopback checks and package build in each). See the [verified run](https://github.com/Nginx1/esxi-mcp/actions/runs/37181729677).

Publish the clean source bundle only. Do not commit private configurations, state databases, staged files, signed URLs, logs or raw acceptance evidence. See [SECURITY](SECURITY.md) and [CONTRIBUTING](CONTRIBUTING.md).

Coverage follows actual ESXi APIs/commands, licenses, privileges, hardware and state. A schema is not proof of server support. This server does not provide physical BMC/BIOS access, power-on after a physical shutdown or multi-host vCenter orchestration. Guest operations require an OS, running VMware Tools and guest credentials. Background OVF/lease work is process-local and cannot automatically survive an MCP process restart. Only stdio is exposed; use trusted clients. Sources: [official MCP SDK v1](https://py.sdk.modelcontextprotocol.io/v1/), [pyVmomi](https://github.com/vmware/pyvmomi).

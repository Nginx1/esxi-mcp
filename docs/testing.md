# Test evidence and limits

Evidence dates: 2026-10-03–04 (Asia/Shanghai). Source and deployed version: **0.3.0**, 63 tools. Aggregate evidence is public; raw inventory, logs, credentials and transfer handles remain private.

| Version / layer | Result | Scope |
| --- | --- | --- |
| v0.3 Windows + Linux/Python 3.12 pytest | 121 passed on each platform; zero failures/errors/skips | Typed SDK contracts, 63-tool stdio handshake, policy, journal replay/secrecy, resume ownership, streaming/Range/checksum, workflow failure/abort/compensation, independent module imports and SDK OVF file semantics |
| v0.3 offline pyVmomi write contract | 9 passed on each platform; zero network calls | Real SDK types and offline stub; common VM writes |
| v0.3 optional SSH loopback integration | 4 passed on each platform | Ephemeral real SSH authentication, host-key mismatch refusal, redaction, bounded concurrent output and uncertain timeout |
| v0.3 package | sdist/wheel build and installed-wheel module/console stdio checks passed | Recorded with hashes in delivery manifest |
| v0.3 live VM | 15 checks passed | Disposable VM creation/config/limits/rename/power/reset/snapshots/disk growth/deletion; missing-Tools refusal |
| v0.3 full live workflow | 8 checks passed | Capabilities/dependencies/14 resource catalogs; dedicated switch/PG/VLAN; request replay; deliberately failed owned plan and compensation; 12MiB staged upload/download/SHA256; complete OVF export/import; cleanup |
| v0.3 real ESXi SSH | 3 queries passed | system version, standard vSwitch inventory, storage filesystems; pre-existing trusted known_hosts; SSH service state/policy unchanged |
| v0.3 existing resources | Stable baseline comparisons passed | 33 existing VM IDs/UUIDs/names/power/CPU/memory; original network config; owned temporary resources removed |
| v0.3 transport | Windows → pinned SSH → deployed MCP → ESXi passed | 63-tool discovery, real reads, write previews and wrong-name refusal |
| Python 3.10 / GitHub CI | Not run | Ubuntu/Windows × Python 3.10/3.12 workflow configured |
| v0.2 retained evidence | 43 live checks passed | 15 VM, 22 resource, 6 NFC; 32 original VMs unchanged at that earlier run |

The live host reports API 8.0.2.0. The v0.3 count of 33 is the baseline for the current run; the older 32-VM baseline is retained as historical evidence. Owned resources from failed attempts were also removed before the final passing run. Testing found and fixed independent-module circular imports, host Tools ISO paths incorrectly interpreted as datastore files, and reversed OVF upload method selection. For SDK file semantics, ordinary created files use PUT and an Overwrite header, while stream VMDK disks use POST; see [Broadcom/VMware govmomi implementation](https://github.com/vmware/govmomi/blob/main/nfc/lease.go).

These are functional checks, not bandwidth/load tests or proof of every SDK operation. Host reboot/shutdown, storage formatting/destruction, management-network disruption, PCI changes and system/account/certificate/patch mutations were not executed on production. Real SSH writes were not executed. Successful guest operations require an isolated OS/Tools VM and guest credentials. The 64TiB validation ceiling has not been tested at scale. Physical BMC/BIOS is outside scope.

## Reproduce offline

```bash
python -m pip install -e '.[dev,admin]'
python -m pytest -q
python scripts/verify_vmomi_contract.py
python scripts/verify_ssh_backend.py
python -m build
```

## Reproduce live

Private `transport.local.json` contains stdio `command`, `args` and optional `env`. Enable relevant writes with an account/license that permits them. Keep evidence private. Run acceptance scripts sequentially, with no concurrent inventory-changing work. A failed task or disconnect can leave owned resources; inspect private checkpoints and complete recovery before rerunning.

```bash
python scripts/check_stdio_client.py --transport transport.local.json --output acceptance.json --schema acceptance-tools.json
python scripts/live_vm_acceptance.py --transport transport.local.json --output-dir acceptance-private --execute
python scripts/live_full_acceptance.py --transport transport.local.json --expected-host esxi.example.com --output acceptance-private/full.json --execute
```

The full script creates a switch with no uplink, portgroups, one file and powered-off OVF test VMs. It removes its own resources and compares existing VMs/network config. It does not format storage or change existing workloads. `live_resource_acceptance.py` and `live_nfc_acceptance.py` retain earlier tests; their current policy requirements must be reviewed before reuse. Real Guest success and destructive host acceptance require separate disposable environments.

# Capability matrix / 能力与边界

0.3.0 has 63 tools. “Implemented” means a callable control surface with local validation. Offline workflow/stub tests verify client behavior, not successful ESXi execution. Version 0.3.0 is deployed and has passing live checks on ESXi API 8.0.2.0; destructive operations and broad compatibility remain unverified.

| Resource / workflow | Implemented | Evidence |
| --- | --- | --- |
| VM inventory, power, resource allocation, creation, rename, snapshots, expansion, deletion | Common tools and generic API | v0.3 live temporary-VM acceptance, 15 checks |
| Existing VMX registration / hardware devices / PCI attachments | Dedicated tools and ConfigSpec | v0.2 live add/remove disk + VMXNET3; registration and other devices not live-tested |
| vSwitch, VLAN/portgroups, VMkernel, uplinks, DNS and routing | network controller and API | v0.3 dedicated isolated switch/PG/VLAN live tests and dependency discovery; management networking not mutated |
| Datastores, VMFS/NFS/vVol, LUN/HBA, partitions, iSCSI, NVMe, multipath | datastore/storage controllers and API | Discovery/schema checked; disruptive writes not live-tested |
| Services, firewall, accounts, permissions, license, time, certificates, patches | Named controllers and API | SDK action catalog checked offline; host mutations not live-tested |
| Host maintenance/reboot/shutdown/lockdown and advanced settings | host/options controllers and API | Exposed and guarded; not executed on the running production host |
| Guest process/file workflows | Tools-backed API and dedicated tools | Missing-Tools rejection verified in v0.2; successful guest operations await an OS/Tools test VM and credentials |
| File transfer, stages, resume, cancel and SHA256 | Background jobs and portable client | v0.3 live 12MiB staged upload/download/SHA256; bounded-memory, Range identity and client resume also verified offline |
| Complete OVF export/import | Descriptor/file mapping, NFC disks, Complete/Abort, manifest | v0.3 complete live OVF export/import on owned powered-off VMs; sequencing/abort and PUT/POST SDK file semantics also tested offline |
| Durable records / idempotency / compensation | SQLite journal and explicit plan | v0.3 live request replay and explicit compensation; owner/uncertainty tests offline |
| Optional ESXCLI/shell | Administrator SSH backend | 4 ephemeral loopback integration checks and 3 real ESXi queries passed; ESXi SSH writes not tested |

## What “all resources” requires

For ESXi software administration, enable the administrator profile and the relevant write/backend settings. Keep exact targets and dependency checks. Protected management VMs can be controlled through the generic API only when deployment and call both opt in. Read-only/operator profiles intentionally expose a narrower executable surface. See [execution guide](resources.md).

The SDK may declare vCenter-only or license/hardware-dependent methods. ESXCLI/shell offers an explicit path for configuration outside the SDK; it cannot make unsupported hardware or privileges available. Physical BMC/BIOS, restoring access after management-network failure, starting a powered-off physical host, automated OS installation, fleet orchestration and cross-process NFC lease restoration require additional systems or workflows.

## Remaining engineering limits

- No automatic continuation of a multi-step OVF/plan after server restart; durable records identify uncertainty and task outcomes. A new process cannot recreate an expired session-bound lease.
- No atomic transaction across host APIs; compensations can fail or be inappropriate after partial effects. No blind retry of uncertain writes.
- Uploads restart; resumable HTTP downloads depend on identity/Range support. The 64TiB bound is a validation ceiling, not a demonstrated throughput/capacity claim.
- Private staging consumes disk and has no automatic retention/garbage-collection service. Operators must inspect active operations before removing old local files.
- Dependency analysis is conservative for known resources, incomplete for arbitrary shell and opaque vendor operations; these require explicit whole-host acknowledgement.
- Broad version/license/hardware coverage, successful Guest operations, real SSH writes and destructive host acceptance remain outstanding.

These limits are disclosed so that tool count is not confused with exhaustive compatibility or test coverage.

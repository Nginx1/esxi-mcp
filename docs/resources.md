# Typed resources, policy and workflows

Use `esxi_capabilities` for actual product/version/managers and `esxi_dependencies` for VM files/networks/datastores and management VMkernel interfaces. SDK schema availability does not establish host/license support.

## Dedicated resource controllers

`esxi_resource_schema(domain)` lists actions; an action argument returns exact declared parameter types. `esxi_resource_get(domain, properties)` reads declared current properties. The 14 `esxi_DOMAIN_manage` tools delegate to the typed bridge and its policy/journal:

```json
{
  "action": "portgroup_create",
  "arguments": {"portgrp": {"name": "mcp-test-pg", "vlanId": 123, "vswitchName": "mcp-test-switch", "policy": {}}},
  "expected_host": "esxi.example.com",
  "dry_run": true
}
```

This is `esxi_network_manage`; execution additionally needs write opt-ins and `allow_disruption=true` because its target is a shared manager. An isolated switch with no uplink does not require pretending that every VM is affected. Actual dependencies are returned. `AddPortGroup` / `UpdatePortGroup` take `portgrp`, not `spec`: see the [NetworkSystem API](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.NetworkSystem.html).

## Generic API

1. Discover with `esxi_managers` or `esxi_inventory`; references contain only `_type` and `_moId`.
2. Inspect `esxi_api_get` and `esxi_api_schema`. Increase `depth`/`max_items` if data is truncated.
3. Preview `esxi_api_invoke`. Typed objects allow a polymorphic `_type`; unknown fields, undeclared methods and mismatched types are rejected.
4. Execute with exact `expected_target='_type:_moId'`, `dry_run=false`, normal and advanced write opt-ins. Non-VM targets require `allow_disruption=true`, including query-like methods routed through this write-capable tool.
5. Poll tasks/operation IDs. A synchronous SDK return does not validate every downstream effect.

## Deployment policy

Profiles are `read_only`, `operator` (default) and `administrator`. Administrative host/storage/account/security APIs require administrator where classified. Arbitrary API calls retain ESXi's privilege checks. Known shared-resource changes are scanned against current VMs and management VMkernel interfaces; unknown targets fail closed unless the administrator explicitly acknowledges unknown impact.

| Guard | Requirement for execution |
| --- | --- |
| Any listed affected VMs | `acknowledged_vm_ids` includes every affected ID |
| Unknown impact | administrator + `allow_unknown_impact=true` |
| Management disruption | administrator + deployment `allow_management_disruption=true` + call `allow_disruption=true` |
| Protected VM impact | administrator + deployment `allow_protected_impact=true` + call `allow_protected_impact=true` |
| Protected datastore/network names | Denied; change private deployment policy deliberately if control is required |

`allowed_operations` / `denied_operations` use case-sensitive glob matching. Denies win. Dedicated controllers and guest/hardware/registration wrappers match the canonical SDK identity, for example `vim.host.NetworkSystem:AddPortGroup`. Common mutation tools and background workflow/stage tools also match their tool names, such as `esxi_power_vm` / `esxi_ovf_import`. SSH queries/writes additionally match `ssh:query` / `ssh:administration`. A multi-step plan must permit its outer tool and every underlying action. These are local execution limits, not a substitute for ESXi account roles. Default-protected basic VM tools remain blocked; administrator generic API calls support the explicit protected-impact override.

All protection is based on current discovered state and known relationships. Opaque device/vendor/shell arguments cannot be comprehensively analyzed. A direct host disruption can sever the connection used to recover it.

## Durable operations and plans

Supported `request_id` values are 1..96 letters/digits/hyphens/underscores and bind to account, host, operation and argument digest. Reuse the same ID for an uncertain submission to inspect/replay the existing result, never to blindly repeat it. Existing executing/failed/needs_review requests are rejected; background jobs replay their handle without relaunch. `esxi_operation_status` refreshes retained task IDs and marks missing tasks/dead workers for review. SQLite and staged files live in private `state_dir`.

`esxi_execute_plan` takes explicit tool/argument steps and optional `compensate` steps. Tasks must finish before subsequent steps. References such as `{"$step":0,"path":["result","_moId"]}` select a previous step's recorded JSON result, without evaluation. A compensation may reference its own completed step. Static steps preview at submission; dynamic steps preview once references exist. Steps recheck immediately before execution. Failures compensate specified completed steps in reverse order only when the failing result is known. Partial effects and compensation failure require review; this is not an atomic transaction. Leases/OVF/transfers use their dedicated workflows, not synchronous plan steps.

## Files and OVF

Legacy `esxi_datastore_transfer` / `esxi_api_transfer` provide bounded inline payloads. For large files use `esxi_stage_upload` → `write_chunk` → `finalize`, then `esxi_transfer_start(source_job_id=...)`. Stage chunks are <=1MiB; identical chunk retries succeed, holes/conflicting bytes fail. Uploads can also stage a trusted HTTPS source. Background jobs have explicit size ceilings, two process-local worker slots, free-disk reserve checks, status/cancel/resume and SHA256 verification. Status/read calls omit private paths and signed URLs. Files are retained privately; no automatic retention service is provided.

Download resume requires an identity validator and exact Content-Range; ignored/changed ranges restart instead of joining different versions. Upload resume retransmits; use explicit overwrite and inspect the remote file after failure. NFC keeps the original authenticated session and heartbeats during streaming, with a configurable retention bound. Process restart interrupts that lease; durable metadata cannot reconstruct it.

`esxi_ovf_export` requires a powered-off VM, exports all lease files, generates an OVF descriptor and SHA256 manifest, then completes the lease. `esxi_ovf_import` validates the descriptor/file mappings, resolves target datastore/networks, obtains an import spec, uploads NFC files and completes the lease; warnings need explicit acceptance. Failure aborts the import lease and reports uncertain cleanup. OVF artifacts use private transfer handles; `scripts/file_client.py` exports/imports a local unpacked bundle. See [OvfManager](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.OvfManager.html) and [HttpNfcLease](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.HttpNfcLease.html) for server protocol/abort semantics.

## Guest and optional SSH

Guest tools require running Tools, an OS and typed guest authentication, for example `vim.vm.guest.NamePasswordAuthentication`. File upload/download first obtains a short-lived guestFile URL, then uses a transfer tool. Filesystem expansion is an explicit guest operation, not an automatic disk-growth side effect.

Optional ESXi SSH uses `.[admin]`, private `ssh.json`, a verified SHA256 host-key pin or known_hosts file, administrator profile and `ssh_admin_enabled=true`. Writes additionally need write opt-ins, exact host and whole-host/protected/management acknowledgement. `esxi_esxcli_query` permits only the server's fixed query catalog; the caller cannot label an arbitrary command read-only. `esxi_esxcli` quotes argv; `esxi_shell` intentionally permits an explicit arbitrary administrator command. Timeout reports uncertainty and never auto-retries. [Paramiko trust behavior](https://docs.paramiko.org/en/stable/api/client.html) underlies the pinned/reject policy.

Read [security](../SECURITY.md), [capabilities](capabilities.md) and [test evidence](testing.md) before enabling broad execution.

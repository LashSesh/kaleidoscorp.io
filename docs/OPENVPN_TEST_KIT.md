# OpenVPN development test kit — 2026-09-22

This document accompanies a local, unsigned development kit for a future isolated
Windows VM. It is not a product installer, approved distribution or completed VM
acceptance. No VM or network change is made by preparing/verifying the kit.

The kit contains the project CLI, service executable and acceptance recorder,
fixed operational reference documents/templates, and a read-only Windows host
probe. It contains no OpenVPN distribution, driver, Windows image/license,
profiles, certificates, recovery keys or journal data. Supply those prerequisites
through the organization's separate approval and test-credential procedures.

## Prepare and verify

Build `ssk-cli` and `ssk-winhost` from one reviewed state. Then use the recorder:

```powershell
ssk-vpn-acceptance kit-create --cli C:\Build\ssk.exe --service C:\Build\ssk-svc.exe --source-revision <full-git-revision> --worktree-dirty --out C:\Transfer\vpn-development-kit
ssk-vpn-acceptance kit-verify --kit C:\Transfer\vpn-development-kit --expected-manifest-sha256 <separately-retained-sha256>
```

Omit `--worktree-dirty` only for a genuinely clean checkout. Source metadata is an
operator declaration; binary hashes identify exact bytes but do not prove a
reproducible build. Preserve local source changes separately. The source binaries
must have Windows x64 executable PE headers; this is a structural check, not
Authenticode verification or proof of runtime compatibility. The kit does not
install runtime prerequisites; the selected build's dependencies must be checked
on the guest before acceptance.

The output directory must be new, with an existing parent. Inputs are checked
before creation; files are copied through pinned source handles, synced and read
back. The final `manifest.json` lists the fixed contents and hashes. Existing or
partial output directories are never overwritten, adopted or deleted. Preserve a
failed partial kit and choose a fresh destination after investigating the error.
Each binary is bounded to 512 MiB, each reference to 256 KiB, the manifest to 64 KiB.

New kits use manifest schema 2, adding the public journal-backup guide to the
fixed inventory. The verifier also accepts the original schema-1 inventory against
its independently retained hash. An older schema-1 verifier rejects schema 2;
use a trusted current verifier. Previously created kit directories remain exact
historical snapshots and are not updated in place. Neither schema includes journal
archives or any other confidential backup data.

Retain the returned manifest SHA-256 independently of the kit, then copy the whole
directory through an approved transfer method. At the destination, verify with an
already trusted recorder before executing transferred binaries. A verifier taken
from an untrusted kit cannot establish its own trust. Verification detects missing,
changed, extra, symlink/reparse and unexpected-path entries; it never executes files.
There is no signature, publisher approval, external upload or automatic extraction.
`development_only` stays true and `release_ready` stays false.

Use a transfer directory with restricted write access. The tool does not provision
or validate Windows ACLs. Verification describes the files at inspection time;
it does not protect them against later replacement by another writer.

## Check the prospective host

On a prospective Windows host, explicitly run the included read-only script:

```powershell
& C:\Transfer\vpn-development-kit\scripts\openvpn-vm-host-probe.ps1 -StorageDrive C:
```

It reads OS/memory/local-disk facts and available VM management commands/common
install locations. Unknown/denied facts remain unknown and block its resource
assessment. It does not inventory/start guests, enable features, install software,
change BIOS/security settings, alter firewall rules or provision directories.
Its planning margins for one guest are 12 GiB total host memory, 6 GiB currently
free memory and 96 GiB free local storage. These are project margins for a guest,
snapshots and evidence, not universal vendor minimums or a guarantee of capacity.
They do not apply to an already provisioned remote guest.

`host_resources_sufficient` is only an inventory-based planning result. `vm_ready`
and `release_ready` remain false. Actual hypervisor compatibility, a disposable
guest, clean snapshot, console access, isolated network, approved distribution/
driver and test principals/credentials must still be established. A detected
hypervisor alone does not identify a usable VM manager or available guest.

Microsoft documents that [the Hyper-V role is unavailable on Windows Home](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v).
When a hypervisor is already active, [normal hardware requirement reporting can
be suppressed](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements);
do not infer disabled firmware virtualization from those flags alone. Guest
requirements must be checked against the selected image; see [Windows 11 VM
requirements](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements).
Do not disable host security features merely to make an unreviewed hypervisor work.

## Start acceptance after prerequisites exist

Use [the evidence workflow](OPENVPN_ACCEPTANCE_TOOL.md) and
[the VM matrix](OPENVPN_VM_ACCEPTANCE.md). Initialize distinct en-US/de-DE runs
from the same kit binaries. Do not initialize runs or mark tests passed merely
because a kit verified or a host resource probe succeeded. Some linked reference
documents belong to the full repository and are not included in this compact kit.

Until a disposable Windows VM and approved test assets are available, all real
privileged acceptance remains pending. No local fixture test proves that deployment,
SCM/driver integration, cross-user ACLs or power-loss behavior passes on that VM.

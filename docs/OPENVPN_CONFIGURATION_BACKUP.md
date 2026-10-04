# Encrypted OpenVPN configuration backups — 2026-09-22

The elevated Windows CLI can create a separate random recovery key, encrypt the
currently committed configuration, verify an archive without exporting plaintext
and restore directly from that archive. Restoration retains the existing journal,
evidence and exact-version checks. No backup command starts OpenVPN or a service,
installs a driver, changes authorization or releases tunnel traffic.

## Prepare storage and key custody

Use existing, administratively owned confidential directories on local storage.
Their ancestors must pass the existing integrity checks. The commands refuse
unsafe owners/ACLs, reparse points, relative/device/UNC paths and missing parents;
they do not create directories or change their permissions. Files are checked for
confidential ACLs, regular-file type and a single hardlink. Keep the key and archive
under separate custody/storage according to the organization's recovery policy.
Putting them on the same lost disk does not provide disaster recovery.

Example paths below are placeholders for already protected directories. First,
create a key file once, in an elevated session:

```powershell
ssk --json winhost vpn config-backup-key-create C:\RecoveryKeys\vpn-recovery.key
```

The file contains a format marker and 32 bytes from the OS cryptographic random
source. Its inherited ACL is checked before any bytes are written; it is synced
and read back before success. The command never prints the key or accepts a key
value/password in arguments or environment variables. Key creation is independent
of the VPN store and journal and therefore does not require an installed/stopped
service. Other commands below require the existing journal and a stopped service.

The recovery key itself is plaintext protected by filesystem permissions. Retain
it in the organization's separately controlled secret storage. Losing it makes the
archive unavailable; exposure compromises every archive encrypted with it. These
commands do not implement an HSM/KMS, escrow, password derivation, key rotation or
remote storage integration. They cannot establish the entropy of a manually
fabricated key file; use the generated key format, not a padded password.

## Create and verify a backup

Stop the service through its normal lifecycle. Diagnose the managed configuration
and obtain its currently committed SHA-256. Then create a new archive:

```powershell
ssk --json winhost vpn config-diagnose
ssk --json winhost vpn config-backup D:\ProtectedBackups\vpn-2026-09-22.sskb --key-file C:\RecoveryKeys\vpn-recovery.key --expected-committed <committed-sha256>
ssk --json winhost vpn config-backup-verify D:\ProtectedBackups\vpn-2026-09-22.sskb --key-file C:\RecoveryKeys\vpn-recovery.key --expected-committed <committed-sha256>
```

Creation verifies the complete journal, takes its existing exclusive lock and
requires the active configuration to match the supplied and journal-committed
digest. Pending maintenance or unhealthy audit prevents backup/verification.
An unresolved process with healthy audit is preserved and does not by itself
prevent protecting the configuration needed for later recovery.

The configuration and key are read through handles denying write/delete sharing.
Encryption happens in memory. The destination is claimed with `create_new`, checked
before writing, synced, read back and authenticated/decrypted internally before
success. Existing filenames, including partial failed outputs, are never adopted
or overwritten. On failure preserve any artifact and choose a fresh reviewed
destination for retry. There is no automatic cleanup of incomplete files.

Verification reads/authenticates/decrypts the archive, checks its configuration
hash and full strict document format, then drops the plaintext buffer. It creates
no file or audit event. It can succeed even when the active/retained configuration
is missing; a healthy journal with the matching commitment is still required.
Old-version verification against a newer journal is refused, just like restoration.

Successful reports contain action, configuration SHA-256, archive SHA-256 and byte
count. They omit keys, endpoints, certificates, profile bytes and plaintext. Save
the report with a protected backup inventory and a separate key-custody reference.
Creation and verification do **not** append export events to the VPN journal;
the CLI result is not a durable export-audit or an external trust anchor. Audit
integration, scheduling, external retention and monitoring remain operating gates.

## Restore without a plaintext import file

For an absent active configuration, run:

```powershell
ssk --json winhost vpn config-restore --expected-committed <committed-sha256> --expected-observed missing --backup D:\ProtectedBackups\vpn-2026-09-22.sskb --key-file C:\RecoveryKeys\vpn-recovery.key
```

For existing damaged bytes, replace `missing` with the observation from diagnosis.
`--backup` and `--key-file` require each other and cannot be combined with `--source`.
Only file paths, never key values, appear on the command line.

Archive authentication, committed digest and full profile/grant parsing must all
pass before evidence, replacement bytes or restore intent are written. Decryption
feeds the same [exact restoration transaction](OPENVPN_CONFIGURATION_RESTORE.md)
as a confidential plaintext source. The archive is held locked during restoration.
No separate plaintext import file is produced. The existing protected active,
temporary and evidence files still contain plaintext as described in that contract.

An older archive cannot restore revoked grants after a newer commit. Process
identity, exit evidence and unresolved recovery state remain unchanged. If the
active configuration is already intact and expectations match, the existing
`already-intact` no-op does not need to read the supplied archive or key; use
`config-backup-verify` to test those artifacts independently.

After interruption, use `config-diagnose` and `config-restore-reconcile`. Once intent
is durable, reconciliation depends on the preserved original evidence and the
active original/committed state; it does not need to decrypt the source again.
Unknown contents, missing evidence and corrupt journal history remain blocked.

## Archive format and cryptographic boundary

Version 1 uses the pinned RustCrypto `chacha20poly1305` 0.10.1 implementation of
[XChaCha20-Poly1305 authenticated encryption](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/).
It uses a 256-bit key and a freshly generated 192-bit nonce for each archive. No
custom cipher, password scheme, reduced-round mode or new Windows FFI is introduced.

| Bytes | Meaning |
|---|---|
| Key 0–7 | ASCII `SSKKEY01` |
| Key 8–39 | 32 random key bytes; exact key file length 40 bytes |
| Archive 0–7 | ASCII `SSKVPN01` |
| Archive 8–39 | Exact configuration SHA-256 |
| Archive 40–63 | Random 24-byte nonce |
| Archive 64 through length minus 17 | Encrypted configuration bytes |
| Final 16 archive bytes | Authentication tag |

The entire 64-byte header is authenticated as additional data. Document bytes are
bounded to 1 MiB, making the maximum archive 1 MiB + 80 bytes. There is no compression,
algorithm negotiation, optional unbounded metadata or trailing payload. Unknown
versions, truncation, appended bytes, wrong keys and modified headers/bodies/tags
are refused. The header exposes the document hash and archive length; this is
metadata, not an encrypted identifier.

Plaintext/key buffers use `Zeroizing`; detached in-place encryption avoids growing
a plaintext-containing buffer. The library wipes its owned cipher key on drop.
This does not guarantee the absence of copies in parser/OS internals, paging,
debuggers, crash dumps or external backup software. The archive is authenticated
by a symmetric key, not signed by an independent approver. Anyone holding that key
can create an archive; the separate journal commitment still governs restoration.
This increment makes no FIPS validation or compliance-certification claim.

## Retention and remaining release gates

| Artifact | Operational requirement |
|---|---|
| Recovery key | Separate confidential custody; preserve all keys needed for retained archives |
| Encrypted archive | Protected inventory, digest, date/version and key reference; verify after approved transfer |
| Current configuration | Keep a verified archive for the currently committed digest after every approved update |
| Earlier archives | Retain under the organization's policy; they cannot replace a newer committed configuration |
| Original/segmented journal | Use the separate [journal snapshot workflow](OPENVPN_JOURNAL_BACKUP.md) and independently retained expectations; the encrypted configuration archive does not contain journal history |
| Active/staged/evidence/temporary plaintext | Existing confidential ACLs; no automatic deletion or encryption of these files |

No retention duration or deletion schedule is inferred. Secret cleanup, archive
pruning and key retirement require a defined policy and implementation. Restoration
after loss of the whole machine/journal remains unsupported until complete journal
backup/restore and trusted commitment recovery exist. This archive layer alone is
not complete disaster recovery or an administrator-proof anti-rollback mechanism.

Tests exercise real temporary files, encryption and Windows file locks/moves with
private ACL observations. They cover round trips, fresh nonces, every single-byte
archive mutation, maximum size, wrong/unsafe/linked keys and archives, version
revocation, output collisions, permission failures before bytes, missing plaintext
sources and an interrupted restore preserving process state. Real ACL inheritance,
separate-user access, copied media, operational key custody and power-loss behavior
remain unexecuted [VM acceptance gates](OPENVPN_VM_ACCEPTANCE.md).
Results: [restart assessment](RESTART_ASSESSMENT_2026-09-21.md);
local logs: `target/restart-audit/vpn-backup-*.log`.

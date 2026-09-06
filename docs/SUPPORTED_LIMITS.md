# Supported limits and environments

**Status:** Phase 4 release baseline (2026-09-06).

## Supported environment

The security-supported development scope is:

- 64-bit macOS and Linux;
- regular local files on filesystems providing reliable same-directory hard links;
- an operating system CSPRNG available through `getrandom`;
- the pinned Rust 1.97.1 toolchain when rebuilding release 0.0.4.

Windows, network filesystems, cloud-synchronized folders, FUSE filesystems, object-store mounts, unusual removable-media filesystems, containers with weak entropy, and 32-bit targets are not security-supported yet. They may work, but file permissions, atomic publication, durability, and failure behavior have not been validated.

The current Unix implementation creates new secret and inventory files with mode `0600` atomically. It does not validate directory permissions or defend against a compromised parent directory.

## Current enforced format limits

| Item | Current behavior |
| --- | --- |
| Archive magic/version | `PQBACK02`, version 2 only |
| Root-key format | `PQROOT02`, 62 bytes |
| Header length | At most 64 KiB |
| Plaintext length | At most 1 TiB (1,099,511,627,776 bytes) |
| Chunk size | 1 byte through 16 MiB |
| Default chunk size | 4 MiB |
| Data frames per archive | At most 1,048,576 (2^20) |
| Chunk index | Sequential 32-bit unsigned; Phase 2 count limit applies first |
| Original filename | UTF-8, safe single component, at most 4096 bytes before encryption |
| ML-KEM ciphertext | Exactly 1568 bytes |
| ML-KEM public key | Exactly 1568 bytes |
| ML-KEM seed | Exactly 64 bytes |
| Root secret | Exactly 32 bytes inside `PQROOT02` |
| Root-key inventory | `PQINVENTORY01` UTF-8 TOML, at most 1 MiB |
| Wrapped DEK | 32-byte DEK plus 16-byte GCM tag |
| Existing output | Never overwritten |
| Trailing archive data | Rejected after authenticated final chunk |
| Restore/archive temporary files | Same destination directory, mode `0600` on Unix, removed on failure when the OS permits |

The smaller applicable plaintext/chunk-count limit wins. For example, one-byte
chunks reach the frame-count limit at 1 MiB, while the default 4 MiB chunk size
reaches the 1 TiB plaintext limit first.

All header-derived allocations are bounded by the 64 KiB header ceiling. Each
frame allocation is bounded by 16 MiB of plaintext plus its 16-byte AEAD tag.
Length totals and allocation sizes use checked arithmetic.

## Limit-change policy

These are conservative engineering ceilings, not a claim that every file up to
the ceiling has a particular formal security strength. Raising them requires a
documented security analysis, boundary tests, and a versioned policy update.

## Retention policy

The cryptography is intended for long-lived archives, but no passive retention duration is guaranteed. Supported operation requires:

- full verification after creation and after every storage copy;
- at least annual restore drills using independent custody copies;
- cryptographic and dependency review at least every two years;
- prompt migration after a material vulnerability or standards change;
- periodic storage-media refresh and checksum verification;
- preservation of source, lockfile, known-good binary, specifications, test vectors, and restore instructions.

A 10–30 year archive is a managed migration objective, not a promise that one binary and format can be ignored for that period.

Tagged releases provide native binaries for Linux x86-64, Intel macOS, and
Apple-silicon macOS. The pipeline performs same-host byte comparison for clean
builds; it does not claim cross-host or cross-toolchain bit-for-bit identity.
The recovery kit supplies vendored dependencies for locked offline builds.

## Filesystem requirements

Recovery's no-replace publication is only assumed atomic when the temporary file and output are in the same directory on a conforming local filesystem with hard-link support. Durability across power loss is not claimed for every filesystem. Verify restored output and application-level contents after recovery.

Secure deletion is not provided. Removing plaintext from SSDs, snapshots, backups, swap, or copy-on-write filesystems is outside the package boundary.

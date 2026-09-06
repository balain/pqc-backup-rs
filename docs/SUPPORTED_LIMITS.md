# Supported limits and environments

**Status:** Phase 0 policy baseline. “Current” values are enforced today; “target” values are approved implementation goals for Phase 2.

## Supported environment

The security-supported development scope is:

- 64-bit macOS and Linux;
- regular local files on filesystems providing reliable same-directory rename;
- an operating system CSPRNG available through `getrandom`;
- a current Rust toolchain capable of building the locked dependencies.

Windows, network filesystems, cloud-synchronized folders, FUSE filesystems, object-store mounts, unusual removable-media filesystems, containers with weak entropy, and 32-bit targets are not security-supported yet. They may work, but file permissions, atomic rename, durability, and failure behavior have not been validated.

The current Unix implementation sets newly written secret files to mode `0600`. It does not validate directory permissions or defend against a compromised parent directory.

## Current enforced format limits

| Item | Current behavior |
| --- | --- |
| Archive magic/version | `PQBACK02`, version 2 only |
| Root-key format | `PQROOT02`, 62 bytes |
| Header length | At most 64 KiB |
| Chunk size | 1 byte through 16 MiB |
| Default chunk size | 4 MiB |
| Chunk index | 32-bit unsigned; overflow fails |
| Original filename | UTF-8, safe single component, at most 4096 bytes before encryption |
| ML-KEM ciphertext | Exactly 1568 bytes |
| ML-KEM public key | Exactly 1568 bytes |
| ML-KEM seed | Exactly 64 bytes |
| Root secret | Exactly 32 bytes inside `PQROOT02` |
| Wrapped DEK | 32-byte DEK plus 16-byte GCM tag |
| Existing output | Never overwritten |
| Trailing archive data | Rejected after authenticated final chunk |

## Known current gap

There is no explicit maximum plaintext size or conservative maximum chunk count below the 32-bit framing boundary. Therefore very large archives are not security-supported even if the program can process them.

## Approved Phase 2 targets

Phase 2 will implement both limits; the smaller applicable limit wins:

- maximum plaintext size: **1 TiB**;
- maximum data chunks under one DEK: **1,048,576 (2^20)**;
- maximum allocation derived from header-controlled data: **64 KiB**;
- maximum chunk allocation: **16 MiB plus authentication framing**.

These are conservative engineering ceilings, not a claim that every file up to the ceiling has a particular formal security strength. Phase 2 must validate them against the final AES-GCM analysis and lower them if that review requires it. Raising them requires a documented security analysis, tests, and a versioned policy update.

Until Phase 2 enforcement lands, operators must keep each input at or below 1 TiB and choose a chunk size that produces no more than 2^20 chunks. A 4 MiB chunk size reaches the plaintext-size ceiling first.

## Retention policy

The cryptography is intended for long-lived archives, but no passive retention duration is guaranteed. Supported operation requires:

- full verification after creation and after every storage copy;
- at least annual restore drills using independent custody copies;
- cryptographic and dependency review at least every two years;
- prompt migration after a material vulnerability or standards change;
- periodic storage-media refresh and checksum verification;
- preservation of source, lockfile, known-good binary, specifications, test vectors, and restore instructions.

A 10–30 year archive is a managed migration objective, not a promise that one binary and format can be ignored for that period.

## Filesystem requirements

Recovery's final rename is only assumed atomic when the temporary file and output are in the same directory on a conforming local filesystem. Durability across power loss is not claimed for every filesystem. Verify restored output and application-level contents after recovery.

Secure deletion is not provided. Removing plaintext from SSDs, snapshots, backups, swap, or copy-on-write filesystems is outside the package boundary.


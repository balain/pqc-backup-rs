# pqbackup

> [!WARNING]
> **Experimental and unaudited.** Do not use `pqbackup` as the sole protection
> for irreplaceable, regulated, or high-value data. Maintain independent tested
> backups and keep the ML-KEM seed separate from the root key.

`pqbackup` is a small Rust CLI for protecting a local `.tgz` backup against
"harvest now, decrypt later" risk.

It is a **reference implementation**, not a replacement for an audited backup
product.

Security policy and planning documents:

- [Security model](docs/SECURITY_MODEL.md)
- [Supported limits and environments](docs/SUPPORTED_LIMITS.md)
- [Risk register](docs/RISK_REGISTER.md)
- [PQBACK02 format](docs/PQBACK02_FORMAT.md)
- [PQROOT02 format](docs/PQROOT02_FORMAT.md)
- [Compatibility policy](docs/FORMAT_COMPATIBILITY.md)
- [Decoder error categories](docs/ERROR_CATEGORIES.md)
- [Long-term security assessment](docs/LONG_TERM_SECURITY_ASSESSMENT.md)
- [Improvement plan](docs/IMPROVEMENT_PLAN.md)
- [Parser fuzzing](docs/FUZZING.md)
- [Deterministic test vectors](test-vectors/manifest.md)

## Quick start: run the complete demo

After building, run the self-contained demonstration in a new directory:

```bash
target/release/pqbackup demo --out-dir ./pqbackup-demo
```

The command creates a harmless sample file, ML-KEM keys, a root key, an
encrypted archive, and a restored copy. It then compares the restored file to
the input. It does not overwrite an existing demo directory. The demo keeps
both recovery secrets together for convenience only; do not copy that custody
pattern for real backups.

## Cryptographic design

For each backup:

1. Generate a fresh random 256-bit Data Encryption Key (DEK).
2. Encrypt the backup in authenticated chunks with AES-256-GCM.
3. Encapsulate a fresh 32-byte secret with ML-KEM-1024 (FIPS 203).
4. Combine:
   - the ML-KEM shared secret; and
   - a separate random 256-bit offline root secret
   using HKDF-SHA-384.
5. Use the resulting 256-bit Key Encryption Key (KEK) to wrap the DEK with
   AES-256-GCM.
6. Store the ML-KEM ciphertext, salt, nonces, encrypted filename metadata,
   wrapped DEK, and encrypted data in the `PQBACK02` envelope.

The archive is therefore not recoverable from the stored ciphertext and ML-KEM
material alone. Recovery requires **both**:

- the 64-byte ML-KEM-1024 decapsulation seed; and
- the independent 32-byte root secret.

That is the important HNDL property: a future catastrophic break of ML-KEM by
itself does not reveal the DEK if the offline root secret remains unavailable.

## Why ML-KEM-1024?

This prototype deliberately chooses ML-KEM-1024 (NIST security category 5) for
long-lived archival data rather than ML-KEM-768.

## Build

Requires a current Rust toolchain:

```bash
cargo build --release
```

Binary:

```bash
target/release/pqbackup
```

For development, replace `target/release/pqbackup` below with
`cargo run --` or `target/debug/pqbackup`.

## Command reference

```text
pqbackup keygen-kem  --out-dir DIR [--name NAME]
pqbackup keygen-root --output PATH [--root-key-id HEX] [--root-key-epoch N]
pqbackup seal INPUT --public-key PATH --root-secret PATH [-o OUTPUT]
               [--chunk-size BYTES]
pqbackup inspect ARCHIVE.pqbk
pqbackup verify ARCHIVE.pqbk --secret-key PATH --root-secret PATH
pqbackup open ARCHIVE.pqbk --secret-key PATH --root-secret PATH [-o OUTPUT]
pqbackup demo [--out-dir DIR]
```

Run `pqbackup <command> --help` for the complete argument help. All commands
refuse to overwrite files; choose a new output path or move the existing file.

## One-time setup

```bash
pqbackup keygen-kem --out-dir ./keys --name home-archive

# Run this directly on the separate root-key medium.
pqbackup keygen-root \
  --output /Volumes/ROOTKEY/home-archive.root.key \
  --root-key-epoch 2026
```

Creates:

```text
keys/home-archive.mlkem1024.pub
keys/home-archive.mlkem1024.seed
/Volumes/ROOTKEY/home-archive.root.key
```

`keygen-root` creates a versioned `PQROOT02` root-key file. It contains the
32-byte secret plus a randomly generated stable 128-bit root-key ID and a
rotation epoch. Supply `--root-key-id` with a 32-hex-character value when a
custody procedure requires a chosen stable ID. The ID and epoch are not secret;
they are bound to every archive and appear in `inspect` output.

Example with an externally assigned stable ID:

```bash
pqbackup keygen-root \
  --output /Volumes/ROOTKEY/home-archive-2026.root.key \
  --root-key-id 0c9f1a2b3d4e5f60718293a4b5c6d7e8 \
  --root-key-epoch 2026
```

The root-key file is binary. Do not open it in an editor, send it by email, or
treat it as a password string. Existing v1 raw 32-byte root-secret files are
not valid v2 root-key files: generate a fresh `PQROOT02` root key before
creating v2 archives.

### Recommended custody

**Backup computer**

```text
home-archive.mlkem1024.pub
```

**Offline device A**

```text
home-archive.mlkem1024.seed
```

**Offline device B**

```text
home-archive.root.key
```

Keeping the two recovery secrets on distinct media gives materially better
failure separation. Keep redundant copies of each secret in controlled,
physically separate locations.

Do not put the two secrets next to the encrypted backup.

## Encrypt a backup

Assume the root-secret USB is mounted temporarily:

```bash
pqbackup seal backup-2026-09-05.tgz \
  --public-key ./keys/home-archive.mlkem1024.pub \
  --root-secret /Volumes/ROOTKEY/home-archive.root.key
```

Output:

```text
backup-2026-09-05.tgz.pqbk
```

Use `-o` when the archive should have a different name or location:

```bash
pqbackup seal backup-2026-09-05.tgz \
  --output /Volumes/BACKUPS/home-2026-09-05.pqbk \
  --public-key ./keys/home-archive.mlkem1024.pub \
  --root-secret /Volumes/ROOTKEY/home-archive.root.key
```

`--chunk-size` defaults to 4 MiB and accepts values from 1 byte through 16 MiB.
It changes streaming/memory behavior, not the required recovery materials.

After sealing:

1. Unmount the root-secret media.
2. Copy the `.pqbk` file to the backup destination(s).
3. Optionally delete the plaintext `.tgz` only after verification and according
   to your retention policy.

## Inspect without decrypting

```bash
pqbackup inspect backup-2026-09-05.tgz.pqbk
```

`inspect` intentionally does not reveal the original filename. It displays the
format, algorithms, file length, chunk size, root-key ID, root-key epoch, and
envelope sizes only.

An inspect result contains attacker-controlled, unauthenticated routing data
until recovery keys validate the archive. It is not proof of the root key,
epoch, creator, or archive history. Archive length and root-key ID/epoch may
also be operationally sensitive.

## Restore

Mount both recovery-secret locations:

```bash
pqbackup open backup-2026-09-05.tgz.pqbk \
  --secret-key /Volumes/PQKEY/home-archive.mlkem1024.seed \
  --root-secret /Volumes/ROOTKEY/home-archive.root.key \
  --output restored.tgz
```

Then verify the tarball normally:

```bash
tar -tzf restored.tgz >/dev/null
```

If `--output` is omitted, `open` decrypts the archived filename only after the
root key and ML-KEM seed authenticate it, then restores into the current
directory. To avoid an accidental filename collision or to choose a destination
explicitly, always pass `--output` in scripts.

The restore is written to a same-directory temporary file and atomically
published without overwriting an existing name only after every chunk
authenticates. A failed restore leaves no completed output file.

## Verify without writing plaintext

Use `verify` after copying an archive to another medium and before deleting a
plaintext source:

```bash
pqbackup verify /Volumes/BACKUPS/home-2026-09-05.pqbk \
  --secret-key /Volumes/PQKEY/home-archive.mlkem1024.seed \
  --root-secret /Volumes/ROOTKEY/home-archive.root.key
```

Verification requires both recovery secrets because it decrypts and
authenticates every payload chunk, but it does not create a plaintext file.

## Suggested backup workflow

A practical local workflow is:

```text
source directory
      |
      v
tar/gzip
      |
      v
backup-YYYY-MM-DD.tgz
      |
      | pqbackup seal
      | + ML-KEM public key
      | + temporarily mounted offline root secret
      v
backup-YYYY-MM-DD.tgz.pqbk
      |
      +----> local backup disk
      |
      +----> NAS / remote object store
      |
      +----> offline copy
```

The ML-KEM private seed is not needed to make backups. It is needed only for
restore. The root secret *is* required during sealing because it forms the
second independent component of the KEK.

For unattended backups, keeping the root secret online weakens the independent
offline-secret property. A hardware-backed secret (HSM, smartcard, or other
non-exportable key mechanism) is the better next step for automation.

## Chunk framing

The file is encrypted in independently authenticated chunks (default 4 MiB).
Each chunk uses:

```text
nonce = random 64-bit file prefix || 32-bit chunk index
AAD   = header hash || chunk index || plaintext length || final flag
```

The final flag is authenticated. Restore rejects:

- reordered chunks;
- modified chunks;
- missing chunks;
- truncation before the final chunk;
- trailing data after the final chunk.

Each backup uses a fresh random DEK and nonce prefix, so AES-GCM nonces are not
reused under the same DEK.

## Enforced archive limits

The decoder and sealer enforce both a 1 TiB plaintext ceiling and a maximum of
1,048,576 authenticated data frames per archive. The smaller limit applies.
Chunk sizes must be between 1 byte and 16 MiB; the default is 4 MiB. Header and
frame allocations are bounded before memory is allocated. See
[supported limits](docs/SUPPORTED_LIMITS.md) for the complete policy.

## Important limitations

- The RustCrypto `ml-kem` implementation currently warns that it has not been
  independently audited.
- This project has not itself received a security review.
- The original filename is encrypted and authenticated in `PQBACK02`. File
  length remains visible to support streaming and recovery checks.
- No ML-DSA signature is included in v2. AES-GCM authenticates the encrypted
  archive to a holder of the keys, but it does not provide third-party sender
  attribution.
- Secure deletion of the plaintext `.tgz` is filesystem/SSD dependent and is
  intentionally outside this tool.
- Long-term backup safety also depends on preserving the recovery secrets,
  software/specification, and migration procedures.
- Security-supported development scope is currently limited to 64-bit macOS
  and Linux using regular local filesystems. See
  [supported limits](docs/SUPPORTED_LIMITS.md) before processing large archives
  or using other operating systems/filesystems.

## Operational checklist

Before relying on an archive:

1. Keep the ML-KEM seed and root key on different protected media.
2. Keep at least two controlled copies of each recovery secret in separate
   locations.
3. Run `verify` on the completed archive and again after copying it elsewhere.
4. Retain this source code, `Cargo.lock`, a known-good binary, test archive,
   and restore instructions with the recovery materials.
5. Practice a complete restore periodically on a separate machine or directory.
6. Rotate to a new root key and epoch according to your retention and risk
   policy; retain old root keys while any archive using them still matters.

## Troubleshooting

`ML-KEM public key must be exactly 1568 bytes` means `seal` received the wrong
file, commonly a root key instead of the `.mlkem1024.pub` file.

`root key is not a PQROOT02 key file` means the input is a v1 raw root secret,
a text file, or the wrong path. Generate a new root key with `keygen-root`.

`root key ID or epoch does not match this archive` means the archive was sealed
under a different root key or key epoch. Locate the matching root-key file
reported by `inspect`.

`DEK unwrap failed` or filename authentication failure means a recovery secret
is incorrect, corrupt, or the archive has been modified. Do not retry with
untrusted replacement files; identify the correct custody copies first.

## Crypto migration

The file header contains explicit algorithm/version identifiers. A future
version can add another KEM or a different wrapping construction while leaving
the large encrypted payload design conceptually intact.

For high-value archives, periodically review the cryptographic suite and
migrate before an algorithm becomes deprecated.

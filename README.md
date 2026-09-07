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
- [Key management and custody](docs/KEY_MANAGEMENT.md)
- [PQINVENTORY01 format](docs/PQINVENTORY01_FORMAT.md)
- [PQBACK02 provenance extension](docs/PQBACK02_PROVENANCE_FORMAT.md)
- [Provenance and signer policy](docs/PROVENANCE_POLICY.md)
- [Long-term security assessment](docs/LONG_TERM_SECURITY_ASSESSMENT.md)
- [Improvement plan](docs/IMPROVEMENT_PLAN.md)
- [Parser fuzzing](docs/FUZZING.md)
- [Deterministic test vectors](test-vectors/manifest.md)
- [Release process](docs/RELEASE_PROCESS.md)
- [Recovery runbook](docs/RECOVERY_RUNBOOK.md)
- [Phase 6 security-review package](docs/SECURITY_REVIEW_PACKAGE.md)
- [Finding and remediation record](docs/PHASE6_REMEDIATION.md)
- [Controlled-pilot procedure and evidence](docs/CONTROLLED_PILOT.md)
- [Production-readiness statement](docs/PRODUCTION_READINESS.md)
- [Residual-risk acceptance template](docs/RESIDUAL_RISK_ACCEPTANCE.md)
- [Future security options](docs/FUTURE_SECURITY_OPTIONS.md)

## Quick start: run the complete demo

After building, run the self-contained demonstration in a new directory:

```bash
target/release/pqbackup demo --out-dir ./pqbackup-demo
```

The command creates a harmless sample file, ML-KEM keys, a root key, an
ML-DSA-87 signer, secret-free custody and trust-policy files, a signed encrypted
archive, and a restored copy. It verifies both archive provenance and encrypted
content before comparing the restored file to the input. It does not overwrite
existing output files. The demo keeps all secrets together for convenience
only; do not copy that custody pattern for real backups.

For the repeatable Phase 6 engineering pilot, which simulates separated
custody and exercises expected failure cases with disposable data, run:

```bash
cargo build --locked
./scripts/run-controlled-pilot.sh target/debug/pqbackup
```

This is not a substitute for the independent review or real physical-custody
drill required before production consideration.

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
7. Optionally sign the complete encrypted envelope and canonical signer
   metadata with ML-DSA-87, then verify it against a separately trusted policy.

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

The repository pins Rust 1.97.1 in `rust-toolchain.toml`. With `rustup`
installed, Cargo selects and installs that toolchain automatically:

```bash
cargo build --release
```

Binary:

```bash
target/release/pqbackup
```

For development, replace `target/release/pqbackup` below with
`cargo run --` or `target/debug/pqbackup`.

## Download a tagged release

Pushing a new `v*` tag runs the complete test, supply-chain, fuzz-smoke,
reproducibility, and offline-recovery workflow. After those checks pass,
GitHub Actions creates a GitHub Release containing:

```text
pqbackup-vX.Y.Z-linux-x86_64.tar.gz
pqbackup-vX.Y.Z-macos-x86_64.tar.gz
pqbackup-vX.Y.Z-macos-aarch64.tar.gz
pqbackup-vX.Y.Z-source.tar.gz
pqbackup-vX.Y.Z-recovery-kit.tar.gz
pqbackup-vX.Y.Z.cdx.json
pqbackup-vX.Y.Z-release-manifest.txt
pqbackup-vX.Y.Z-trusted-root.jsonl
pqbackup-vX.Y.Z-provenance.sigstore.json
SHA256SUMS
```

Download the assets from the repository's Releases page, verify the checksum
manifest and build provenance, then extract the binary for your platform:

```bash
shasum -a 256 -c SHA256SUMS
gh attestation verify \
  pqbackup-vX.Y.Z-linux-x86_64.tar.gz \
  -R OWNER/REPOSITORY \
  --bundle pqbackup-vX.Y.Z-provenance.sigstore.json
tar -xzf pqbackup-vX.Y.Z-linux-x86_64.tar.gz
./pqbackup --help
```

Use `macos-aarch64` for Apple silicon and `macos-x86_64` for Intel macOS.
Preserve the recovery kit, detached provenance bundle, trusted-root file, and
checksum manifest together. The [recovery runbook](docs/RECOVERY_RUNBOOK.md)
documents online and offline verification, rebuilding, test-vector recovery,
media refresh, and migration drills.

## Command reference

```text
pqbackup keygen-kem  --out-dir DIR [--name NAME]
pqbackup keygen-root --output PATH [--root-key-id HEX] [--root-key-epoch N]
pqbackup keygen-signing --out-dir DIR [--name NAME]
               [--signer-key-id HEX] [--signer-key-epoch N]
pqbackup seal INPUT --public-key PATH --root-secret PATH [-o OUTPUT]
               [--chunk-size BYTES] [--expect-root-key-id HEX]
               [--expect-root-key-epoch N]
pqbackup inspect ARCHIVE.pqbk
pqbackup sign ARCHIVE.pqbk --signing-key PATH [-o SIGNED.pqbk]
pqbackup provenance-verify SIGNED.pqbk --public-key PATH --policy PATH
               [--allow-retired]
pqbackup key-info PATH --kind root|kem-public|kem-seed|archive|signing-public|signing-seed
pqbackup inventory init INVENTORY.toml
pqbackup inventory add INVENTORY.toml --root-secret PATH --label TEXT
               --custody TEXT [--custody TEXT] [--status STATUS]
pqbackup inventory list INVENTORY.toml
pqbackup inventory check INVENTORY.toml
pqbackup inventory locate INVENTORY.toml ARCHIVE.pqbk
pqbackup inventory set-status INVENTORY.toml --root-key-id HEX
               --root-key-epoch N --status STATUS
pqbackup signer-policy init POLICY.toml
pqbackup signer-policy add POLICY.toml --public-key PATH --identity TEXT
               [--status trusted|retired|revoked]
pqbackup signer-policy list POLICY.toml
pqbackup signer-policy check POLICY.toml
pqbackup signer-policy set-status POLICY.toml --signer-key-id HEX
               --signer-key-epoch N --status trusted|retired|revoked
pqbackup verify ARCHIVE.pqbk --secret-key PATH --root-secret PATH
pqbackup open ARCHIVE.pqbk --secret-key PATH --root-secret PATH [-o OUTPUT]
pqbackup demo [--out-dir DIR]
```

Run `pqbackup <command> --help` for the complete argument help. Commands that
create keys, archives, demos, or inventories refuse to overwrite files.
`inventory add` and `inventory set-status` atomically update an existing
inventory. Signer-policy updates are also atomic.
Compromise-related lifecycle transitions are one-way: a compromised or
destroyed root-key epoch cannot become active again, and a revoked signer epoch
cannot become trusted or retired. Create a new epoch instead.

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

Validate files and compare the public-key fingerprint derived from both ML-KEM
files before separating them:

```bash
pqbackup key-info ./keys/home-archive.mlkem1024.pub --kind kem-public
pqbackup key-info ./keys/home-archive.mlkem1024.seed --kind kem-seed
pqbackup key-info /Volumes/ROOTKEY/home-archive.root.key --kind root
```

The two ML-KEM commands must print the same `public SHA-256` value. `key-info`
never prints secret bytes.

### Create a custody inventory

The inventory records only root-key IDs, epochs, lifecycle status, labels, and
human-readable custody locations. Store no passwords, recovery phrases, key
bytes, PINs, or unlock instructions in it.

```bash
pqbackup inventory init ./root-key-inventory.toml

pqbackup inventory add ./root-key-inventory.toml \
  --root-secret /Volumes/ROOTKEY/home-archive.root.key \
  --label "Home archive annual root" \
  --custody "Primary sealed offline copy" \
  --custody "Offsite sealed recovery copy"

pqbackup inventory check ./root-key-inventory.toml
pqbackup inventory list ./root-key-inventory.toml
```

The inventory is operationally sensitive even though it contains no key
material. On supported Unix systems it is created with mode `0600`.

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

### Optional provenance setup

Archive signing is separate from encryption and recovery. Generate the signing
seed in its own protected location:

```bash
pqbackup keygen-signing \
  --out-dir /Volumes/SIGNING-KEY \
  --name home-archive-signer \
  --signer-key-epoch 2026

pqbackup key-info \
  /Volumes/SIGNING-KEY/home-archive-signer.mldsa87.pub \
  --kind signing-public
```

Create the trust policy on a verification system and bind the public-key
fingerprint to a meaningful identity:

```bash
pqbackup signer-policy init ./signer-policy.toml

pqbackup signer-policy add ./signer-policy.toml \
  --public-key /Volumes/SIGNING-KEY/home-archive-signer.mldsa87.pub \
  --identity "Home backup signing key"

pqbackup signer-policy check ./signer-policy.toml
pqbackup signer-policy list ./signer-policy.toml
```

Authenticate the public key and policy through a channel independent from the
archive storage. The policy contains no secret bytes, but an attacker who can
replace it can substitute a signer identity.

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
  --root-secret /Volumes/ROOTKEY/home-archive.root.key \
  --expect-root-key-id 0c9f1a2b3d4e5f60718293a4b5c6d7e8 \
  --expect-root-key-epoch 2026
```

The expectation flags are recommended in automation. Sealing stops before
creating an archive when the mounted root key does not match either value.

`--chunk-size` defaults to 4 MiB and accepts values from 1 byte through 16 MiB.
It changes streaming/memory behavior, not the required recovery materials.

After sealing:

1. Unmount the root-secret media.
2. If provenance is required, sign the unsigned archive.
3. Copy the final `.pqbk` file to the backup destination(s).
4. Optionally delete the plaintext `.tgz` only after verification and according
   to your retention policy.

## Sign an encrypted archive

Signing is a separate operation so the provenance seed never needs to coexist
with the plaintext or either recovery secret:

```bash
pqbackup sign backup-2026-09-05.tgz.pqbk \
  --signing-key /Volumes/SIGNING-KEY/home-archive-signer.mldsa87.seed \
  --output backup-2026-09-05.signed.pqbk
```

The command copies the complete unsigned envelope, appends one canonical
ML-DSA-87 trailer, verifies the resulting structure, and atomically publishes
the signed output. It refuses to overwrite files or sign an already signed
archive. Preserve the unsigned source until the signed copy verifies.

Verify creator provenance without recovery secrets:

```bash
pqbackup provenance-verify backup-2026-09-05.signed.pqbk \
  --public-key ./home-archive-signer.mldsa87.pub \
  --policy ./signer-policy.toml
```

This verifies the exact encrypted bytes, signer ID/epoch, public-key
fingerprint, trusted human identity, and lifecycle state. A `retired` signer is
rejected unless `--allow-retired` is explicitly supplied for an approved
historical archive. A `revoked` signer is always rejected.

Signatures do not prove creation time or freshness. A replayed valid archive
still verifies; use an authenticated external catalog or trusted timestamp when
rollback detection is required. See the
[provenance policy](docs/PROVENANCE_POLICY.md).

## Inspect without decrypting

```bash
pqbackup inspect backup-2026-09-05.tgz.pqbk
```

`inspect` intentionally does not reveal the original filename or trusted signer
identity. It displays the
format, algorithms, file length, chunk size, root-key ID, root-key epoch, and
envelope size. For a signed archive it also reports an unverified signature
presence, signer ID, and signer epoch.

An inspect result contains attacker-controlled, unauthenticated routing data
until recovery keys validate the archive. It is not proof of the root key,
epoch, creator, or archive history. Use `provenance-verify` for creator identity.
Archive length and key IDs/epochs may also be operationally sensitive.

Locate the matching custody record without mounting either recovery secret:

```bash
pqbackup inventory locate ./root-key-inventory.toml backup-2026-09-05.tgz.pqbk
```

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

`open` authenticates encryption but does not make a signer-trust decision. If a
provenance trailer is present, it is structurally validated and the command
prints a reminder to run `provenance-verify` separately.

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
This `verify` command checks encrypted-content integrity, not creator identity;
use `provenance-verify` for the separate signer-policy decision.

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
- trailing data after the final chunk unless it is exactly one well-formed
  `PQSIG001` provenance trailer;
- truncated, nested, malformed, or extra provenance data.

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
- The automated controlled pilot simulates custody on one host; independent
  review, real separated-media recovery, and named risk acceptance remain
  incomplete. The current production decision is NO-GO.
- The original filename is encrypted and authenticated in `PQBACK02`. File
  length remains visible to support streaming and recovery checks.
- An optional ML-DSA-87 extension provides creator attribution only when its
  public key and signer policy were authenticated independently. The upstream
  RustCrypto `ml-dsa` implementation and this integration are not independently
  audited.
- Archive signatures do not provide a trusted time, append-only history,
  deletion detection, uniqueness, or newest-backup selection.
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
4. If provenance matters, run `provenance-verify` using a protected trust
   policy and retain historical signer public keys and policy snapshots.
5. Retain this source code, `Cargo.lock`, a known-good binary, test archive,
   and restore instructions with the recovery materials.
6. Practice a complete restore periodically on a separate machine or directory.
7. Rotate to new recovery and signing epochs according to your retention and risk
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

`archive provenance signature is invalid` means the encrypted envelope or
signed metadata changed, or the supplied public key is not the signing key.

`public key fingerprint does not match the trusted signer policy` means the
key file and policy disagree. Stop and authenticate both through the approved
distribution channel; do not add the replacement key merely to make
verification pass.

## Crypto migration

The file header contains explicit algorithm/version identifiers. A future
version can add another KEM or a different wrapping construction while leaving
the large encrypted payload design conceptually intact.

For high-value archives, periodically review the cryptographic suite and
migrate before an algorithm becomes deprecated.

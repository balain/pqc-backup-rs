# Key management and custody

**Status:** Phase 3 operational baseline
**Applies to:** `PQBACK02`, `PQROOT02`, and `PQINVENTORY01`

This document defines the minimum lifecycle for pqbackup recovery material. It
does not replace an organization's access-control, incident-response, records,
or legal-retention policies.

## Recovery material

Every archive requires both secret classes:

1. the 64-byte ML-KEM-1024 decapsulation seed; and
2. the 32-byte root secret inside a `PQROOT02` file.

The ML-KEM public key may remain online for sealing. The seed and root key must
be kept on independently controlled media. Do not store either secret in the
root-key inventory, beside the encrypted archive, in source control, in shell
history, or in a password-manager note that contains the other secret.

## Initial provisioning

1. Generate the ML-KEM material on a trusted host with `keygen-kem`.
2. Validate the public key and seed separately with `key-info`; their displayed
   public SHA-256 fingerprints must match.
3. Move the seed to its offline custody locations and remove working copies
   according to the storage technology's deletion policy.
4. Generate the root key independently with `keygen-root`, preferably directly
   on its destination medium.
5. Validate and record its ID and epoch with `key-info --kind root`.
6. Create at least two controlled copies of each secret class, keeping root-key
   copies separate from seed copies.
7. Create a `PQINVENTORY01` file and record descriptive custody locations only.
8. Seal a non-sensitive test archive, then verify and restore it independently
   with each designated recovery-copy set.

Secret and inventory files are created with mode `0600` on supported macOS and
Linux filesystems. Directory permissions, removable-media encryption, physical
controls, and access logging remain operator responsibilities.

## Root-key IDs and epochs

A root-key ID identifies a logical root-key lineage. Retain the same ID when
rotating to a new epoch within that lineage, and generate fresh secret bytes for
every epoch. Never reuse the same secret under a different epoch merely to make
the inventory appear rotated.

Epoch meaning is deployment-defined. A four-digit year is convenient for annual
rotation, but event counters are equally valid. Document the policy and use the
sealing assertions in automated jobs:

```bash
pqbackup seal backup.tgz \
  --public-key ./keys/archive.mlkem1024.pub \
  --root-secret /Volumes/ROOTKEY/archive-2027.root.key \
  --expect-root-key-id 00112233445566778899aabbccddeeff \
  --expect-root-key-epoch 2027
```

## Inventory workflow

```bash
pqbackup inventory init ./root-key-inventory.toml

pqbackup inventory add ./root-key-inventory.toml \
  --root-secret /Volumes/ROOTKEY/archive-2027.root.key \
  --label "Archive root lineage, 2027" \
  --custody "Primary sealed offline copy" \
  --custody "Offsite sealed recovery copy"

pqbackup inventory locate ./root-key-inventory.toml archive.pqbk
pqbackup inventory check ./root-key-inventory.toml
```

`inventory locate` reads only the archive's unauthenticated routing header. The
result helps retrieve a candidate key; successful `verify` or `open` is the
authentication decision.

The repository's `.gitignore` excludes the documented
`root-key-inventory*.toml` naming pattern. Custody inventories remain
operationally sensitive and should stay out of public source control regardless
of filename.

## Rotation

1. Choose the next epoch under the existing stable root-key ID.
2. Generate a new `PQROOT02` file with fresh secret bytes and the chosen ID and
   epoch.
3. Create and verify independent custody copies.
4. Add the epoch to the inventory as `active`.
5. Update sealing automation to assert the new ID and epoch.
6. Seal and restore a test archive before routine use.
7. Mark the previous epoch `retired`; retain it while any dependent archive is
   still required.

```bash
pqbackup inventory set-status ./root-key-inventory.toml \
  --root-key-id 00112233445566778899aabbccddeeff \
  --root-key-epoch 2026 \
  --status retired
```

Changing a root key does not alter existing archives. Migration requires
decrypting and resealing each archive under the new epoch, then independently
verifying the replacement before retiring the old archive.

Inventory lifecycle changes through the CLI are monotonic. An active epoch may
be retired, compromised, or destroyed; a retired epoch may become compromised
or destroyed; a compromised epoch may become destroyed. A compromised,
destroyed, or retired epoch cannot return to active. Create a fresh epoch
instead. This protects against accidental state rollback but does not
authenticate the inventory file itself.

## Retirement and destruction

Retirement prohibits new sealing but preserves recovery capability. Mark the
inventory record `retired`, remove it from active automation, and continue
testing recovery while dependent archives remain.

Destruction is irreversible. Before marking `destroyed` or destroying media:

- inventory every archive that depends on the ID and epoch;
- confirm those archives expired or were successfully migrated;
- obtain the approvals required by the governing retention policy;
- account for redundant copies, snapshots, escrow, and disaster-recovery media;
- record the destruction outside this unauthenticated inventory.

Secure deletion characteristics of SSD, flash, copy-on-write, and cloud storage
are outside pqbackup's control.

## Compromise response

If one secret class may be exposed, stop using the affected material, mark the
record `compromised` where applicable, preserve evidence, create fresh ML-KEM
and root material, and migrate important archives. The remaining independent
secret is still intended to protect confidentiality, but incident response must
not assume it will remain secure indefinitely.

If both the ML-KEM seed and matching root secret are exposed, treat every
accessible dependent archive as potentially decryptable. Rotate both classes,
reseal from trusted plaintext or a trusted recovery, and follow the applicable
data-exposure process. Deleting the old keys does not revoke copies already
obtained by an attacker.

## Recovery drill

At least annually and after every lifecycle change:

1. start with a clean trusted host and a known-good pqbackup build;
2. retrieve one seed copy and one separately held root-key copy;
3. use `key-info` and `inventory locate` to select and cross-check materials;
4. run `verify`, restore to a new destination, and validate application-level
   contents;
5. repeat using the alternate custody copies;
6. record date, archive identifier, key ID/epoch, software version, outcome, and
   responsible operator outside the inventory.

Never perform the only recovery drill against the only copy of an archive or
secret.

## Memory, crash dumps, and provider boundary

Secret buffers and derived keys are zeroized where supported by their Rust
types. This does not prevent exposure through swap, hibernation, crash dumps,
debuggers, compromised kernels, DMA, or a hostile process. The current CLI does
not lock memory or configure operating-system crash-dump policy. Use a hardened
recovery host with full-disk encryption, controlled swap/hibernation, restricted
debugging, and an administratively enforced no-core-dump policy where required.

The cryptographic path now depends on a `RootSecretProvider` interface that
returns root metadata and derives an archive KEK. The file provider is the only
implemented backend. A future non-exportable provider can perform root-secret
operations in a keystore or HSM without returning raw root bytes to the archive
logic, provided it can implement the exact frozen v2 HKDF construction.

## Provider evaluation

Before adding a provider, evaluate:

- whether it can preserve the exact `PQBACK02` KEK derivation;
- whether root secret bytes ever leave the device;
- authentication, PIN retry, lockout, and unattended-operation behavior;
- stable device/key identifiers and epoch mapping;
- backup, cloning, escrow, replacement, and disaster recovery;
- availability of the device, driver, and protocol over the archive lifetime;
- audit logs and tamper response;
- failure behavior and protection against silent fallback to raw files.

OS keystores may improve local access control but often remain tied to one host
or account. Smartcards and HSMs can provide stronger non-exportability but may
not support the required derivation directly. External secret brokers improve
central policy and auditing while adding network, service, and account
dependencies. No backend is approved until its recovery and migration paths are
tested independently.

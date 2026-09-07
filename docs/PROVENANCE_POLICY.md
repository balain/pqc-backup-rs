# Archive provenance and signer policy

**Policy format:** `PQSIGNERS01`
**Applies to:** the optional `PQSIG001` extension on `PQBACK02` archives

## Trust model

An archive trailer is self-asserted until all of these are independently
provided and checked:

- the ML-DSA-87 public key;
- a trusted `PQSIGNERS01` policy;
- an authenticated distribution path for both files; and
- the `provenance-verify` result.

Do not trust a signer ID printed by `inspect`. The policy, not the archive,
maps a cryptographic key to a human, service, organization, or release role.
An attacker who can replace both the public key and policy can name any
identity, so protect policy distribution and changes at least as strongly as
the archive provenance decision requires.

## Recommended roles and custody

Generate provenance keys independently from ML-KEM and root recovery keys.
The signing seed grants authority to create archives attributed to its policy
identity; it does not decrypt archives. Keep it offline or in a hardened
signing environment, and copy only the public key to verification systems.

For automated signing, use a dedicated restricted host and short rotation
epochs. `pqbackup` 0.0.6 uses exportable seed files and does not yet support an
HSM or remote signer.

## Policy format

The policy is bounded UTF-8 TOML with a maximum size of 1 MiB. Unknown fields,
duplicate `(id, epoch)` pairs, non-canonical hexadecimal values, control
characters, bidi formatting controls, and identities over 300 bytes are
rejected.

```toml
format = "PQSIGNERS01"

[[signers]]
id = "00112233445566778899aabbccddeeff"
epoch = 2026
identity = "Backup release signing service"
status = "trusted"
public_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

The policy stores no secret bytes. Its contents are integrity-sensitive and
the CLI creates it with mode `0600` on supported Unix systems.

## Lifecycle states

| State | Default verification behavior | Intended use |
| --- | --- | --- |
| `trusted` | Accept after signature and fingerprint verification | Current approved signer epoch |
| `retired` | Reject unless `--allow-retired` is explicit | Historical key whose authority ended normally |
| `revoked` | Always reject | Compromised, misissued, or no longer trustworthy key |

`--allow-retired` is only for an archive already approved as historical. It
does not override `revoked`.

Lifecycle changes through the CLI are monotonic. A trusted signer may be
retired or revoked, and a retired signer may later be revoked. A revoked epoch
cannot return to trusted or retired; generate and authenticate a new epoch.

Never delete a record merely because its key is retired or revoked. Historical
records provide the policy evidence needed to interpret older archives. Store
dated, authenticated policy snapshots and a change log outside this file if
auditability matters.

## Provisioning

```bash
pqbackup keygen-signing \
  --out-dir /Volumes/SIGNING-KEY \
  --name archive-signer \
  --signer-key-epoch 2026

pqbackup signer-policy init ./signer-policy.toml

pqbackup signer-policy add ./signer-policy.toml \
  --public-key /Volumes/SIGNING-KEY/archive-signer.mldsa87.pub \
  --identity "Backup release signing service"

pqbackup signer-policy check ./signer-policy.toml
pqbackup signer-policy list ./signer-policy.toml
```

Verify the displayed ID and SHA-256 fingerprint over an authenticated channel
before distributing the policy.

## Rotation

1. Generate a new seed/public pair with a new epoch. Reuse a stable ID only
   when policy explicitly treats the epochs as one logical signer lineage.
2. Authenticate and add the new public key as `trusted`.
3. Begin signing new archives with the new seed.
4. Change the old epoch to `retired` after the transition window.
5. Retain the old public key, policy record, and authenticated policy history.

```bash
pqbackup signer-policy set-status ./signer-policy.toml \
  --signer-key-id 00112233445566778899aabbccddeeff \
  --signer-key-epoch 2026 \
  --status retired
```

## Compromise and revocation

If a signing seed may have been exposed:

1. Stop signing with it.
2. Mark its exact ID and epoch `revoked` in every maintained policy.
3. Distribute the updated authenticated policy through the normal trust path.
4. Inventory every archive attributed to that epoch.
5. Re-establish provenance from an independently verified unsigned envelope or
   from content verified through the recovery/application workflow.
6. Record the incident time and affected archive range externally.

A signature alone cannot determine whether it was made before compromise.
Without a trusted timestamp or external catalog, revocation necessarily rejects
all archives for that key epoch.

## Replay, rollback, and timestamps

A copied valid signed archive remains valid. This is the correct behavior for
a detached artifact signature and is covered by a regression test. To detect
replay, deletion, or rollback, maintain an authenticated external catalog with
at least:

- archive SHA-256;
- signer ID and epoch;
- application backup sequence or source snapshot ID;
- creation/acceptance time from a trusted system;
- supersession or deletion state; and
- a monotonic or append-only integrity mechanism.

Version 0.0.6 does not implement that catalog or a trusted timestamp protocol.
Therefore provenance verification answers **who signed these exact encrypted
bytes under the current policy**, not **when they were signed** or **whether
they are the newest backup**.

## Independent review gate

The format and implementation remain experimental. Before relying on creator
identity for high-value decisions, obtain independent review of the signed
representation, ML-DSA usage, parser behavior, key distribution, policy update
process, and compromise response. Repository tests are evidence, not an audit.

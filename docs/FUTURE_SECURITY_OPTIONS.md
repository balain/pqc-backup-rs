# Future security options: non-exportable root keys and authenticated catalogs

**Status:** design options; neither option is implemented or approved
**Applies after:** the 0.0.6 Phase 6 review candidate
**Recommended order:** non-exportable root-key provider first, authenticated
archive catalog second

## Purpose

This document compares two substantial security extensions that remain after
the original six-phase improvement plan:

1. a non-exportable or hardware-backed root-key provider; and
2. an authenticated archive catalog for freshness, rollback, replay, and
   deletion evidence.

They address different risks. The provider primarily limits extraction of a
long-lived recovery secret. The catalog primarily establishes authenticated
state across multiple otherwise valid archives. Neither eliminates endpoint
compromise, replaces independent backups, or completes the outstanding Phase 6
external-review and real-custody gates.

## Current baseline

`PQBACK02` derives each archive's 256-bit Key Encryption Key (KEK) from:

```text
IKM  = ML-KEM shared secret || 32-byte root secret
salt = archive HKDF salt
info = "pqbackup/v2/archive-kek/aes-256-gcm"
KEK  = HKDF-SHA-384(IKM, salt, info, 32 bytes)
```

The file provider reads the complete `PQROOT02` secret into the process. A
`RootSecretProvider` boundary already separates root metadata and KEK
derivation from the rest of the archive logic, but no non-file backend exists.

The optional `PQSIG001` trailer authenticates one exact encrypted archive and
its signer ID/epoch. It does not establish when the archive was made, whether a
newer archive exists, or whether another valid archive was deleted. Those facts
require trusted state outside the archive itself.

## Option A: non-exportable root-key provider

### Objective

Keep the long-lived 32-byte root secret inside a hardware device or isolated
service while allowing `pqbackup` to derive the exact KEK required by the
frozen v2 format.

The backend must return root-key ID/epoch metadata and a derived archive KEK,
but must never return the root-secret bytes. It must fail closed when the
configured provider is unavailable or lacks the required capability.

### Security benefit

The current root-key file can be copied by malware, an operator mistake, a
filesystem backup, or a privileged process whenever it is mounted. Because one
root epoch may protect many archives, that extraction has a potentially broad
and long-lived blast radius.

A correctly implemented non-exportable provider can:

- prevent routine direct export of the root secret;
- require a PIN, device presence, quorum, role, or service authorization;
- restrict which operation the key may perform;
- provide audit events for derivation attempts;
- support safer unattended sealing without leaving an exportable root file on
  the sealing host; and
- make a one-time compromise less likely to yield a reusable copy of the root
  secret.

This is most valuable during sealing. A compromised sealing host may observe
that archive's plaintext, ML-KEM shared secret, and returned KEK, but a device
that enforces non-exportability can still prevent theft of the root secret for
arbitrary future or historical use.

### What it does not protect

- Plaintext is still present on the sealing or recovery host.
- The per-archive KEK and DEK still enter process memory under the current
  provider contract.
- A compromised host with authorized provider access may request operations
  while its session remains valid.
- Recovery still requires the ML-KEM seed and access to the matching provider
  key.
- Hardware loss, lockout, service outage, or lost credentials can make every
  dependent archive unrecoverable.
- It does not provide archive freshness, deletion detection, or rollback
  protection.
- It does not make the overall application or cryptographic composition
  independently audited.

This option reduces root-secret extraction risk; it does not move encryption
or decryption of the archive payload into the device.

### Compatibility requirement

The first provider must preserve `PQBACK02` exactly. The device or service must
implement the same HKDF-SHA-384 extract-and-expand construction over the
32-byte ML-KEM shared secret followed by the 32-byte device-held root secret,
with the archive salt and fixed info string shown above.

If a provider cannot perform that construction without exporting the root
secret, it is incompatible with v2. Changing the derivation requires a new
archive format and migration plan; it must not be hidden behind the v2 provider
interface.

### Candidate backend types

| Backend | Advantages | Disadvantages | Assessment |
| --- | --- | --- | --- |
| PKCS#11 HSM or token | Cross-vendor API, non-exportable objects, roles/PINs, potential audit support | Mechanism support varies; drivers and token behavior differ; backup and replacement are vendor-specific | Preferred starting point after selecting and testing an actual device |
| External derivation broker | Central authorization, logging, quorum, and potentially strong hardware behind the service | Adds network/service/account dependencies and a remote attack surface; offline recovery needs a separate design | Viable for managed deployments, less suitable for isolated archival recovery |
| Operating-system keystore | Lower deployment cost and familiar account controls | Symmetric secret may still be returned to the process; often tied to one host or account | Useful storage hardening, but not automatically a non-exportable provider |
| Apple Secure Enclave | Hardware-bound operations and platform authentication | Apple's documented interface supports NIST P-256 key operations rather than arbitrary symmetric-root HKDF | Not a direct implementation of the frozen v2 root derivation |
| Command or subprocess plugin | Easy to prototype and permits vendor tools | Environment, argument, output, and executable substitution risks; KEK crosses a process boundary | Test adapter only unless a narrow authenticated protocol is designed and reviewed |

PKCS#11 3.2 defines HKDF-related mechanisms, including profiles using
`CKM_HKDF_DERIVE_DATA`, but conformance to a specification does not establish
that a particular device implements the exact required mechanism or semantics.
Capability probing and known-answer tests are mandatory. See the
[OASIS PKCS#11 3.2 profiles](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.2/pkcs11-profiles-v3.2.html).

Apple documents Secure Enclave key protection as supporting NIST P-256
elliptic-curve keys. It should therefore not be described as a direct v2 root
provider without a separately reviewed construction and likely a new format.
See [Apple's Secure Enclave key documentation](https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave).

### Proposed user interface

Exact syntax is subject to review. The important requirements are explicit
provider selection, no ambiguous fallback, and secret-free configuration.

```text
pqbackup seal INPUT \
  --public-key archive.mlkem1024.pub \
  --root-provider pkcs11 \
  --root-provider-config ./root-provider.toml \
  --expect-root-key-id HEX \
  --expect-root-key-epoch N

pqbackup verify ARCHIVE.pqbk \
  --secret-key archive.mlkem1024.seed \
  --root-provider pkcs11 \
  --root-provider-config ./root-provider.toml
```

The existing `--root-secret` file workflow should remain available for format
recovery and controlled migration. A command must reject simultaneous file and
non-file provider selection.

Provider configuration may contain a module path, token label, object ID, key
ID, and epoch. It must not contain a PIN or secret. PINs should arrive through
a protected interactive mechanism or provider-specific secure channel, not a
command-line argument or committed environment file.

### Implementation phases

#### A1. Select and qualify a target

- Choose one specific HSM/token model and supported firmware.
- Confirm exact HKDF-SHA-384 mechanism behavior before writing integration
  code.
- Define Linux and macOS driver support, licensing, and minimum versions.
- Define key backup, cloning, escrow, replacement, and end-of-life procedures.
- Create a public non-secret interoperability profile for the selected target.

This is a gating decision. A generic PKCS#11 implementation without a real
qualified target would create compatibility claims that the project cannot
support.

#### A2. Harden the provider contract

- Add a provider-kind and provider-configuration abstraction.
- Preserve the existing metadata and derivation contract.
- Define provider error categories without leaking unnecessary token state.
- Add explicit capability checks before key creation or archive operations.
- Prohibit file fallback after a non-file provider was requested.
- Ensure provider identifiers and epochs are cross-checked with archive
  metadata.
- Zeroize all returned KEKs and temporary shared-secret buffers.

#### A3. Implement the PKCS#11 backend

- Load only an explicitly configured module.
- Select tokens and objects by stable identifiers, not display names alone.
- Use a non-extractable key object with the minimum permitted mechanisms.
- Authenticate through a protected PIN/session path.
- Construct the exact v2 HKDF input without exporting root bytes.
- Bound sessions, retries, input sizes, timeouts, and error handling.
- Avoid logging module configuration, token serials, PIN state, shared secrets,
  salts tied to sensitive operations, or returned KEKs.

#### A4. Add lifecycle and recovery operations

- Provision a root ID/epoch directly into the provider.
- Validate metadata without performing a real archive operation.
- Rotate to a new epoch without mutating an old epoch.
- Mark compromised or retired objects through documented policy.
- Exercise two independent device or escrow copies.
- Document migration before hardware, firmware, or drivers become unavailable.

#### A5. Test and review

- Use a software PKCS#11 token for deterministic CI behavior.
- Run known-answer comparisons between file and device providers.
- Test missing module, missing token, wrong object, wrong epoch, locked PIN,
  retry exhaustion, disconnect, timeout, concurrent access, and device reset.
- Verify no file fallback and no root bytes in logs or configuration.
- Run the controlled pilot with the real target hardware.
- Commission targeted independent review of the provider boundary and device
  assumptions.

### Operational risks

- Vendor or driver abandonment during the archive retention period.
- A single uncloneable device becoming a catastrophic availability dependency.
- PIN retry lockout or inaccessible administrator roles.
- Backup procedures that make the key exportable and undermine the security
  claim.
- Firmware changes that alter supported mechanisms or behavior.
- Token identifiers that are not stable after replacement.
- Operators confusing test, production, retired, and compromised objects.
- Recovery kits containing software but not a working device, driver, or
  credential procedure.

At least two independently controlled recovery-capable provider instances or
an approved escrow/reconstruction mechanism are required before real use.

### Estimated cost

| Work | Estimate |
| --- | --- |
| Provider/API design and CLI changes | 1–2 engineering weeks |
| Software-token backend and automated tests | 2–3 engineering weeks |
| Real hardware integration and failure testing | 2–4 engineering weeks |
| Custody, backup, recovery, and migration procedures | 1–3 operational weeks |
| Independent targeted review and remediation | External schedule and cost |

These ranges assume one selected device already supports the required
construction. Unsupported HKDF semantics or a new-format design can
substantially increase the work.

### Deliverables

- Versioned provider configuration specification.
- PKCS#11 provider implementation with no-fallback enforcement.
- Software-token CI test fixture.
- Qualified-device interoperability profile.
- Provisioning, rotation, compromise, backup, and recovery runbooks.
- Updated threat model, risk register, pilot, and review package.

### Exit criteria

- The root-secret bytes never leave the qualified provider in supported use.
- File and provider implementations derive identical v2 KEKs for public test
  vectors.
- Wrong devices, objects, IDs, epochs, and capabilities fail closed.
- No silent fallback to file keys exists.
- Two independent recovery-capable provider copies pass clean-system drills.
- A reviewer approves the provider integration and its documented claims.

## Option B: authenticated archive catalog

### Objective

Maintain authenticated state across archives so an operator can determine not
only whether one archive is valid, but whether it belongs to the accepted
history and is the expected current generation for a protected dataset.

The catalog should remain separate from `PQBACK02`. Archives retain their
current bytes; the catalog records their digests and operational state.

### Security benefit

An independently protected catalog can provide evidence of:

- archive inclusion in an accepted backup history;
- the expected sequence or generation for a dataset;
- an older valid archive being presented as current;
- an expected archive missing from storage;
- replacement of an archive with different bytes;
- approved supersession, retention expiry, or deletion;
- the root and signer epochs expected for each generation; and
- policy changes and migration history.

This addresses the gap where two archives can both pass content and provenance
verification even though one is stale or no longer authorized for restoration.

### What it does not protect

- It does not encrypt archives or protect root, ML-KEM, or signing secrets.
- It cannot prevent deletion; it can only provide evidence when expected state
  is available for comparison.
- It cannot detect rollback if the attacker can replace the catalog and every
  trusted checkpoint with an older mutually consistent copy.
- A catalog timestamp is not trusted merely because it is signed. Trusted time
  requires an external timestamping or acceptance authority.
- It does not prove application-level backup completeness.
- It does not make an unavailable catalog service acceptable during emergency
  recovery unless an offline checkpoint procedure exists.

### Required trust anchor

The verifier must possess a catalog public key and a trusted recent checkpoint
through a channel independent of the archives and active catalog storage. At
minimum, the checkpoint identifies:

- catalog format and catalog ID;
- accepted sequence/tree size;
- current chain or Merkle root;
- catalog signing-key ID and epoch;
- checkpoint creation or acceptance context; and
- a signature over the canonical checkpoint.

If the archive storage, catalog, public key, policy, and last checkpoint can all
be rolled back together, the design provides integrity but not freshness.

### Recommended initial construction

Begin with a single-writer signed linear journal rather than a networked Merkle
transparency service. Each canonical entry should include the previous entry
digest, producing an authenticated chain. Verification is linear in catalog
size but operationally simple and independently implementable.

A later scale-oriented version may use a Merkle tree with signed checkpoints,
inclusion proofs, and consistency proofs. RFC 9162 provides a standardized
example of how Merkle consistency proofs establish that a newer tree extends a
previous tree without changing its earlier entries. See
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html). Adopting that structure
would still require a pqbackup-specific canonical entry and policy design.

### Proposed `PQCATALOG01` model

The following is a design sketch, not a frozen format.

```text
Catalog header
  magic/version
  catalog ID
  catalog signing-key ID and epoch
  dataset namespace policy

Entry
  sequence number
  previous entry SHA-384
  event type
  dataset ID
  application snapshot/generation ID
  archive SHA-256
  archive byte length
  PQBACK02 envelope length
  root-key ID and epoch
  provenance state
  signer-key ID and epoch, when present
  prior generation reference, when applicable
  operator-supplied event time, explicitly untrusted unless externally anchored
  reason or policy reference for supersession/deletion
  canonical-entry signature
```

Event types should be explicit, for example:

- `accepted`: add a successfully verified archive generation;
- `superseded`: identify the approved replacement generation;
- `expired`: record a retention-policy decision;
- `deleted`: record an expected deletion after policy approval;
- `compromised`: reject an archive or key epoch for restoration decisions; and
- `migrated`: link old and replacement archives after verified recovery and
  resealing.

Deleting or editing old entries must be invalid. Corrections append a new event
that references the incorrect entry.

### Key separation

Use a dedicated catalog-signing key rather than automatically reusing the
archive signing seed. Archive signing authorizes creation of encrypted bytes;
catalog signing authorizes history and restore-selection decisions. Combining
those roles increases the impact of one compromised key.

The catalog public key, policy, and checkpoints must have an authenticated
distribution path. The key format may reuse the existing ML-DSA-87 primitives,
but requires a new domain separator and independently specified canonical
statement.

### Proposed user interface

Exact names are subject to review.

```text
pqbackup catalog init CATALOG --catalog-id HEX --policy POLICY

pqbackup catalog accept CATALOG ARCHIVE.pqbk \
  --dataset-id DATASET \
  --generation GENERATION \
  --catalog-signing-key KEY \
  --secret-key KEM-SEED \
  --root-secret ROOT-KEY \
  --provenance-public-key SIGNER-PUBLIC \
  --provenance-policy SIGNER-POLICY

pqbackup catalog verify CATALOG \
  --catalog-public-key PUBLIC \
  --catalog-policy POLICY \
  --checkpoint CHECKPOINT

pqbackup catalog reconcile CATALOG STORAGE-DIRECTORY \
  --checkpoint CHECKPOINT

pqbackup catalog checkpoint CATALOG \
  --catalog-signing-key KEY \
  --output CHECKPOINT
```

`accept` should verify archive structure, content, provenance when required,
root/signer metadata, and the expected prior generation before appending. A
mode that records an archive without content verification must be named and
reported as weaker; it must not silently produce a fully accepted event.

### Implementation phases

#### B1. Define policy and canonical format

- Define dataset identity and generation uniqueness.
- Specify single-writer authority and catalog key lifecycle.
- Define event state transitions and correction behavior.
- Freeze canonical byte encoding, hashes, domains, limits, and error classes.
- Define which verification steps are mandatory before acceptance.
- Define trusted checkpoint distribution and retention.

#### B2. Implement the local signed journal

- Strict bounded parser and canonical encoder.
- Atomic append or replacement without partial state.
- Sequence and previous-digest enforcement.
- Dedicated catalog signatures and trust policy.
- Commands to initialize, append, verify, list, and checkpoint.
- Refusal to rewrite or delete historical entries.

#### B3. Reconcile storage and recovery

- Compare catalog entries with one or more storage locations.
- Report missing, extra, modified, stale, superseded, expired, and compromised
  archives without deleting anything.
- Require explicit dataset/generation selection during recovery.
- Include catalog and checkpoints in the recovery kit and restore drill.
- Define emergency recovery when the newest checkpoint is unavailable.

#### B4. Add adversarial testing and review

- Truncation and appended-garbage tests.
- Entry reordering, duplication, omission, and digest substitution.
- Sequence rollback and forked-history tests.
- Wrong catalog, signer, key epoch, dataset, and generation.
- Checkpoint rollback and stale-checkpoint behavior.
- Interrupted append and concurrent-writer behavior.
- Parser fuzzing and resource-boundary tests.
- Independent review of canonicalization, state transitions, and trust model.

### Operational risks

- The latest trusted checkpoint may be unavailable during recovery.
- A single writer can equivocate by producing two valid histories unless
  checkpoints are witnessed or compared externally.
- Operators may mistake a valid but stale checkpoint for current state.
- Catalog loss can remove freshness evidence even when archives remain
  decryptable.
- Overly broad signing authority can approve deletion or compromise events.
- Dataset naming and generation assignment can become inconsistent across
  automation.
- A network service introduces availability, authentication, and multi-tenant
  risks beyond the current local CLI scope.

The first version should remain local and single-writer. A distributed service
should be a separate design and review project.

### Estimated cost

| Work | Estimate |
| --- | --- |
| Threat model, policy, and canonical format | 1–2 engineering weeks |
| Signed linear journal and CLI | 2–3 engineering weeks |
| Reconciliation, checkpoint, and recovery integration | 1–2 engineering weeks |
| Negative tests, fuzzing, and documentation | 1–2 engineering weeks |
| Merkle or multi-writer service, if required | Additional 4–8+ engineering weeks |
| Independent targeted review and remediation | External schedule and cost |

### Deliverables

- `PQCATALOG01` and checkpoint specifications.
- Catalog signing-key and trust-policy documentation.
- Init, accept, verify, list, checkpoint, and reconcile commands.
- Deterministic positive and negative vectors.
- Parser fuzz target and state-machine regression tests.
- Recovery, checkpoint-distribution, key-rotation, and incident procedures.
- Updated threat model, risk register, pilot, and review package.

### Exit criteria

- A verifier with a trusted checkpoint detects entry mutation, omission,
  reordering, truncation, and rollback before that checkpoint.
- Storage reconciliation identifies missing, unexpected, modified, stale, and
  superseded archives without destructive action.
- Catalog key rotation and revocation have explicit historical behavior.
- A lost catalog copy can be recovered from independent authenticated copies.
- Forked histories are detected by the deployment's checkpoint-witness process.
- Documentation never claims trusted time without an actual trusted time
  source.
- Independent reviewers approve the format and trust assumptions.

## Comparative decision matrix

| Criterion | Non-exportable provider | Authenticated catalog |
| --- | --- | --- |
| Primary property | Root-secret extraction resistance | Cross-archive freshness and history |
| Risks addressed | Primarily R-011; reduces part of R-004 blast radius | Primarily R-008 and R-015; supports R-020 operations |
| Protects confidentiality | Directly strengthens secret custody | No |
| Detects archive modification | Existing archive checks already do this | Yes, at storage/history level |
| Detects valid rollback | No | Yes, relative to a trusted checkpoint |
| Detects deletion | No | Yes, when expected state remains available |
| Requires archive format change | No, if exact v2 HKDF is preserved | No |
| External dependency | Hardware/driver/service | Trusted checkpoint storage or witness |
| Portability | Device-dependent | High for a local file format |
| Long-term availability risk | Hardware, credentials, drivers, vendor | Catalog/checkpoint loss or writer failure |
| Initial engineering complexity | High | Medium for linear journal; high for transparency service |
| Operational complexity | High | Medium to high |
| Independent review required | Yes | Yes |

## Recommendation and sequencing

Implement the non-exportable provider first if the project's primary objective
remains long-term confidentiality and harvest-now-decrypt-later protection.
The root secret is long-lived, currently exportable, and reused across an
epoch, while the existing provider boundary gives this work a defined
integration point. Preventing bulk root-secret extraction provides more direct
value to that objective than adding cross-archive state.

The recommended sequence is:

1. **Phase 7: non-exportable root-key provider.** Select one real device,
   confirm exact v2 HKDF support, implement a no-fallback PKCS#11 backend, and
   complete two-copy hardware recovery drills.
2. **Phase 8: authenticated archive catalog.** Freeze `PQCATALOG01`, implement
   a local single-writer signed journal and independently retained checkpoints,
   then add storage reconciliation.

There are two reasons to reverse the order:

- the intended deployment has a contractual requirement to identify the
  newest accepted backup or detect deletion/rollback; or
- no selected provider can yet implement the exact v2 derivation, while a
  catalog can proceed without changing archive encryption.

Hardware procurement and capability testing can run in parallel with catalog
format design, but neither phase should claim completion until its operational
controls and independent review are finished.

## Relationship to Phase 6

These options are future engineering improvements, not substitutes for Phase
6. Production consideration still requires:

- independent review of the complete candidate;
- remediation and independent retesting of material findings;
- a real separated-custody clean-system pilot;
- deployment-specific residual-risk acceptance by a named owner; and
- claims limited to the evidence actually obtained.

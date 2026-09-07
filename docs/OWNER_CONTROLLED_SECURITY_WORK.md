# Security work controlled by the project owner

**Scope:** engineering, documentation, and organizational controls that can be
completed without claiming an independent audit, third-party timestamp, formal
certification, or regulatory approval

## Purpose

This document identifies work the project owner can directly authorize,
implement, test, and document. Completing it creates the evidence package needed
for external review and validation, but it does not create independent evidence
by itself.

The owner controls four areas:

1. archive-catalog engineering;
2. cryptographic-module integration preparation;
3. internal operational controls and drills; and
4. accurate release and security claims.

External activities and evidence are listed separately in
`docs/EXTERNAL_ASSURANCE_REQUIREMENTS.md`.

## 1. Implement authenticated archive history

### Define the catalog policy

The owner can define and document:

- the datasets that receive catalog entries;
- how each dataset receives a stable identifier;
- who may assign generation or snapshot identifiers;
- whether content verification and provenance verification are mandatory
  before accepting an archive;
- which events are valid, such as accepted, superseded, migrated, expired,
  compromised, and deleted;
- which state transitions are irreversible;
- catalog signing-key roles, epochs, rotation, retirement, and revocation;
- how often trusted checkpoints are produced; and
- how long catalogs, checkpoints, public keys, and policies are retained.

The policy must state that a locally supplied timestamp is not trusted time.

### Specify `PQCATALOG01`

Create a separate, bounded, canonical format rather than modifying
`PQBACK02`. At minimum, each entry should bind:

```text
catalog ID and format version
monotonic sequence number
previous entry digest
event type
dataset ID
application generation or snapshot ID
archive SHA-256 and byte length
PQBACK02 envelope length
root-key ID and epoch
archive provenance status
signer-key ID and epoch, when present
prior or replacement generation reference
policy/reason reference
catalog-signing key ID and epoch
signature over the canonical entry
```

Corrections must append a new event. Existing entries must never be edited or
deleted. A dedicated catalog signing key is preferable because archive creation
and history approval are different authorities.

### Implement catalog commands

The owner can add and maintain commands such as:

```text
pqbackup catalog init
pqbackup catalog accept
pqbackup catalog list
pqbackup catalog verify
pqbackup catalog checkpoint
pqbackup catalog reconcile
pqbackup catalog supersede
pqbackup catalog compromise
```

Required behaviors:

- `accept` verifies the archive and every configured policy requirement before
  appending an accepted event;
- every append checks the current sequence and previous digest;
- catalog updates use bounded parsing and atomic no-replace publication;
- `verify` validates the complete chain, signatures, key lifecycle, and a
  supplied trusted checkpoint;
- `reconcile` reports missing, unexpected, modified, stale, superseded, and
  compromised archives without deleting or modifying storage; and
- weaker recording modes are explicitly named and cannot produce a fully
  accepted entry.

### Create checkpoints under owner control

The owner can generate signed checkpoints containing:

- catalog ID;
- last accepted sequence number;
- last-entry digest or Merkle root;
- catalog signing-key ID and epoch;
- checkpoint policy version; and
- a canonical signature.

The owner can place checkpoint copies with organizationally separate internal
custodians, on independent media, and in the recovery kit. This provides a
useful rollback boundary even without an external timestamp authority.

It does not provide independently attested time. It also does not detect
rollback if an attacker can replace every catalog and checkpoint copy.

### Test adversarial catalog behavior

The owner can implement regression, property, and fuzz tests for:

- older valid archive presented as current;
- deleted accepted archive;
- catalog truncation and appended garbage;
- entry mutation, omission, duplication, and reordering;
- sequence reuse or regression;
- previous-digest substitution;
- forked histories;
- stale and substituted checkpoints;
- wrong catalog or archive signing key;
- retired and revoked signing epochs;
- invalid state transitions;
- interrupted writes and destination races;
- concurrent-writer rejection;
- storage reconciliation across multiple directories; and
- parser allocation and length limits.

Add deterministic positive and negative vectors before freezing the catalog
format.

## 2. Prepare for validated cryptography

### Select the exact assurance target

The owner must make a written decision identifying:

- intended users and deployment environment;
- data classification and retention period;
- jurisdiction and applicable contracts;
- whether FIPS 140-3 is actually required;
- whether the requirement is to use a validated module or validate a new
  module;
- required security level and approved mode;
- required operating systems and processor architectures;
- whether ML-KEM and ML-DSA must operate inside the validated boundary; and
- exact permitted product claims.

Terms such as “FIPS compliant,” “government grade,” and “certified” must not be
used without a defined requirement and supporting evidence.

### Produce a cryptographic inventory

Document every cryptographic operation and dependency, including:

- random-number generation and entropy source;
- ML-KEM key generation, encapsulation, and decapsulation;
- ML-DSA key generation, signing, and verification;
- SHA-256, SHA-384, and SHAKE use;
- HMAC and HKDF construction;
- AES-256-GCM encryption, wrapping, and authentication;
- key import, export, storage, zeroization, and destruction;
- startup and conditional self-test needs;
- approved and non-approved modes; and
- every place sensitive security parameters cross a module boundary.

Map each operation to source code, algorithm identifiers, test vectors, and the
proposed module or provider responsible for it.

### Evaluate integration architectures

The owner can prepare two designs for external evaluation:

#### Use an existing validated module

- Search the official CMVP database for active modules.
- Record certificate number, module version, operational environments,
  algorithms, approved mode, caveats, and security-policy requirements.
- Confirm the application will call the validated module without modifying its
  validated boundary.
- Design adapters that prevent accidental fallback to RustCrypto or another
  non-validated implementation in the claimed mode.
- Add a runtime command that reports the selected module, approved-mode status,
  and certificate reference without claiming that `pqbackup` itself is
  validated.

#### Define a new pqbackup cryptographic module

- Move cryptographic services behind a small stable interface.
- Define the software or hybrid module boundary.
- Freeze supported platforms and build inputs.
- Define roles, services, authentication, state transitions, approved mode,
  self-tests, sensitive-parameter handling, and error states.
- Separate CLI and storage orchestration from the proposed module.
- Prepare vendor evidence and a draft module security policy.

The owner can design and prepare either path. Only the external process can
issue algorithm or module validation evidence.

### Investigate the custom two-secret construction

Prepare a precise description of:

```text
IKM  = 32-byte ML-KEM shared secret || 32-byte independent root secret
salt = archive HKDF salt
info = "pqbackup/v2/archive-kek/aes-256-gcm"
KEK  = HKDF-SHA-384(IKM, salt, info, 32 bytes)
```

Document domains, key ownership, secret generation, security rationale,
failure handling, and test vectors. The owner can prepare this evidence, but
must not decide unilaterally that the construction is an approved FIPS service.
That determination requires the chosen validation path and external review.

### Build compliance-friendly controls

The owner can implement:

- explicit approved/non-approved operating modes;
- no-fallback enforcement;
- deterministic reporting of module/provider selection;
- integrity checks for configuration and policy files;
- bounded audit events that exclude plaintext and secret values;
- role separation for archive, catalog, and release signing;
- controlled configuration baselines;
- reproducible builds and dependency manifests;
- documented change-impact analysis; and
- evidence collection for every release gate.

These controls improve readiness but do not constitute certification.

## 3. Complete internal operational controls

The owner or operating organization controls:

- assigning named accountable owners;
- maintaining two independent ML-KEM seed copies;
- maintaining two independent root-key copies or provider instances;
- separating archive, recovery, signing, policy, and checkpoint custody;
- authenticating signer and catalog-policy distribution;
- conducting clean-system restore drills;
- measuring recovery time and recording operator errors;
- retaining release kits, trusted roots, SBOMs, and verification instructions;
- reviewing dependencies and standards on schedule;
- running compromise, loss, corruption, and migration exercises;
- defining incident-response escalation; and
- approving narrowly scoped residual-risk decisions.

These activities may involve multiple people, but they remain under the
organization's direct control. They must use real media, systems, roles, and
procedures rather than only directory simulations.

## 4. Maintain accurate claims

The owner controls all repository and release wording. Until external evidence
exists:

- retain the experimental and unaudited warning;
- do not describe `pqbackup` as FIPS validated;
- do not describe individual algorithms as proof of module validation;
- do not claim trusted time without an external time authority;
- do not claim replay or rollback detection without a verified independent
  checkpoint;
- do not claim production approval based only on internal tests; and
- identify the exact commit, module, operating environment, and policy covered
  by every future assurance statement.

## Owner-controlled deliverables

| Deliverable | Owner can complete independently? | External input eventually required? |
| --- | --- | --- |
| Catalog threat model and policy | Yes | Independent review for assurance |
| `PQCATALOG01` specification and vectors | Yes | Independent review before production reliance |
| Catalog CLI, parser, tests, and fuzzing | Yes | Independent assessment/retest |
| Signed internal checkpoints | Yes | External TSA/witness only for independent time or broader equivocation evidence |
| Cryptographic inventory and boundary design | Yes | Laboratory agreement and validation |
| Existing-module integration | Yes | Valid certificate and vendor/lab interpretation |
| Draft module security policy and evidence | Yes | Accredited laboratory testing and CMVP decision |
| Real internal custody and restore drills | Yes | Independent observer if required by deployment policy |
| Repository warning and claim language | Yes | Legal/compliance approval for regulated claims |

## Recommended execution order

1. Define the intended deployment and assurance target.
2. Freeze the catalog threat model and policy.
3. Specify and implement the local signed catalog and checkpoint format.
4. Add reconciliation, negative tests, vectors, and fuzzing.
5. Complete the cryptographic inventory and two candidate module-boundary
   designs.
6. Run real internal custody and recovery drills.
7. Assemble a versioned evidence package for external reviewers and a
   validation laboratory.
8. Do not change readiness claims until the external evidence in
   `docs/EXTERNAL_ASSURANCE_REQUIREMENTS.md` is complete.

## Internal readiness definition

The owner-controlled work is ready for external handoff when:

- every format and security claim is traceable to code and tests;
- catalog rollback, deletion, fork, and corruption tests pass;
- a trusted internal checkpoint detects a stale valid archive;
- cryptographic operations and sensitive-parameter boundaries are inventoried;
- the candidate module boundary and supported environments are frozen;
- real custody and clean-system recovery evidence exists;
- known limitations and disputed decisions are recorded; and
- the exact candidate commit and dependency lockfile are identified.

Internal readiness is not independent approval, FIPS validation, trusted time,
or compliance certification.

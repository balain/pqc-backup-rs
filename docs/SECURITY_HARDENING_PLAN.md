# Security hardening and YubiKey implementation plan

**Created:** 2026-09-07  
**Baseline reviewed:** package version 0.1.1  
**Status:** Phase 1 engineering complete in 0.1.2; Phases 2–6 planned  
**Constraint:** external review, third-party validation, and certification are not feasible at this time

## Purpose and scope

This plan records the recommendations from the current code review and organizes
them into owner-controlled implementation phases. The priorities are correct
verification, reduced secret exposure, recoverable YubiKey protection, and
authenticated backup history. External validation is not a dependency for doing
this work or completing its internal acceptance criteria.

Completion demonstrates the specific engineering and operational results recorded
here. It does not constitute an independent audit, certification, or proof of
cryptographic security. Retain the existing experimental and unaudited status.

This is a new follow-on plan. Its phase numbers are local to this document; they
do not change the completion records in [the original improvement plan](./IMPROVEMENT_PLAN.md).
Where older plans make external review a readiness gate, preserve that historical
distinction rather than treating internal completion as external approval.

Related documents:

- [Security model](./SECURITY_MODEL.md)
- [Supported limits](./SUPPORTED_LIMITS.md)
- [Format compatibility](./FORMAT_COMPATIBILITY.md)
- [Provenance policy](./PROVENANCE_POLICY.md)
- [Future security options](./FUTURE_SECURITY_OPTIONS.md)
- [Owner-controlled security work](./OWNER_CONTROLLED_SECURITY_WORK.md)
- [Recovery runbook](./RECOVERY_RUNBOOK.md)

## Review baseline and evidence

The review covered `src/main.rs`, security and format documentation, unit tests,
fuzz targets, dependency policy, and the GitHub Actions workflow. The following
checks passed locally during the review:

| Check | Result | Evidence boundary |
| --- | --- | --- |
| `cargo test --locked --offline` | 30 tests passed | Existing regression coverage only |
| `cargo clippy --locked --offline --all-targets --all-features -- -D warnings` | Passed | Static linting, not security verification |
| `cargo build --locked --offline` | Passed | Build emitted an Xcode environment warning |
| `./scripts/run-controlled-pilot.sh target/debug/pqbackup` | All scenarios passed | Separated directories on one host simulate custody |

The review did not run a fresh dependency-advisory scan, extended fuzz campaign,
physical-token experiment, real separated-custody drill, or independent
cryptographic assessment. The findings below are based on source inspection;
the archive-substitution race was not reproduced during this review.

Preserve existing strengths: authenticated chunk ordering and final-frame
semantics, bounded archive parsing, separate recovery secrets, private temporary
outputs, no-overwrite publication, deterministic vectors, and dependency policy.

## Phase order and dependencies

| Phase | Priority | Outcome | Dependencies |
| --- | --- | --- | --- |
| 1 | High | Verification and reported identity apply to the same archive bytes | Existing baseline |
| 2 | High | Bounded key reads, better memory cleanup, safer file lifecycle | Existing baseline; coordinate with Phase 1 storage changes |
| 3 | Medium | Internally testable modules and broader platform/failure coverage | Preserve Phase 1 and 2 behavior |
| 4 | Medium | Optional YubiKey protection with tested alternate recovery | Phase 2 secret handling; Phase 3 test interfaces |
| 5 | Medium | Signed archive history and independent internal checkpoints | Phase 1 verification; Phase 2 durable writes |
| 6 | High operational value | Real recovery evidence and maintained release materials | Applies throughout; final drill includes shipped features |

The default feature order is verification fixes, secret/file handling, YubiKey
protection, then catalog support. Begin recovery drills and testing improvements
earlier. If no suitable physical token is available, defer Phase 4 hardware
acceptance and proceed with the catalog. If rollback or deletion is the dominant
risk, implement Phase 5 before Phase 4.

## Phase 1: Make verification a single, enforceable decision

**Status:** Engineering complete, 2026-09-07, package 0.1.2. Changes are in the
working tree; no implementation commit or published release is asserted here.

Implemented a shared streaming reader that feeds the signature digest and
whole-archive SHA-256 from exactly the parsed bytes. Signature hashing stops at
the envelope boundary and adds the canonical statement; the whole-archive hash
also covers the trailer. Required `open` and `verify` use that same stream for
AEAD authentication and enforce signer policy before success/publication.
Default unsigned recovery and frozen format vectors remain supported.

Internal evidence:

- `cargo test --locked --offline`: 35 tests passed, including five new test
  functions for CLI policy combinations, required restore rejection/cleanup,
  identity/fingerprint/lifecycle enforcement, post-parse path changes, and
  mid-stream replacement/in-place mutation.
- `cargo clippy --locked --offline --all-targets --all-features -- -D warnings`:
  passed.
- `cargo build --locked --offline`: passed; CLI version reports 0.1.2.
- `scripts/run-controlled-pilot.sh target/debug/pqbackup`: passed, including
  signature-required verify/restore and unsigned-required rejection.
- Deterministic signed/unsigned vectors passed unchanged; no dependency or
  archive-format changes were required.

Evidence is local automated testing on the development host. Physical custody,
other platform runs, and external assurance are not claimed by this phase.
Verification identifies consumed bytes; it does not lock the storage path
against subsequent changes. Existing plaintext-temporary-file crash limits
remain for Phase 2.

### 1.1 Bind signature verification and reported hashes to identical bytes

**Observed behavior:** `verify_provenance` calls `scan_archive_layout`,
`feed_provenance_message`, and `sha256_file`, each of which opens the archive
path separately. Replacement or modification between reads can make the printed
SHA-256 identify bytes that were not signature-verified. This does not break
ML-DSA; it breaks the association between verification and the reported object.

**Implementation:**

- Refactor parsing, signature hashing, and archive hashing to consume the same
  byte sequence. Prefer a streaming verifier that computes both digests while
  parsing, or make a bounded, private archive snapshot and operate on that.
- If using a snapshot, stream the copy to disk rather than loading an archive
  into memory. Enforce archive size limits and handle insufficient storage.
- Do not assume that merely opening a file once prevents in-place writes by
  another process. A descriptor prevents path replacement from selecting a new
  inode, but does not make its contents immutable.
- Parse the canonical trailer and reject unsupported trailing bytes before
  returning success. Compute the reported whole-archive hash over the exact
  envelope and trailer accepted by that operation.
- Return a structured verification result, including verified hash, byte length,
  signer identity, signer epoch, and policy decision. CLI output should format
  that result instead of reopening the path.

### 1.2 Add a signature-required restore policy

**Observed behavior:** `open` and `verify` authenticate encrypted contents but
only report that a signature is present. The optional trailer can be removed,
leaving a valid unsigned envelope. This is current format behavior, not an AEAD
failure; operators currently cannot require trusted provenance in one restore.

**Implementation:**

- Add an explicit signature-required mode to `open` and `verify`, with a trusted
  signer public key and signer policy. Proposed flag names are
  `--require-provenance`, `--signer-public-key`, and `--signer-policy`; finalize
  them against existing CLI conventions before implementation.
- Require both complete content authentication and an acceptable signature
  before publishing plaintext or reporting combined verification success.
- Reject missing, stripped, malformed, invalid, revoked, or untrusted signatures
  in this mode. Retired signers require the existing explicit historical policy.
- Reject incomplete policy arguments. Clearly distinguish content authentication
  from signer authentication in all output and help text.
- Use the same bytes for content and provenance verification. Running the two
  current commands sequentially against a mutable path is not sufficient.
- Preserve valid unsigned archives and existing optional behavior when the new
  policy is not requested. Do not change frozen archive bytes or KDF semantics.

### Tests and acceptance criteria

- Add deterministic tests that substitute a path between verification stages and
  mutate the input during processing. Use synchronization hooks rather than
  timing-dependent sleeps.
- Demonstrate that a successful reported hash always identifies accepted bytes.
- Test valid signatures, stripped trailers, altered signatures, wrong public
  keys, fingerprint mismatch, revoked signers, and explicit retired acceptance.
- Assert that every policy failure leaves no published plaintext destination.
- All existing signed and unsigned vectors and recovery tests remain valid.

**Deliverables:** shared verification API, CLI policy support, regression tests,
and updated provenance policy and command documentation.

## Phase 2: Harden secrets, file reads, and publication

### 2.1 Reduce unprotected copies in memory

**Observed behavior:** `encode_root_key` and `encode_signing_secret` return
ordinary vectors containing secrets. Their callers do not zeroize those encoded
copies. The sealing plaintext chunk buffer is also an ordinary vector.

**Implementation:**

- Return or immediately wrap secret serialization buffers in `Zeroizing`.
- Use zeroizing plaintext buffers during sealing and review the decrypted
  filename, buffered I/O, temporary arrays, and error paths for sensitive copies.
- Inventory ownership and drop behavior for ML-KEM seeds/shared secrets, root
  secrets, signing seeds, DEKs, KEKs, and KDF state. Check dependency behavior
  rather than assuming a feature flag covers every exported value or copy.
- Scope secrets to the shortest practical operation. Avoid unnecessary clones
  and prevent secrets, PINs, and plaintext from entering debug output or errors.
- Assess platform-supported core-dump suppression and memory locking as optional
  defense in depth. Document failures and limits; do not claim complete protection
  from swap, kernel access, or a compromised process.

### 2.2 Bound and validate key-file input

**Observed behavior:** fixed-size readers and the file root provider use
`fs::read` before checking the size. Inventory and policy readers inspect path
metadata and then reopen the path. New secrets receive mode `0600`, but imported
or existing secrets are not checked for ownership or permissive access.

**Implementation:**

- Open once and obtain metadata from the descriptor. Require regular files for
  key, policy, and inventory inputs under the supported local-file model.
- Read fixed-size keys with an expected-size-plus-one limit and reject both
  truncation and extra bytes. Apply maximum-plus-one limits to policy/inventory
  text reads even if metadata reports an acceptable length.
- Define a strict secret-file permission policy for supported Unix systems,
  including ownership, group/other access, and relevant ACL limitations.
- Decide and document symlink handling. Provide explicit compatibility handling
  for intentional custody layouts rather than silently following unsafe paths.
- Validate or clearly require trusted parent directories. Permission checks
  alone do not defend against a directory that an attacker can replace.

### 2.3 Handle crashes and partial file creation

**Observed behavior:** normal error paths remove temporary restore files, but
process termination or power loss can leave plaintext remnants. Publication
syncs file contents but does not sync parent directory entries. Key generation
can also leave partial files or an incomplete public/secret pair after failure.

**Implementation:**

- Preserve no-overwrite publication and synchronize parent directories after
  relevant link, rename, creation, and removal operations on supported systems.
- Specify results for failure after publication: an output may exist even when
  final cleanup or durability confirmation fails. Errors must describe this
  state without encouraging a destructive retry.
- Use private staging and best-effort rollback for newly created key files.
  Publish a complete usable pair or clearly identify incomplete generation;
  never remove or overwrite pre-existing files during cleanup.
- Document plaintext temporary-file behavior and recommend an encrypted local
  restore volume. Add a cautious inspection/cleanup procedure for abandoned
  files that checks ownership, type, location, and active-operation state.
- Never automatically delete arbitrary files merely because their names match
  a temporary-file prefix. Do not claim secure erasure on SSDs or snapshots.

### Tests and acceptance criteria

- Oversized, truncated, non-regular, and disallowed-permission inputs fail with
  bounded reads and actionable errors.
- Add injected failures for writes, flushes, synchronization, publication, and
  cleanup; test destination collisions and key-pair partial failure.
- Use subprocess termination tests to establish actual remnant behavior.
- Review secret ownership explicitly; a passing functional test does not prove
  that all compiler or library copies have been erased.
- Existing archive formats, no-overwrite guarantees, and vectors remain intact.

**Deliverables:** hardened I/O helpers, secret-lifetime inventory, failure tests,
and updated supported-filesystem and recovery guidance.

## Phase 3: Improve internal testability and regression evidence

### Implementation

- Split the 4,085-line reviewed `src/main.rs` into focused modules for archive
  format/parsing, cryptographic operations, key providers, filesystem handling,
  provenance/policy, and CLI orchestration.
- Establish a library boundary for tests and fuzz targets. Replace fuzz targets
  that include the entire CLI source with direct calls to narrow library APIs.
- Keep mechanical refactoring separate from cryptographic or format changes.
  Preserve known-answer vectors before and after each extraction.
- Extend fuzzing beyond individual decoders and frame traversal to bounded
  complete archive processing and combined provenance/content verification.
  Use disposable deterministic test keys and strict resource limits.
- Include valid seeds so fuzzing reaches meaningful authenticated paths. Add
  structured tests that generate valid archives and then mutate boundaries,
  lengths, ordering, final flags, trailers, and policy transitions.
- Retain fast pull-request fuzz smoke checks; run longer scheduled campaigns
  with retained corpora and reproducible crash artifacts. Set budgets based on
  available internal infrastructure and record actual duration and coverage.
- Run functional recovery tests on Linux x86-64, Intel macOS, and Apple-silicon
  macOS, matching the released binaries. Release builds alone do not exercise
  platform-specific permissions, publication, and cleanup behavior.
- Retain locked dependencies, advisory policy, pinned workflow actions, release
  attestations, and offline rebuild materials already present in the project.

### Tests and acceptance criteria

- All existing deterministic vectors remain byte-identical.
- Fuzz crashes are reproducible and become regression tests when actionable.
- Full verification and file-failure paths have direct coverage through public
  library interfaces rather than source inclusion.
- Record the actual operating system, architecture, filesystem, toolchain, and
  command for each platform result; mark unavailable environments as pending.

**Deliverables:** module extraction, library API, expanded fuzz/property tests,
platform CI coverage, and updated [fuzzing documentation](./FUZZING.md).

## Phase 4: Add recoverable YubiKey protection for root keys

### Design decision and security boundary

Start with a YubiKey-unlocked encrypted root-key container. Preserve the random
32-byte archive root secret and the exact existing `PQBACK02` derivation:

```text
IKM  = ML-KEM shared secret || root secret
KEK  = HKDF-SHA-384(IKM, archive salt,
                  "pqbackup/v2/archive-kek/aes-256-gcm", 32 bytes)
```

Use native FIDO2 `hmac-secret` through a maintained library to obtain
credential-specific material. Derive a purpose-bound wrapping key with HKDF
and use authenticated encryption to protect the existing root secret. The
container is a new, separately versioned storage format; it is not a change to
the archive format or an in-place reinterpretation of `PQROOT02`.

The token's credential secret remains in hardware, but its derived output and
the unlocked archive root enter host memory. This reduces stored-secret theft
and requires device participation. It does not make the archive root
non-exportable during use or protect plaintext from malware on the host.

The existing `RootSecretProvider` can be implemented by a provider that unlocks
this container and performs the unchanged v2 derivation locally. Name and
document this as a wrapped-root provider, not a hardware-only derivation service.
The non-exportable design in [future options](./FUTURE_SECURITY_OPTIONS.md)
remains a separate objective. Documented YubiKey PIV RSA/ECC operations are not a
direct implementation of the required concatenation and HKDF construction.

### Container specification

Before implementation, define canonical encoding and limits for:

- Magic/version and explicit algorithm identifiers.
- Root ID and epoch, bound to the encrypted payload.
- A bounded list of recipient slots, each with credential ID, relying-party
  identifier, salt/derivation inputs, nonce, and encrypted root payload.
- Authenticated context binding version, root metadata, recipient identity, and
  algorithm parameters. Reject ambiguity, unknown mandatory fields, oversized
  values, and unsupported algorithms before expensive work.
- Fresh nonces and precise domain separation for the native FIDO operation and
  root-wrapping KDF. Do not reuse archive KDF domains for container encryption.

No field layout or new magic value in this plan is a frozen specification.
Create positive/negative vectors and format documentation before freezing it.

### Enrollment and runtime behavior

- Probe the actual token model and firmware for `hmac-secret` and required PIN
  verification capabilities. Do not assume all devices sold as YubiKeys qualify.
- Require PIN verification and user presence for the intended operations. Check
  actual library/protocol behavior; a host-side prompt alone is not enforcement.
- Obtain PINs interactively without echo. Never use command-line arguments,
  environment variables, logs, or persistent configuration to carry PINs.
- Enroll at least two independent devices, each wrapping the same random root
  under its own derived wrapping key. Their credentials and derived outputs
  differ; registering the same account on a spare does not clone recovery.
- Preserve all necessary credential metadata and container copies in recovery
  materials. Do not depend on a live website or network service during restore.
- Fail closed for absent devices, unsupported features, cancellation, wrong
  PINs, lockout, tampered containers, or failed authentication. Avoid automated
  PIN retries that can lock the token.
- Do not silently fall back to a plaintext root file. Any emergency alternative
  must be an explicitly selected, documented recovery procedure.

### Migration, loss, and recovery

- Import an existing root into a new container without overwriting the source.
  Keep root bytes, ID, and epoch unchanged so existing archives remain usable.
- Verify unlocking and an actual archive restore independently with each token
  before retiring any plaintext root copy under the custody procedure.
- Keep ML-KEM seed custody separate from tokens, containers, and root recovery
  copies. Hardware protection does not replace the two-secret separation model.
- Add a replacement token while a working token or controlled recovery copy is
  available. Loss of every unlock path means loss of dependent archives.
- Removing a recipient slot does not revoke older copied containers. After
  suspected root exposure, generate a new root epoch and migrate archives that
  require renewed protection; do not promise revocation of stolen ciphertext.
- Define whether a separately protected offline emergency root copy is retained.
  Record the recovery benefit and its remaining extraction risk explicitly.

### Tests and acceptance criteria

- Mock tests cover wrong devices, cancellation, timeouts, unsupported firmware,
  PIN errors, tampering, recipient substitution, unknown algorithms, interrupted
  enrollment, and cleanup. Mocks do not count as hardware validation.
- Run real enrollment and offline restore tests with both physical devices on
  each claimed platform, including unplug/replug and replacement enrollment.
- Confirm PIN and presence requirements, no fallback, and absence of secrets
  in stdout, stderr, logs, and persisted configuration.
- Restore pre-existing archives with the wrapped original root; vectors and
  archive bytes remain unchanged.
- Keep hardware acceptance pending until physical tests are completed. No
  external assessor is required for these owner-run tests.

**Deliverables:** container specification, wrapped-root provider, enrollment and
recovery commands, device compatibility matrix, tests, and updated custody guide.

### Design references

Official Yubico documentation consulted during the review:

- [Native CTAP2 hmac-secret guidance](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html)
- [PRF derivation and multi-device envelope guidance](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html)
- [YubiKey PIV capabilities](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html)

Recheck device and library capabilities when implementation begins. These
references inform the design; they do not validate pqbackup's integration.

## Phase 5: Add authenticated backup history and checkpoints

### Objective and trust boundary

An individually valid archive does not establish that it is the newest accepted
backup or that another backup was deleted. Implement a local signed append-only
journal, following the existing catalog design discussion. A transparency service
or third-party timestamp authority is not required for this first version.

Keep a trusted checkpoint separately from the active catalog and archive store.
It anchors an internally accepted sequence and digest. If every checkpoint can
also be rolled back, the catalog cannot establish freshness. Local timestamps
remain operator assertions, not independently trusted time.

### Implementation

- Define stable dataset IDs, application generation IDs, retention rules, signer
  roles, and allowed lifecycle transitions before freezing the catalog format.
- Start with a single-writer signed hash chain. Each bounded canonical entry
  binds catalog ID, sequence, previous digest, event type, dataset/generation,
  archive digest and length, root ID/epoch, verified provenance result, and any
  superseded or migrated generation reference.
- Use a dedicated catalog signing key and explicitly trusted policy. An archive
  creator need not automatically have authority to approve backup history.
- Require Phase 1 combined verification before recording a fully accepted
  archive when provenance is mandated. Bind the entry to the verifier's result,
  not a later reread of a mutable archive path.
- Serialize writers and reject stale updates. Use atomic durable publication;
  corrections append new events rather than editing accepted history.
- Generate signed checkpoints containing catalog ID, accepted sequence, chain
  digest, signer identity/epoch, and policy version. Retain copies on separate
  internal media or with separate internal custodians.
- Add read-only reconciliation for missing, unexpected, modified, superseded,
  and stale archives. Never make detection automatically delete backup data.
- Define signing-key rotation and compromise behavior, checkpoint trust
  distribution, and recovery of the catalog itself.

### Tests and acceptance criteria

- Detect rollback behind a supplied trusted checkpoint, deleted accepted
  archives, truncation, mutation, reordered entries, duplicate sequences, and
  conflicting histories relative to known state.
- Reject substituted checkpoints, wrong keys, invalid signatures, disallowed
  lifecycle transitions, and concurrent stale writes.
- Explicitly test the limitation that a valid but stale checkpoint cannot prove
  knowledge of later events that the verifier has never received.
- Recover and reconcile on an offline clean system using separately held
  checkpoint and trust material.

**Deliverables:** catalog policy/specification, canonical vectors, commands,
fuzz/regression tests, and checkpoint custody/recovery instructions.

## Phase 6: Establish real recovery and release evidence

### Work

- Perform an owner-run drill on a separate clean recovery system using real
  custody media. Keep directory simulation as CI coverage, not as evidence of
  independent custody or hardware recovery.
- Exercise each ML-KEM seed copy and each root recovery path separately. After
  Phase 4 ships, include both tokens and a lost-primary-token scenario.
- Restore representative empty, small, multi-chunk, and large archives, including
  historical root epochs and retired signers under explicit policy.
- Validate application-level contents after cryptographic verification. Archive
  integrity does not establish that a live application's source data was a
  consistent snapshot; document quiescing or snapshot requirements for sealing.
- Exercise corrupted copies, missing secrets, lockout, compromised signing keys,
  stale catalogs, and interrupted restores. Record failures and recovery steps.
- Preserve source, lockfile, vendored dependencies, compatible binaries, format
  specifications, vectors, release provenance, and verification instructions.
  Add token libraries and credential/container metadata needed for offline use.
- Record recovery duration, required equipment, operator errors, and whether
  each separately held copy was actually usable. Do not include secret values.
- Assign an owner for periodic restores, media refresh, dependency monitoring,
  and incident-driven key migration. Follow or tighten the existing annual
  restore-drill policy based on the deployment's needs.

### Acceptance criteria

- A separate system restores and validates application contents using each
  intended alternate recovery path without fetching missing dependencies.
- Recovery evidence identifies the commit/release, platform, tested artifacts,
  custody paths, date, operator, elapsed time, and unresolved limitations.
- Documentation accurately distinguishes implemented features, simulated tests,
  physical tests, and deferred external assurance.
- A named owner accepts remaining operational risks for the intended use; no
  claim of audit, certification, or independent validation is introduced.

**Deliverables:** completed internal drill record, updated recovery kit/runbook,
release checklist, and deployment-specific residual-risk record.

## Completion tracking

For each phase, record the implementation commit, test commands/results,
remaining limitations, and responsible owner. Use these states consistently:

| State | Meaning |
| --- | --- |
| Planned | Work is specified but not implemented |
| Engineering complete | Code, documentation, and applicable automated tests pass |
| Operationally tested | Required physical-device or real-custody tests pass |
| Deferred | Work cannot currently proceed; reason and recovery path are recorded |

Phase 1 is **Engineering complete** in 0.1.2, with evidence above. Phases 2–6
remain **Planned**. Bump the package patch version once for each subsequently
completed implementation phase, updating Cargo.toml, Cargo.lock, and changelog
together. External assurance remains deferred and is tracked separately from
the owner-controlled acceptance criteria above.

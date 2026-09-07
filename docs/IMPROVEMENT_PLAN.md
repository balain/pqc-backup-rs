# pqbackup improvement plan

**Created:** 2026-09-05  
**Basis:** [Long-term security assessment](./LONG_TERM_SECURITY_ASSESSMENT.md)  
**Current format:** `PQBACK02` archives and `PQROOT02` root keys

**Phase status:** Phases 0, 1, and 2 completed on 2026-09-06. Phase 3 engineering completed on 2026-09-06; its operator recovery-drill gate remains pending. Phase 4 engineering completed on 2026-09-06; signed-tag, two-person verification, separate-copy, and scheduled-owner gates remain pending. Phase 5 engineering completed on 2026-09-06. Phase 6 engineering preparation and simulated pilot completed on 2026-09-06; independent review, real separated-custody pilot, and named risk acceptance remain pending.

## Objective

Move `pqbackup` from a promising reference implementation to a reviewable, testable archival tool with explicit security limits, reproducible recovery materials, and an evidence-based production-readiness decision.

This plan does not assume that completing engineering work alone makes the package suitable for regulated or irreplaceable data. Independent review and operational validation are release gates.

## Guiding principles

- Preserve decryptability of existing `PQBACK02` archives unless a documented migration explicitly supersedes the format.
- Treat key custody and future recovery as product requirements, not deployment notes.
- Keep cryptographic constructions small, deterministic to parse, and independently testable.
- Make every security limit machine-enforced where practical.
- Do not claim audit, validation, certification, or production readiness without supporting evidence.
- Maintain independent verified backups throughout development and migration.

## Priority summary

| Priority | Work | Main risk addressed |
| --- | --- | --- |
| P0 | Scope, safety limits, format specification | Undocumented assumptions and unsafe use |
| P0 | Comprehensive tests and parser fuzzing | Custom-format and malformed-input risk |
| P1 | Secret and key-custody hardening | Endpoint and recovery-secret exposure |
| P1 | Reproducible releases and recovery kits | Multi-decade recoverability |
| P1 | Independent security review | Unknown design and implementation defects |
| P2 | Optional signed provenance | Missing creator identity and rollback evidence |
| P2 | Hardware-backed key support | Exportable root-key exposure |

Effort labels in this document are relative planning sizes, not calendar commitments: **S** is a focused change, **M** is a multi-part feature, and **L** is a substantial project or external engagement.

## Phase 0 — Establish safety boundaries

**Status: Completed (2026-09-05).** Evidence is recorded in
[`SECURITY_MODEL.md`](./SECURITY_MODEL.md),
[`SUPPORTED_LIMITS.md`](./SUPPORTED_LIMITS.md),
[`RISK_REGISTER.md`](./RISK_REGISTER.md), the CLI help, README, and changelog.

**Goal:** prevent the prototype from being mistaken for an audited production system and resolve the decisions that affect later design.

### Work

- Add a prominent maturity statement to CLI help, README, release notes, and generated documentation.
- Define supported operating systems, filesystems, maximum input size, and expected retention periods.
- Decide whether the legacy combined `keygen` command will be removed, hidden behind an explicit unsafe flag, or retained only for demos.
- Define the intended root-key epoch policy: annual, quarterly, event-driven, or deployment-defined.
- Decide whether sender identity/provenance is in scope. Do not add signatures without a key-distribution and revocation model.
- Create a risk register that tracks every finding in the assessment, its owner, mitigation, and evidence.
- Document that `inspect` reads unauthenticated routing metadata until recovery keys validate the archive.

### Deliverables

- `docs/SECURITY_MODEL.md`: assets, adversaries, trust boundaries, exclusions, and misuse cases.
- `docs/SUPPORTED_LIMITS.md`: enforced and operational limits.
- `docs/RISK_REGISTER.md`: assessment findings mapped to planned controls.
- Updated CLI warnings and removal/deprecation decision for combined key generation.

### Exit criteria

- Every assessment finding has an owner and disposition.
- Unsupported use cases are plainly stated.
- Archive and chunk-count limits have approved target values ready for implementation.
- Signature/provenance scope is explicitly accepted or deferred.

**Estimated effort:** S–M.

## Phase 1 — Specify and lock down the formats

**Status: Completed (2026-09-06).** The archive/root-key specifications,
compatibility policy, error categories, and deterministic positive/negative
vectors are versioned in `docs/` and `test-vectors/`.

**Goal:** make independent recovery and compatible reimplementation possible without reading the Rust source.

### Work

- Write a byte-level `PQBACK02` specification covering:
  - endianness and exact field order;
  - field lengths, algorithms, and domain-separation strings;
  - filename encoding and validation;
  - AAD construction for metadata, DEK wrapping, and chunks;
  - nonce construction and uniqueness requirements;
  - empty-file behavior and final-chunk semantics;
  - maximum values and rejection behavior;
  - root-key ID/epoch semantics;
  - temporary-output and overwrite behavior.
- Write a byte-level `PQROOT02` key-file specification.
- Define canonical error categories without exposing secret-dependent detail.
- Generate deterministic test vectors using fixed test-only randomness.
- Store expected header bytes, ciphertext, restored plaintext hashes, and negative vectors.
- Document compatibility policy: v2 decoding stability, future version dispatch, and migration expectations.

### Deliverables

- `docs/PQBACK02_FORMAT.md`.
- `docs/PQROOT02_FORMAT.md`.
- `test-vectors/` containing positive and negative vectors with provenance.
- A format-version compatibility policy.

### Exit criteria

- A developer unfamiliar with the code can parse the header and reproduce every AAD input from the specification.
- Tests fail if any format byte or domain separator changes unintentionally.
- Vectors cover empty, one-chunk, multi-chunk, maximum filename, Unicode filename, and corrupted archive cases.
- Existing v2 archives remain readable or a migration tool and explicit breaking-version decision are provided.

**Estimated effort:** M.

## Phase 2 — Harden parsing, limits, and cryptographic usage

**Status: Completed (2026-09-06).** The implementation now enforces 1 TiB and
2^20-frame ceilings, bounds parser allocations, uses checked arithmetic and
private atomic temporary files, performs single-pass recovery, and builds
without warnings. Tests cover boundary, end-to-end, corruption, truncation,
wrong-key, path, collision, permission, and simulated storage-failure cases.
Three production-parser fuzz targets and CI smoke campaigns are in `fuzz/` and
`.github/workflows/rust.yml`; local 1,000-run AddressSanitizer smoke campaigns
completed without crashes on 2026-09-06.

**Goal:** make hostile archive processing predictable and enforce the format’s security bounds.

### Work

- Enforce a conservative maximum archive size and maximum number of AES-GCM invocations per DEK.
- Validate declared plaintext length against chunk size and expected maximum chunk count before large allocations or writes.
- Add checked arithmetic to every field-length, frame-length, and total-length calculation.
- Cap all allocations derived from archive-controlled values.
- Review error paths so authentication failures never leave completed plaintext output.
- Ensure temporary files use restrictive permissions and are cleaned up on every failure path.
- Validate restored filenames as single UTF-8 path components on supported macOS/Linux hosts; reject NUL, separators, dot/parent components, and path traversal. Preserve Unicode bytes without normalization so frozen v2 names do not silently change.
- Review the two-pass filename/open flow for unnecessary secret operations and consistent failure behavior.
- Replace deprecated nonce-construction APIs and eliminate compiler warnings.
- Document and test that nonce values cannot repeat under one DEK.
- Review all secret-bearing values for copies and lifetime; expand `Zeroizing` coverage where APIs permit.

### Testing

- End-to-end tests for seal, inspect, verify, open, empty files, and multiple chunk sizes.
- Mutation tests for every header field and frame field.
- Truncation tests at every structural boundary.
- Wrong ML-KEM seed, wrong root secret, wrong ID, and wrong epoch tests.
- Output collision, permissions, interrupted write, disk-full simulation, and input-changing-during-seal tests.
- `cargo-fuzz` targets for header decode, root-key decode, and frame traversal.
- Property tests for encode/decode agreement and chunk ordering.
- Sanitizer/Miri runs where dependencies and supported targets allow them.

### Deliverables

- Enforced limits in code and documentation.
- Integration, corruption, property, and fuzz test suites.
- CI jobs for tests, formatting, linting, and fuzz smoke runs.
- Zero-warning supported builds.

### Exit criteria

- Malformed input cannot trigger unbounded allocation, panic, path escape, or completed partial restore in the tested corpus.
- Each documented limit has a boundary test.
- The fuzz suite completes its agreed campaign without crashes or hangs.
- The project builds cleanly with warnings treated as errors.

**Estimated effort:** L.

## Phase 3 — Improve key lifecycle and custody

**Status: Engineering completed; operational validation pending (2026-09-06).**
The CLI now provides typed key validation, ML-KEM public fingerprints, a
secret-free `PQINVENTORY01` custody inventory, lifecycle status changes,
archive-to-custody lookup, and optional root ID/epoch assertions during seal.
Secret files receive restrictive permissions at creation, and archive
cryptography uses a provider boundary capable of future non-exportable
backends. [`KEY_MANAGEMENT.md`](./KEY_MANAGEMENT.md) defines provisioning,
rotation, retirement, compromise, destruction, migration, and recovery drills.
Completion still requires operators to exercise two genuinely independent
custody copies in their deployment environment.

**Goal:** reduce the chance that key handling defeats the two-secret design.

### Work

- Remove or clearly quarantine combined key generation from production workflows.
- Add a root-key inventory format that maps stable IDs and epochs to custody locations without storing secret bytes.
- Add commands to display key metadata, validate a key file, and report which root ID/epoch an archive requests.
- Define rotation, retirement, compromise, destruction, and archive-migration procedures.
- Add optional confirmation that sealing uses the intended root ID/epoch.
- Ensure secret files are created with restrictive permissions on every supported platform.
- Evaluate memory locking and crash-dump suppression, documenting platform limitations.
- Design a provider interface for root secrets so raw files are not the only backend.
- Evaluate OS keystores, smartcards, HSMs, or external secret brokers based on the intended deployment environment.
- Keep the ML-KEM seed and root secret independently backed up and test both recovery paths.

### Deliverables

- `docs/KEY_MANAGEMENT.md`.
- Key inventory and validation commands.
- Root-secret provider interface.
- At least one hardened custody workflow with a tested recovery runbook.

### Exit criteria

- Production documentation never instructs users to co-locate the two secret classes.
- A lost, retired, or compromised epoch has a documented response.
- Operators can identify the required key without exposing its secret bytes.
- Two independent recovery copies have been exercised in a clean-room restore drill.

**Estimated effort:** M–L.

## Phase 4 — Build a durable release and recovery process

**Engineering status:** Completed on 2026-09-06. The repository now pins build
inputs, checks dependency advisories/licenses/sources, builds and compares each
supported native binary twice, emits an SBOM and manifests, publishes attested
multi-platform assets, and validates a vendored source tree with Cargo offline.
The recovery and release runbooks define drills and preservation schedules.
Operational exit criteria require approved tag-signing credentials, two human
verifiers, controlled recovery-kit copies, and named schedule owners; those
cannot be satisfied by repository changes alone and remain pending.

**Goal:** ensure an archive can still be restored when today’s development environment is gone.

### Work

- Pin the Rust toolchain and retain `Cargo.lock`.
- Add dependency license, vulnerability, and source-integrity checks.
- Produce reproducible or independently verifiable release builds.
- Sign source tags, release manifests, binaries, format documents, and test-vector manifests.
- Generate checksums and software bills of materials.
- Build release artifacts for every supported platform.
- Create a recovery kit containing:
  - source archive;
  - lockfile and toolchain information;
  - format specifications;
  - known-good binaries;
  - positive and negative test vectors;
  - plaintext hashes for non-sensitive test content;
  - offline restore instructions;
  - release signatures and verification instructions.
- Test restoration in a clean environment without network access.
- Define periodic media-refresh, bit-rot checking, and cryptographic-migration schedules.

### Deliverables

- Automated release pipeline.
- Versioned, signed recovery-kit artifact.
- `docs/RECOVERY_RUNBOOK.md`.
- `docs/RELEASE_PROCESS.md`.

### Exit criteria

- Two people can independently reproduce or verify a release.
- A clean offline system can validate the tool and restore the known-good test archive.
- Recovery-kit copies exist in separate controlled locations.
- Scheduled restore drills and archive migration reviews have named owners.

**Estimated effort:** L.

## Phase 5 — Add provenance only if required

**Engineering status: Completed (2026-09-06).** `PQSIG001` uses ML-DSA-87
to sign the exact frozen `PQBACK02` envelope plus canonical signer metadata.
Separate key generation, signing, verification, and `PQSIGNERS01` policy
commands implement trusted/retired/revoked lifecycle behavior. Specifications,
operator policy, migration guidance, parser fuzz targets, and substitution,
replay, mutation, wrong-key, retired, revoked, truncation, and extra-data tests
are included. A valid replay intentionally remains valid; trusted time and
rollback selection require an external authenticated catalog. Independent
reviewer approval is not an engineering deliverable and remains pending.

**Goal:** provide creator authentication and substitution evidence, plus an
explicit foundation for external rollback controls, without confusing any of
them with encryption integrity.

This phase is conditional. Skip it if the product only needs confidentiality and holder-authenticated integrity.

### Work

- Define who or what signs archives and how verification keys become trusted.
- Select a reviewed signature construction and parameter set appropriate to the retention period.
- Specify a canonical signed representation covering the complete encrypted envelope and relevant policy metadata.
- Define signing-key ID, epoch, rotation, revocation, compromise, and historical verification behavior.
- Decide whether a trusted timestamp or external append-only catalog is needed.
- Treat signatures as a new format version or rigorously specified compatible extension.
- Add substitution, replay, rollback, revoked-key, and wrong-signer tests.

### Deliverables

- Provenance threat model and key policy.
- Signed-envelope specification.
- Verification command and negative test vectors.
- Migration plan for unsigned archives.

### Exit criteria

- Verification answers “who created this archive under which trusted key policy,” not merely “someone with decryption capability created it.”
- Revoked and historical keys have explicit behavior.
- Independent reviewers approve the canonicalization and signing scope.

**Estimated effort:** L.

## Phase 6 — Independent review and controlled pilot

**Engineering status: Prepared; external gates pending (2026-09-06).** The
candidate now includes an independent-review brief, durable remediation
register, clean offline-rebuild and controlled-pilot automation, pilot evidence
procedure, deployment risk-acceptance template, and an explicit NO-GO
production-readiness statement. Maintainer pre-review findings have regression
coverage. No external review or real independent-custody drill has occurred;
Phase 6 is therefore not complete.

**Goal:** obtain external evidence and validate the complete technical and operational system.

### Work

- Freeze the candidate format and implementation before review.
- Commission independent review covering cryptographic composition, Rust safety, parser robustness, side channels within scope, key management, and recovery operations.
- Resolve findings with regression tests and written dispositions.
- Run a controlled pilot using non-critical data and realistic separated media.
- Test archive theft, corrupted media, lost key copy, wrong epoch, compromised key, software rebuild, and offline restore scenarios.
- Measure operational errors, recovery time, and documentation gaps.
- Make an explicit go/no-go decision for each proposed deployment class.

### Deliverables

- External review report and remediation record.
- Pilot report and restore-drill evidence.
- Deployment-specific residual-risk acceptance.
- Final production-readiness statement with narrowly defined scope.

### Exit criteria

- No unresolved critical or high-severity review finding.
- All review fixes have regression coverage.
- Pilot restores succeed from independent custody copies and a clean recovery environment.
- A named owner accepts residual risks for the exact intended use.
- Marketing and documentation claims match the evidence.

**Estimated effort:** L plus external review time.

## Cross-phase release gates

The following gates apply regardless of phase completion:

### Experimental release

- Current status.
- Allowed for demonstrations, testing, and non-authoritative defense-in-depth copies.
- Must carry the prototype warning.

### Limited pilot release

Requires Phases 0–4, continuous tests, recovery-kit validation, and no known critical defects. Data must remain independently recoverable outside `pqbackup`.

### Production consideration

Requires Phase 6, resolution of material findings, tested key custody, documented restore drills, and deployment-specific risk acceptance. Phase 5 is additionally required when provenance or sender identity matters.

### Regulated or high-assurance use

Requires separate compliance analysis and, where applicable, validated cryptographic modules and approved operational controls. This plan alone cannot establish compliance.

## Suggested implementation order

1. Complete Phase 0 decisions.
2. Develop Phase 1 specifications and vectors before further format changes.
3. Implement Phase 2 limits/tests against those specifications.
4. Build Phase 3 key workflows in parallel once root-key semantics are fixed.
5. Establish Phase 4 releases before asking external reviewers to assess a candidate.
6. Complete Phase 5 only if provenance is an accepted requirement.
7. Freeze, review, remediate, and pilot in Phase 6.

## Plan completion definition

The improvement program is complete only when:

- format behavior and limits are independently understandable;
- hostile-input testing supports parser safety claims;
- key custody and rotation are operationally tested;
- releases and recovery kits are reproducible or independently verifiable;
- a clean offline restore succeeds from preserved materials;
- independent review findings are resolved or formally accepted;
- deployment claims are limited to the evidence obtained;
- migration and periodic restore schedules are active.

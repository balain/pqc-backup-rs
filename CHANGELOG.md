# Changelog

All notable security-relevant and user-visible changes are recorded here.

## Unreleased

## 0.1.2 - 2026-09-07

### Security hardening plan — Phase 1

- Bound provenance parsing, signature verification, and the reported SHA-256/byte length to one consumed archive stream, eliminating separate path reads for verification and reporting.
- Added `--require-provenance`, `--signer-public-key`, and `--signer-policy` to `open` and `verify`; required restore publishes plaintext only after content authentication and trusted signer verification both succeed.
- Reject incomplete policy arguments and missing, stripped, invalid, untrusted, and revoked signatures in required mode; historical retired signers require explicit `--allow-retired`.
- Added deterministic path-replacement/in-place-mutation tests and required-policy failure/cleanup coverage.
- Preserved default unsigned recovery and all frozen archive, signature, and KDF encodings.

## 0.0.6 - 2026-09-06

### Phase 6 review candidate and controlled pilot

- Added an independent-review package, finding/remediation register, controlled-pilot evidence procedure, residual-risk template, and explicit production-readiness decision.
- Added a disposable controlled-pilot gate covering encrypted filename inspection, clean recovery, archive theft, corruption, lost secret copies, wrong epochs, revoked signers, and signer substitution.
- Added a clean locked offline rebuild before the controlled pilot in CI.
- Made root-key and signer lifecycle transitions monotonic so compromised, destroyed, or revoked epochs cannot regain authority.
- Added regression coverage for irreversible lifecycle transitions and malformed ML-KEM public-key rejection.
- Preserved a NO-GO decision for production until an independent review, real separated-custody drill, and named deployment owner acceptance are complete.

## 0.0.5 - 2026-09-06

### Phase 5 archive provenance

- Added separate ML-DSA-87 signing seed/public-key generation with stable signer IDs and rotation epochs.
- Added a rigorously specified `PQSIG001` trailer that signs every byte of the frozen `PQBACK02` encrypted envelope plus canonical signer metadata.
- Added a bounded `PQSIGNERS01` trust policy that binds IDs, epochs, identities, lifecycle states, and public-key fingerprints.
- Added separate `sign` and `provenance-verify` commands so signing authority does not need recovery keys or plaintext.
- Rejects unsigned, modified, substituted, nested, truncated, retired-by-default, revoked, wrong-key, and policy-mismatch verification cases.
- Expanded demo mode, key inspection, documentation, tests, and fuzz targets for provenance.
- Documented that signatures provide creator authentication but not trusted time, deletion detection, replay prevention, or newest-backup selection.

## 0.0.4 - 2026-09-06

### Phase 4 durable releases and recovery

- Pinned Rust 1.97.1, the fuzzing nightly/tool, dependency-policy tool, SBOM generator, and every GitHub Action revision.
- Added continuous advisory, license, dependency-policy, wildcard, and dependency-source checks.
- Added clean same-host reproducibility checks and native release binaries for Linux x86-64, Intel macOS, and Apple-silicon macOS.
- Added CycloneDX SBOMs, SHA-256 manifests, GitHub/Sigstore build-provenance attestations, and offline trusted-root preservation.
- Added a versioned recovery kit with source, vendored dependencies, pinned build inputs, specifications, vectors, platform binaries, and an offline locked test gate.
- Added release and recovery runbooks with two-person verification, bit-rot, media-refresh, restore-drill, and cryptographic-migration schedules.
- Added the public deterministic ML-KEM seed fixture needed to exercise the known-good archive from an isolated recovery kit.

## 0.0.3 - 2026-09-06

### Release automation

- Changed `v*` tag builds from temporary Actions artifacts to GitHub Releases with a packaged Linux x86-64 binary and SHA-256 checksum.

### Phase 3 key lifecycle and custody

- Added `key-info` validation for root keys, ML-KEM public keys, ML-KEM seeds, and archive routing headers without displaying secret bytes.
- Added matching SHA-256 public-key fingerprints for ML-KEM public/seed pairing.
- Added the bounded, secret-free `PQINVENTORY01` custody inventory with init, add, list, check, locate, and lifecycle status commands.
- Added optional root-key ID and epoch assertions to `seal` for safer automation.
- Added a root-secret provider boundary suitable for future non-exportable backends while retaining the file provider.
- Changed secret and inventory creation to apply Unix mode `0600` at file creation time.
- Added key lifecycle, rotation, compromise, destruction, provider, and independent recovery-drill guidance.
- Expanded the demo and test suite for inventory, key validation, redundant recovery copies, permissions, and root expectation failures.

## 0.0.2 - 2026-09-06

### Phase 2 hostile-input hardening

- Enforced maximum plaintext size of 1 TiB and at most 2^20 data frames per archive.
- Added checked arithmetic and bounded all archive-controlled header and frame allocations.
- Changed seal and restore to use restrictive same-directory temporary files, atomic no-replace publication, overwrite refusal, and failure cleanup.
- Reduced restore to one archive/KEM pass while keeping the encrypted filename as the default destination.
- Replaced deprecated AES-GCM nonce construction and enabled warning-free lint/build gates.
- Tightened filename validation without changing the frozen v2 Unicode byte representation.
- Added end-to-end, limit, corruption, truncation, key mismatch, path, collision, permission, storage-failure, and nonce-uniqueness tests.
- Added production-parser fuzz targets for headers, root keys, and frame traversal plus CI fuzz smoke runs.

### Phase 1 format baseline

- Froze byte-level specifications for `PQBACK02` and `PQROOT02`.
- Added a strict compatibility and migration policy plus canonical decoder error categories.
- Added deterministic vectors for empty, one-chunk, multi-chunk, Unicode-filename, and maximum-filename archives.
- Added complete canonical archive/root-key hex fixtures and component checksums.
- Added tests that fail on unintended format, cryptographic-domain, or fixture changes.
- Rejects undefined data-frame flag bits.

### Phase 0 safety baseline

- Marked the CLI and documentation as experimental and unaudited.
- Removed the combined `keygen` command so normal production workflows cannot generate both recovery secret classes together.
- Kept `demo` as a disposable teaching workflow and added an explicit runtime warning that its co-located keys are unsafe for real archives.
- Defined the threat model, trust boundaries, supported environments, retention policy, and unsupported use cases.
- Established provisional Phase 2 limits of 1 TiB plaintext and 2^20 data chunks per archive.
- Deferred sender authentication/provenance until a signing-key trust, distribution, rotation, and revocation model is approved.
- Added a risk register mapping assessment findings to owners, phases, and release gates.

The package remains a reference implementation and is not approved as the sole protection for critical data.
